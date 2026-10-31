"""Cryptographic provenance verification orchestrator."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
from pathlib import Path

from ..ecosystems import RegistryError, get_ecosystem, make_client
from . import npm as npm_mod
from . import pypi as pypi_mod
from .base import finalize_status, verify_attestation_structure
from .identity import evaluate_trust
from .intoto import match_subject_digest
from .models import (
    AttestationStatus,
    BindingStatus,
    CertificateStatus,
    ProvenanceResult,
    SignatureStatus,
)
from .sigstore import SIGSTORE_AVAILABLE, verify_bundle
from .slsa import extract_slsa, find_source_commit, find_source_repo, is_slsa


def _hash_file(path: Path) -> dict[str, str]:
    hashes = {"sha256": hashlib.sha256(), "sha512": hashlib.sha512()}
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            for h in hashes.values():
                h.update(chunk)
    return {algo: h.hexdigest() for algo, h in hashes.items()}


def _decode_dsse(att: dict) -> dict | None:
    envelope = (att.get("bundle") or {}).get("dsseEnvelope") or att.get("dsseEnvelope") or {}
    try:
        statement = json.loads(base64.b64decode(envelope.get("payload", ""), validate=True))
    except (ValueError, TypeError):
        return None
    return statement if isinstance(statement, dict) else None


def _select_statement(data):
    """Find the in-toto statement to verify.

    npm lists several attestations (a publish attestation and SLSA provenance), each as a Sigstore
    bundle whose statement is base64 inside a DSSE envelope. Prefer the SLSA one.
    """
    if not isinstance(data, dict):
        return data
    direct = data.get("statement") or data.get("attestation")
    if direct is not None:
        return direct
    atts = data.get("attestations")
    if isinstance(atts, list) and atts:
        candidates = [a for a in atts if isinstance(a, dict)]
        candidates.sort(key=lambda a: "slsa.dev/provenance" not in str(a.get("predicateType", "")))
        for att in candidates:
            statement = att.get("statement") or _decode_dsse(att)
            if statement is not None:
                return statement
        return atts[0]
    return data


def verify_provenance(
    ecosystem_name: str,
    package: str,
    version: str | None = None,
    *,
    artifact_digest: str | None = None,
    expected_repository: str | None = None,
    expected_commit: str | None = None,
    expected_workflow: str | None = None,
    source: str | None = None,
    no_cache: bool = False,
    progress=None,
) -> ProvenanceResult:
    progress = progress or (lambda m: None)
    result = ProvenanceResult(ecosystem=ecosystem_name, package_name=package, package_version=version or "")
    dims = result.dimensions

    # Resolve release metadata.
    try:
        with make_client() as client:
            eco = get_ecosystem(ecosystem_name)
            release = eco.resolve(client, package, version, "auto")
            result.package_version = release.version
            # download to compute digest if not provided
            digests: dict[str, str] = {"sha256": artifact_digest} if artifact_digest else {}
            if artifact_digest is None:
                try:
                    with tempfile.TemporaryDirectory(prefix="wtmt-pv-") as tmp:
                        artifact_path, _ = eco.download(client, release, Path(tmp) / "artifact")
                        digests = _hash_file(artifact_path)
                except Exception:
                    digests = {}
            result.actual_artifact_digest = digests.get("sha256")

            if ecosystem_name == "npm":
                progress("Retrieving npm attestations")
                found, data, errors = npm_mod.retrieve_attestations(client, release.name, release.version)
            else:
                progress("Retrieving PyPI attestations")
                found, data, errors = pypi_mod.retrieve_attestation(client, release.name, release.version, release.artifact_filename)
            if errors:
                result.warnings.extend(errors)
            if not found:
                # distinguish unavailable vs not found: if errors present -> retrieval error
                if errors and any("returned" in e or "failed" in e for e in errors):
                    dims.retrieval = __import__("whotouchedmytarball.provenance.models", fromlist=["RetrievalStatus"]).RetrievalStatus.ERROR
                else:
                    dims.retrieval = __import__("whotouchedmytarball.provenance.models", fromlist=["RetrievalStatus"]).RetrievalStatus.NOT_FOUND
                result.verification_errors.extend(errors)
                result.raw_attestation = data
                result.status = finalize_status(result)
                return result

            dims.retrieval = __import__("whotouchedmytarball.provenance.models", fromlist=["RetrievalStatus"]).RetrievalStatus.SUCCESS
            result.attestation_found = True
            result.raw_attestation = data

            statement = _select_statement(data)

            # Validate structure.
            errs = verify_attestation_structure(statement)
            if errs:
                dims.attestation = AttestationStatus.INVALID
                result.verification_errors.extend(errs)
            else:
                dims.attestation = AttestationStatus.VALID

            from .intoto import parse_statement
            parsed, perrs = parse_statement(statement)
            if perrs:
                result.verification_errors.extend(perrs)
                if dims.attestation == AttestationStatus.VALID:
                    dims.attestation = AttestationStatus.INVALID
            if parsed:
                # subject digest binding
                if digests:
                    if match_subject_digest(parsed, digests):
                        dims.artifact_binding = BindingStatus.MATCH
                    else:
                        dims.artifact_binding = BindingStatus.MISMATCH
                        result.verification_errors.append("attested subject digest does not match actual artifact")
                else:
                    dims.artifact_binding = BindingStatus.NOT_CHECKED
                # SLSA extraction
                if is_slsa(parsed):
                    slsa_info = extract_slsa(parsed)
                    result.repository_url = find_source_repo(slsa_info, None)
                    result.source_commit = find_source_commit(slsa_info)
                    result.build_workflow = slsa_info.get("build_type")
                    result.builder_identity = slsa_info.get("builder_id")
                    # attempt commit from materials? Keep best-effort empty.
                    # trust evaluation
                    repo_source = expected_repository
                    if repo_source is None:
                        # use release repository if available
                        repo_source = release.repository_url if hasattr(release, "repository_url") else None
                    ts = evaluate_trust(
                        expected_repo=repo_source if repo_source else expected_repository,
                        expected_commit=expected_commit,
                        expected_workflow=expected_workflow,
                        attested_repo=result.repository_url,
                        attested_commit=result.source_commit,
                        attested_workflow=result.build_workflow,
                    )
                    result.trust_status = ts
                    dims.identity_trust = ts
                else:
                    dims.attestation = AttestationStatus.INVALID
                    result.verification_errors.append("unsupported or non-SLSA predicate")
                # Sigstore verify (best effort)
                if SIGSTORE_AVAILABLE and isinstance(data, dict) and "bundle" in data:
                    ok, sigerrs, info = verify_bundle(data["bundle"], None)
                    dims.signature = SignatureStatus.VALID if ok else SignatureStatus.INVALID
                    dims.certificate = CertificateStatus.VALID if ok else CertificateStatus.INVALID
                    result.issuer = info.get("issuer")
                    result.signer_identity = info.get("signer_identity")
                    result.transparency_verified = info.get("transparency_verified")
                    result.verification_errors.extend(sigerrs)
                else:
                    # no bundle to verify
                    if dims.signature == SignatureStatus.NOT_CHECKED:
                        dims.signature = SignatureStatus.NOT_CHECKED
                    dims.certificate = CertificateStatus.NOT_CHECKED
                    result.transparency_verified = None

            # Evaluate trust if not already (for non-SLSA but valid attestation)
            if result.trust_status is None:
                result.trust_status = __import__("whotouchedmytarball.provenance.models", fromlist=["TrustStatus"]).TrustStatus.UNKNOWN_IDENTITY

            expected_repo = expected_repository or getattr(release, "repository_url", None)
            if expected_repo and result.repository_url:
                pass
            # identity trust recompute using expected inputs
            ts = evaluate_trust(
                expected_repo=expected_repository or expected_repo,
                expected_commit=expected_commit,
                expected_workflow=expected_workflow,
                attested_repo=result.repository_url,
                attested_commit=result.source_commit,
                attested_workflow=result.build_workflow,
            )
            result.trust_status = ts
            dims.identity_trust = ts

            # mark attestation incomplete if missing fields
            if result.source_commit is None and result.repository_url is None:
                if dims.attestation == AttestationStatus.VALID:
                    dims.attestation = AttestationStatus.INCOMPLETE
            result.status = finalize_status(result)
            return result
    except RegistryError as exc:
        result.verification_errors.append(str(exc))
        dims.retrieval = __import__("whotouchedmytarball.provenance.models", fromlist=["RetrievalStatus"]).RetrievalStatus.ERROR
        result.status = finalize_status(result)
        return result
    except Exception as exc:  # noqa: BLE001
        result.verification_errors.append(f"verification error: {exc}")
        dims.retrieval = __import__("whotouchedmytarball.provenance.models", fromlist=["RetrievalStatus"]).RetrievalStatus.ERROR
        result.status = finalize_status(result)
        return result
