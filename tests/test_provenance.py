"""Provenance verification and trust continuity (PRD FR-10, FR-11, SEC-6, SEC-9). Offline: registry is faked."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
from pathlib import Path

import pytest

from whotouchedmytarball.ecosystems.base import ReleaseInfo
from whotouchedmytarball.ecosystems.npm import parse_npm_attestations
from whotouchedmytarball.provenance import verifier
from whotouchedmytarball.provenance.base import finalize_status
from whotouchedmytarball.provenance.identity import commit_match, evaluate_trust, repo_match
from whotouchedmytarball.provenance.intoto import match_subject_digest, parse_statement
from whotouchedmytarball.provenance.models import (
    AttestationStatus,
    BindingStatus,
    ProvenanceResult,
    RetrievalStatus,
    TrustStatus,
    VerificationStatus,
)
from whotouchedmytarball.trust.compare import detect_changes
from whotouchedmytarball.trust.models import IdentityObservation, TrustBaseline

COMMIT = "0123456789abcdef0123456789abcdef01234567"
REPO = "https://github.com/acme/widget"


def slsa_statement(digest: str, repo: str = REPO, algo: str = "sha256") -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "pkg:npm/widget@1.0.0", "digest": {algo: digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
                "externalParameters": {"workflow": {"repository": repo, "path": ".github/workflows/release.yml"}},
                "resolvedDependencies": [{"uri": f"git+{repo}@refs/tags/v1.0.0", "digest": {"gitCommit": COMMIT}}],
            },
        },
    }


# --- identity matching (SEC-6) -------------------------------------------------------------------

def test_commit_match_accepts_full_and_abbreviated_commits():
    assert commit_match(COMMIT, COMMIT)
    assert commit_match(COMMIT, COMMIT[:7])
    assert commit_match(COMMIT.upper(), COMMIT)


@pytest.mark.parametrize("attested", ["0", "01", "012345"])
def test_commit_match_rejects_too_short_prefixes(attested):
    """A one-character 'commit' must not match every commit that starts with that character."""
    assert not commit_match(COMMIT, attested)


@pytest.mark.parametrize("attested", [
    "https://github.com/acme/widget-evil",
    "https://github.com/acme-evil/widget",
    "https://github.com.evil.example/acme/widget",
    "https://gitlab.com/acme/widget",
])
def test_repo_match_rejects_look_alikes(attested):
    assert not repo_match(REPO, attested)


@pytest.mark.parametrize("attested", ["git+https://github.com/Acme/Widget.git", "git@github.com:acme/widget.git",
                                      "https://github.com/acme/widget/"])
def test_repo_match_accepts_equivalent_spellings(attested):
    assert repo_match(REPO, attested)


def test_evaluate_trust_flags_other_repository():
    status = evaluate_trust(expected_repo=REPO, expected_commit=None, expected_workflow=None,
                            attested_repo="https://github.com/attacker/widget", attested_commit=COMMIT,
                            attested_workflow=None)
    assert status == TrustStatus.IDENTITY_MISMATCH.value


def test_evaluate_trust_flags_other_commit():
    status = evaluate_trust(expected_repo=REPO, expected_commit=COMMIT, expected_workflow=None,
                            attested_repo=REPO, attested_commit="f" * 40, attested_workflow=None)
    assert status == TrustStatus.SOURCE_REVISION_MISMATCH.value


# --- in-toto parsing ------------------------------------------------------------------------------

def test_subject_digest_binding():
    stmt = slsa_statement("ab" * 32)
    assert match_subject_digest(stmt, "ab" * 32)
    assert match_subject_digest(stmt, "sha256:" + "AB" * 32)
    assert not match_subject_digest(stmt, "cd" * 32)


@pytest.mark.parametrize("raw, error", [
    ("{not json", "invalid JSON"),
    ([], "not an object"),
    ({"_type": "https://in-toto.io/Statement/v1", "subject": [], "predicateType": "x"}, "no subjects"),
    ({"_type": "evil", "subject": [{"name": "a", "digest": {"sha256": "x"}}], "predicateType": "x"}, "statement type"),
    ({"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "a", "digest": {"md5": "x"}}],
      "predicateType": "x"}, "sha256"),
])
def test_malformed_statements_are_rejected(raw, error):
    _, errors = parse_statement(raw)
    assert any(error in e for e in errors)


def test_npm_attestation_claims_are_parsed():
    envelope = base64.b64encode(json.dumps(slsa_statement("ab" * 32)).encode()).decode()
    doc = {"attestations": [{"predicateType": "https://slsa.dev/provenance/v1",
                             "bundle": {"dsseEnvelope": {"payload": envelope}}}]}
    prov = parse_npm_attestations(doc)
    assert prov.available and prov.repository == REPO and prov.commit == COMMIT
    assert prov.workflow == ".github/workflows/release.yml"


def test_npm_attestations_without_slsa_are_not_provenance():
    assert not parse_npm_attestations({"attestations": [{"predicateType": "https://github.com/npm/attestation"}]}).available


# --- status precedence (FR-10, SEC-6) ------------------------------------------------------------

def result_with(**dims) -> ProvenanceResult:
    r = ProvenanceResult(ecosystem="npm", package_name="widget", package_version="1.0.0")
    r.dimensions.retrieval = RetrievalStatus.SUCCESS
    r.dimensions.attestation = AttestationStatus.VALID
    for k, v in dims.items():
        setattr(r.dimensions, k, v)
    return r


def test_digest_mismatch_is_not_hidden_behind_unavailable_signature_check():
    """An attestation for different bytes is hard negative evidence, with or without sigstore."""
    assert finalize_status(result_with(artifact_binding=BindingStatus.MISMATCH)) == VerificationStatus.DIGEST_MISMATCH


def test_identity_mismatch_is_not_hidden_behind_unavailable_signature_check():
    status = finalize_status(result_with(artifact_binding=BindingStatus.MATCH,
                                         identity_trust=TrustStatus.IDENTITY_MISMATCH))
    assert status == VerificationStatus.IDENTITY_MISMATCH


def test_missing_provenance_is_reported_as_missing():
    r = result_with()
    r.dimensions.retrieval = RetrievalStatus.NOT_FOUND
    assert finalize_status(r) == VerificationStatus.MISSING_PROVENANCE


# --- end-to-end verify_provenance with a fake registry -----------------------------------------

class FakeEco:
    name = "npm"

    def __init__(self, artifact_bytes: bytes):
        self.artifact_bytes = artifact_bytes
        self.download_dirs: list[Path] = []

    def resolve(self, client, package, version, dist="auto"):
        return ReleaseInfo(ecosystem="npm", name=package, version=version or "1.0.0",
                           artifact_url="https://registry.invalid/widget-1.0.0.tgz",
                           artifact_filename="widget-1.0.0.tgz", repository_url=REPO)

    def download(self, client, release, dest_dir):
        self.download_dirs.append(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        target = dest_dir / release.artifact_filename
        target.write_bytes(self.artifact_bytes)
        return target, "verified"


@pytest.fixture
def fake_registry(monkeypatch):
    def install(artifact: bytes, attested_digest: str, repo: str = REPO) -> FakeEco:
        eco = FakeEco(artifact)
        monkeypatch.setattr(verifier, "make_client", lambda: contextlib.nullcontext(object()))
        monkeypatch.setattr(verifier, "get_ecosystem", lambda name: eco)
        monkeypatch.setattr(verifier.npm_mod, "retrieve_attestations",
                            lambda client, name, version: (True, slsa_statement(attested_digest, repo), []))
        return eco
    return install


def test_attestation_for_different_artifact_is_digest_mismatch(fake_registry):
    fake_registry(b"tampered tarball", attested_digest=hashlib.sha256(b"original tarball").hexdigest())
    result = verifier.verify_provenance("npm", "widget", "1.0.0")
    assert result.status == VerificationStatus.DIGEST_MISMATCH
    assert any("does not match" in e for e in result.verification_errors)


def test_attestation_from_other_repository_is_identity_mismatch(fake_registry):
    data = b"tarball"
    fake_registry(data, attested_digest=hashlib.sha256(data).hexdigest(), repo="https://github.com/attacker/widget")
    result = verifier.verify_provenance("npm", "widget", "1.0.0", expected_repository=REPO)
    assert result.status == VerificationStatus.IDENTITY_MISMATCH


def test_download_uses_private_temporary_directory(fake_registry):
    """SEC-9: never a fixed shared path such as /tmp/wtmt-pv, and nothing left behind."""
    data = b"tarball"
    eco = fake_registry(data, attested_digest=hashlib.sha256(data).hexdigest())
    result = verifier.verify_provenance("npm", "widget", "1.0.0")
    assert result.actual_artifact_digest == hashlib.sha256(data).hexdigest()
    (dest,) = eco.download_dirs
    assert dest != Path("/tmp") / "wtmt-pv"
    assert not dest.exists()


# --- trust continuity (FR-11) --------------------------------------------------------------------

def baseline(**kw) -> TrustBaseline:
    return TrustBaseline(ecosystem="npm", package_name="widget", repository_url=REPO,
                         first_observed_at="t1", last_observed_at="t1", **kw)


def observation(**kw) -> IdentityObservation:
    kw.setdefault("repository_url", REPO)
    return IdentityObservation(ecosystem="npm", package_name="widget", version="1.0.1", observed_at="t2", **kw)


def test_trust_repository_owner_change_is_high():
    (change,) = detect_changes(baseline(), observation(repository_url="https://github.com/attacker/widget"))
    assert change.category == "repository_owner_changed" and change.severity == "high"


def test_trust_repository_disappearing_is_flagged():
    """A hijacked release often drops the repository link; that must not look like 'no change'."""
    changes = detect_changes(baseline(), observation(repository_url=None))
    assert any(c.field == "repository_url" and c.severity == "high" for c in changes)


def test_trust_provenance_loss_is_flagged():
    changes = detect_changes(baseline(provenance_status="VERIFIED"),
                             observation(provenance_status="MISSING_PROVENANCE"))
    assert any(c.category == "provenance_degraded" for c in changes)


def test_trust_commit_mutation_for_known_version_is_critical():
    changes = detect_changes(baseline(source_commit=COMMIT), observation(source_commit="f" * 40),
                             version_previously_seen=True)
    assert any(c.severity == "critical" for c in changes)


def test_trust_new_commit_for_new_version_is_informational():
    changes = detect_changes(baseline(source_commit=COMMIT), observation(source_commit="f" * 40))
    assert [c.severity for c in changes] == ["info"]


# --- real npm response shapes, through the real NpmEcosystem (regression for `verify-provenance`) --

def npm_registry(tarball: bytes, attested_digest: str):
    """MockTransport that answers like registry.npmjs.org does for a release with provenance.

    npm attests the tarball's sha512 (not sha256), inside a base64 DSSE envelope.
    """
    import httpx

    statement = slsa_statement(attested_digest, algo="sha512")
    statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["uri"] = f"git+{REPO}@refs/heads/main"
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    att_url = "https://registry.npmjs.org/-/npm/v1/attestations/widget@1.0.0"
    dist = {"tarball": "https://registry.npmjs.org/widget/-/widget-1.0.0.tgz",
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode(),
            "attestations": {"url": att_url, "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}}
    version_doc = {"name": "widget", "version": "1.0.0", "dist": dist, "repository": {"url": f"git+{REPO}.git"}}
    routes = {
        "/widget": {"name": "widget", "dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": version_doc},
                    "time": {"1.0.0": "2026-01-01T00:00:00Z"}},
        "/widget/1.0.0": version_doc,
        "/-/npm/v1/attestations/widget@1.0.0": {"attestations": [
            {"predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
             "bundle": {"dsseEnvelope": {"payload": base64.b64encode(b'{"_type": "publish"}').decode()}}},
            {"predicateType": "https://slsa.dev/provenance/v1",
             "bundle": {"dsseEnvelope": {"payload": payload, "payloadType": "application/vnd.in-toto+json"}}},
        ]},
    }

    def handler(request):
        if request.url.path.endswith(".tgz"):
            return httpx.Response(200, content=tarball)
        doc = routes.get(request.url.path)
        return httpx.Response(200, json=doc) if doc is not None else httpx.Response(404)

    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def test_real_npm_attestation_format_is_verified(monkeypatch):
    tarball = b"genuine tarball"
    monkeypatch.setattr(verifier, "make_client", npm_registry(tarball, hashlib.sha512(tarball).hexdigest()))
    result = verifier.verify_provenance("npm", "widget", "1.0.0")
    assert result.attestation_found
    assert result.dimensions.artifact_binding == BindingStatus.MATCH
    assert result.repository_url and repo_match(REPO, result.repository_url)
    assert result.source_commit == COMMIT
    assert result.status not in (VerificationStatus.INVALID_ATTESTATION, VerificationStatus.IDENTITY_MISMATCH,
                                 VerificationStatus.MISSING_PROVENANCE)


def test_real_npm_attestation_for_other_bytes_is_digest_mismatch(monkeypatch):
    monkeypatch.setattr(verifier, "make_client", npm_registry(b"tampered", hashlib.sha512(b"genuine").hexdigest()))
    assert verifier.verify_provenance("npm", "widget", "1.0.0").status == VerificationStatus.DIGEST_MISMATCH


def test_subject_binding_accepts_sha512_subjects():
    stmt = slsa_statement("ab" * 64, algo="sha512")
    assert not parse_statement(stmt)[1]
    assert match_subject_digest(stmt, {"sha256": "cd" * 32, "sha512": "ab" * 64})
    assert not match_subject_digest(stmt, {"sha256": "cd" * 32, "sha512": "ef" * 64})
