"""Provenance verification data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    VERIFIED_UNTRUSTED = "VERIFIED_UNTRUSTED"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    INVALID_CERTIFICATE = "INVALID_CERTIFICATE"
    INVALID_ATTESTATION = "INVALID_ATTESTATION"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    MISSING_PROVENANCE = "MISSING_PROVENANCE"
    INCOMPLETE_PROVENANCE = "INCOMPLETE_PROVENANCE"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    VERIFICATION_UNAVAILABLE = "VERIFICATION_UNAVAILABLE"
    RETRIEVAL_ERROR = "RETRIEVAL_ERROR"


class TrustStatus(str, Enum):
    TRUSTED_IDENTITY = "TRUSTED_IDENTITY"
    UNTRUSTED_IDENTITY = "UNTRUSTED_IDENTITY"
    UNKNOWN_IDENTITY = "UNKNOWN_IDENTITY"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    SOURCE_REVISION_MISMATCH = "SOURCE_REVISION_MISMATCH"
    WORKFLOW_MISMATCH = "WORKFLOW_MISMATCH"
    INCOMPLETE_IDENTITY = "INCOMPLETE_IDENTITY"


class RetrievalStatus(str, Enum):
    SUCCESS = "SUCCESS"
    NOT_FOUND = "NOT_FOUND"
    ERROR = "ERROR"
    UNAVAILABLE = "UNAVAILABLE"


class SignatureStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    NOT_CHECKED = "NOT_CHECKED"


class CertificateStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    NOT_CHECKED = "NOT_CHECKED"


class BindingStatus(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NOT_CHECKED = "NOT_CHECKED"


class AttestationStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    INCOMPLETE = "INCOMPLETE"
    NOT_CHECKED = "NOT_CHECKED"


@dataclass
class ProvenanceDimensions:
    retrieval: RetrievalStatus = RetrievalStatus.NOT_FOUND
    signature: SignatureStatus = SignatureStatus.NOT_CHECKED
    certificate: CertificateStatus = CertificateStatus.NOT_CHECKED
    artifact_binding: BindingStatus = BindingStatus.NOT_CHECKED
    attestation: AttestationStatus = AttestationStatus.NOT_CHECKED
    identity_trust: TrustStatus = TrustStatus.UNKNOWN_IDENTITY


@dataclass
class ProvenanceResult:
    ecosystem: str
    package_name: str
    package_version: str

    status: VerificationStatus = VerificationStatus.MISSING_PROVENANCE
    trust_status: TrustStatus = TrustStatus.UNKNOWN_IDENTITY

    dimensions: ProvenanceDimensions = field(default_factory=ProvenanceDimensions)

    attestation_found: bool = False
    signature_valid: bool = False
    certificate_valid: bool = False
    issuer: str | None = None
    signer_identity: str | None = None

    subject_digest: str | None = None
    actual_artifact_digest: str | None = None

    repository_url: str | None = None
    source_commit: str | None = None
    source_ref: str | None = None
    build_workflow: str | None = None
    builder_identity: str | None = None

    transparency_verified: bool | None = None

    verification_errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    raw_attestation: dict[str, Any] | list[Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        import dataclasses

        def conv(o):
            if isinstance(o, Path):
                return str(o)
            if isinstance(o, Enum):
                return o.value
            if dataclasses.is_dataclass(o) and not isinstance(o, type):
                return {k: conv(v) for k, v in dataclasses.asdict(o).items()}
            if isinstance(o, (list, tuple)):
                return [conv(x) for x in o]
            if isinstance(o, dict):
                return {k: conv(v) for k, v in o.items()}
            return o

        return conv(self)
