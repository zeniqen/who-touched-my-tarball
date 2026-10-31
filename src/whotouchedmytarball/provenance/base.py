"""Shared provenance base helpers."""

from __future__ import annotations

from .models import (
    AttestationStatus,
    BindingStatus,
    CertificateStatus,
    ProvenanceResult,
    RetrievalStatus,
    SignatureStatus,
    TrustStatus,
    VerificationStatus,
)
from .sigstore import SIGSTORE_AVAILABLE


def finalize_status(result: ProvenanceResult) -> VerificationStatus:
    d = result.dimensions
    if d.retrieval == RetrievalStatus.UNAVAILABLE:
        return VerificationStatus.VERIFICATION_UNAVAILABLE
    if d.retrieval == RetrievalStatus.ERROR:
        return VerificationStatus.RETRIEVAL_ERROR
    if d.retrieval == RetrievalStatus.NOT_FOUND:
        return VerificationStatus.MISSING_PROVENANCE
    if d.signature == SignatureStatus.NOT_CHECKED and not SIGSTORE_AVAILABLE:
        return VerificationStatus.VERIFICATION_UNAVAILABLE
    if d.artifact_binding == BindingStatus.MISMATCH:
        return VerificationStatus.DIGEST_MISMATCH
    if d.signature == SignatureStatus.INVALID:
        return VerificationStatus.INVALID_SIGNATURE
    if d.certificate == CertificateStatus.INVALID:
        return VerificationStatus.INVALID_CERTIFICATE
    if d.attestation == AttestationStatus.INVALID:
        return VerificationStatus.INVALID_ATTESTATION
    if d.attestation == AttestationStatus.INCOMPLETE:
        return VerificationStatus.INCOMPLETE_PROVENANCE
    if d.identity_trust in (TrustStatus.IDENTITY_MISMATCH, TrustStatus.SOURCE_REVISION_MISMATCH,
                            TrustStatus.WORKFLOW_MISMATCH):
        return VerificationStatus.IDENTITY_MISMATCH
    if (d.signature == SignatureStatus.VALID and d.certificate == CertificateStatus.VALID
            and d.artifact_binding == BindingStatus.MATCH
            and d.attestation in (AttestationStatus.VALID, AttestationStatus.NOT_CHECKED)):
        if d.identity_trust == TrustStatus.TRUSTED_IDENTITY:
            return VerificationStatus.VERIFIED
        return VerificationStatus.VERIFIED_UNTRUSTED
    return VerificationStatus.INVALID_ATTESTATION


def verify_attestation_structure(att: dict | None) -> list[str]:
    errors = []
    if not isinstance(att, dict):
        errors.append("attestation is not an object")
        return errors
    from .intoto import parse_statement

    stmt, errs = parse_statement(att.get("statement") or att)
    errors.extend(errs)
    return errors
