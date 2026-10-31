"""Deterministic identity comparison engine."""

from __future__ import annotations

from datetime import datetime, timezone

from .identity import ObservedIdentity, baseline_to_observed, from_observation
from .models import TrustBaseline, IdentityObservation, TrustChange, ChangeStatus


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _change(field, prev, curr, severity, category, explanation, evidence) -> TrustChange:
    return TrustChange(
        field=field,
        previous_value=None if prev is None else str(prev),
        current_value=None if curr is None else str(curr),
        severity=severity,
        category=category,
        explanation=explanation,
        evidence=evidence or {},
        first_detected_at=_now(),
        status=ChangeStatus.NEW,
    )


def detect_changes(baseline: TrustBaseline | None, observation: IdentityObservation,
                   *, version_previously_seen: bool = False) -> list[TrustChange]:
    changes: list[TrustChange] = []
    if baseline is None:
        # Initial observation: no changes to report; remains observed (not trusted).
        return changes

    prev = baseline_to_observed(baseline)
    curr = from_observation(observation)
    evidence_base = {"package": observation.package_name, "ecosystem": observation.ecosystem,
                     "version": observation.version, "observed_at": observation.observed_at}

    # Repository URL
    if prev.repository_url and curr.repository_url and prev.repository_url != curr.repository_url:
        owner_changed = prev.repository_owner != curr.repository_owner
        name_changed = prev.repository_name != curr.repository_name
        if owner_changed and name_changed:
            sev = "critical"
            cat = "repository_replaced"
        elif owner_changed:
            sev = "high"
            cat = "repository_owner_changed"
        elif name_changed:
            sev = "medium"
            cat = "repository_renamed"
        else:
            sev = "low"
            cat = "repository_url_changed"
        changes.append(_change("repository_url", prev.repository_url, curr.repository_url, sev, cat,
                               "Repository identity changed.", {**evidence_base}))

    # Source commit
    if prev.source_commit and curr.source_commit and prev.source_commit != curr.source_commit:
        # New version expected new commit; same/old version mutation is suspicious.
        if version_previously_seen:
            sev = "critical"
            cat = "source_commit_mutated_for_known_version"
        else:
            sev = "info"
            cat = "source_commit_changed_for_new_version"
        changes.append(_change("source_commit", prev.source_commit, curr.source_commit, sev, cat,
                               "Source commit changed.", evidence_base))

    # Source ref
    if prev.source_ref and curr.source_ref and prev.source_ref != curr.source_ref:
        changes.append(_change("source_ref", prev.source_ref, curr.source_ref, "medium", "source_ref_changed",
                               "Source reference changed.", evidence_base))

    # Publisher identity
    if prev.publisher_identity and curr.publisher_identity and prev.publisher_identity != curr.publisher_identity:
        changes.append(_change("publisher_identity", prev.publisher_identity, curr.publisher_identity, "high",
                               "publisher_changed", "Publisher identity changed.", evidence_base))

    # Issuer
    if prev.issuer and curr.issuer and prev.issuer != curr.issuer:
        changes.append(_change("issuer", prev.issuer, curr.issuer, "high", "issuer_changed",
                               "OIDC issuer changed.", evidence_base))

    # Signer
    if prev.signer_identity and curr.signer_identity and prev.signer_identity != curr.signer_identity:
        changes.append(_change("signer_identity", prev.signer_identity, curr.signer_identity, "high",
                               "signer_changed", "Signing identity changed.", evidence_base))

    # Workflow
    if prev.build_workflow and curr.build_workflow and prev.build_workflow != curr.build_workflow:
        changes.append(_change("build_workflow", prev.build_workflow, curr.build_workflow, "medium",
                               "workflow_changed", "Build workflow changed.", evidence_base))

    # Builder
    if prev.builder_identity and curr.builder_identity and prev.builder_identity != curr.builder_identity:
        changes.append(_change("builder_identity", prev.builder_identity, curr.builder_identity, "medium",
                               "builder_changed", "Builder identity changed.", evidence_base))

    # Provenance status disappearance/degradation
    if prev.provenance_status in ("VERIFIED", "VERIFIED_UNTRUSTED") and curr.provenance_status not in (
            "VERIFIED", "VERIFIED_UNTRUSTED") and curr.provenance_status is not None:
        sev = "critical" if curr.provenance_status in ("INVALID_SIGNATURE", "DIGEST_MISMATCH") else "medium"
        changes.append(_change("provenance_status", prev.provenance_status, curr.provenance_status, sev,
                               "provenance_degraded", "Previously valid provenance is now invalid or missing.",
                               evidence_base))

    # Artifact digest change for already observed version
    if version_previously_seen and prev.artifact_digest and curr.artifact_digest and prev.artifact_digest != curr.artifact_digest:
        changes.append(_change("artifact_digest", prev.artifact_digest, curr.artifact_digest, "critical",
                               "artifact_digest_changed", "Artifact digest changed for an already observed version.",
                               evidence_base))

    # Current artifact digest vs baseline digest (baseline had digest)
    if (not version_previously_seen) and baseline.artifact_digest and curr.artifact_digest and baseline.artifact_digest != curr.artifact_digest:
        # baseline artifact digest differs; suspicious if version same? version unknown at baseline maybe.
        pass

    return changes
