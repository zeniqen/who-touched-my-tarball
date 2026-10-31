"""Repository/workflow identity normalization and trust evaluation."""

from __future__ import annotations

import re


def normalize_repo_url(url: str | None) -> str | None:
    if not url:
        return None
    u = url.strip()
    u = re.sub(r"^git\+", "", u)
    u = re.sub(r"^git@([^:]+):", r"https://\1/", u)
    u = re.sub(r"^(git|ssh)://(git@)?", "https://", u)
    u = u.rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    return u.lower()


def repo_match(expected: str | None, attested: str | None) -> bool:
    ne, na = normalize_repo_url(expected), normalize_repo_url(attested)
    return bool(ne and na and ne == na)


def commit_match(expected: str | None, attested: str | None) -> bool:
    if not expected or not attested:
        return False
    return expected.lower() == attested.lower() or expected.lower().startswith(attested.lower()) or attested.lower().startswith(expected.lower())


def evaluate_trust(*, expected_repo: str | None, expected_commit: str | None,
                   expected_workflow: str | None, attested_repo: str | None,
                   attested_commit: str | None, attested_workflow: str | None) -> str:
    from .models import TrustStatus

    if attested_repo is None and attested_commit is None and attested_workflow is None:
        return TrustStatus.INCOMPLETE_IDENTITY.value
    if expected_repo is None:
        # No expectation: identity is observed but unknown.
        return TrustStatus.UNKNOWN_IDENTITY.value
    if not repo_match(expected_repo, attested_repo):
        return TrustStatus.IDENTITY_MISMATCH.value
    if expected_commit and attested_commit and not commit_match(expected_commit, attested_commit):
        return TrustStatus.SOURCE_REVISION_MISMATCH.value
    if expected_workflow and attested_workflow and expected_workflow != attested_workflow:
        return TrustStatus.WORKFLOW_MISMATCH.value
    return TrustStatus.TRUSTED_IDENTITY.value
