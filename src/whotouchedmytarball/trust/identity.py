"""Repository identity normalization (reuses provenance normalizer concepts)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .models import IdentityObservation, TrustBaseline


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


def repo_owner_name(url: str | None) -> tuple[str | None, str | None]:
    nu = normalize_repo_url(url)
    if not nu:
        return None, None
    try:
        parsed = urlparse(nu)
        parts = [p for p in parsed.path.split("/") if p]
    except Exception:
        return None, None
    if len(parts) < 2:
        return None, None
    return parts[0], parts[1]


def repo_identity(url: str | None) -> tuple[str | None, str | None, str | None]:
    """Return normalized url, owner, name."""
    nu = normalize_repo_url(url)
    owner, name = repo_owner_name(nu)
    return nu, owner, name


@dataclass
class ObservedIdentity:
    repository_url: str | None
    repository_owner: str | None
    repository_name: str | None
    source_commit: str | None
    source_ref: str | None
    publisher_identity: str | None
    issuer: str | None
    signer_identity: str | None
    build_workflow: str | None
    builder_identity: str | None
    provenance_status: str | None
    artifact_digest: str | None


def from_observation(obs: IdentityObservation) -> ObservedIdentity:
    nu, owner, name = repo_identity(obs.repository_url)
    return ObservedIdentity(
        repository_url=nu,
        repository_owner=owner,
        repository_name=name,
        source_commit=obs.source_commit,
        source_ref=obs.source_ref,
        publisher_identity=obs.publisher_identity,
        issuer=obs.issuer,
        signer_identity=obs.signer_identity,
        build_workflow=obs.build_workflow,
        builder_identity=obs.builder_identity,
        provenance_status=obs.provenance_status,
        artifact_digest=obs.artifact_digest,
    )


def baseline_to_observed(b: TrustBaseline) -> ObservedIdentity:
    nu, owner, name = repo_identity(b.repository_url)
    return ObservedIdentity(
        repository_url=nu,
        repository_owner=owner,
        repository_name=name,
        source_commit=b.source_commit,
        source_ref=b.source_ref,
        publisher_identity=b.publisher_identity,
        issuer=b.issuer,
        signer_identity=b.signer_identity,
        build_workflow=b.build_workflow,
        builder_identity=b.builder_identity,
        provenance_status=b.provenance_status,
        artifact_digest=None,
    )
