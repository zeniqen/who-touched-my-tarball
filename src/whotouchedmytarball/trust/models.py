"""Trust continuity data models."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field
from enum import Enum
from typing import Any


class BaselineStatus(str, Enum):
    OBSERVED = "OBSERVED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    TRUSTED = "TRUSTED"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class ObservationKind(str, Enum):
    INITIAL = "INITIAL"
    UPDATE = "UPDATE"


class ChangeStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    RESOLVED = "RESOLVED"


@dataclass
class TrustBaseline:
    ecosystem: str
    package_name: str

    repository_url: str | None = None
    repository_owner: str | None = None
    repository_name: str | None = None

    source_commit: str | None = None
    source_ref: str | None = None

    publisher_identity: str | None = None
    issuer: str | None = None
    signer_identity: str | None = None

    build_workflow: str | None = None
    builder_identity: str | None = None

    provenance_status: str | None = None
    artifact_digest: str | None = None

    first_observed_at: str = ""
    last_observed_at: str = ""

    baseline_status: BaselineStatus = BaselineStatus.OBSERVED
    approved_at: str | None = None
    approved_by: str | None = None

    baseline_id: int | None = None


@dataclass
class IdentityObservation:
    ecosystem: str
    package_name: str
    version: str

    repository_url: str | None = None
    repository_owner: str | None = None
    repository_name: str | None = None

    source_commit: str | None = None
    source_ref: str | None = None

    publisher_identity: str | None = None
    issuer: str | None = None
    signer_identity: str | None = None

    build_workflow: str | None = None
    builder_identity: str | None = None

    provenance_status: str | None = None
    artifact_digest: str | None = None

    observed_at: str = ""
    version_first_seen: bool = True


@dataclass
class TrustChange:
    change_id: int | None = None
    ecosystem: str = ""
    package_name: str = ""

    field: str = ""
    previous_value: str | None = None
    current_value: str | None = None

    severity: str = "medium"
    category: str = ""

    explanation: str = ""
    evidence: dict[str, Any] = dc_field(default_factory=dict)

    first_detected_at: str = ""
    status: ChangeStatus = ChangeStatus.NEW
