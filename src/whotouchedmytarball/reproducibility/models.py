"""Data models for reproducible build verification."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class VerificationStatus(str, Enum):
    EXACT_MATCH = "EXACT_MATCH"
    NORMALIZED_MATCH = "NORMALIZED_MATCH"
    CONTENT_MISMATCH = "CONTENT_MISMATCH"
    MISSING_FILES = "MISSING_FILES"
    UNEXPECTED_FILES = "UNEXPECTED_FILES"
    BUILD_FAILURE = "BUILD_FAILURE"
    SOURCE_REVISION_MISMATCH = "SOURCE_REVISION_MISMATCH"
    INSUFFICIENT_BUILD_INFORMATION = "INSUFFICIENT_BUILD_INFORMATION"
    UNSUPPORTED_BUILD_SYSTEM = "UNSUPPORTED_BUILD_SYSTEM"
    ENVIRONMENT_UNAVAILABLE = "ENVIRONMENT_UNAVAILABLE"
    VERIFICATION_ERROR = "VERIFICATION_ERROR"


class NetworkPolicy(str, Enum):
    NONE = "none"
    LIMITED = "limited"
    FULL = "full"


@dataclass
class BuildLimits:
    timeout: int = 600  # seconds
    cpu: float = 2.0
    memory_mb: int = 2048
    disk_mb: int = 4096


@dataclass
class ProvenanceInfo:
    repository: str | None = None
    commit: str | None = None
    tag: str | None = None
    registry_version: str | None = None


@dataclass
class BuildEnvironmentInfo:
    image: str = ""
    toolchain: dict[str, str] = field(default_factory=dict)
    runtime_version: str = ""
    os: str = ""
    architecture: str = ""
    docker_available: bool = False
    network_policy: NetworkPolicy = NetworkPolicy.NONE


@dataclass
class BuildRecipe:
    ecosystem: str
    build_system: str = ""
    build_commands: list[str] = field(default_factory=list)
    install_commands: list[str] = field(default_factory=list)
    required_tools: list[str] = field(default_factory=list)
    lockfile: str | None = None
    source_commit: str | None = None
    confidence: float = 0.0
    notes: list[str] = field(default_factory=list)


@dataclass
class BuildResult:
    success: bool
    exit_code: int = 0
    status: VerificationStatus = VerificationStatus.VERIFICATION_ERROR
    build_command: str = ""
    build_tool: str = ""
    runtime_version: str = ""
    os: str = ""
    architecture: str = ""
    duration_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    artifact_paths: list[Path] = field(default_factory=list)
    dependency_versions: dict[str, str] = field(default_factory=dict)
    environment: BuildEnvironmentInfo = field(default_factory=BuildEnvironmentInfo)
    notes: list[str] = field(default_factory=list)


@dataclass
class FileComparison:
    path: str
    status: str  # "identical" | "modified" | "missing" | "unexpected"
    registry_hash: str | None = None
    rebuilt_hash: str | None = None
    difference_type: str = ""
    affects_runtime: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    diff_excerpt: str = ""


@dataclass
class ArtifactComparison:
    original_hash: str = ""
    rebuilt_hash: str = ""
    normalized_original_hash: str = ""
    normalized_rebuilt_hash: str = ""
    files_matched: list[str] = field(default_factory=list)
    files_mismatched: list[FileComparison] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    unexpected_files: list[str] = field(default_factory=list)
    metadata_differences: list[dict[str, Any]] = field(default_factory=list)
    normalization_rules: list[str] = field(default_factory=list)
    normalized: bool = False


@dataclass
class VerificationResult:
    status: VerificationStatus
    ecosystem: str
    package: str
    version: str
    source_repository: str | None = None
    source_commit: str | None = None
    registry_artifact_hash: str = ""
    rebuilt_artifact_hash: str = ""
    normalized_artifact_hash: str | None = None
    build_environment: BuildEnvironmentInfo = field(default_factory=BuildEnvironmentInfo)
    build_command: str = ""
    build_duration_seconds: float = 0.0
    files_matched: int = 0
    files_mismatched: int = 0
    missing_files: list[str] = field(default_factory=list)
    unexpected_files: list[str] = field(default_factory=list)
    comparison: ArtifactComparison | None = None
    build_logs: str = ""
    notes: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    build_recipe: BuildRecipe | None = None

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
