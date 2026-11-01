"""Data models shared across the analyzer."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def step_down(self) -> Severity:
        return _BY_RANK[max(0, self.rank - 1)]

    @staticmethod
    def max(*values: Severity) -> Severity:
        return max(values, key=lambda s: s.rank) if values else Severity.INFO


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_BY_RANK = {v: k for k, v in _SEVERITY_RANK.items()}


class DiffKind(str, Enum):
    MODIFIED = "modified"  # file exists on both sides with different content
    PACKAGE_ONLY = "package_only"  # file shipped in the package but absent from source


class Category(str, Enum):
    PACKAGING_METADATA = "packaging_metadata"  # PKG-INFO, *.dist-info, *.egg-info
    BUILD_OUTPUT = "build_output"  # dist/, *.min.js, compiled files
    GENERATED = "generated"  # version files, files marked as generated
    FORMATTING = "formatting"  # whitespace / line ending differences only
    DOCUMENTATION = "documentation"  # README, LICENSE, CHANGELOG copied in at publish time
    MANIFEST_CHANGE = "manifest_change"  # package.json / setup.py / pyproject differences
    BUILD_SCRIPT = "build_script"  # configure, *.m4, install scripts, .pth files
    UNEXPLAINED = "unexplained"  # no benign explanation found
    SUSPICIOUS = "suspicious"  # strong malicious indicators


class Signal(BaseModel):
    rule: str
    description: str
    severity: Severity
    line: int | None = None
    snippet: str = ""
    explained_by: str | None = None  # why this signal was downgraded, if it was


class AIAssessment(BaseModel):
    model: str
    verdict: str  # benign | suspicious | malicious | uncertain
    confidence: float
    explanation: str
    reasons: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    path: str
    kind: DiffKind
    category: Category
    severity: Severity
    reason: str
    source_path: str | None = None
    signals: list[Signal] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    diff_excerpt: str = ""
    added_lines: int = 0
    removed_lines: int = 0
    ai: AIAssessment | None = None


class Provenance(BaseModel):
    available: bool = False
    kind: str | None = None
    repository: str | None = None
    commit: str | None = None
    ref: str | None = None
    workflow: str | None = None
    matches_source: bool | None = None
    note: str = ""


class SourceInfo(BaseModel):
    repository: str | None = None
    ref: str | None = None
    commit: str | None = None
    resolved_by: str = ""
    root_prefix: str = ""


class Report(BaseModel):
    tool_version: str
    ecosystem: str
    package: str
    version: str
    artifact: str
    artifact_integrity: str = "not checked"
    source: SourceInfo | None = None
    provenance: Provenance = Field(default_factory=Provenance)
    previous_version: str | None = None
    verdict: str  # CLEAN | REVIEW | SUSPICIOUS
    risk_score: int
    summary: str
    stats: dict[str, int] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    reproducible_build: dict | None = None
    provenance_verification: dict | None = None
    trust_continuity: dict | None = None
