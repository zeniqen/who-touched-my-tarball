"""Benchmark data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Scenario:
    scenario_id: str
    name: str
    ecosystem: str
    category: str
    label: str  # "malicious" or "benign"
    artifact_path: Path
    source_path: Path
    expected_signals: list[str] = field(default_factory=list)
    severity: str = "medium"
    fixture_sha256: str | None = None


@dataclass
class ScenarioResult:
    scenario_id: str
    label: str
    predicted_malicious: bool
    verdict: str
    risk_score: int
    duration_seconds: float
    findings: list[str] = field(default_factory=list)
    triggered_signals: list[str] = field(default_factory=list)
    matched_signals: list[str] = field(default_factory=list)
    error: str | None = None
    inconclusive: bool = False
    infrastructure_failure: bool = False


@dataclass
class RunSummary:
    run_id: str
    dataset_version: str
    started_at: str
    finished_at: str
    total: int
    malicious: int
    benign: int
    tp: int
    tn: int
    fp: int
    fn: int
    inconclusive: int
    precision: float
    recall: float
    specificity: float
    f1: float
    accuracy: float
    fpr: float
    fnr: float
    results: list[ScenarioResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
