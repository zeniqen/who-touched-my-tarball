"""Benchmark runner invoking the real analyzer."""

from __future__ import annotations

import time

from ..analyzer import AnalyzeOptions, analyze_local
from .models import Scenario, ScenarioResult


def run_scenario(scenario: Scenario) -> ScenarioResult:
    start = time.monotonic()
    try:
        report = analyze_local(scenario.artifact_path, str(scenario.source_path), opts=AnalyzeOptions(use_previous=False, ai=None))
        dur = time.monotonic() - start
        predicted = report.verdict == "SUSPICIOUS"  # REVIEW is normal for many legitimate releases
        triggered = []
        for f in report.findings:
            for sig in getattr(f, "signals", []) or []:
                triggered.append(getattr(sig, "rule", None) or getattr(sig, "description", ""))
        triggered = sorted(set(x for x in triggered if x))
        matched = [s for s in (scenario.expected_signals or []) if s in triggered]
        return ScenarioResult(
            scenario_id=scenario.scenario_id,
            label=scenario.label,
            predicted_malicious=predicted,
            verdict=report.verdict,
            risk_score=report.risk_score,
            duration_seconds=dur,
            findings=[f.path for f in report.findings],
            triggered_signals=triggered,
            matched_signals=matched,
        )
    except Exception as exc:  # noqa: BLE001
        dur = time.monotonic() - start
        return ScenarioResult(
            scenario_id=scenario.scenario_id,
            label=scenario.label,
            predicted_malicious=False,
            verdict="ERROR",
            risk_score=0,
            duration_seconds=dur,
            error=str(exc),
            inconclusive=True,
            infrastructure_failure=True,
        )


def run_scenarios(scenarios, *, timeout=None):
    results = []
    for scen in scenarios:
        results.append(run_scenario(scen))
    return results
