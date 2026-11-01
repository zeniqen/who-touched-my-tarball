"""Benchmark report rendering."""

from __future__ import annotations

import json
from pathlib import Path


def render_terminal(summary, console) -> None:
    console.print(f"Total: {summary.total} (malicious={summary.malicious}, benign={summary.benign})")
    console.print(f"TP={summary.tp} TN={summary.tn} FP={summary.fp} FN={summary.fn} inconclusive={summary.inconclusive}")
    console.print(f"Precision={summary.precision:.3f} Recall={summary.recall:.3f} F1={summary.f1:.3f} FPR={summary.fpr:.3f}")


def write_json(path: Path, summary) -> None:
    import dataclasses
    path.write_text(json.dumps(dataclasses.asdict(summary), indent=2, default=str))
