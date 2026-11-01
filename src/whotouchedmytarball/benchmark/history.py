"""Historical benchmark run persistence."""

from __future__ import annotations

import json
import os
import platform
import subprocess
from pathlib import Path


def store_dir() -> Path:
    base = Path(os.environ.get("WTMT_HOME") or Path.home() / ".wtmt") / "benchmarks"
    base.mkdir(parents=True, exist_ok=True)
    return base


def git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        return out.stdout.strip() if out.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def save_run(summary) -> Path:
    import dataclasses
    d = store_dir()
    path = d / f"{summary.run_id}.json"
    payload = dataclasses.asdict(summary)
    payload.setdefault("metadata", {})
    payload["metadata"].update({
        "git_commit": git_commit(),
        "python_version": platform.python_version(),
        "os": platform.platform(),
    })
    import datetime
    payload["metadata"]["saved_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    path.write_text(json.dumps(payload, indent=2, default=str))
    return path


def load_run(run_id: str):
    path = store_dir() / f"{run_id}.json"
    return json.loads(path.read_text())


def list_runs():
    return sorted(p.stem for p in store_dir().glob("*.json"))
