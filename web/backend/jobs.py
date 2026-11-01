"""In-memory background job manager for WTMT operations."""

from __future__ import annotations

import json
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"


class Job:
    def __init__(self, job_id: str, kind: str, command: list[str], workdir: Path, timeout: int):
        self.id = job_id
        self.kind = kind
        self.command = command
        self.workdir = workdir
        self.timeout = timeout
        self.status = "queued"
        self.logs: list[str] = []
        self._lock = threading.Lock()
        self.exit_code: int | None = None
        self.started_at = datetime.utcnow().isoformat() + "Z"
        self.finished_at: str | None = None
        self.error: str | None = None
        self.result: dict[str, Any] = {"files": []}
        self.process: subprocess.Popen | None = None

    def log(self, line: str) -> None:
        with self._lock:
            self.logs.append(line)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "kind": self.kind,
                "command": self.command,
                "status": self.status,
                "exit_code": self.exit_code,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "log_count": len(self.logs),
                "result": self.result,
                "error": self.error,
            }

    def logs_since(self, offset: int) -> list[str]:
        with self._lock:
            return self.logs[offset:]


JOBS: dict[str, Job] = {}


def create_job(kind: str, command: list[str], timeout: int, workdir: Path) -> Job:
    job_id = f"job-{int(time.time() * 1000)}-{len(JOBS)}"
    job = Job(job_id, kind, command, workdir, timeout)
    workdir.mkdir(parents=True, exist_ok=True)
    JOBS[job_id] = job
    thread = threading.Thread(target=_run_job, args=(job,), daemon=True)
    thread.start()
    return job


def _append_downloadable_files(job: Job) -> None:
    names = []
    for path in sorted(job.workdir.rglob("*")):
        if path.is_file():
            relative = path.relative_to(job.workdir)
            if len(relative.parts) <= 3:
                names.append(str(relative))
    job.result["files"] = names[:100]
    for candidate in ("report.json", "report.md", "output.json", "benchmark.json", "result.json"):
        p = job.workdir / candidate
        if p.exists():
            try:
                job.result[candidate] = json.loads(p.read_text())
            except (OSError, json.JSONDecodeError):
                job.result[candidate] = None


def _reader(pipe, job: Job, prefix: str = "") -> None:
    try:
        for line in iter(pipe.readline, ""):
            if line:
                job.log(f"{prefix}{line.rstrip()}")
    finally:
        pipe.close()


def _run_job(job: Job) -> None:
    env = {
        **__import__("os").environ,
        "PYTHONPATH": str(SRC) + __import__("os").pathsep + __import__("os").environ.get("PYTHONPATH", ""),
        "WTMT_HOME": str(job.workdir.parent / "wtmt-home"),
    }
    job.status = "running"
    try:
        job.process = subprocess.Popen(
            job.command,
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        threads = [
            threading.Thread(target=_reader, args=(job.process.stdout, job), daemon=True),
            threading.Thread(target=_reader, args=(job.process.stderr, job), name=None, kwargs={"prefix": "[stderr] "}, daemon=True),
        ]
        for thread in threads:
            thread.start()
        job.process.wait(timeout=job.timeout)
        for thread in threads:
            thread.join(timeout=2)
        job.exit_code = job.process.returncode
        if job.exit_code in (0, 1, 2):
            job.status = "completed"
        else:
            job.status = "failed"
        _append_downloadable_files(job)
    except subprocess.TimeoutExpired:
        if job.process:
            job.process.kill()
        job.error = f"Command timed out after {job.timeout} seconds."
        job.status = "failed"
    except Exception as exc:  # noqa: BLE001
        job.error = str(exc)
        job.status = "failed"
    finally:
        job.finished_at = datetime.utcnow().isoformat() + "Z"


def get_job(job_id: str) -> Job | None:
    return JOBS.get(job_id)
