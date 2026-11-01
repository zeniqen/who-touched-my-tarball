"""FastAPI control centre for the WTMT Python CLI and analysis engine."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from . import jobs as jobmanager  # noqa: E402

WORKSPACE = ROOT / ".wtmt-web"
UPLOADS = WORKSPACE / "uploads"
WORKSPACE.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="WTMT Security Lab", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(ROOT / "web" / "frontend")), name="static")

ALLOWED_ARTIFACT_SUFFIXES = {".tgz", ".tar.gz", ".whl", ".zip", ".tar"}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
ALLOWED_KINDS = {
    "check", "diff", "tamper", "redteam", "verify-build", "verify-provenance",
    "watch-add", "watch-remove", "watch-list", "watch-run",
    "trust-show", "trust-history", "trust-changes", "trust-baseline",
    "trust-approve", "trust-reject", "trust-acknowledge",
    "benchmark-run", "benchmark-list", "benchmark-compare", "version",
}


def _parse_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).lower() in {"1", "true", "yes", "on"}


def _add_flag(cmd: list[str], *parts: str) -> None:
    cmd.extend(parts)


def build_command(kind: str, params: dict[str, Any], job_id: str) -> tuple[list[str], Path, int, dict[str, Any]]:
    if kind not in ALLOWED_KINDS:
        raise HTTPException(status_code=400, detail=f"Unsupported operation: {kind}")

    jobdir = WORKSPACE / "jobs" / job_id
    timeout = 600
    meta: dict[str, Any] = {"report_json": str(jobdir / "report.json")}
    py = sys.executable
    cmd: list[str] = []

    if kind == "check":
        cmd = ["check", params["ecosystem"], params["package"]]
        if params.get("version"):
            cmd.append(params["version"])
        if params.get("dist", "auto"):
            cmd.extend(["--dist", params.get("dist", "auto")])
        if params.get("source"):
            cmd.extend(["--source", params["source"]])
        if params.get("ref"):
            cmd.extend(["--ref", params["ref"]])
        _add_flag(cmd, "--previous" if _parse_bool(params.get("previous", True)) else "--no-previous")
        _add_flag(cmd, "--ai" if _parse_bool(params.get("ai", False)) else "--no-ai")
        if params.get("model"):
            cmd.extend(["--model", params["model"]])
        if params.get("fallback_model"):
            cmd.extend(["--fallback-model", params["fallback_model"]])
        if params.get("ollama_host"):
            cmd.extend(["--ollama-host", params["ollama_host"]])
        if params.get("max_ai"):
            cmd.extend(["--max-ai", str(params["max_ai"])])
        cmd.extend(["--json", str(jobdir / "report.json")])
        if _parse_bool(params.get("md_output", False)):
            cmd.extend(["--md", str(jobdir / "report.md")])
        if _parse_bool(params.get("show_all", False)):
            _add_flag(cmd, "--all")
        if _parse_bool(params.get("quiet", False)):
            _add_flag(cmd, "--quiet")
        if _parse_bool(params.get("exit_zero", False)):
            _add_flag(cmd, "--exit-zero")

    elif kind == "diff":
        cmd = ["diff", params["artifact"], params.get("source") or ""]
        if params.get("ecosystem"):
            cmd.extend(["--ecosystem", params["ecosystem"]])
        if params.get("ref"):
            cmd.extend(["--ref", params["ref"]])
        if params.get("previous_artifact"):
            cmd.extend(["--previous", params["previous_artifact"]])
        if params.get("name"):
            cmd.extend(["--name", params["name"]])
        if params.get("version"):
            cmd.extend(["--version", params["version"]])
        _add_flag(cmd, "--ai" if _parse_bool(params.get("ai", False)) else "--no-ai")
        if params.get("model"):
            cmd.extend(["--model", params["model"]])
        if params.get("fallback_model"):
            cmd.extend(["--fallback-model", params["fallback_model"]])
        if params.get("ollama_host"):
            cmd.extend(["--ollama-host", params["ollama_host"]])
        if params.get("max_ai"):
            cmd.extend(["--max-ai", str(params["max_ai"])])
        cmd.extend(["--json", str(jobdir / "report.json")])
        if _parse_bool(params.get("md_output", False)):
            cmd.extend(["--md", str(jobdir / "report.md")])
        if _parse_bool(params.get("show_all", False)):
            _add_flag(cmd, "--all")
        if _parse_bool(params.get("quiet", False)):
            _add_flag(cmd, "--quiet")
        if _parse_bool(params.get("exit_zero", False)):
            _add_flag(cmd, "--exit-zero")

    elif kind == "tamper":
        cmd = ["tamper"]
        if params.get("file"):
            cmd.extend(["--file", params["file"]])
        else:
            if params.get("ecosystem"):
                cmd.append(params["ecosystem"])
            if params.get("package"):
                cmd.append(params["package"])
            if params.get("version"):
                cmd.append(params["version"])
        if params.get("attack"):
            cmd.extend(["--attack", params["attack"]])
        if params.get("dist"):
            cmd.extend(["--dist", params["dist"]])
        out_dir = jobdir / "tampered"
        cmd.extend(["--out", str(out_dir)])
        if _parse_bool(params.get("list_attacks", False)):
            cmd.append("--list")
        meta["redteam_out"] = str(out_dir)

    elif kind == "redteam":
        keep = jobdir / "redteam"
        cmd = ["redteam"]
        if params.get("file"):
            cmd.extend(["--file", params["file"]])
        else:
            if params.get("ecosystem"):
                cmd.append(params["ecosystem"])
            if params.get("package"):
                cmd.append(params["package"])
            if params.get("version"):
                cmd.append(params["version"])
        if params.get("source"):
            cmd.extend(["--source", params["source"]])
        if params.get("ref"):
            cmd.extend(["--ref", params["ref"]])
        if params.get("previous_artifact"):
            cmd.extend(["--previous", params["previous_artifact"]])
        if params.get("dist"):
            cmd.extend(["--dist", params["dist"]])
        attacks = params.get("attacks") or params.get("attack_list")
        if not attacks and params.get("attack") and str(params.get("single", "yes")).lower() not in {"no", "false", "0", "all"}:
            attacks = [params["attack"]]
        for attack in (attacks or []):
            cmd.extend(["--attack", str(attack)])
        cmd.extend(["--keep", str(keep)])
        _add_flag(cmd, "--ai" if _parse_bool(params.get("ai", False)) else "--no-ai")
        if params.get("model"):
            cmd.extend(["--model", params["model"]])
        if params.get("fallback_model"):
            cmd.extend(["--fallback-model", params["fallback_model"]])
        if params.get("ollama_host"):
            cmd.extend(["--ollama-host", params["ollama_host"]])
        if params.get("max_ai"):
            cmd.extend(["--max-ai", str(params["max_ai"])])
        cmd.extend(["--json", str(jobdir / "report.json")])
        if _parse_bool(params.get("quiet", False)):
            _add_flag(cmd, "--quiet")
        meta["keep"] = str(keep)

    elif kind == "verify-build":
        cmd = ["verify-build", params["ecosystem"], params["spec"]]
        if params.get("timeout"):
            cmd.extend(["--timeout", str(params["timeout"])])
        if params.get("memory_limit"):
            cmd.extend(["--memory-limit", str(params["memory_limit"])])
        if params.get("cpu_limit"):
            cmd.extend(["--cpu-limit", str(params["cpu_limit"])])
        if params.get("network_policy"):
            cmd.extend(["--network-policy", params["network_policy"]])
        if params.get("output") is not None:
            cmd.extend(["--output", str(jobdir / "output.json")])
        if params.get("source"):
            cmd.extend(["--source", params["source"]])
        if params.get("ref"):
            cmd.extend(["--ref", params["ref"]])
        if _parse_bool(params.get("keep_build_artifacts", False)):
            _add_flag(cmd, "--keep-build-artifacts")
        if _parse_bool(params.get("verbose", False)):
            _add_flag(cmd, "--verbose")

    elif kind == "verify-provenance":
        cmd = ["verify-provenance", params["ecosystem"], params["spec"]]
        if params.get("expected_repository"):
            cmd.extend(["--expected-repository", params["expected_repository"]])
        if params.get("expected_commit"):
            cmd.extend(["--expected-commit", params["expected_commit"]])
        if params.get("expected_workflow"):
            cmd.extend(["--expected-workflow", params["expected_workflow"]])
        cmd.extend(["--output", str(jobdir / "output.json")])
        if _parse_bool(params.get("json_out", False)):
            _add_flag(cmd, "--json")
        if _parse_bool(params.get("verbose", False)):
            _add_flag(cmd, "--verbose")
        if _parse_bool(params.get("no_cache", False)):
            _add_flag(cmd, "--no-cache")
        if _parse_bool(params.get("strict", False)):
            _add_flag(cmd, "--strict")

    elif kind == "watch-add":
        cmd = ["watch", "add", params["ecosystem"], params["package"]]
        if params.get("baseline"):
            cmd.extend(["--baseline", params["baseline"]])

    elif kind == "watch-remove":
        cmd = ["watch", "remove", params["ecosystem"], params["package"]]

    elif kind == "watch-list":
        cmd = ["watch", "list"]

    elif kind == "watch-run":
        out_dir = jobdir / "reports"
        cmd = ["watch", "run", "--out", str(out_dir)]
        if params.get("interval"):
            cmd.extend(["--interval", str(params["interval"])])
        _add_flag(cmd, "--ai" if _parse_bool(params.get("ai", False)) else "--no-ai")
        if params.get("model"):
            cmd.extend(["--model", params["model"]])
        if params.get("fallback_model"):
            cmd.extend(["--fallback-model", params["fallback_model"]])
        if params.get("ollama_host"):
            cmd.extend(["--ollama-host", params["ollama_host"]])
        if params.get("max_ai"):
            cmd.extend(["--max-ai", str(params["max_ai"])])
        meta["out_dir"] = str(out_dir)

    elif kind == "trust-show":
        cmd = ["trust", "show", params["ecosystem"], params["package"]]

    elif kind == "trust-history":
        cmd = ["trust", "history", params["ecosystem"], params["package"]]

    elif kind == "trust-changes":
        cmd = ["trust", "changes", params["ecosystem"], params["package"]]

    elif kind == "trust-baseline":
        cmd = ["trust", "baseline", params["ecosystem"], params["package"]]

    elif kind == "trust-approve":
        cmd = ["trust", "approve", params["ecosystem"], params["package"], "--change-id", str(params["change_id"])]

    elif kind == "trust-reject":
        cmd = ["trust", "reject", params["ecosystem"], params["package"], "--change-id", str(params["change_id"])]

    elif kind == "trust-acknowledge":
        cmd = ["trust", "acknowledge", params["ecosystem"], params["package"], "--change-id", str(params["change_id"])]

    elif kind == "benchmark-run":
        path = jobdir / "benchmark.json"
        cmd = ["benchmark", "run", "--output", str(path)]
        if params.get("scenario"):
            cmd.extend(["--scenario", params["scenario"]])

    elif kind == "benchmark-list":
        # Typer exposes two "list" commands with the same name; this invokes the scenario list path.
        cmd = ["benchmark", "list"]

    elif kind == "benchmark-compare":
        cmd = ["benchmark", "compare", "--baseline", params["baseline"], "--current", params["current"]]

    elif kind == "version":
        cmd = ["version"]

    full = [py, "-m", "whotouchedmytarball.cli", *cmd]
    timeout = int(params.get("timeout_override", timeout))
    if kind in {"redteam", "verify-build", "watch-run"}:
        timeout = max(timeout, 1200)
    return full, jobdir, timeout, meta


class JobRequest(BaseModel):
    kind: str
    params: dict[str, Any] = {}

@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "root": str(ROOT)}


@app.get("/api/attacks")
def attacks() -> dict[str, Any]:
    from whotouchedmytarball.redteam import ATTACKS

    return {key: {"title": value.title, "incident": value.incident, "formats": list(value.formats)} for key, value in ATTACKS.items()}


@app.get("/api/inventory")
def inventory() -> dict[str, Any]:
    return {
        "modules": [
            "Dashboard", "Package Analysis", "Source Comparison", "Red-Team Lab",
            "Reproducible Build Verification", "Provenance Verification", "Trust Continuity",
            "Detection Benchmarking", "Monitoring", "Reports and History", "Advanced Command Builder",
        ],
        "supported_kinds": sorted(ALLOWED_KINDS),
    }


@app.post("/api/uploads")
async def upload_artifact(file: UploadFile = File(...)):
    suffix = "".join(Path(file.filename or "").suffixes).lower()
    if suffix not in ALLOWED_ARTIFACT_SUFFIXES:
        raise HTTPException(status_code=400, detail=f"Unsupported artifact type: {suffix}")
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Artifact is too large.")
    upload_id = f"upload-{int(__import__('time').time() * 1000)}"
    dst = UPLOADS / upload_id
    dst.mkdir(parents=True, exist_ok=True)
    path = dst / (file.filename or "artifact")
    path.write_bytes(content)
    return {"upload_id": upload_id, "filename": file.filename, "path": str(path), "size": len(content)}


@app.post("/api/jobs")
def create_job(request: JobRequest):
    job_id = None
    import uuid
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    jobdir = WORKSPACE / "jobs" / job_id
    command, _, timeout, meta = build_command(request.kind, request.params, job_id)
    job = jobmanager.create_job(request.kind, command, timeout, jobdir)
    job.result["meta"] = meta
    return {"job_id": job.id, "command": command, "meta": meta}


@app.get("/api/jobs")
def list_jobs():
    return [j.snapshot() for j in sorted(jobmanager.JOBS.values(), key=lambda x: x.id, reverse=True)]


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = jobmanager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job.snapshot()


@app.get("/api/jobs/{job_id}/logs")
def job_logs(job_id: str, offset: int = 0):
    job = jobmanager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"offset": offset, "lines": job.logs_since(offset), "status": job.status, "total": len(job.logs)}


@app.get("/api/jobs/{job_id}/stream")
def stream_job(job_id: str):
    job = jobmanager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    def generate():
        sent = 0
        while True:
            new_lines = job.logs_since(sent)
            for line in new_lines:
                yield f"data: {json.dumps({'line': line})}\n\n"
            sent += len(new_lines)
            snapshot = job.snapshot()
            if snapshot["status"] != "running" and sent >= snapshot["log_count"]:
                yield f"event: done\ndata: {json.dumps(snapshot)}\n\n"
                break
            import time
            time.sleep(0.2)

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.get("/api/files/{job_id}/{file_path:path}")
def download_file(job_id: str, file_path: str):
    job = jobmanager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    full = (job.workdir / file_path).resolve()
    if not str(full).startswith(str(job.workdir.resolve())):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not full.exists() or not full.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(full, filename=full.name)


@app.get("/", response_class=HTMLResponse)
def index():
    return (ROOT / "web" / "frontend" / "index.html").read_text()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web.backend.main:app", host="0.0.0.0", port=8000, reload=True)
