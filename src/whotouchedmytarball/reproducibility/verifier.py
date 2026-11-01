"""Top-level reproducible build verification orchestrator."""

from __future__ import annotations

import datetime
import shutil
import tempfile
from pathlib import Path

from ..analyzer import _resolve_source
from ..archive import extract
from ..ecosystems import get_ecosystem, make_client
from .builder import DockerBuildExecutor
from .compare import classify_status, compare_artifact_trees
from .environment import docker_available
from .models import (
    BuildEnvironmentInfo,
    BuildLimits,
    NetworkPolicy,
    VerificationResult,
    VerificationStatus,
)
from .recipe import discover_recipe, has_sufficient_information, is_supported_build_system


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def verify_build(
    ecosystem_name: str,
    package: str,
    version: str | None = None,
    *,
    source: str | None = None,
    ref: str | None = None,
    timeout: int = 600,
    memory_limit: int = 2048,
    cpu_limit: float = 2.0,
    disk_limit: int = 4096,
    network_policy: NetworkPolicy = NetworkPolicy.NONE,
    keep_build_artifacts: bool = False,
    image: str = "python:3.11-slim",
    progress=None,
) -> VerificationResult:
    progress = progress or (lambda m: None)
    result = VerificationResult(
        status=VerificationStatus.VERIFICATION_ERROR,
        ecosystem=ecosystem_name,
        package=package,
        version=version or "",
        started_at=_now(),
        build_environment=BuildEnvironmentInfo(docker_available=docker_available(), network_policy=network_policy),
    )
    workdir = Path(tempfile.mkdtemp(prefix="wtmt-verify-"))
    notes: list[str] = []
    try:
        # Environment check first.
        if not docker_available():
            result.status = VerificationStatus.ENVIRONMENT_UNAVAILABLE
            result.limitations.append("Docker is not available; builds cannot be executed in an isolated environment.")
            notes.append("ENVIRONMENT_UNAVAILABLE: docker not found or daemon not responding.")
            result.notes = notes
            result.finished_at = _now()
            return result

        eco = get_ecosystem(ecosystem_name)
        with make_client() as client:
            progress("Looking up release")
            release = eco.resolve(client, package, version, "auto")
            result.version = release.version
            progress("Downloading registry artifact")
            artifact_path, integrity = eco.download(client, release, workdir / "artifact")
            result.registry_artifact_hash = _hash_file(artifact_path)
            provenance = eco.provenance(client, release)

            # Source resolution.
            progress("Locating source")
            commits = [provenance.commit] if getattr(provenance, "commit", None) else []
            tags = eco.tag_candidates(release.name, release.version)
            source_root, source_info = _resolve_source(
                source=source, ref=ref, repository=release.repository_url,
                commits=commits, tags=tags,
                fallback_commits=[release.git_head] if release.git_head else [],
                notes=notes, progress=progress,
                package_root=None, hints=[release.repository_directory] if release.repository_directory else [],
            )

        if source_root is None:
            result.status = VerificationStatus.SOURCE_REVISION_MISMATCH
            notes.append("Could not resolve a source checkout for this release.")
            result.notes = notes
            result.finished_at = _now()
            return result

        # Source commit must be identifiable.
        commit = getattr(source_info, "commit", None) if source_info else None
        repo_url = getattr(source_info, "repository", None) if source_info else None
        if not commit:
            result.status = VerificationStatus.SOURCE_REVISION_MISMATCH
            notes.append("Source revision could not be reliably identified; refusing to claim reproducibility.")
            result.notes = notes
            result.finished_at = _now()
            return result

        result.source_repository = repo_url
        result.source_commit = commit

        # Detect dirty tree.
        try:
            from ..sources import SourceCheckout  # noqa: F401
        except Exception:
            pass

        # Recipe discovery.
        progress("Discovering build recipe")
        recipe = discover_recipe(source_root, ecosystem_name)
        result.build_recipe = recipe
        if not recipe.build_commands or not has_sufficient_information(recipe):
            result.status = VerificationStatus.INSUFFICIENT_BUILD_INFORMATION
            notes.append("Build recipe could not be determined confidently.")
            result.notes = notes
            result.finished_at = _now()
            return result
        if not is_supported_build_system(recipe):
            result.status = VerificationStatus.UNSUPPORTED_BUILD_SYSTEM
            notes.append(f"Unsupported build system: {recipe.build_system}")
            result.notes = notes
            result.finished_at = _now()
            return result

        # Dirty source check (best-effort, only for git checkouts).
        dirty = _is_dirty(source_root)
        if dirty:
            result.status = VerificationStatus.SOURCE_REVISION_MISMATCH
            notes.append("Source checkout is dirty or modified; refusing to build.")
            result.notes = notes
            result.finished_at = _now()
            return result

        # Build.
        progress("Building in isolated environment")
        limits = BuildLimits(timeout=timeout, cpu=cpu_limit, memory_mb=memory_limit, disk_mb=disk_limit)
        executor = DockerBuildExecutor()
        executor.config.image = image
        build_result = executor.build(
            recipe, source_root, workdir / "rebuilt", limits=limits,
            network_policy=network_policy, timeout=timeout, ecosystem=ecosystem_name,
        )
        result.build_command = build_result.build_command
        result.build_duration_seconds = build_result.duration_seconds
        result.build_environment = build_result.environment
        result.build_logs = (build_result.stdout or "") + "\n" + (build_result.stderr or "")
        result.notes = notes + build_result.notes

        if not build_result.success:
            result.status = build_result.status
            result.finished_at = _now()
            return result

        rebuilt_artifact = build_result.artifact_paths[0] if build_result.artifact_paths else None
        if rebuilt_artifact is None:
            result.status = VerificationStatus.BUILD_FAILURE
            notes.append("Build completed but produced no artifact.")
            result.notes = notes
            result.finished_at = _now()
            return result

        result.rebuilt_artifact_hash = _hash_file(rebuilt_artifact)

        # Compare.
        progress("Comparing artifacts")
        reg_root = extract(artifact_path, workdir / "pkg-reg").root
        reb_root = extract(rebuilt_artifact, workdir / "pkg-reb").root
        comparison = compare_artifact_trees(
            reg_root, reb_root, registry_archive=artifact_path, rebuilt_archive=rebuilt_artifact,
        )
        result.comparison = comparison
        result.files_matched = len(comparison.files_matched)
        result.files_mismatched = len(comparison.files_mismatched)
        result.missing_files = list(comparison.missing_files)
        result.unexpected_files = list(comparison.unexpected_files)
        result.normalized_artifact_hash = comparison.normalized_rebuilt_hash

        result.status = classify_status(comparison, True)

        if not keep_build_artifacts:
            shutil.rmtree(workdir / "rebuilt", ignore_errors=True)

        result.notes = notes
        result.finished_at = _now()
        return result
    except Exception as exc:  # noqa: BLE001
        result.status = VerificationStatus.VERIFICATION_ERROR
        result.notes = notes + [f"Verification error: {exc}"]
        result.finished_at = _now()
        return result
    finally:
        if not keep_build_artifacts:
            shutil.rmtree(workdir, ignore_errors=True)


def _hash_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_dirty(root: Path) -> bool:
    # Only meaningful for git checkouts; if .git present, check status.
    git_dir = root / ".git"
    if not git_dir.exists():
        return False
    try:
        from ..sources import _git
        out = _git(["status", "--porcelain"], cwd=root)
        return bool(out.strip())
    except Exception:
        return False
