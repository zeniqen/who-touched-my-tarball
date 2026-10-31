"""Independent build execution inside an isolated environment."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .environment import DockerBuildEnvironment, DockerConfig, EnvironmentUnavailableError
from .models import BuildEnvironmentInfo, BuildLimits, BuildResult, NetworkPolicy, VerificationStatus


class BuildExecutor:
    """Base build executor interface."""

    def build(self, recipe, source_root: Path, output_dir: Path, *, limits: BuildLimits,
             network_policy: NetworkPolicy, timeout: int, ecosystem: str) -> BuildResult:
        raise NotImplementedError


class DockerBuildExecutor(BuildExecutor):
    def __init__(self, config: DockerConfig | None = None):
        self.config = config or DockerConfig()

    def build(self, recipe, source_root: Path, output_dir: Path, *, limits: BuildLimits,
             network_policy: NetworkPolicy, timeout: int, ecosystem: str) -> BuildResult:
        output_dir.mkdir(parents=True, exist_ok=True)
        cfg = DockerConfig(
            image=self.config.image,
            user=self.config.user,
            network_policy=network_policy,
            limits=limits,
            env=dict(self.config.env),
        )
        env = DockerBuildEnvironment(cfg)
        if not env.available():
            return BuildResult(
                success=False,
                status=VerificationStatus.ENVIRONMENT_UNAVAILABLE,
                notes=["Docker is not available; reproducible build verification cannot run."],
                environment=env.info(),
            )

        if ecosystem == "npm":
            build_cmd = [
                "bash", "-lc",
                "set -e; rm -rf /work; mkdir -p /work /out; cp -a /src/. /work/; cd /work; "
                "if [ -f package-lock.json ]; then npm ci --ignore-scripts; elif [ -f yarn.lock ]; then yarn install --frozen-lockfile; else npm install --ignore-scripts; fi; "
                "if npm run | grep -q ' build'; then npm run build; fi; "
                "npm pack --pack-destination /out --ignore-scripts",
            ]
        else:
            build_cmd = [
                "bash", "-lc",
                "set -e; rm -rf /work; mkdir -p /work /out; cp -a /src/. /work/; cd /work; "
                "python -m pip install --no-cache-dir build; "
                "python -m build --outdir /out /work",
            ]

        start = time.monotonic()
        try:
            result = env.run(
                build_cmd,
                mounts={str(source_root): "/src", str(output_dir): ("/out", "rw")},
                workdir="/",
                timeout=timeout,
            )
        except EnvironmentUnavailableError as exc:
            return BuildResult(
                success=False,
                status=VerificationStatus.ENVIRONMENT_UNAVAILABLE,
                notes=[str(exc)],
                environment=env.info(),
                duration_seconds=time.monotonic() - start,
            )
        finally:
            env.cleanup()

        artifacts = [p for p in output_dir.iterdir() if p.is_file()] if output_dir.exists() else []
        success = result.exit_code == 0 and bool(artifacts)
        status = VerificationStatus.BUILD_FAILURE if not success else VerificationStatus.VERIFICATION_ERROR
        build_command = " ".join(build_cmd)
        return BuildResult(
            success=success,
            exit_code=result.exit_code,
            status=status,
            build_command=build_command,
            build_tool="npm" if ecosystem == "npm" else "python-build",
            runtime_version="",
            stdout=result.stdout[-20000:],
            stderr=result.stderr[-20000:],
            duration_seconds=result.duration if result.duration else time.monotonic() - start,
            artifact_paths=artifacts,
            environment=env.info(),
        )


def ensure_image(image: str) -> bool:
    exe = shutil.which("docker")
    if not exe:
        return False
    try:
        subprocess.run([exe, "image", "inspect", image], capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False
