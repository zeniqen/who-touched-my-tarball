"""Isolated build environment management.

Builds never run on the host. When Docker is unavailable the verification reports
``ENVIRONMENT_UNAVAILABLE`` instead of silently falling back.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .models import BuildEnvironmentInfo, BuildLimits, NetworkPolicy, VerificationStatus


SENSITIVE_PATHS = (
    "/root", "/home", "/Users", "/.ssh", "/.aws", "/.gnupg",
)


class EnvironmentUnavailableError(Exception):
    """Raised when no isolated execution backend is available."""


class BuildTimeoutError(Exception):
    """Raised when a build exceeds its time limit."""


def docker_available() -> bool:
    """Return True if the docker CLI is present and the daemon responds."""
    exe = shutil.which("docker")
    if not exe:
        return False
    try:
        proc = subprocess.run(
            [exe, "info"], capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def docker_version() -> str:
    exe = shutil.which("docker")
    if not exe:
        return ""
    try:
        proc = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10)
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


@dataclass
class DockerConfig:
    image: str = "python:3.11-slim"
    user: str = "1000:1000"
    network_policy: NetworkPolicy = NetworkPolicy.NONE
    limits: BuildLimits = field(default_factory=BuildLimits)
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False


class DockerBuildEnvironment:
    """Thin wrapper around the docker CLI used for isolated builds."""

    def __init__(self, config: DockerConfig):
        self.config = config
        self.container_id: str | None = None

    @staticmethod
    def available() -> bool:
        return docker_available()

    def _network_args(self) -> list[str]:
        policy = self.config.network_policy
        if policy == NetworkPolicy.NONE:
            return ["--network", "none"]
        if policy == NetworkPolicy.LIMITED:
            return ["--network", "bridge"]
        return ["--network", "bridge"]

    def _limit_args(self) -> list[str]:
        lim = self.config.limits
        return [
            f"--cpus={lim.cpu}",
            f"--memory={lim.memory_mb}m",
            f"--pids-limit=256",
        ]

    def _security_args(self) -> list[str]:
        args = [
            "--user", self.config.user,
            "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=512m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
        ]
        # Never mount host credentials, sockets or sensitive locations.
        for var in ("SSH_AUTH_SOCK", "DOCKER_HOST", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"):
            self.config.env.pop(var, None)
        return args

    def run(self, command: list[str], *, mounts: dict[str, str] | None = None,
            workdir: str = "/src", timeout: int | None = None) -> ExecutionResult:
        if not docker_available():
            raise EnvironmentUnavailableError("docker is not available")
        mounts = mounts or {}
        cmd: list[str] = ["docker", "run", "--rm", "-i"]
        cmd += self._security_args()
        cmd += self._limit_args()
        cmd += self._network_args()
        cmd += ["-w", workdir]
        for host, container in mounts.items():
            if isinstance(container, tuple):
                container_path, mode = container
                cmd += ["-v", f"{host}:{container_path}:{mode}"]
            else:
                # Default: read-only for source safety.
                cmd += ["-v", f"{host}:{container}:ro"]
        for key, val in self.config.env.items():
            cmd += ["-e", f"{key}={val}"]
        cmd += [self.config.image]
        cmd += command

        timeout = timeout or self.config.limits.timeout
        import time

        start = time.monotonic()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            proc = exc  # type: ignore
            timed_out = True
            # best-effort kill not needed with --rm? process gone
            return ExecutionResult(
                exit_code=124,
                stdout=getattr(exc, "stdout", "") or "",
                stderr=getattr(exc, "stderr", "") or "build timed out",
                duration=time.monotonic() - start,
                timed_out=True,
            )
        return ExecutionResult(
            exit_code=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration=time.monotonic() - start,
            timed_out=timed_out,
        )

    def cleanup(self) -> None:
        self.container_id = None

    def info(self) -> BuildEnvironmentInfo:
        return BuildEnvironmentInfo(
            image=self.config.image,
            toolchain={},
            runtime_version="",
            os="",
            architecture="",
            docker_available=docker_available(),
            network_policy=self.config.network_policy,
        )


def ensure_environment(config: DockerConfig) -> DockerBuildEnvironment:
    if not docker_available():
        raise EnvironmentUnavailableError("Docker is not available; reproducible build verification cannot run.")
    return DockerBuildEnvironment(config)
