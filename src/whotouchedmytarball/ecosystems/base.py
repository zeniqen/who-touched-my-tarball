"""Ecosystem adapter interface.

Each package ecosystem (npm, PyPI, ...) implements this interface. Adding a new ecosystem means
adding one adapter; the comparison, classification and reporting code does not change.
"""

from __future__ import annotations

import base64
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .. import __version__
from ..models import Provenance

USER_AGENT = f"whotouchedmytarball/{__version__} (+https://github.com/zeniqen/who-touched-my-tarball)"


class RegistryError(Exception):
    pass


@dataclass
class ReleaseInfo:
    ecosystem: str
    name: str
    version: str
    artifact_url: str
    artifact_filename: str
    repository_url: str | None = None
    repository_directory: str | None = None
    git_head: str | None = None
    expected_digests: dict[str, str] = field(default_factory=dict)  # algorithm -> hex digest
    previous_version: str | None = None
    raw: dict = field(default_factory=dict)


def make_client() -> httpx.Client:
    return httpx.Client(timeout=httpx.Timeout(60.0, connect=15.0), follow_redirects=True,
                        headers={"User-Agent": USER_AGENT})


class Ecosystem(ABC):
    name: str

    @abstractmethod
    def resolve(self, client: httpx.Client, package: str, version: str | None, dist: str = "auto") -> ReleaseInfo:
        """Look up a release in the registry."""

    @abstractmethod
    def latest_version(self, client: httpx.Client, package: str) -> str:
        """Return the newest published version."""

    @abstractmethod
    def provenance(self, client: httpx.Client, release: ReleaseInfo) -> Provenance:
        """Return build provenance published by the registry, if any."""

    @abstractmethod
    def tag_candidates(self, package: str, version: str) -> list[str]:
        """Likely git tag names for a version."""

    def download(self, client: httpx.Client, release: ReleaseInfo, dest_dir: Path) -> tuple[Path, str]:
        dest_dir.mkdir(parents=True, exist_ok=True)
        target = dest_dir / release.artifact_filename
        with client.stream("GET", release.artifact_url) as resp:
            if resp.status_code != 200:
                raise RegistryError(f"download failed ({resp.status_code}): {release.artifact_url}")
            with open(target, "wb") as fh:
                for chunk in resp.iter_bytes():
                    fh.write(chunk)
        return target, verify_digests(target, release.expected_digests)


def verify_digests(path: Path, expected: dict[str, str]) -> str:
    if not expected:
        return "registry did not publish a digest"
    data = path.read_bytes()
    results = []
    for algo, value in expected.items():
        h = hashlib.new(algo, data)
        actual = h.hexdigest()
        if value.lower() != actual.lower():
            raise RegistryError(f"{algo} digest mismatch for {path.name}: registry says {value}, got {actual}")
        results.append(algo)
    return "verified against registry digest (" + ", ".join(results) + ")"


def sri_to_hex(integrity: str) -> tuple[str, str] | None:
    """Convert an npm Subresource Integrity string (sha512-base64) into (algorithm, hex)."""
    if not integrity or "-" not in integrity:
        return None
    algo, b64 = integrity.split("-", 1)
    try:
        return algo, base64.b64decode(b64).hex()
    except ValueError:
        return None
