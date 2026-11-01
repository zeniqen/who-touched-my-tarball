"""Download a real release (and its predecessor) to tamper with."""

from __future__ import annotations

from pathlib import Path

from ..ecosystems import RegistryError, ReleaseInfo, get_ecosystem, make_client


def download_release(ecosystem: str, package: str, version: str | None, dist: str, dest: Path, *,
                     with_previous: bool = True) -> tuple[ReleaseInfo, Path, Path | None]:
    """Return (release, artifact, previous artifact or None). Downloads are checked against registry digests."""
    eco = get_ecosystem(ecosystem)
    with make_client() as client:
        release = eco.resolve(client, package, version, dist)
        artifact, _ = eco.download(client, release, dest / "artifact")
        previous = None
        if with_previous and release.previous_version:
            try:
                prev = eco.resolve(client, package, release.previous_version, dist)
                previous, _ = eco.download(client, prev, dest / "previous")
            except (RegistryError, OSError, ValueError):
                previous = None
    return release, artifact, previous
