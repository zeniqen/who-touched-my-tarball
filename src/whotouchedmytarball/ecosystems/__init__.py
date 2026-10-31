"""Registry of supported ecosystems."""

from __future__ import annotations

from pathlib import Path

from .base import Ecosystem, RegistryError, ReleaseInfo, make_client
from .npm import NpmEcosystem
from .pypi import PyPIEcosystem

ECOSYSTEMS: dict[str, Ecosystem] = {
    "npm": NpmEcosystem(),
    "pypi": PyPIEcosystem(),
}


def get_ecosystem(name: str) -> Ecosystem:
    key = name.lower()
    if key in ("pip", "python", "pypi"):
        key = "pypi"
    if key in ("node", "js", "npm"):
        key = "npm"
    if key not in ECOSYSTEMS:
        raise RegistryError(f"unsupported ecosystem {name!r}; supported: {', '.join(ECOSYSTEMS)}")
    return ECOSYSTEMS[key]


def guess_ecosystem(artifact: Path, extracted_root: Path) -> str:
    name = artifact.name.lower()
    if name.endswith((".whl", ".egg")) or (extracted_root / "PKG-INFO").exists():
        return "pypi"
    if (extracted_root / "package.json").exists() or name.endswith(".tgz"):
        return "npm"
    if (extracted_root / "setup.py").exists() or (extracted_root / "pyproject.toml").exists():
        return "pypi"
    return "npm"


__all__ = ["ECOSYSTEMS", "Ecosystem", "RegistryError", "ReleaseInfo", "get_ecosystem", "guess_ecosystem",
           "make_client"]
