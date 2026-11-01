"""Benchmark dataset: real-shaped base packages, each untouched and tampered with every modelled attack.

Bases are an npm package (the offline demo) and a Python project published as an sdist and a wheel.
Each base is a benign scenario; each (base, applicable attack) pair is a malicious scenario built with
``wtmt tamper``. Fixtures are regenerated on every run so they can never go stale.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXAMPLES = ROOT / "examples" / "offline-demo"

PY_SOURCE = {
    "pyproject.toml": "[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n\n"
                      "[project]\nname = 'tinycalc'\nversion = '1.0.0'\n",
    "setup.py": "from setuptools import setup\n\nsetup()\n",
    "README.md": "# tinycalc\n\nAdds numbers.\n",
    "src/tinycalc/__init__.py": "from .core import add\n\n__all__ = ['add']\n",
    "src/tinycalc/core.py": "def add(a: int, b: int) -> int:\n    return a + b\n",
    "tests/test_core.py": "from tinycalc import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n",
}


def fixture_root() -> Path:
    base = Path(os.environ.get("WTMT_HOME") or Path.home() / ".wtmt") / "benchmark-fixtures"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _write_tree(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(content)
    return root


def _python_bases(fr: Path) -> tuple[Path, Path, Path]:
    src = _write_tree(fr / "tinycalc-source", PY_SOURCE)
    sdist = fr / "tinycalc-1.0.0.tar.gz"
    files = {**{k: v for k, v in PY_SOURCE.items() if not k.startswith("tests/")},
             "PKG-INFO": "Metadata-Version: 2.1\nName: tinycalc\nVersion: 1.0.0\n",
             "src/tinycalc.egg-info/PKG-INFO": "Metadata-Version: 2.1\nName: tinycalc\n",
             "src/tinycalc.egg-info/SOURCES.txt": "setup.py\nsrc/tinycalc/__init__.py\n",
             "setup.cfg": "[egg_info]\ntag_build = \ntag_date = 0\n\n"}
    with tarfile.open(sdist, "w:gz") as tar:
        for rel, content in sorted(files.items()):
            data = content.encode()
            info = tarfile.TarInfo(f"tinycalc-1.0.0/{rel}")
            info.size, info.mtime = len(data), 1761868800
            tar.addfile(info, io.BytesIO(data))
    wheel = fr / "tinycalc-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("tinycalc/__init__.py", PY_SOURCE["src/tinycalc/__init__.py"])
        zf.writestr("tinycalc/core.py", PY_SOURCE["src/tinycalc/core.py"])
        zf.writestr("tinycalc-1.0.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: tinycalc\nVersion: 1.0.0\n")
        zf.writestr("tinycalc-1.0.0.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: setuptools\n")
        zf.writestr("tinycalc-1.0.0.dist-info/RECORD", "tinycalc/__init__.py,,\n")
    return src, sdist, wheel


def bases() -> list[tuple[str, str, Path, Path]]:
    """(base id, ecosystem, artifact, source) for every untouched base package."""
    fr = fixture_root()
    for child in fr.iterdir():
        shutil.rmtree(child) if child.is_dir() else child.unlink()
    npm_src = fr / "demo-source"
    shutil.copytree(EXAMPLES / "source", npm_src)
    npm_pkg = fr / "hardcarry-demo-lib-1.0.0.tgz"
    shutil.copy2(EXAMPLES / "clean.tgz", npm_pkg)
    py_src, sdist, wheel = _python_bases(fr)
    return [("npm-demo", "npm", npm_pkg, npm_src), ("pypi-sdist", "pypi", sdist, py_src),
            ("pypi-wheel", "pypi", wheel, py_src)]


def scenarios():
    from ..redteam import ATTACKS, applicable_attacks, tamper
    from .models import Scenario

    out = []
    for base_id, eco, artifact, source in bases():
        out.append(Scenario(scenario_id=f"{base_id}-clean", name=f"{base_id}: untouched release", ecosystem=eco,
                            category="clean", label="benign", artifact_path=artifact, source_path=source,
                            severity="info", fixture_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest()))
        for attack in applicable_attacks(artifact):
            tampered = tamper(artifact, attack.id, fixture_root() / "tampered" / base_id)
            out.append(Scenario(
                scenario_id=f"{base_id}-{attack.id}", name=f"{base_id}: {ATTACKS[attack.id].title}",
                ecosystem=eco, category=attack.id, label="malicious", artifact_path=tampered.artifact,
                source_path=source, severity="high",
                fixture_sha256=hashlib.sha256(tampered.artifact.read_bytes()).hexdigest()))
    return out
