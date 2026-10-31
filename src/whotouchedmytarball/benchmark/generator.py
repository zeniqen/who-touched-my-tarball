"""Bootstrap a small benchmark fixture cache (synthetic, inert)."""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXAMPLES = ROOT / "examples" / "offline-demo"


def fixture_root() -> Path:
    base = Path.home() / ".cache" / "wtmt" / "benchmark-fixtures"
    base.mkdir(parents=True, exist_ok=True)
    return base


def ensure_fixtures() -> Path:
    fr = fixture_root()
    for name in ("clean.tgz", "tampered.tgz"):
        src = EXAMPLES / name
        dst = fr / name
        if src.exists() and not dst.exists():
            shutil.copy2(src, dst)
    # source tree
    srcdir = EXAMPLES / "source"
    dstdir = fr / "source"
    if srcdir.exists() and not dstdir.exists():
        shutil.copytree(srcdir, dstdir)
    return fr


def scenarios():
    from .models import Scenario
    fr = ensure_fixtures()
    cats = ["benign_build", "code_injection", "install_attack", "obfuscation", "provenance", "trust", "repro"]
    out = []
    for i in range(25):
        malicious = i % 2 == 1
        cat = cats[i % len(cats)]
        out.append(Scenario(
            scenario_id=f"npm-{ 'mal' if malicious else 'ben' }-{i:03d}",
            name=f"Synthetic {cat} scenario {i}",
            ecosystem="npm",
            category=cat,
            label="malicious" if malicious else "benign",
            artifact_path=fr / ("tampered.tgz" if malicious else "clean.tgz"),
            source_path=fr / "source",
            severity="high" if malicious else "info",
        ))
    return out
