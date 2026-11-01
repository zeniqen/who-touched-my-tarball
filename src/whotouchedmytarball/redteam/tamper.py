"""Apply a modelled attack to a copy of a real package, keeping its original layout."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from ..archive import extract
from .attacks import ATTACKS, NPM, SDIST, WHEEL, Attack, NotApplicable

FIXED_MTIME = 1761868800  # reproducible archives
SUFFIXES = (".tar.gz", ".tgz", ".whl", ".zip")
WARNING = ("DO NOT INSTALL. This package was deliberately tampered with by `wtmt tamper` to test supply-chain "
           "detection. Its payloads are inert (TEST-NET/.invalid endpoints), but it is not the published release.")


@dataclass
class TamperResult:
    attack: str
    artifact: Path
    manifest: Path
    changed_files: list[str] = field(default_factory=list)


def detect_format(artifact: Path) -> str:
    """``npm`` (package/ tarball), ``sdist`` (tarball with PKG-INFO) or ``wheel``."""
    name = artifact.name.lower()
    if name.endswith((".whl", ".zip")):
        return WHEEL
    with tarfile.open(artifact, "r:*") as tf:
        names = [m.name for m in tf.getmembers()]
    if any(n.count("/") <= 1 and n.endswith("PKG-INFO") for n in names):
        return SDIST
    return NPM


def applicable_attacks(artifact: Path) -> list[Attack]:
    fmt = detect_format(artifact)
    return [a for a in ATTACKS.values() if fmt in a.formats]


def tampered_name(base: Path, attack_id: str) -> str:
    for suffix in SUFFIXES:
        if base.name.lower().endswith(suffix):
            return f"{base.name[: -len(suffix)]}+wtmt-redteam-{attack_id}{base.name[-len(suffix):]}"
    return f"{base.name}+wtmt-redteam-{attack_id}"


def tamper(base: Path, attack_id: str, out_dir: Path) -> TamperResult:
    """Write ``base`` with ``attack_id`` applied into ``out_dir``. Raises KeyError or NotApplicable."""
    attack = ATTACKS[attack_id]
    fmt = detect_format(base)
    if fmt not in attack.formats:
        raise NotApplicable(f"{attack_id} applies to {', '.join(attack.formats)} packages, not {fmt}")
    out_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="wtmt-tamper-"))
    try:
        tree = work / "tree"
        root = extract(base, tree).root
        changed = attack.inject(root, fmt)
        prefix = root.relative_to(tree).as_posix()
        artifact = out_dir / tampered_name(base, attack_id)
        _repack(tree, artifact, wheel=(fmt == WHEEL))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    manifest = artifact.with_name(artifact.name + ".wtmt-redteam.json")
    manifest.write_text(json.dumps({
        "warning": WARNING,
        "attack": attack.id,
        "title": attack.title,
        "modelled_on": attack.incident,
        "base_artifact": base.name,
        "base_sha256": hashlib.sha256(base.read_bytes()).hexdigest(),
        "tampered_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "archive_prefix": "" if prefix == "." else prefix,
        "changed_files": changed,
    }, indent=2) + "\n")
    return TamperResult(attack.id, artifact, manifest, changed)


def _repack(tree: Path, artifact: Path, *, wheel: bool) -> None:
    files = sorted(p for p in tree.rglob("*") if p.is_file())
    if wheel:
        with zipfile.ZipFile(artifact, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in files:
                info = zipfile.ZipInfo(p.relative_to(tree).as_posix(), date_time=(2025, 10, 31, 0, 0, 0))
                info.external_attr = 0o644 << 16
                zf.writestr(info, p.read_bytes(), zipfile.ZIP_DEFLATED)
        return
    with tarfile.open(artifact, "w:gz") as tar:
        for p in files:
            data = p.read_bytes()
            info = tarfile.TarInfo(p.relative_to(tree).as_posix())
            info.size, info.mtime, info.mode = len(data), FIXED_MTIME, 0o644
            tar.addfile(info, io.BytesIO(data))


__all__ = ["NotApplicable", "TamperResult", "applicable_attacks", "detect_format", "tamper"]
