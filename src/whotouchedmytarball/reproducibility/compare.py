"""Artifact comparison for reproducible build verification."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from ..compare import list_files, sha256
from .models import ArtifactComparison, FileComparison, VerificationStatus
from .normalize import normalize_archive, normalized_tree_hash, sha256_file

RUNTIME_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".ts", ".py", ".pth", ".sh", ".bash",
    ".so", ".dll", ".dylib", ".node", ".bin", ".exe", ".json",
}


def _affects_runtime(path: str) -> bool:
    low = path.lower()
    if any(low.endswith(ext) for ext in RUNTIME_EXTENSIONS):
        return True
    if "scripts" in low.split("/") or "bin" in low.split("/"):
        return True
    return False


def compare_artifact_trees(registry_root: Path, rebuilt_root: Path, *, registry_archive: Path | None = None,
                            rebuilt_archive: Path | None = None) -> ArtifactComparison:
    reg_files = list_files(registry_root) if registry_root else {}
    reb_files = list_files(rebuilt_root) if rebuilt_root else {}

    comparison = ArtifactComparison()
    if registry_archive is not None:
        comparison.original_hash = sha256_file(registry_archive)
    else:
        comparison.original_hash = _root_hash(registry_root) if registry_root else ""
    if rebuilt_archive is not None:
        comparison.rebuilt_hash = sha256_file(rebuilt_archive)
    else:
        comparison.rebuilt_hash = _root_hash(rebuilt_root) if rebuilt_root else ""

    if registry_archive is not None and rebuilt_archive is not None:
        d1 = Path(tempfile.mkdtemp())
        d2 = Path(tempfile.mkdtemp())
        try:
            comparison.normalized_original_hash = normalize_archive(registry_archive, d1 / "n")[1]
            comparison.normalized_rebuilt_hash = normalize_archive(rebuilt_archive, d2 / "n")[1]
        except ValueError:
            comparison.normalized_original_hash = normalized_tree_hash(registry_root) if registry_root and reg_files else ""
            comparison.normalized_rebuilt_hash = normalized_tree_hash(rebuilt_root) if rebuilt_root and reb_files else ""
    else:
        comparison.normalized_original_hash = normalized_tree_hash(registry_root) if registry_root and reg_files else ""
        comparison.normalized_rebuilt_hash = normalized_tree_hash(rebuilt_root) if rebuilt_root and reb_files else ""

    reg_names = set(reg_files)
    reb_names = set(reb_files)

    matches = []
    for name in sorted(reg_names & reb_names):
        rh = sha256(reg_files[name])
        bh = sha256(reb_files[name])
        if rh == bh:
            matches.append(name)
            comparison.files_matched.append(name)
        else:
            comparison.files_mismatched.append(FileComparison(
                path=name,
                status="modified",
                registry_hash=rh,
                rebuilt_hash=bh,
                difference_type="content",
                affects_runtime=_affects_runtime(name),
            ))
    for name in sorted(reg_names - reb_names):
        comparison.missing_files.append(name)
        comparison.files_mismatched.append(FileComparison(
            path=name,
            status="missing",
            registry_hash=sha256(reg_files[name]),
            rebuilt_hash=None,
            difference_type="missing",
            affects_runtime=_affects_runtime(name),
        ))
    for name in sorted(reb_names - reg_names):
        comparison.unexpected_files.append(name)
        comparison.files_mismatched.append(FileComparison(
            path=name,
            status="unexpected",
            registry_hash=None,
            rebuilt_hash=sha256(reb_files[name]),
            difference_type="unexpected",
            affects_runtime=_affects_runtime(name),
        ))

    comparison.normalization_rules = [r.name for r in __import__("whotouchedmytarball.reproducibility.normalize", fromlist=["NORMALIZATION_RULES"]).NORMALIZATION_RULES]
    comparison.normalized = bool(
        comparison.normalized_original_hash and comparison.normalized_original_hash == comparison.normalized_rebuilt_hash
    )
    return comparison


def _root_hash(root: Path) -> str:
    # Hash of whole extracted tree (file contents + paths) approximated by normalized tree hash on raw bytes.
    # We keep original hash as sha256 of concatenated file bytes in path order for traceability.
    files = list_files(root)
    h = hashlib.sha256()
    for rel in sorted(files):
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        with open(files[rel], "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        h.update(b"\n")
    return h.hexdigest()


def classify_status(comparison: ArtifactComparison, build_succeeded: bool) -> VerificationStatus:
    if not build_succeeded:
        return VerificationStatus.BUILD_FAILURE
    modified = comparison.files_mismatched
    if comparison.missing_files:
        return VerificationStatus.MISSING_FILES
    if comparison.unexpected_files:
        return VerificationStatus.UNEXPECTED_FILES
    if modified:
        if comparison.normalized_original_hash and comparison.normalized_original_hash == comparison.normalized_rebuilt_hash:
            return VerificationStatus.NORMALIZED_MATCH
        return VerificationStatus.CONTENT_MISMATCH
    # no file-level differences
    if comparison.original_hash and comparison.original_hash == comparison.rebuilt_hash:
        return VerificationStatus.EXACT_MATCH
    if comparison.normalized_original_hash and comparison.normalized_original_hash == comparison.normalized_rebuilt_hash:
        return VerificationStatus.NORMALIZED_MATCH
    return VerificationStatus.EXACT_MATCH


def compare_artifacts(*a, **k):
    return compare_artifact_trees(*a, **k)
