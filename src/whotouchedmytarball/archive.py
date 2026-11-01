"""Safe extraction of package archives.

Package archives are untrusted input. Extraction never follows links, never writes outside the
destination directory, and never executes anything.
"""

from __future__ import annotations

import os
import shutil
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

MAX_TOTAL_BYTES = 1024 * 1024 * 1024  # 1 GiB uncompressed
MAX_FILES = 50_000


class UnsafeArchiveError(Exception):
    """Raised when an archive tries to escape the extraction directory or is too large."""


class UnsupportedArchiveError(Exception):
    """Raised for archive formats the tool does not understand."""


@dataclass
class ExtractResult:
    root: Path
    skipped: list[str] = field(default_factory=list)  # links / special files that were not extracted


TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz", ".tbz2", ".txz")
ZIP_SUFFIXES = (".whl", ".zip", ".egg")


def is_supported(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(TAR_SUFFIXES) or name.endswith(ZIP_SUFFIXES)


def _safe_relpath(name: str) -> str:
    """Validate an archive member name and return a safe relative POSIX path."""
    cleaned = name.replace("\\", "/")
    if cleaned.startswith("/") or (len(cleaned) > 1 and cleaned[1] == ":"):
        raise UnsafeArchiveError(f"absolute path in archive: {name!r}")
    parts = [p for p in PurePosixPath(cleaned).parts if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnsafeArchiveError(f"path traversal in archive: {name!r}")
    return "/".join(parts)


def _write_member(dest: Path, rel: str, data_stream) -> int:
    target = dest / rel
    resolved_dest = dest.resolve()
    if not str(target.resolve()).startswith(str(resolved_dest) + os.sep):
        raise UnsafeArchiveError(f"member escapes destination: {rel!r}")
    written = 0
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "wb") as out:
            while True:
                chunk = data_stream.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                out.write(chunk)
    except (FileExistsError, NotADirectoryError, IsADirectoryError) as exc:
        raise UnsafeArchiveError(f"archive uses {rel!r} as both a file and a directory") from exc
    return written


def _claim(seen: dict[str, str], rel: str) -> None:
    """Refuse names that differ only in case: on case-insensitive file systems (macOS, Windows) the
    second one would overwrite the first on disk, so the analyzed content would not be what ships."""
    other = seen.setdefault(rel.lower(), rel)
    if other != rel:
        raise UnsafeArchiveError(f"archive has names that differ only in case: {other!r} and {rel!r}")


def extract(archive: Path, dest: Path) -> ExtractResult:
    """Extract ``archive`` into ``dest`` and return the content root.

    A single top-level directory (``package/`` for npm, ``name-version/`` for sdists) is
    treated as the root.
    """
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()
    skipped: list[str] = []
    total = 0
    count = 0
    seen: dict[str, str] = {}

    if name.endswith(TAR_SUFFIXES):
        with tarfile.open(archive, "r:*") as tf:
            for member in tf.getmembers():
                rel = _safe_relpath(member.name)
                if not rel:
                    continue
                if member.isdir():
                    continue
                if not member.isfile():
                    skipped.append(f"{rel} ({'symlink' if member.issym() else 'link/special file'})")
                    continue
                _claim(seen, rel)
                count += 1
                total += member.size
                if count > MAX_FILES or total > MAX_TOTAL_BYTES:
                    raise UnsafeArchiveError("archive too large to analyze safely")
                stream = tf.extractfile(member)
                if stream is None:
                    continue
                _write_member(dest, rel, stream)
    elif name.endswith(ZIP_SUFFIXES):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                rel = _safe_relpath(info.filename)
                if not rel or info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:  # symlink stored in zip
                    skipped.append(f"{rel} (symlink)")
                    continue
                _claim(seen, rel)
                count += 1
                total += info.file_size
                if count > MAX_FILES or total > MAX_TOTAL_BYTES:
                    raise UnsafeArchiveError("archive too large to analyze safely")
                with zf.open(info) as stream:
                    _write_member(dest, rel, stream)
    else:
        raise UnsupportedArchiveError(f"unsupported archive type: {archive.name}")

    return ExtractResult(root=_single_root(dest), skipped=skipped)


def _single_root(dest: Path) -> Path:
    entries = [p for p in dest.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def copy_tree(src: Path, dest: Path) -> Path:
    shutil.copytree(src, dest, symlinks=True)
    return dest
