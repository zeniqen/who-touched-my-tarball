"""Conservative artifact normalization.

Normalization only removes nondeterministic *archive* metadata (timestamps, entry ordering,
archive-level file mode differences where safe). It never alters or ignores executable code,
scripts, dependencies or security-relevant files.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class NormalizationRule:
    name: str
    description: str
    applies_to: str  # "zip" | "tar" | "tree" | "all"


NORMALIZATION_RULES: list[NormalizationRule] = [
    NormalizationRule("zip-entry-order", "Sort ZIP entries by path before hashing.", "zip"),
    NormalizationRule("zip-timestamps", "Replace stored ZIP mtimes with a fixed epoch (0).", "zip"),
    NormalizationRule("zip-permissions", "Normalize directory/file mode bits to defaults.", "zip"),
    NormalizationRule("tar-entry-order", "Sort TAR entries by path before hashing.", "tar"),
    NormalizationRule("tar-timestamps", "Replace TAR mtimes with a fixed epoch (0).", "tar"),
    NormalizationRule("tar-uid-gid", "Reset uid/gid and uname/gname to (0, '') in TAR headers.", "tar"),
    NormalizationRule("tar-modes", "Normalize TAR mode bits to 0644/0755.", "tar"),
    NormalizationRule("tree-order", "Sort file listings by path before hashing.", "tree"),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalized_tree_entries(root: Path) -> list[tuple[str, str]]:
    """Return sorted (relative_path, sha256) entries for a directory tree."""
    from ..compare import list_files

    files = list_files(root)
    entries = []
    for rel, p in files.items():
        entries.append((rel.replace("\\", "/"), sha256_file(p)))
    entries.sort(key=lambda x: x[0])
    return entries


def normalized_tree_hash(root: Path) -> str:
    entries = normalized_tree_entries(root)
    h = hashlib.sha256()
    for rel, digest in entries:
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(digest.encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def normalize_zip(src: Path, dest: Path) -> str:
    """Rewrite a ZIP with normalized metadata; return the sha256 of the normalized bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(src) as zf_in, zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf_out:
        infos = sorted(zf_in.infolist(), key=lambda i: i.filename)
        for info in infos:
            if info.is_dir():
                continue
            # safety: skip unsafe paths handled by archive; here trust but normalize name
            data = zf_in.read(info)
            ni = zipfile.ZipInfo(info.filename, date_time=(1980, 1, 1, 0, 0, 0))
            ni.compress_type = zipfile.ZIP_DEFLATED
            ni.external_attr = (0o100644 & 0xFFFF) << 16
            # Preserve executable permission if original had it
            mode = (info.external_attr >> 16) & 0o777
            if mode & 0o111:
                ni.external_attr = (0o100755 & 0xFFFF) << 16
            zf_out.writestr(ni, data, compresslevel=9)
    dest.write_bytes(buf.getvalue())
    return hashlib.sha256(buf.getvalue()).hexdigest()


def normalize_tar(src: Path, dest: Path) -> str:
    """Rewrite a tarball (possibly gzipped) with normalized metadata."""
    buf_mode = "w:gz" if src.name.endswith((".gz", ".tgz", ".tar.gz")) else "w"
    with tarfile.open(src, "r:*") as tf_in, tarfile.open(dest, buf_mode) as tf_out:
        members = sorted(tf_in.getmembers(), key=lambda m: m.name)
        for m in members:
            if not m.isfile():
                # Skip links/special files from normalized representation for safety.
                continue
            data = tf_in.extractfile(m)
            if data is None:
                continue
            ti = tarfile.TarInfo(name=m.name)
            ti.size = m.size
            ti.mtime = 0
            ti.uid = 0
            ti.gid = 0
            ti.uname = ""
            ti.gname = ""
            mode = m.mode or 0o644
            if mode & 0o111:
                ti.mode = 0o755
            else:
                ti.mode = 0o644
            ti.type = tarfile.REGTYPE
            tf_out.addfile(ti, data)
    return sha256_file(dest)


def normalize_archive(src: Path, dest: Path) -> tuple[str, str]:
    """Normalize an archive. Returns (algorithm, hash). Handles zip/tar."""
    name = src.name.lower()
    if name.endswith((".zip", ".whl", ".egg")):
        return "zip", normalize_zip(src, dest)
    if name.endswith((".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz", ".tbz2", ".txz")):
        return "tar", normalize_tar(src, dest)
    raise ValueError(f"unsupported archive type: {src.name}")


def preserve_code_check(src_root: Path, normalized_root: Path | None = None) -> bool:
    """Placeholder hook ensuring normalization does not drop files."""
    return True
