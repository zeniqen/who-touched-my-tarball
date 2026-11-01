"""Map files in a published package onto files in a source tree and compute raw differences."""

from __future__ import annotations

import difflib
import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

IGNORED_DIRS = {".git", ".hg", ".svn"}
MAX_DIFF_BYTES = 4 * 1024 * 1024  # largest file whose content is scanned
LINE_DIFF_MAX_BYTES = 512 * 1024  # largest file that gets a line-level diff
EXCERPT_LINES = 80  # lines of a package-only file kept as its excerpt


@dataclass
class RawDiff:
    path: str  # path inside the package
    kind: str  # "modified" | "package_only"
    package_file: Path
    source_path: str | None = None
    source_file: Path | None = None
    whitespace_only: bool = False
    diff_excerpt: str = ""
    added: list[tuple[int, str]] = field(default_factory=list)  # (line number in package file, text)
    removed_count: int = 0

    def package_bytes(self) -> bytes:
        return self.package_file.read_bytes()

    def source_bytes(self) -> bytes | None:
        return self.source_file.read_bytes() if self.source_file else None


@dataclass
class Comparison:
    package_files: dict[str, Path]
    source_files: dict[str, Path]
    root_prefix: str
    identical: list[str]
    diffs: list[RawDiff]
    source_only: list[str]


def list_files(root: Path) -> dict[str, Path]:
    """List regular files under ``root``.

    Symlinks are followed only when they point inside ``root`` (source repositories often link
    shared test fixtures, and sdists contain the dereferenced copies). Links that leave the tree
    are ignored so a hostile repository cannot make the tool read host files.
    """
    files: dict[str, Path] = {}
    real_root = root.resolve()

    def inside(path: Path) -> bool:
        return path == real_root or real_root in path.parents

    def walk(directory: Path, rel: str, ancestors: frozenset[Path]) -> None:
        real = directory.resolve()
        if real in ancestors or len(files) > 200_000:  # symlink loop or absurdly large tree
            return
        ancestors = ancestors | {real}
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.name in IGNORED_DIRS:
                continue
            entry_rel = f"{rel}{entry.name}"
            if entry.is_symlink():
                try:
                    target = entry.resolve(strict=True)
                except (OSError, RuntimeError):
                    continue
                if not inside(target):
                    continue
            if entry.is_dir():
                walk(entry, entry_rel + "/", ancestors)
            elif entry.is_file():
                files[entry_rel] = entry

    walk(root, "", frozenset())
    return files


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_root_prefix(package_paths: list[str], source_paths: list[str], hints: list[str] | None = None) -> str:
    """Find the directory inside the source tree that corresponds to the package root.

    Handles monorepos (``packages/foo/``) and src layouts (``src/``) without hard-coded rules,
    by voting on where package files appear in the source tree. A directory the registry declares
    (npm ``repository.directory``) wins when package files really exist there; voting alone can be
    fooled by committed copies of build output, such as test fixtures in the react repository.
    """
    source_set = set(source_paths)
    for hint in hints or []:
        hint = hint.strip("/") + "/"
        if hint != "/" and any(hint + p in source_set for p in package_paths):
            return hint

    by_name: dict[str, list[str]] = defaultdict(list)
    for s in source_paths:
        by_name[PurePosixPath(s).name].append(s)

    votes: Counter[str] = Counter()
    for p in package_paths[:5000]:
        candidates = by_name.get(PurePosixPath(p).name, [])
        if len(candidates) > 50:  # very common names (index.js, __init__.py) are weak evidence
            continue
        for s in candidates:
            if s == p:
                votes[""] += 1
            elif s.endswith("/" + p):
                votes[s[: -len(p)]] += 1

    if not votes:
        return ""
    best = max(votes.items(), key=lambda kv: (kv[1], kv[0] == ""))
    return best[0]


def _lookup(path: str, prefix: str, source_set: set[str], by_name: dict[str, list[str]]) -> str | None:
    if prefix + path in source_set:
        return prefix + path
    if path in source_set:
        return path
    # Stay inside the package directory: in a monorepo, a same-named file in another package or a
    # test fixture is not this file's source.
    candidates = [s for s in by_name.get(PurePosixPath(path).name, [])
                  if s.endswith("/" + path) and s.startswith(prefix)]
    if len(candidates) == 1:
        return candidates[0]
    return None


def decode_text(data: bytes) -> str | None:
    if b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _normalize_ws(text: str) -> list[str]:
    return [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n") if line.strip()]


def compare_trees(package_root: Path, source_root: Path | None, hints: list[str] | None = None) -> Comparison:
    package_files = list_files(package_root)
    source_files = list_files(source_root) if source_root else {}

    if not source_files:
        diffs = [RawDiff(path=p, kind="package_only", package_file=f) for p, f in sorted(package_files.items())]
        for d in diffs:
            _fill_package_only(d)
        return Comparison(package_files, source_files, "", [], diffs, [])

    prefix = detect_root_prefix(sorted(package_files), sorted(source_files), hints)
    source_set = set(source_files)
    by_name: dict[str, list[str]] = defaultdict(list)
    for s in source_files:
        by_name[PurePosixPath(s).name].append(s)

    identical: list[str] = []
    diffs: list[RawDiff] = []
    matched_source: set[str] = set()

    for path, pkg_file in sorted(package_files.items()):
        src_path = _lookup(path, prefix, source_set, by_name)
        if src_path is None:
            d = RawDiff(path=path, kind="package_only", package_file=pkg_file)
            _fill_package_only(d)
            diffs.append(d)
            continue
        matched_source.add(src_path)
        src_file = source_files[src_path]
        if pkg_file.stat().st_size == src_file.stat().st_size and sha256(pkg_file) == sha256(src_file):
            identical.append(path)
            continue
        d = RawDiff(path=path, kind="modified", package_file=pkg_file, source_path=src_path, source_file=src_file)
        _fill_modified(d)
        diffs.append(d)

    in_scope = [s for s in source_files if s.startswith(prefix)] if prefix else list(source_files)
    source_only = sorted(set(in_scope) - matched_source)
    return Comparison(package_files, source_files, prefix, identical, diffs, source_only)


def _fill_package_only(d: RawDiff) -> None:
    if d.package_file.stat().st_size > MAX_DIFF_BYTES:
        return
    text = decode_text(d.package_bytes())
    if text is None:
        return
    d.added = list(enumerate(text.splitlines(), start=1))
    # Show the start of the new file as an all-added diff, so reports and the model see its content.
    excerpt = ["--- /dev/null", f"+++ package/{d.path}"] + [f"+{t[:300]}" for _, t in d.added[:EXCERPT_LINES]]
    if len(d.added) > EXCERPT_LINES:
        excerpt.append(f"... ({len(d.added) - EXCERPT_LINES} more lines)")
    d.diff_excerpt = "\n".join(excerpt)


def _fill_modified(d: RawDiff) -> None:
    pkg_bytes = d.package_bytes()
    src_bytes = d.source_bytes() or b""
    pkg_text = decode_text(pkg_bytes)
    src_text = decode_text(src_bytes)
    if pkg_text is None or src_text is None:
        d.diff_excerpt = "(binary file differs)"
        return
    if _normalize_ws(pkg_text) == _normalize_ws(src_text):
        d.whitespace_only = True
        return
    if len(pkg_bytes) > LINE_DIFF_MAX_BYTES or len(src_bytes) > LINE_DIFF_MAX_BYTES:
        d.diff_excerpt = "(file too large for a line diff; scanning whole package file)"
        d.added = list(enumerate(pkg_text.splitlines(), start=1))
        return

    src_lines = src_text.splitlines()
    pkg_lines = pkg_text.splitlines()
    matcher = difflib.SequenceMatcher(a=src_lines, b=pkg_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "insert"):
            d.added.extend((j + 1, pkg_lines[j]) for j in range(j1, j2))
        if tag in ("replace", "delete"):
            d.removed_count += i2 - i1

    excerpt = list(
        difflib.unified_diff(src_lines, pkg_lines, fromfile=f"source/{d.source_path}", tofile=f"package/{d.path}",
                             lineterm="", n=2)
    )
    if len(excerpt) > 80:
        excerpt = excerpt[:80] + [f"... ({len(excerpt) - 80} more diff lines)"]
    d.diff_excerpt = "\n".join(line[:300] for line in excerpt)
