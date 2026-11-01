"""Locate and fetch the source repository that a release claims to be built from."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

KNOWN_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")
GIT_TIMEOUT = 300


class SourceError(Exception):
    pass


@dataclass
class RepoRef:
    url: str  # normalized https URL, e.g. https://github.com/owner/repo
    subdirectory: str | None = None


@dataclass
class SourceCheckout:
    path: Path
    repository: str
    ref: str | None
    commit: str | None
    resolved_by: str
    notes: list[str] = field(default_factory=list)


def normalize_repo_url(raw: str | None) -> RepoRef | None:
    """Turn the many ways registries spell a repository into ``https://host/owner/repo``."""
    if not raw:
        return None
    url = raw.strip()
    m = re.match(r"^(github|gitlab|bitbucket):([\w.-]+/[\w.-]+)$", url)
    if m:
        host = {"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}[m.group(1)]
        url = f"https://{host}/{m.group(2)}"
    elif re.match(r"^[\w.-]+/[\w.-]+$", url):
        url = f"https://github.com/{url}"
    url = re.sub(r"^git\+", "", url)
    url = re.sub(r"^git@([^:]+):", r"https://\1/", url)
    url = re.sub(r"^(git|ssh)://(git@)?", "https://", url)
    url = re.sub(r"^http://", "https://", url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    parts = [p for p in parsed.path.split("/") if p]
    if host not in KNOWN_HOSTS or len(parts) < 2:
        return None
    owner, repo = parts[0], re.sub(r"\.git$", "", parts[1])
    subdir = None
    if len(parts) > 4 and parts[2] == "tree":
        subdir = "/".join(parts[4:])
    return RepoRef(url=f"https://{host}/{owner}/{repo}", subdirectory=subdir)


def same_repository(a: str | None, b: str | None) -> bool:
    ra, rb = normalize_repo_url(a), normalize_repo_url(b)
    return bool(ra and rb and ra.url.lower() == rb.url.lower())


def cache_dir() -> Path:
    base = os.environ.get("WTMT_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "wtmt")
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_ASKPASS": "true"})
    return env


def _git(args: list[str], cwd: Path | None = None) -> str:
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "advice.detachedHead=false", *args]
    try:
        proc = subprocess.run(cmd, cwd=cwd, env=_git_env(), capture_output=True, text=True, timeout=GIT_TIMEOUT)
    except FileNotFoundError as exc:
        raise SourceError("git is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise SourceError(f"git timed out: {' '.join(args[:2])}") from exc
    if proc.returncode != 0:
        raise SourceError(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "git failed")
    return proc.stdout


def list_remote_tags(url: str) -> list[str]:
    out = _git(["ls-remote", "--tags", "--refs", url])
    tags = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1].startswith("refs/tags/"):
            tags.append(parts[1][len("refs/tags/"):])
    return tags


def pick_tag(tags: list[str], candidates: list[str]) -> str | None:
    lookup = {t.lower(): t for t in tags}
    for c in candidates:
        if c.lower() in lookup:
            return lookup[c.lower()]
    return None


def fetch_source(url: str, *, commit: str | None = None, tag_candidates: list[str] | None = None,
                 ref: str | None = None) -> SourceCheckout:
    """Shallow-fetch the source at an exact commit, tag or ref into the cache directory."""
    resolved_by = ""
    target_ref = ref
    if commit:
        target_ref = commit
        resolved_by = "commit recorded by the registry/provenance"
    elif ref:
        resolved_by = "ref given on the command line"
    else:
        tags = list_remote_tags(url)
        tag = pick_tag(tags, tag_candidates or [])
        if not tag:
            raise SourceError(
                "could not find a release tag in the repository (tried: " + ", ".join((tag_candidates or [])[:6]) + ")"
            )
        target_ref = tag
        resolved_by = f"release tag `{tag}`"

    # "+submodules" keeps checkouts cached before submodules were fetched from being reused.
    key = hashlib.sha256(f"{url}@{target_ref}+submodules".encode()).hexdigest()[:16]
    dest = cache_dir() / "src" / key
    marker = dest.parent / f"{key}.done"
    if marker.exists() and dest.exists():
        commit_id, _, note = marker.read_text().partition("\n")
        return SourceCheckout(dest, url, target_ref, commit_id.strip() or None, resolved_by + " (cached)",
                              [note.strip()] if note.strip() else [])

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    try:
        _git(["init", "-q"], cwd=dest)
        _git(["remote", "add", "origin", url], cwd=dest)
        fetch_ref = target_ref if commit else (f"refs/tags/{target_ref}" if not ref else target_ref)
        try:
            _git(["fetch", "-q", "--depth", "1", "origin", fetch_ref], cwd=dest)
        except SourceError:
            if commit or ref:
                raise
            _git(["fetch", "-q", "--depth", "1", "origin", target_ref], cwd=dest)
        _git(["checkout", "-q", "FETCH_HEAD"], cwd=dest)
        head = _git(["rev-parse", "HEAD"], cwd=dest).strip()
    except SourceError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    notes = [_fetch_submodules(dest)] if (dest / ".gitmodules").is_file() else []
    notes = [n for n in notes if n]
    marker.write_text(head + ("\n" + notes[0] if notes else ""))
    return SourceCheckout(dest, url, target_ref, head, resolved_by, notes)


def _fetch_submodules(dest: Path) -> str | None:
    """Fetch git submodules at the commits the release pins, so vendored code (numpy's meson,
    highway, ...) is compared instead of looking like package-only files.

    Only https is allowed: a hostile .gitmodules must not make the tool read local paths (file://)
    or run commands through other transports. Returns a note if some submodules could not be fetched.
    """
    https_only = ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always"]
    try:
        _git([*https_only, "submodule", "update", "--init", "--recursive", "--depth", "1", "--jobs", "4"], cwd=dest)
    except SourceError as exc:
        return f"Some git submodules could not be fetched ({exc}); their files may show up as package-only"
    return None
