from __future__ import annotations

import io
import tarfile

import pytest

from whotouchedmytarball.archive import UnsafeArchiveError, extract

from .conftest import make_tgz, make_zip


def test_npm_tarball_strips_package_prefix(tmp_path):
    archive = make_tgz(tmp_path / "a.tgz", {"index.js": "x", "lib/a.js": "y"})
    result = extract(archive, tmp_path / "out")
    assert (result.root / "index.js").read_text() == "x"
    assert (result.root / "lib" / "a.js").exists()


def test_wheel_keeps_multiple_roots(tmp_path):
    archive = make_zip(tmp_path / "demo-1.0-py3-none-any.whl", {"demo/__init__.py": "", "demo-1.0.dist-info/METADATA": ""})
    result = extract(archive, tmp_path / "out")
    assert (result.root / "demo" / "__init__.py").exists()


def test_path_traversal_is_rejected(tmp_path):
    archive = tmp_path / "evil.tgz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo("../../escape.txt")
        info.size = 3
        tar.addfile(info, io.BytesIO(b"bad"))
    with pytest.raises(UnsafeArchiveError):
        extract(archive, tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()


def test_absolute_path_in_zip_is_rejected(tmp_path):
    archive = make_zip(tmp_path / "evil.zip", {"/etc/passwd": "x"})
    with pytest.raises(UnsafeArchiveError):
        extract(archive, tmp_path / "out")


def test_symlinks_are_skipped_not_followed(tmp_path):
    archive = tmp_path / "link.tgz"
    with tarfile.open(archive, "w:gz") as tar:
        link = tarfile.TarInfo("package/secret")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)
        data = tarfile.TarInfo("package/index.js")
        data.size = 1
        tar.addfile(data, io.BytesIO(b"x"))
    result = extract(archive, tmp_path / "out")
    assert not (result.root / "secret").exists()
    assert any("secret" in s for s in result.skipped)
