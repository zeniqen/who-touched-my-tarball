from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest


def write_tree(root: Path, files: dict[str, str | bytes]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
    return root


def make_tgz(path: Path, files: dict[str, str | bytes], prefix: str = "package/") -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for rel, content in files.items():
            data = content if isinstance(content, bytes) else content.encode()
            info = tarfile.TarInfo(prefix + rel)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def make_zip(path: Path, files: dict[str, str | bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for rel, content in files.items():
            zf.writestr(rel, content)
    return path


INDEX_JS = "'use strict';\nfunction add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n"


def npm_manifest(**extra) -> str:
    doc = {"name": "demo", "version": "1.0.0", "main": "index.js", "scripts": {"test": "node test.js"}}
    doc.update(extra)
    return json.dumps(doc, indent=2) + "\n"


@pytest.fixture
def npm_source(tmp_path: Path) -> Path:
    return write_tree(tmp_path / "source", {
        "package.json": npm_manifest(),
        "index.js": INDEX_JS,
        "test.js": "require('./index');\n",
        "README.md": "# demo\n",
    })
