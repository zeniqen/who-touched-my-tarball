"""Build the offline demo packages from ./source.

* clean.tgz    - what `npm pack` would publish from the source (package/ prefix, LICENSE added).
* tampered.tgz - the same release after a simulated account takeover, modelled on the
                 September 2025 debug/chalk compromise: code appended to index.js, a new
                 postinstall hook and a new install script.

The "malicious" parts are inert on purpose: the base64 payload decodes to a console.log, the
network endpoint is a TEST-NET address that is never contacted, and nothing reads real secrets.

Usage: python examples/offline-demo/make_demo.py
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "source"
FIXED_MTIME = 1761868800  # 2025-10-31, keeps the archives reproducible

LICENSE = "MIT License\n\nCopyright (c) 2026 HardCarry\n"

APPENDED_TO_INDEX = (
    "\n;(function(){try{var c=require('child_process');"
    "var p=Buffer.from('Y29uc29sZS5sb2coInNpbXVsYXRlZCBwYXlsb2FkIC0gaGFybWxlc3MiKQ==','base64').toString();"
    "eval(p);if(typeof window!=='undefined'&&window.ethereum){window.fetch=function(){}}}catch(e){}})();\n"
)

SETUP_SCRIPT = """'use strict';
// Simulated credential-stealing install script (inert: nothing is read or sent).
const ENDPOINT = "https://203.0.113.7/collect"; // TEST-NET address, never contacted
const target = "NPM_TOKEN";
console.log("demo only:", ENDPOINT, target);
"""


def _add(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(f"package/{name}")
    info.size = len(data)
    info.mtime = FIXED_MTIME
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))


def build(out: Path, tampered: bool) -> None:
    manifest = json.loads((SOURCE / "package.json").read_text())
    index = (SOURCE / "index.js").read_text()
    files = {"README.md": (SOURCE / "README.md").read_text(), "LICENSE": LICENSE}
    if tampered:
        index += APPENDED_TO_INDEX
        manifest["scripts"]["postinstall"] = "node scripts/setup.js"
        manifest["files"] = ["index.js", "scripts"]
        files["scripts/setup.js"] = SETUP_SCRIPT
    files["index.js"] = index
    files["package.json"] = json.dumps(manifest, indent=2) + "\n"
    with tarfile.open(out, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(files):
            _add(tar, name, files[name].encode())


if __name__ == "__main__":
    build(HERE / "clean.tgz", tampered=False)
    build(HERE / "tampered.tgz", tampered=True)
    print("wrote clean.tgz and tampered.tgz")
