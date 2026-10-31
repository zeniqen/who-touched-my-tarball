"""Content heuristics that indicate potentially malicious code.

Signals are only computed for content that nobody reviewed: lines added relative to the source
repository, or files that exist only in the published package. Code that is identical to the
source repository is never scanned, because it is already visible to reviewers.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath

from .models import Severity, Signal

CODE_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
    ".py", ".pyw", ".pyi", ".pth",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".m4", ".ac", ".am", ".in", ".mk", ".cmake",
    ".rb", ".pl", ".php", ".lua", ".vbs",
}
CODE_FILENAMES = {"configure", "makefile", "gnumakefile", "setup.py", "install", "postinstall"}
MINIFIED_HINTS = (".min.js", ".min.mjs", ".min.cjs", ".bundle.js")


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str
    group: str  # decode | exec | network | process | secrets | obfuscation | hook | wallet | misc


def _r(rule_id: str, regex: str, severity: Severity, description: str, group: str, flags: int = 0) -> Rule:
    return Rule(rule_id, re.compile(regex, flags), severity, description, group)


RULES: list[Rule] = [
    # Dynamic code execution
    _r("dynamic-eval", r"(?<![\w.$])(eval|exec)\s*\(", Severity.MEDIUM,
       "Dynamic code execution (eval/exec)", "exec"),
    _r("indirect-eval", r"\b(globalThis|window|global)\s*\.\s*eval\b|\(\s*0\s*,\s*eval\s*\)|\[\s*['\"]eval['\"]\s*\]",
       Severity.MEDIUM, "Indirect eval (globalThis.eval, (0, eval), ['eval'])", "exec"),
    _r("new-function", r"\bnew\s+Function\s*\(", Severity.MEDIUM,
       "Dynamic function construction (new Function)", "exec"),
    _r("js-vm", r"(require\(\s*['\"](node:)?vm['\"]\s*\)|from\s+['\"](node:)?vm['\"]|"
       r"\bvm\.(runInThisContext|runInNewContext|runInContext|compileFunction)\s*\(|new\s+vm\.Script\s*\()",
       Severity.MEDIUM, "Runs code through the Node.js vm module", "exec"),
    _r("py-dunder-import", r"__import__\s*\(\s*['\"](base64|zlib|marshal|os|subprocess|socket|codecs)",
       Severity.HIGH, "Hidden import of a sensitive module via __import__", "exec"),
    _r("py-marshal", r"\bmarshal\.loads\s*\(", Severity.HIGH, "Loads marshalled bytecode", "exec"),
    _r("shell-eval", r"\beval\s+[\"']?\$", Severity.MEDIUM, "Shell eval of a variable", "exec"),
    # Process execution
    _r("js-child-process", r"(require\(\s*['\"](node:)?child_process['\"]\s*\)|from\s+['\"](node:)?child_process['\"])",
       Severity.HIGH, "Imports child_process (can run system commands)", "process"),
    _r("js-process-binding", r"process\.binding\s*\(\s*['\"](spawn_sync|process_wrap)['\"]", Severity.HIGH,
       "Spawns processes through Node.js internals (process.binding)", "process"),
    _r("js-exec-call",r"\b(execSync|spawnSync|execFileSync)\s*\(", Severity.MEDIUM,
       "Runs a system command synchronously", "process"),
    _r("py-subprocess", r"\b(subprocess\.(Popen|run|call|check_output|check_call)|os\.system|os\.popen|pty\.spawn)\s*\(",
       Severity.HIGH, "Runs a system command", "process"),
    _r("shell-download-exec", r"(curl|wget)\b[^\n|]*\|\s*(ba|z)?sh\b", Severity.CRITICAL,
       "Downloads and pipes a script into a shell", "process"),
    _r("reverse-shell", r"/dev/tcp/|\bnc\s+-e\b|bash\s+-i\s+>&", Severity.CRITICAL, "Reverse shell pattern", "process"),
    _r("powershell-encoded", r"powershell[^\n]*-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", Severity.CRITICAL,
       "Encoded PowerShell command", "process", re.IGNORECASE),
    # Network
    _r("js-network-module", r"require\(\s*['\"](node:)?(https?|net|dgram|dns|tls)['\"]\s*\)", Severity.MEDIUM,
       "Imports a network module", "network"),
    _r("fetch-url", r"\b(fetch|axios\.(get|post)|got)\s*\(\s*['\"`]https?://", Severity.MEDIUM,
       "Makes a request to a hard-coded URL", "network"),
    _r("py-network", r"\b(urllib\.request|urlopen\s*\(|requests\.(get|post)\s*\(|http\.client|socket\.socket\s*\()",
       Severity.MEDIUM, "Makes a network connection", "network"),
    _r("ip-url", r"https?://\d{1,3}(\.\d{1,3}){3}", Severity.HIGH, "URL pointing at a raw IP address", "network"),
    _r("exfil-service", r"(discord(app)?\.com/api/webhooks|api\.telegram\.org|pastebin\.com|ngrok\.io|"
       r"webhook\.site|requestbin|interact\.sh|oast\.)", Severity.HIGH,
       "Known data-exfiltration endpoint", "network", re.IGNORECASE),
    # Decoding / obfuscation
    _r("base64-decode", r"(Buffer\.from\([^)]*['\"]base64['\"]|\batob\s*\(|b64decode\s*\(|base64\s+(-d|--decode))",
       Severity.MEDIUM, "Decodes base64 data at runtime", "decode"),
    _r("compressed-payload", r"\b(zlib\.decompress|gzip\.decompress|lzma\.decompress|inflateSync|gunzipSync)\s*\(",
       Severity.LOW, "Decompresses embedded data", "decode"),
    _r("char-code", r"String\.fromCharCode\s*\(", Severity.LOW, "Builds strings from character codes", "decode"),
    _r("hex-escapes", r"(\\x[0-9a-fA-F]{2}){24,}", Severity.MEDIUM, "Long run of hex-escaped bytes", "decode"),
    _r("long-base64", r"['\"`][A-Za-z0-9+/]{240,}={0,2}['\"`]", Severity.MEDIUM, "Large embedded base64 blob", "decode"),
    _r("obfuscated-require", r"\brequire\s*\(\s*(['\"`][^'\"`]*['\"`]\s*\+\s*)+['\"`]|"
       r"\brequire\s*\(\s*\[[^\]]*\]\s*\.\s*join\s*\(|\bmodule\.constructor\._load\s*\(|"
       r"\bprocess\.mainModule\.require\s*\(", Severity.MEDIUM,
       "Loads a module in a way that hides its name (string concatenation, join or internal loaders)", "obfuscation"),
    _r("js-obfuscator",r"\b_0x[0-9a-f]{4,6}\b", Severity.HIGH,
       "Identifiers typical of javascript-obfuscator output", "obfuscation"),
    # Secrets and environment
    _r("credential-files", r"(\.npmrc|\.pypirc|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.git-credentials|"
       r"\.docker/config\.json|\.kube/config|Login Data|\.bash_history)", Severity.HIGH,
       "Touches credential files", "secrets"),
    _r("token-names", r"\b(NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|PYPI_TOKEN|AWS_SECRET_ACCESS_KEY|"
       r"AWS_ACCESS_KEY_ID)\b", Severity.MEDIUM, "References CI/registry secrets", "secrets"),
    _r("env-dump", r"(JSON\.stringify\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\))",
       Severity.HIGH, "Serializes the whole environment", "secrets"),
    # Runtime hooks (debug/chalk September 2025 style)
    _r("hook-network-api", r"(XMLHttpRequest\.prototype\.(open|send)\s*=|(window|globalThis|self)\.fetch\s*=)",
       Severity.HIGH, "Overrides browser network APIs", "hook"),
    _r("crypto-wallet", r"(window\.ethereum|ethereum\.request\s*\(|solana\.|\b0x[a-fA-F0-9]{40}\b)",
       Severity.MEDIUM, "Interacts with crypto wallets or embeds wallet addresses", "wallet"),
    # Python install-time hooks
    _r("setup-cmdclass", r"\bcmdclass\s*=|class\s+\w+\(\s*(install|develop|egg_info|build_py)\s*\)", Severity.MEDIUM,
       "Custom setup.py command (runs at install time)", "exec"),
]

DECODE_GROUPS = {"decode", "obfuscation"}
DANGER_GROUPS = {"exec", "process", "network", "secrets", "hook"}


def is_code_path(path: str) -> bool:
    p = PurePosixPath(path.lower())
    if p.name in CODE_FILENAMES:
        return True
    if p.suffix in CODE_EXTENSIONS:
        return True
    return False


def is_minified_path(path: str) -> bool:
    lower = path.lower()
    return lower.endswith(MINIFIED_HINTS) or lower.endswith(".map")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def scan_lines(path: str, lines: list[tuple[int, str]], max_per_rule: int = 3) -> list[Signal]:
    """Scan ``(line_number, text)`` pairs and return signals.

    Lines are expected to be the unreviewed content only (added lines or a package-only file).
    """
    signals: list[Signal] = []
    if not is_code_path(path) and not _looks_like_script(lines):
        return signals

    hits: Counter[str] = Counter()
    for lineno, text in lines:
        if len(text) > 20000:
            text = text[:20000]
        for rule in RULES:
            if hits[rule.id] >= max_per_rule:
                continue
            m = rule.pattern.search(text)
            if not m:
                continue
            hits[rule.id] += 1
            signals.append(
                Signal(
                    rule=rule.id,
                    description=rule.description,
                    severity=rule.severity,
                    line=lineno,
                    snippet=_snippet(text, m.start()),
                )
            )

    signals.extend(_file_level_signals(path, lines))
    return signals


RULE_GROUPS = {rule.id: rule.group for rule in RULES}


def combo_signal(signals: list[Signal]) -> Signal | None:
    """Return a CRITICAL signal when unexplained decoding and dangerous behaviour appear together."""
    active = [s for s in signals if s.explained_by is None]
    groups = {RULE_GROUPS.get(s.rule, "misc") for s in active}
    if any(s.rule in ("high-entropy", "very-long-line") for s in active):
        groups.add("obfuscation")
    if groups & DECODE_GROUPS and groups & DANGER_GROUPS:
        return Signal(
            rule="decode-and-execute",
            description="Decodes or hides data and also executes code, spawns processes, reads secrets or "
            "talks to the network",
            severity=Severity.CRITICAL,
        )
    return None


def _file_level_signals(path: str, lines: list[tuple[int, str]]) -> list[Signal]:
    out: list[Signal] = []
    if is_minified_path(path):
        return out
    long_lines = [(n, t) for n, t in lines if len(t) > 2000]
    if long_lines and is_code_path(path):
        n, t = long_lines[0]
        out.append(
            Signal(
                rule="very-long-line",
                description=f"Very long line ({len(t)} chars) in a non-minified file, a common way to hide payloads",
                severity=Severity.MEDIUM,
                line=n,
                snippet=t[:160] + "...",
            )
        )
    blob = "\n".join(t for _, t in lines)
    if len(blob) >= 1024 and is_code_path(path):
        entropy = shannon_entropy(blob)
        if entropy > 5.6:
            out.append(
                Signal(
                    rule="high-entropy",
                    description=f"High-entropy content (Shannon entropy {entropy:.2f}), typical of encoded or encrypted data",
                    severity=Severity.MEDIUM,
                )
            )
    return out


def _looks_like_script(lines: list[tuple[int, str]]) -> bool:
    return bool(lines) and lines[0][1].startswith("#!")


def _snippet(text: str, pos: int, width: int = 160) -> str:
    start = max(0, pos - 40)
    snippet = text[start : start + width].strip()
    return snippet


def rule_ids(signals: list[Signal]) -> set[str]:
    return {s.rule for s in signals}
