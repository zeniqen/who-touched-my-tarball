"""Red-team mode: tamper real-looking releases with modelled attacks and prove wtmt catches each one."""

from __future__ import annotations

import json
import re
import tarfile
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from whotouchedmytarball.analyzer import AnalyzeOptions, analyze_local
from whotouchedmytarball.cli import app
from whotouchedmytarball.redteam import ATTACKS, NotApplicable, applicable_attacks, run_campaign, tamper

from .conftest import make_tgz, make_zip, write_tree

DEMO = Path(__file__).resolve().parent.parent / "examples" / "offline-demo"
OPTS = AnalyzeOptions(ai=None)
runner = CliRunner()

PY_SOURCE = {
    "pyproject.toml": "[build-system]\nrequires = ['setuptools']\n[project]\nname = 'demo'\nversion = '1.0'\n",
    "setup.py": "from setuptools import setup\nsetup()\n",
    "src/demo/__init__.py": "from .core import add\n__all__ = ['add']\n",
    "src/demo/core.py": "def add(a, b):\n    return a + b\n",
    "README.md": "# demo\n",
}


@pytest.fixture
def pypi_base(tmp_path):
    src = write_tree(tmp_path / "pysrc", PY_SOURCE)
    sdist = make_tgz(tmp_path / "demo-1.0.tar.gz", {**PY_SOURCE, "PKG-INFO": "Metadata-Version: 2.1\nName: demo\n"},
                     prefix="demo-1.0/")
    wheel = make_zip(tmp_path / "demo-1.0-py3-none-any.whl", {
        "demo/__init__.py": PY_SOURCE["src/demo/__init__.py"], "demo/core.py": PY_SOURCE["src/demo/core.py"],
        "demo-1.0.dist-info/METADATA": "Name: demo\n", "demo-1.0.dist-info/RECORD": "demo/__init__.py,,\n",
    })
    return src, sdist, wheel


def members(path: Path) -> dict[str, bytes]:
    if path.name.endswith(".whl"):
        with zipfile.ZipFile(path) as zf:
            return {n: zf.read(n) for n in zf.namelist()}
    with tarfile.open(path) as tf:
        return {m.name: tf.extractfile(m).read() for m in tf.getmembers() if m.isfile()}


# --- registry ------------------------------------------------------------------------------------

def test_registry_covers_the_modelled_attacks():
    ids = set(ATTACKS)
    assert {"postinstall-dropper", "wallet-hook", "injected-dependency", "xz-m4", "pth-autorun"} <= ids
    for attack in ATTACKS.values():
        assert attack.title and attack.incident and attack.formats


def test_applicable_attacks_depend_on_the_package_format(tmp_path, pypi_base):
    _, sdist, wheel = pypi_base
    npm = {a.id for a in applicable_attacks(DEMO / "clean.tgz")}
    sd = {a.id for a in applicable_attacks(sdist)}
    wh = {a.id for a in applicable_attacks(wheel)}
    assert "postinstall-dropper" in npm and "xz-m4" not in npm and "pth-autorun" not in npm
    assert "xz-m4" in sd and "pth-autorun" not in sd
    assert "pth-autorun" in wh and "xz-m4" not in wh


# --- tamper --------------------------------------------------------------------------------------

def test_tamper_keeps_layout_and_changes_only_what_it_reports(tmp_path):
    out = tamper(DEMO / "clean.tgz", "wallet-hook", tmp_path / "out")
    before, after = members(DEMO / "clean.tgz"), members(out.artifact)
    assert set(after) == set(before)  # same files, same package/ prefix
    changed = {n for n in before if before[n] != after[n]}
    assert changed == {f"package/{p}" for p in out.changed_files} == {"package/index.js"}


def test_tamper_writes_a_do_not_install_manifest(tmp_path):
    out = tamper(DEMO / "clean.tgz", "postinstall-dropper", tmp_path / "out")
    manifest = json.loads(out.manifest.read_text())
    assert manifest["attack"] == "postinstall-dropper" and "DO NOT INSTALL" in manifest["warning"]
    assert manifest["base_sha256"] and set(manifest["changed_files"]) == {"package.json", "scripts/setup.js"}
    assert out.artifact.name.endswith(".tgz") and "wtmt-redteam" in out.artifact.name


def test_attack_that_does_not_fit_the_format_is_refused(tmp_path):
    with pytest.raises(NotApplicable):
        tamper(DEMO / "clean.tgz", "pth-autorun", tmp_path / "out")


def test_unknown_attack_is_refused(tmp_path):
    with pytest.raises(KeyError):
        tamper(DEMO / "clean.tgz", "nope", tmp_path / "out")


@pytest.mark.parametrize("attack_id", sorted(ATTACKS))
def test_payloads_are_inert(attack_id, tmp_path, pypi_base):
    """Injected content may only point at TEST-NET addresses or .invalid domains."""
    _, sdist, wheel = pypi_base
    base = next(b for b in (DEMO / "clean.tgz", sdist, wheel) if ATTACKS[attack_id].fits(b))
    out = tamper(base, attack_id, tmp_path / "out")
    before = members(base)
    old_lines = {line for v in before.values() for line in v.decode("utf-8", "replace").splitlines()}
    injected = [line for name, v in members(out.artifact).items() if before.get(name) != v
                for line in v.decode("utf-8", "replace").splitlines() if line not in old_lines]
    assert injected
    for host in re.findall(r"https?://([^/'\"\s:]+)", "\n".join(injected)):
        assert host.startswith("192.0.2.") or host.endswith(".invalid"), host


# --- detection: every attack on every base it fits must be SUSPICIOUS ----------------------------

def npm_cases():
    return [a.id for a in ATTACKS.values() if "npm" in a.formats]


@pytest.mark.parametrize("attack_id", npm_cases())
def test_npm_attack_is_caught(attack_id, tmp_path):
    out = tamper(DEMO / "clean.tgz", attack_id, tmp_path / "out")
    report = analyze_local(out.artifact, str(DEMO / "source"), opts=OPTS)
    assert report.verdict == "SUSPICIOUS", (attack_id, report.summary)


@pytest.mark.parametrize("fmt", ["sdist", "wheel"])
def test_pypi_attacks_are_caught(fmt, tmp_path, pypi_base):
    src, sdist, wheel = pypi_base
    base = sdist if fmt == "sdist" else wheel
    attacks = applicable_attacks(base)
    assert attacks
    for attack in attacks:
        out = tamper(base, attack.id, tmp_path / attack.id)
        report = analyze_local(out.artifact, str(src), ecosystem="pypi", opts=OPTS)
        assert report.verdict == "SUSPICIOUS", (fmt, attack.id, report.summary)


# --- campaign: the detection matrix ----------------------------------------------------------------

def test_campaign_builds_a_detection_matrix(tmp_path):
    result = run_campaign(DEMO / "clean.tgz", str(DEMO / "source"), workdir=tmp_path, opts=OPTS)
    assert result.baseline.verdict == "CLEAN" and not result.baseline.caught
    assert [r.attack for r in result.rows] == npm_cases()
    assert all(r.caught for r in result.rows), [(r.attack, r.verdict) for r in result.rows if not r.caught]
    assert result.detection_rate == 1.0 and result.baseline_ok
    assert all(r.evidence for r in result.rows)  # each row says which file/rule caught it


def test_campaign_can_select_attacks(tmp_path):
    result = run_campaign(DEMO / "clean.tgz", str(DEMO / "source"), workdir=tmp_path, opts=OPTS,
                          attacks=["wallet-hook"])
    assert [r.attack for r in result.rows] == ["wallet-hook"]


# --- CLI -----------------------------------------------------------------------------------------

def test_cli_lists_attacks():
    result = runner.invoke(app, ["tamper", "--list"])
    assert result.exit_code == 0 and "postinstall-dropper" in result.output and "xz-m4" in result.output


def test_cli_tampers_a_local_file(tmp_path):
    result = runner.invoke(app, ["tamper", "--file", str(DEMO / "clean.tgz"), "--attack", "injected-dependency",
                                 "--out", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert list(tmp_path.glob("*wtmt-redteam*.tgz"))


def test_cli_redteam_offline_matrix(tmp_path):
    result = runner.invoke(app, ["redteam", "--file", str(DEMO / "clean.tgz"), "--source", str(DEMO / "source"),
                                 "--no-ai", "--json", str(tmp_path / "m.json")])
    assert result.exit_code == 0, result.output
    data = json.loads((tmp_path / "m.json").read_text())
    assert data["detection_rate"] == 1.0 and data["baseline"]["verdict"] == "CLEAN"
    assert "caught" in result.output.lower()


# --- benchmark is now real base packages x attacks --------------------------------------------------

def test_benchmark_scenarios_are_bases_times_attacks(tmp_path, monkeypatch):
    monkeypatch.setenv("WTMT_HOME", str(tmp_path))
    from whotouchedmytarball.benchmark.dataset import default_scenarios
    from whotouchedmytarball.benchmark.runner import run_scenarios

    scenarios = default_scenarios()
    artifacts = {s.artifact_path for s in scenarios}
    assert len(artifacts) == len(scenarios)  # no file reused under a different name
    benign = [s for s in scenarios if s.label == "benign"]
    malicious = [s for s in scenarios if s.label == "malicious"]
    assert len(benign) >= 3 and len(malicious) >= len(ATTACKS)
    assert {s.category for s in malicious} == set(ATTACKS)
    results = run_scenarios(scenarios)
    wrong = [(r.scenario_id, r.verdict) for r in results if r.predicted_malicious != (r.label == "malicious")]
    assert not wrong
