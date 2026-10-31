"""CLI exit codes on the committed offline demo (no network, no model)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from whotouchedmytarball.cli import app

DEMO = Path(__file__).resolve().parent.parent / "examples" / "offline-demo"
runner = CliRunner()


def run(*args: str):
    return runner.invoke(app, ["diff", *args, str(DEMO / "source"), "--no-ai", "--quiet"])


def test_clean_demo_exits_zero():
    result = run(str(DEMO / "clean.tgz"))
    assert result.exit_code == 0, result.output
    assert result.output.startswith("CLEAN")


def test_tampered_demo_exits_two():
    result = run(str(DEMO / "tampered.tgz"))
    assert result.exit_code == 2, result.output
    assert result.output.startswith("SUSPICIOUS")


def test_writes_json_and_markdown(tmp_path):
    result = runner.invoke(app, ["diff", str(DEMO / "tampered.tgz"), str(DEMO / "source"), "--no-ai", "--quiet",
                                 "--json", str(tmp_path / "r.json"), "--md", str(tmp_path / "r.md")])
    assert result.exit_code == 2
    assert '"verdict": "SUSPICIOUS"' in (tmp_path / "r.json").read_text()
    assert "## Evidence" in (tmp_path / "r.md").read_text()
