"""Release monitoring (PRD FR-9, FR-11, SEC-8). Registry and analysis are faked; SQLite is real."""

from __future__ import annotations

import contextlib
from types import SimpleNamespace

import pytest

from whotouchedmytarball import monitor
from whotouchedmytarball.ecosystems import RegistryError
from whotouchedmytarball.models import Report, SourceInfo


@pytest.fixture
def watch(tmp_path, monkeypatch):
    """A watch list whose registry returns ``latest[name]`` and whose analysis is recorded."""
    latest: dict[str, str] = {}
    analyzed: list[tuple[str, str]] = []

    def latest_version(client, name):
        value = latest[name]
        if isinstance(value, Exception):
            raise value
        return value

    eco = SimpleNamespace(name="npm", latest_version=latest_version)
    monkeypatch.setattr(monitor, "make_client", lambda: contextlib.nullcontext(object()))
    monkeypatch.setattr(monitor, "get_ecosystem", lambda name: eco)

    def fake_analyze(eco_name, name, version, opts=None):
        analyzed.append((name, version))
        return Report(tool_version="t", ecosystem=eco_name, package=name, version=version, artifact="a.tgz",
                      verdict="CLEAN", risk_score=0, summary="ok",
                      source=SourceInfo(repository="https://github.com/acme/widget", commit="a" * 40))

    monkeypatch.setattr(monitor, "analyze_release", fake_analyze)
    conn = monitor.connect(tmp_path / "watch.db")
    out = tmp_path / "reports"
    return SimpleNamespace(conn=conn, out=out, latest=latest, analyzed=analyzed,
                           run=lambda: monitor.run_once(conn, out))


def test_add_list_remove(watch):
    monitor.add(watch.conn, "npm", "widget")
    monitor.add(watch.conn, "npm", "widget")  # idempotent
    assert [r[1] for r in monitor.list_watched(watch.conn)] == ["widget"]
    assert monitor.remove(watch.conn, "npm", "widget")
    assert monitor.list_watched(watch.conn) == []


def test_new_release_is_analyzed_once(watch):
    monitor.add(watch.conn, "npm", "widget")
    watch.latest["widget"] = "1.0.0"
    assert [r.verdict for r in watch.run()] == ["CLEAN"]
    assert [r.verdict for r in watch.run()] == ["UNCHANGED"]
    assert watch.analyzed == [("widget", "1.0.0")]


def test_baseline_version_is_not_reanalyzed(watch):
    monitor.add(watch.conn, "npm", "widget", baseline="2.0.0")
    watch.latest["widget"] = "2.0.0"
    assert [r.verdict for r in watch.run()] == ["UNCHANGED"]


def test_one_failing_package_does_not_stop_the_others(watch):
    monitor.add(watch.conn, "npm", "broken")
    monitor.add(watch.conn, "npm", "widget")
    watch.latest.update({"broken": RegistryError("registry down"), "widget": "1.0.0"})
    results = {r.name: r for r in watch.run()}
    assert results["broken"].verdict == "ERROR" and "registry down" in results["broken"].error
    assert results["widget"].verdict == "CLEAN"


def test_each_version_gets_its_own_report(watch):
    """4.4.1 and 4.4.2 must not both be written to npm-widget-4.4.json."""
    monitor.add(watch.conn, "npm", "widget")
    paths = []
    for version in ("4.4.1", "4.4.2"):
        watch.latest["widget"] = version
        (result,) = watch.run()
        paths.append(result.report_path)
        assert version in result.report_path.name
    assert paths[0] != paths[1] and all(p.exists() for p in paths)
    assert len(list(watch.out.glob("*.json"))) == 2


@pytest.mark.parametrize("version", ["../../../escaped", "1.0.0/../../../escaped", "..\\..\\escaped"])
def test_report_names_from_registry_cannot_escape_output_dir(watch, version):
    """SEC-8: versions come from the registry and are untrusted."""
    monitor.add(watch.conn, "npm", "@scope/widget")
    watch.latest["@scope/widget"] = version
    (result,) = watch.run()
    written = list(watch.out.parent.rglob("*.json")) + list(watch.out.parent.rglob("*.md"))
    assert written and all(p.parent == watch.out for p in written)
    assert result.report_path.parent == watch.out


def test_trust_baseline_created_on_first_release(watch):
    monitor.add(watch.conn, "npm", "widget")
    watch.latest["widget"] = "1.0.0"
    watch.run()
    (row,) = monitor.list_baselines(watch.conn, "npm", "widget")
    assert "https://github.com/acme/widget" in row
