from __future__ import annotations

from whotouchedmytarball.compare import compare_trees, detect_root_prefix

from .conftest import write_tree


def test_identical_modified_and_package_only(tmp_path):
    src = write_tree(tmp_path / "src", {"a.js": "one\n", "b.js": "two\n", "test.js": "t\n"})
    pkg = write_tree(tmp_path / "pkg", {"a.js": "one\n", "b.js": "two\nthree\n", "extra.js": "x\n"})
    comp = compare_trees(pkg, src)
    kinds = {d.path: d.kind for d in comp.diffs}
    assert comp.identical == ["a.js"]
    assert kinds == {"b.js": "modified", "extra.js": "package_only"}
    assert comp.source_only == ["test.js"]
    modified = next(d for d in comp.diffs if d.path == "b.js")
    assert modified.added == [(2, "three")]


def test_whitespace_only_difference(tmp_path):
    src = write_tree(tmp_path / "src", {"a.py": "x = 1\r\ny = 2\r\n"})
    pkg = write_tree(tmp_path / "pkg", {"a.py": "x = 1   \ny = 2\n"})
    comp = compare_trees(pkg, src)
    assert comp.diffs[0].whitespace_only


def test_src_layout_prefix_detection():
    pkg = ["demo/__init__.py", "demo/core.py", "demo/util.py", "demo-1.0.dist-info/METADATA"]
    src = ["src/demo/__init__.py", "src/demo/core.py", "src/demo/util.py", "tests/test_core.py", "pyproject.toml"]
    assert detect_root_prefix(pkg, src) == "src/"


def test_monorepo_prefix_detection():
    pkg = ["package.json", "index.js", "lib/parse.js", "lib/format.js"]
    src = ["package.json", "packages/core/package.json", "packages/core/index.js", "packages/core/lib/parse.js",
           "packages/core/lib/format.js", "packages/other/index.js"]
    assert detect_root_prefix(pkg, src, hints=["packages/core"]) == "packages/core/"


def test_no_source_marks_everything_package_only(tmp_path):
    pkg = write_tree(tmp_path / "pkg", {"a.js": "1\n"})
    comp = compare_trees(pkg, None)
    assert [d.kind for d in comp.diffs] == ["package_only"]


def test_internal_symlinks_are_followed_external_ignored(tmp_path):
    src = write_tree(tmp_path / "src", {"shared/ca.crt": "cert\n"})
    (src / "valid").mkdir()
    (src / "valid" / "ca").symlink_to("../shared")
    outside = write_tree(tmp_path / "outside", {"secret.txt": "nope\n"})
    (src / "leak").symlink_to(outside)
    pkg = write_tree(tmp_path / "pkg", {"valid/ca/ca.crt": "cert\n"})
    comp = compare_trees(pkg, src)
    assert comp.identical == ["valid/ca/ca.crt"]
    assert not any(p.startswith("leak/") for p in comp.source_files)


def test_declared_directory_beats_committed_build_copies(tmp_path):
    """react's repo keeps built cjs/ copies in a fixture; the registry's repository.directory must win."""
    src = write_tree(tmp_path / "src", {
        "packages/react/package.json": "{}\n",
        "packages/react/index.js": "module.exports = 1;\n",
        "fixtures/old/package.json": "{}\n",
        "fixtures/old/cjs/react.development.js": "old build\n",
        "fixtures/old/cjs/react.production.min.js": "old build\n",
    })
    pkg = write_tree(tmp_path / "pkg", {
        "package.json": "{}\n",
        "index.js": "module.exports = 1;\n",
        "cjs/react.development.js": "new build\n",
        "cjs/react.production.min.js": "new build\n",
    })
    assert compare_trees(pkg, src).root_prefix == "fixtures/old/"  # voting alone is fooled
    comp = compare_trees(pkg, src, hints=["packages/react"])
    assert comp.root_prefix == "packages/react/"
    kinds = {d.path: d.kind for d in comp.diffs}
    assert kinds == {"cjs/react.development.js": "package_only", "cjs/react.production.min.js": "package_only"}
