from pathlib import Path

from whotouchedmytarball.reproducibility.recipe import discover_recipe, has_sufficient_information
from whotouchedmytarball.reproducibility.normalize import normalized_tree_hash, normalize_archive
from whotouchedmytarball.reproducibility.compare import compare_artifact_trees, classify_status
from whotouchedmytarball.reproducibility.environment import docker_available
from whotouchedmytarball.reproducibility.models import VerificationStatus, NetworkPolicy

def write_tree(root, files):
    from pathlib import Path
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
    return root
from whotouchedmytarball.reproducibility.verifier import verify_build


def test_recipe_npm(tmp_path):
    src = write_tree(tmp_path / "s", {"package.json": '{"name":"d","version":"1.0.0","scripts":{"build":"echo hi"}}\n', "package-lock.json": "{}\n", "index.js": "x\n"})
    r = discover_recipe(src, "npm")
    assert r.build_commands == ["npm run build"]
    assert r.lockfile is not None
    assert has_sufficient_information(r)


def test_recipe_missing(tmp_path):
    src = write_tree(tmp_path / "s", {"README.md": "hi\n"})
    r = discover_recipe(src, "npm")
    assert not has_sufficient_information(r)


def test_normalize_tree_hash_order_independent(tmp_path):
    a = write_tree(tmp_path / "a", {"b.txt": "x\n", "a.txt": "y\n"})
    b = write_tree(tmp_path / "b", {"a.txt": "y\n", "b.txt": "x\n"})
    assert normalized_tree_hash(a) == normalized_tree_hash(b)


def test_compare_exact(tmp_path):
    a = write_tree(tmp_path / "a", {"index.js": "x\n"})
    b = write_tree(tmp_path / "b", {"index.js": "x\n"})
    comp = compare_artifact_trees(a, b)
    assert comp.files_matched == ["index.js"]
    assert classify_status(comp, True) == VerificationStatus.EXACT_MATCH


def test_compare_missing_unexpected(tmp_path):
    a = write_tree(tmp_path / "a", {"index.js": "x\n", "extra.js": "y\n"})
    b = write_tree(tmp_path / "b", {"index.js": "x\n"})
    comp = compare_artifact_trees(a, b)
    assert "extra.js" in comp.missing_files
    a2 = write_tree(tmp_path / "a2", {"index.js": "x\n"})
    b2 = write_tree(tmp_path / "b2", {"index.js": "x\n", "more.js": "y\n"})
    comp2 = compare_artifact_trees(a2, b2)
    assert "more.js" in comp2.unexpected_files


def test_environment_unavailable_returns_status(tmp_path):
    # docker is not available in test env, verifier should return ENVIRONMENT_UNAVAILABLE
    res = verify_build("npm", "debug", "4.4.1")
    assert res.status == VerificationStatus.ENVIRONMENT_UNAVAILABLE


def test_network_policy_enum():
    assert NetworkPolicy("none") == NetworkPolicy.NONE
