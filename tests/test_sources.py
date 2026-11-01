"""Source fetching with real (local) git repositories; no network needed."""

from __future__ import annotations

import subprocess

from whotouchedmytarball import sources


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "protocol.file.allow=always",
                    "-c", "init.defaultBranch=main", *args], cwd=cwd, check=True, capture_output=True)


def test_submodules_are_fetched_over_https_only(tmp_path, monkeypatch):
    """Submodules are fetched, but a .gitmodules pointing at a local path must not be followed."""
    sub = tmp_path / "secret"
    sub.mkdir()
    git(sub, "init", "-q")
    (sub / "secret.txt").write_text("host file\n")
    git(sub, "add", ".")
    git(sub, "commit", "-qm", "secret")

    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "index.js").write_text("module.exports = 1;\n")
    git(repo, "submodule", "add", "-q", str(sub), "vendor/secret")
    git(repo, "add", "index.js")
    git(repo, "commit", "-qm", "release")

    calls = []
    real_git = sources._git

    def recording_git(args, cwd=None):
        calls.append(args)
        return real_git(args, cwd)

    monkeypatch.setenv("WTMT_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(sources, "_git", recording_git)
    checkout = sources.fetch_source(str(repo), ref="HEAD")

    assert (checkout.path / "index.js").is_file()
    submodule_call = next(a for a in calls if "submodule" in a)
    assert "protocol.allow=never" in submodule_call and "protocol.https.allow=always" in submodule_call
    assert not (checkout.path / "vendor" / "secret" / "secret.txt").exists()
    assert any("submodules could not be fetched" in n for n in checkout.notes)
