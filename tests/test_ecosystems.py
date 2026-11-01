"""Registry retrieval, integrity and extensibility (PRD FR-1, FR-12, SEC-5). Network is mocked."""

from __future__ import annotations

import base64
import hashlib

import httpx
import pytest

from whotouchedmytarball import analyzer, ecosystems
from whotouchedmytarball.analyzer import AnalyzeOptions, analyze_release
from whotouchedmytarball.ecosystems import RegistryError, get_ecosystem
from whotouchedmytarball.ecosystems.base import Ecosystem, ReleaseInfo, sri_to_hex, verify_digests
from whotouchedmytarball.ecosystems.npm import NpmEcosystem
from whotouchedmytarball.models import Provenance

from .conftest import INDEX_JS, make_tgz, npm_manifest


@pytest.mark.parametrize("alias, name", [("npm", "npm"), ("node", "npm"), ("JS", "npm"), ("pypi", "pypi"),
                                         ("pip", "pypi"), ("Python", "pypi")])
def test_ecosystem_aliases(alias, name):
    assert get_ecosystem(alias).name == name


def test_unknown_ecosystem_is_a_clear_error():
    with pytest.raises(RegistryError, match="unsupported ecosystem"):
        get_ecosystem("cargo")


def test_sri_integrity_is_converted_to_hex():
    digest = hashlib.sha512(b"data").digest()
    assert sri_to_hex("sha512-" + base64.b64encode(digest).decode()) == ("sha512", digest.hex())
    assert sri_to_hex("") is None and sri_to_hex("nodash") is None


def test_digest_mismatch_is_rejected(tmp_path):
    f = tmp_path / "a.tgz"
    f.write_bytes(b"tampered")
    with pytest.raises(RegistryError, match="digest mismatch"):
        verify_digests(f, {"sha256": hashlib.sha256(b"original").hexdigest()})
    assert "verified" in verify_digests(f, {"sha256": hashlib.sha256(b"tampered").hexdigest()})


def test_npm_tag_candidates_cover_monorepo_conventions():
    tags = NpmEcosystem().tag_candidates("@scope/widget", "1.2.3")
    assert {"v1.2.3", "1.2.3", "@scope/widget@1.2.3", "widget@1.2.3", "widget-v1.2.3"} <= set(tags)


# --- FR-12: a new ecosystem is one adapter; nothing else changes --------------------------------

class ToyEcosystem(Ecosystem):
    """A made-up registry served by httpx.MockTransport."""

    name = "toy"

    def __init__(self, tarball: bytes, published_digest: str):
        self.tarball, self.published_digest = tarball, published_digest

    def resolve(self, client, package, version, dist="auto"):
        return ReleaseInfo(ecosystem="toy", name=package, version=version or "1.0.0",
                           artifact_url="https://toy.invalid/demo-1.0.0.tgz", artifact_filename="demo-1.0.0.tgz",
                           expected_digests={"sha256": self.published_digest})

    def latest_version(self, client, package):
        return "1.0.0"

    def provenance(self, client, release):
        return Provenance(available=False, note="toy registry has no provenance")

    def tag_candidates(self, package, version):
        return [f"v{version}"]


@pytest.fixture
def toy_registry(monkeypatch, tmp_path):
    def install(tarball: bytes, published_digest: str | None = None) -> None:
        eco = ToyEcosystem(tarball, published_digest or hashlib.sha256(tarball).hexdigest())
        monkeypatch.setitem(ecosystems.ECOSYSTEMS, "toy", eco)
        transport = httpx.MockTransport(lambda request: httpx.Response(200, content=tarball))
        monkeypatch.setattr(analyzer, "make_client", lambda: httpx.Client(transport=transport))
    return install


def test_new_ecosystem_adapter_runs_the_full_pipeline(toy_registry, tmp_path, npm_source):
    tarball = make_tgz(tmp_path / "demo.tgz", {"package.json": npm_manifest(), "index.js": INDEX_JS}).read_bytes()
    toy_registry(tarball)
    report = analyze_release("toy", "demo", "1.0.0", source=str(npm_source), opts=AnalyzeOptions(ai=None))
    assert report.ecosystem == "toy" and report.verdict == "CLEAN"
    assert "verified against registry digest" in report.artifact_integrity


def test_download_that_does_not_match_registry_digest_is_refused(toy_registry, tmp_path, npm_source):
    tarball = make_tgz(tmp_path / "demo.tgz", {"package.json": npm_manifest(), "index.js": INDEX_JS}).read_bytes()
    toy_registry(tarball, published_digest=hashlib.sha256(b"what the registry signed").hexdigest())
    with pytest.raises(RegistryError, match="digest mismatch"):
        analyze_release("toy", "demo", "1.0.0", source=str(npm_source), opts=AnalyzeOptions(ai=None))
