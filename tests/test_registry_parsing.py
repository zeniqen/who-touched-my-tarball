"""Parsing of registry metadata, provenance and repository URLs (no network)."""

from __future__ import annotations

import base64
import json

from whotouchedmytarball.ecosystems.npm import NpmEcosystem, parse_npm_attestations
from whotouchedmytarball.ecosystems.pypi import PyPIEcosystem, find_repository, parse_pypi_provenance
from whotouchedmytarball.sources import normalize_repo_url, pick_tag, same_repository


def test_normalize_repo_urls():
    cases = {
        "git+https://github.com/debug-js/debug.git": "https://github.com/debug-js/debug",
        "git@github.com:psf/requests.git": "https://github.com/psf/requests",
        "github:chalk/chalk": "https://github.com/chalk/chalk",
        "chalk/chalk": "https://github.com/chalk/chalk",
        "git://github.com/a/b.git": "https://github.com/a/b",
        "https://www.github.com/a/b/issues": "https://github.com/a/b",
    }
    for raw, expected in cases.items():
        assert normalize_repo_url(raw).url == expected
    assert normalize_repo_url("https://example.com/not/a/forge") is None
    ref = normalize_repo_url("https://github.com/babel/babel/tree/main/packages/babel-core")
    assert ref.subdirectory == "packages/babel-core"
    assert same_repository("git+https://github.com/A/B.git", "https://github.com/a/b")


def test_tag_candidates_and_pick():
    tags = ["v4.4.0", "v4.4.1", "debug@5.0.0"]
    assert pick_tag(tags, NpmEcosystem().tag_candidates("debug", "4.4.1")) == "v4.4.1"
    assert pick_tag(["requests-2.0", "v2.32.3"], PyPIEcosystem().tag_candidates("requests", "2.32.3")) == "v2.32.3"
    assert pick_tag(["1.0"], ["v2.0", "2.0"]) is None


def _b64(obj) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


def test_parse_npm_slsa_provenance():
    statement = {
        "predicate": {
            "buildDefinition": {
                "externalParameters": {"workflow": {"repository": "https://github.com/acme/lib",
                                                    "path": ".github/workflows/release.yml", "ref": "refs/tags/v1.2.3"}},
                "resolvedDependencies": [{"uri": "git+https://github.com/acme/lib@refs/tags/v1.2.3",
                                          "digest": {"gitCommit": "abc123"}}],
            }
        }
    }
    doc = {"attestations": [
        {"predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1", "bundle": {}},
        {"predicateType": "https://slsa.dev/provenance/v1",
         "bundle": {"dsseEnvelope": {"payload": _b64(statement)}}},
    ]}
    prov = parse_npm_attestations(doc)
    assert prov.available and prov.commit == "abc123"
    assert prov.repository == "https://github.com/acme/lib"
    assert prov.workflow == ".github/workflows/release.yml"


def test_parse_pypi_provenance():
    statement = {"subject": [{"name": "demo-1.0.tar.gz"}]}
    doc = {"attestation_bundles": [{
        "publisher": {"kind": "GitHub", "repository": "acme/demo", "workflow": "release.yml"},
        "attestations": [{"envelope": {"statement": _b64(statement)}}],
    }]}
    prov = parse_pypi_provenance(doc, "demo-1.0.tar.gz")
    assert prov.available and prov.repository == "https://github.com/acme/demo"
    assert "does not name" not in prov.note


def test_find_repository_prefers_source_link():
    info = {"project_urls": {"Documentation": "https://demo.readthedocs.io",
                             "Source": "https://github.com/acme/demo"}, "home_page": "https://acme.dev"}
    assert find_repository(info) == "https://github.com/acme/demo"


def test_npm_previous_version_skips_prereleases():
    doc = {"versions": {"1.0.0": {}, "1.1.0-beta.1": {}, "1.1.0": {}},
           "time": {"1.0.0": "2024-01-01", "1.1.0-beta.1": "2024-02-01", "1.1.0": "2024-03-01"}}
    assert NpmEcosystem._previous(doc, "1.1.0") == "1.0.0"
