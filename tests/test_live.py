"""Live evaluation on real releases (PRD section 8). Opt-in: ``pytest -m live``; needs network and git."""

from __future__ import annotations

import pytest

from whotouchedmytarball.analyzer import AnalyzeOptions, analyze_release
from whotouchedmytarball.provenance.models import VerificationStatus
from whotouchedmytarball.provenance.verifier import verify_provenance

pytestmark = pytest.mark.live

OPTS = AnalyzeOptions(ai=None)

# Recent legitimate releases: differences are expected (build output, metadata) but none are malicious.
REAL_RELEASES = [
    ("npm", "debug", "4.4.1", "auto"),
    ("npm", "axios", "1.7.9", "auto"),
    ("npm", "ky", "1.7.4", "auto"),
    ("pypi", "requests", "2.32.3", "sdist"),
    ("pypi", "requests", "2.32.3", "wheel"),
]


@pytest.mark.parametrize("eco, name, version, dist", REAL_RELEASES, ids=lambda v: str(v))
def test_real_release_is_not_suspicious(eco, name, version, dist):
    report = analyze_release(eco, name, version, dist=dist, opts=OPTS)
    serious = [f"{f.path}: {f.reason}" for f in report.findings if f.severity.rank >= 3]
    assert report.verdict != "SUSPICIOUS", serious
    assert report.source is not None and report.source.commit, "source revision should be resolved"
    assert "verified" in report.artifact_integrity


def test_npm_provenance_claims_match_fetched_source():
    report = analyze_release("npm", "semver", "7.7.1", opts=OPTS)
    assert report.provenance.available
    assert report.provenance.repository == "https://github.com/npm/node-semver"
    assert report.source.commit == report.provenance.commit


def test_verify_provenance_reads_real_npm_attestation():
    result = verify_provenance("npm", "semver", "7.7.1")
    assert result.attestation_found
    assert result.status not in (VerificationStatus.INVALID_ATTESTATION, VerificationStatus.DIGEST_MISMATCH), \
        result.verification_errors
