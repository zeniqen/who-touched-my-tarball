from whotouchedmytarball.trust.compare import detect_changes
from whotouchedmytarball.trust.identity import normalize_repo_url
from whotouchedmytarball.trust.models import BaselineStatus, IdentityObservation, TrustBaseline


def test_repo_normalization():
    assert normalize_repo_url("git@github.com:Org/Repo.git") == "https://github.com/org/repo"
    assert normalize_repo_url("https://github.com/Org/Repo/") == "https://github.com/org/repo"


def test_repo_change_detection():
    baseline = TrustBaseline(ecosystem="npm", package_name="demo", repository_url="https://github.com/org/repo",
                            first_observed_at="t1", last_observed_at="t1")
    obs = IdentityObservation(ecosystem="npm", package_name="demo", version="1.0.1",
                              repository_url="https://github.com/other/repo", observed_at="t2")
    changes = detect_changes(baseline, obs)
    assert any(c.field == "repository_url" for c in changes)


def test_no_change_same_identity():
    baseline = TrustBaseline(ecosystem="npm", package_name="demo", repository_url="https://github.com/org/repo",
                            first_observed_at="t1", last_observed_at="t1", baseline_status=BaselineStatus.OBSERVED)
    obs = IdentityObservation(ecosystem="npm", package_name="demo", version="1.0.1",
                              repository_url="https://github.com/org/repo", observed_at="t2")
    changes = detect_changes(baseline, obs)
    assert changes == []


def test_initial_observation_no_baseline_no_changes():
    obs = IdentityObservation(ecosystem="npm", package_name="demo", version="1.0.0", observed_at="t1")
    assert detect_changes(None, obs) == []
