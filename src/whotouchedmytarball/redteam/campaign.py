"""Red-team campaign: analyze a release, then every tampered copy of it, and build a detection matrix."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..analyzer import AnalyzeOptions, analyze_local
from ..models import Report, Severity
from .attacks import ATTACKS
from .tamper import applicable_attacks, tamper

CAUGHT = "SUSPICIOUS"


@dataclass
class Row:
    attack: str
    title: str
    incident: str
    verdict: str
    risk_score: int
    caught: bool
    evidence: list[str] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)


@dataclass
class CampaignResult:
    package: str
    baseline: Row
    rows: list[Row] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        return sum(r.caught for r in self.rows) / len(self.rows) if self.rows else 0.0

    @property
    def baseline_ok(self) -> bool:
        """The untouched release must not be flagged, or the matrix proves nothing."""
        return self.baseline.verdict != CAUGHT

    def to_dict(self) -> dict:
        return {"package": self.package, "baseline": asdict(self.baseline), "rows": [asdict(r) for r in self.rows],
                "detection_rate": self.detection_rate, "baseline_ok": self.baseline_ok}


def _evidence(report: Report, limit: int = 3) -> list[str]:
    out = []
    for f in sorted(report.findings, key=lambda f: -f.severity.rank):
        if f.severity.rank < Severity.HIGH.rank:
            break
        rules = [s.rule for s in f.signals if s.severity.rank >= Severity.MEDIUM.rank and not s.explained_by]
        out.append(f"{f.path}: " + (", ".join(dict.fromkeys(rules)) if rules else f.reason))
    return out[:limit]


def _row(report: Report, attack: str, title: str, incident: str, changed: list[str] | None = None) -> Row:
    return Row(attack, title, incident, report.verdict, report.risk_score, report.verdict == CAUGHT,
               _evidence(report), changed or [])


def run_campaign(artifact: Path, source: str | None, *, workdir: Path, ecosystem: str | None = None,
                 ref: str | None = None, previous: Path | None = None, attacks: list[str] | None = None,
                 opts: AnalyzeOptions | None = None, baseline_report: Report | None = None,
                 package: str | None = None, version: str | None = None) -> CampaignResult:
    """Analyze ``artifact`` and a tampered copy per attack, all against the same source and baseline.

    ``baseline_report`` lets a caller reuse the registry analysis of the original release.
    """
    opts = opts or AnalyzeOptions(ai=None)

    def analyze(path: Path) -> Report:
        return analyze_local(path, source, ecosystem=ecosystem, ref=ref, previous_artifact=previous,
                             package=package, version=version, opts=opts)

    base = baseline_report or analyze(artifact)
    result = CampaignResult(package=package or artifact.name,
                            baseline=_row(base, "(original release)", "Untouched published artifact", "-"))
    selected = [ATTACKS[a] for a in attacks] if attacks else applicable_attacks(artifact)
    for attack in selected:
        opts.progress(f"Red team: {attack.id}")
        tampered = tamper(artifact, attack.id, workdir / attack.id)
        result.rows.append(_row(analyze(tampered.artifact), attack.id, attack.title, attack.incident,
                                tampered.changed_files))
    return result
