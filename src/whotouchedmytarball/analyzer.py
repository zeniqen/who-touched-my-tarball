"""End-to-end analysis pipeline: registry -> artifact -> source -> comparison -> report."""

from __future__ import annotations

import json
import shutil
import tempfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .archive import extract
from .classify import ClassifyContext, classify, code_stems, collect_source_context
from .compare import compare_trees, list_files
from .ecosystems import RegistryError, get_ecosystem, guess_ecosystem, make_client
from .llm import OllamaClient, apply_assessment
from .models import Category, Finding, Provenance, Report, Severity, SourceInfo
from .sources import SourceCheckout, SourceError, fetch_source, normalize_repo_url, same_repository

SEVERITY_WEIGHT = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 6, Severity.HIGH: 25, Severity.CRITICAL: 50}
AI_SKIP = {Category.FORMATTING, Category.PACKAGING_METADATA, Category.DOCUMENTATION}


class AnalysisError(Exception):
    pass


@dataclass
class AnalyzeOptions:
    use_previous: bool = True
    ai: OllamaClient | None = None
    max_ai: int = 12
    progress: Callable[[str], None] = field(default=lambda message: None)


def analyze_release(ecosystem_name: str, package: str, version: str | None = None, *, dist: str = "auto",
                    source: str | None = None, ref: str | None = None,
                    opts: AnalyzeOptions | None = None) -> Report:
    """Analyze a release published on a registry."""
    opts = opts or AnalyzeOptions()
    eco = get_ecosystem(ecosystem_name)
    workdir = Path(tempfile.mkdtemp(prefix="wtmt-"))
    notes: list[str] = []
    try:
        with make_client() as client:
            opts.progress(f"Looking up {package} {version or '(latest)'} on {eco.name}")
            release = eco.resolve(client, package, version, dist)
            opts.progress(f"Downloading {release.artifact_filename}")
            artifact, integrity = eco.download(client, release, workdir / "artifact")
            pkg = extract(artifact, workdir / "package")
            notes += [f"Not extracted (links/special files): {s}" for s in pkg.skipped]

            opts.progress("Reading build provenance")
            provenance = eco.provenance(client, release)

            previous_root = None
            if opts.use_previous and release.previous_version:
                try:
                    opts.progress(f"Downloading previous release {release.previous_version} as a baseline")
                    prev = eco.resolve(client, package, release.previous_version, dist)
                    prev_artifact, _ = eco.download(client, prev, workdir / "previous-artifact")
                    previous_root = extract(prev_artifact, workdir / "previous").root
                except (RegistryError, OSError, ValueError) as exc:
                    notes.append(f"Previous release baseline unavailable: {exc}")

        opts.progress("Locating the source repository")
        hints = [release.repository_directory] if release.repository_directory else []
        source_root, source_info = _resolve_source(
            source=source, ref=ref, repository=release.repository_url,
            commits=[provenance.commit] if provenance.commit else [],
            tags=eco.tag_candidates(release.name, release.version),
            fallback_commits=[release.git_head] if release.git_head else [], notes=notes, progress=opts.progress,
            package_root=pkg.root, hints=hints,
        )
        return analyze_trees(
            ecosystem=eco.name, package=release.name, version=release.version,
            artifact_label=release.artifact_url, package_root=pkg.root, source_root=source_root,
            source_info=source_info, provenance=provenance, integrity=integrity,
            previous_version=release.previous_version if previous_root else None, previous_root=previous_root,
            hints=hints, opts=opts, notes=notes,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def analyze_local(artifact: Path, source: str | None, *, ecosystem: str | None = None, ref: str | None = None,
                  package: str | None = None, version: str | None = None, previous_artifact: Path | None = None,
                  opts: AnalyzeOptions | None = None) -> Report:
    """Analyze a local package file (for example a suspicious copy) against a source tree or URL."""
    opts = opts or AnalyzeOptions()
    workdir = Path(tempfile.mkdtemp(prefix="wtmt-"))
    notes: list[str] = []
    try:
        if artifact.is_dir():
            pkg_root = artifact
        else:
            pkg = extract(artifact, workdir / "package")
            pkg_root = pkg.root
            notes += [f"Not extracted (links/special files): {s}" for s in pkg.skipped]
        eco_name = ecosystem or guess_ecosystem(artifact, pkg_root)
        previous_root = None
        if previous_artifact:
            previous_root = previous_artifact if previous_artifact.is_dir() else extract(
                previous_artifact, workdir / "previous").root

        source_root, source_info = _resolve_source(
            source=source, ref=ref, repository=None, commits=[], tags=[], notes=notes, progress=opts.progress,
        )
        name, ver = package or artifact.name, version or "local"
        return analyze_trees(
            ecosystem=eco_name, package=name, version=ver, artifact_label=str(artifact),
            package_root=pkg_root, source_root=source_root, source_info=source_info, provenance=Provenance(
                available=False, note="Local artifact: registry provenance not checked"),
            integrity="local file (no registry digest)",
            previous_version=previous_artifact.name if previous_artifact else None, previous_root=previous_root,
            hints=[], opts=opts, notes=notes,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _resolve_source(*, source: str | None, ref: str | None, repository: str | None, commits: list[str],
                    tags: list[str], notes: list[str], progress: Callable[[str], None],
                    fallback_commits: list[str] | None = None, package_root: Path | None = None,
                    hints: list[str] | None = None) -> tuple[Path | None, SourceInfo | None]:
    """Fetch the source, trying the most trustworthy ref first.

    Order: --ref, signed provenance commit, the project's release tag, then npm ``gitHead``.
    Neither the tag nor gitHead is signed, and either can be wrong (react 18.3.1's gitHead points
    at a 19.0.0 commit; lodash 4.17.21's tag points at a different tree than the one published).
    When they disagree, both are fetched and the one matching more published files is used.
    """
    fallback_commits = [c for c in dict.fromkeys(fallback_commits or []) if c not in commits]
    if source and Path(source).expanduser().is_dir():
        path = Path(source).expanduser()
        return path, SourceInfo(repository=str(path), resolved_by="local directory given on the command line")

    repo_ref = normalize_repo_url(source or repository)
    if not repo_ref:
        notes.append("No source repository could be determined; only content checks were run")
        return None, None

    attempts: list[dict] = []
    if ref:
        attempts.append({"ref": ref})
    attempts += [{"commit": c} for c in dict.fromkeys(commits)]
    if tags:
        attempts.append({"tag_candidates": tags})
    attempts += [{"commit": c} for c in fallback_commits]
    if not attempts:
        attempts.append({"tag_candidates": []})

    for attempt in attempts:
        try:
            progress(f"Fetching {repo_ref.url} at {attempt.get('ref') or attempt.get('commit') or 'release tag'}")
            checkout = fetch_source(repo_ref.url, **attempt)
            if "tag_candidates" in attempt and checkout.commit:
                checkout = _closest_checkout(checkout, repo_ref.url, fallback_commits, package_root, hints,
                                             notes, progress)
            notes += checkout.notes
            return checkout.path, SourceInfo(
                repository=checkout.repository, ref=checkout.ref, commit=checkout.commit,
                resolved_by=checkout.resolved_by,
            )
        except SourceError as exc:
            notes.append(f"Source fetch failed ({', '.join(f'{k}={v}' for k, v in attempt.items() if k != 'tag_candidates') or 'tags'}): {exc}")
    notes.append(f"Could not fetch {repo_ref.url}; only content checks were run")
    return None, SourceInfo(repository=repo_ref.url, resolved_by="unavailable")


def _closest_checkout(tag_checkout: SourceCheckout, url: str, other_commits: list[str], package_root: Path | None,
                      hints: list[str] | None, notes: list[str], progress: Callable[[str], None]) -> SourceCheckout:
    """When the release tag and gitHead disagree, keep whichever matches more published files byte for byte."""
    others = [c for c in other_commits if c != tag_checkout.commit]
    if not others:
        return tag_checkout
    if package_root is None:
        notes += [f"The registry's gitHead {c[:12]} differs from the release tag's commit "
                  f"{tag_checkout.commit[:12]}; compared against the tag" for c in others]
        return tag_checkout

    def matches(checkout: SourceCheckout) -> int:
        return len(compare_trees(package_root, checkout.path, hints).identical)

    best, best_score = tag_checkout, matches(tag_checkout)
    for commit in others:
        try:
            progress(f"Release tag and gitHead disagree; also fetching gitHead {commit[:12]}")
            candidate = fetch_source(url, commit=commit)
        except SourceError as exc:
            notes.append(f"The registry's gitHead {commit[:12]} differs from the release tag but could not be "
                         f"fetched ({exc}); compared against the tag")
            continue
        score = matches(candidate)
        winner = candidate if score > best_score else best
        notes.append(f"The release tag's commit {tag_checkout.commit[:12]} and the registry's gitHead {commit[:12]} "
                     f"differ: {best_score} vs {score} published files match exactly; compared against "
                     f"{'gitHead' if winner is candidate else 'the tag'}")
        best, best_score = winner, max(score, best_score)
    return best


def analyze_trees(*, ecosystem: str, package: str, version: str, artifact_label: str, package_root: Path,
                  source_root: Path | None, source_info: SourceInfo | None, provenance: Provenance,
                  integrity: str, previous_version: str | None, previous_root: Path | None, hints: list[str],
                  opts: AnalyzeOptions, notes: list[str]) -> Report:
    opts.progress("Comparing package contents with the source")
    comp = compare_trees(package_root, source_root, hints)
    if source_info is not None:
        source_info.root_prefix = comp.root_prefix

    source_rules: set[str] = set()
    stems: set[str] = set()
    source_manifest = None
    if source_root is not None:
        opts.progress("Learning normal patterns from the source repository")
        source_rules, stems = collect_source_context(comp.source_files, comp.root_prefix)
        manifest = source_root / comp.root_prefix / "package.json"
        if ecosystem == "npm" and manifest.is_file():
            try:
                source_manifest = json.loads(manifest.read_text(encoding="utf-8"))
            except (ValueError, UnicodeDecodeError):
                source_manifest = None

    ctx = ClassifyContext(
        ecosystem=ecosystem,
        source_available=source_root is not None,
        source_rules=source_rules,
        source_compiled_stems=stems,
        source_code_stems=code_stems(comp.source_files),
        source_manifest=source_manifest,
        previous_version=previous_version,
        previous_files=list_files(previous_root) if previous_root else None,
    )
    findings = [classify(d, ctx) for d in comp.diffs]
    _run_ai(findings, package, ecosystem, opts, notes)

    if provenance.available and source_info and source_info.repository and provenance.repository:
        provenance.matches_source = same_repository(provenance.repository, source_info.repository)
        if provenance.matches_source is False:
            notes.append(f"Provenance says the package was built from {provenance.repository}, but the "
                         f"declared source is {source_info.repository}")
        if provenance.commit and source_info.commit and provenance.commit != source_info.commit:
            notes.append(f"Compared against commit {source_info.commit[:12]}, but provenance names "
                         f"{provenance.commit[:12]}")

    findings.sort(key=lambda f: (-f.severity.rank, f.path))
    score, verdict = _score(findings, source_root is not None, provenance)
    stats = _stats(comp, findings)
    return Report(
        tool_version=__version__,
        ecosystem=ecosystem,
        package=package,
        version=version,
        artifact=artifact_label,
        artifact_integrity=integrity,
        source=source_info,
        provenance=provenance,
        previous_version=previous_version,
        verdict=verdict,
        risk_score=score,
        summary=_summary(verdict, findings, stats, source_root is not None),
        stats=stats,
        findings=findings,
        notes=notes,
    )


def _run_ai(findings: list[Finding], package: str, ecosystem: str, opts: AnalyzeOptions, notes: list[str]) -> None:
    if not opts.ai or opts.max_ai <= 0:
        return
    candidates = [f for f in findings if f.category not in AI_SKIP and f.severity.rank >= Severity.LOW.rank]
    candidates.sort(key=lambda f: -f.severity.rank)
    if not candidates:
        return
    if not opts.ai.available():
        notes.append(f"Ollama not reachable at {opts.ai.host}; AI explanations skipped ({opts.ai.last_error})")
        return
    for finding in candidates[: opts.max_ai]:
        opts.progress(f"Asking {opts.ai.model} about {finding.path}")
        result = opts.ai.assess(finding, package, ecosystem)
        if result:
            apply_assessment(finding, result)
        elif opts.ai.last_error:
            notes.append(f"AI assessment failed for {finding.path}: {opts.ai.last_error}")
    if len(candidates) > opts.max_ai:
        notes.append(f"AI explanations limited to the top {opts.max_ai} of {len(candidates)} findings")


def _score(findings: list[Finding], has_source: bool, provenance: Provenance) -> tuple[int, str]:
    low = sum(1 for f in findings if f.severity == Severity.LOW)
    score = sum(SEVERITY_WEIGHT[f.severity] for f in findings if f.severity != Severity.LOW) + min(10, low)
    if provenance.matches_source is False:
        score += 25
    score = min(100, score)
    top = Severity.max(*(f.severity for f in findings)) if findings else Severity.INFO
    if top.rank >= Severity.HIGH.rank:
        verdict = "SUSPICIOUS"
    elif top == Severity.MEDIUM or provenance.matches_source is False:
        verdict = "REVIEW"
    elif not has_source:
        verdict = "UNVERIFIED"
    else:
        verdict = "CLEAN"
    return score, verdict


def _stats(comp, findings: list[Finding]) -> dict[str, int]:
    sev = Counter(f.severity.value for f in findings)
    return {
        "package_files": len(comp.package_files),
        "source_files": len(comp.source_files),
        "identical": len(comp.identical),
        "modified": sum(1 for d in comp.diffs if d.kind == "modified"),
        "package_only": sum(1 for d in comp.diffs if d.kind == "package_only"),
        "source_only": len(comp.source_only),
        **{f"severity_{k}": sev.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
    }


def _summary(verdict: str, findings: list[Finding], stats: dict[str, int], has_source: bool) -> str:
    if not has_source:
        base = f"{stats['package_files']} files scanned without a source repository to compare against."
    else:
        base = (f"{stats['identical']} of {stats['package_files']} published files are byte-identical to the source; "
                f"{stats['modified']} differ and {stats['package_only']} exist only in the package.")
    serious = [f for f in findings if f.severity.rank >= Severity.HIGH.rank]
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    if verdict == "SUSPICIOUS":
        names = ", ".join(f.path for f in serious[:3])
        return f"{base} {len(serious)} high-risk difference(s) need immediate attention: {names}."
    if verdict == "REVIEW":
        return f"{base} {len(medium)} difference(s) have no benign explanation and should be reviewed."
    if verdict == "UNVERIFIED":
        return f"{base} No suspicious content found, but the build could not be verified against source."
    return f"{base} Every difference is explained by normal packaging or build steps."
