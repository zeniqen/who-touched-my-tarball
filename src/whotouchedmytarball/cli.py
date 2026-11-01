"""Command line interface: ``wtmt``."""

from __future__ import annotations

import time
from pathlib import Path

import typer
from rich.console import Console

from . import __version__
from .analyzer import AnalyzeOptions, analyze_local, analyze_release
from .archive import UnsafeArchiveError, UnsupportedArchiveError
from .ecosystems import RegistryError, get_ecosystem
from .llm import DEFAULT_FALLBACK, DEFAULT_MODEL, OllamaClient
from .models import Report
from .provenance.verifier import verify_provenance
from .report import render_terminal, to_markdown
from .reproducibility.models import NetworkPolicy
from .reproducibility.verifier import verify_build

app = typer.Typer(
    help="WhoTouchedMyTarball: check whether a published npm/PyPI package matches its source code.",
    no_args_is_help=True,
    add_completion=False,
)
watch_app = typer.Typer(help="Monitor packages and analyze every new release.", no_args_is_help=True)
app.add_typer(watch_app, name="watch")
benchmark_app = typer.Typer(help="Detection benchmarking.", no_args_is_help=True)
app.add_typer(benchmark_app, name="benchmark")
trust_app = typer.Typer(help="Inspect and manage trust baselines.", no_args_is_help=True)
app.add_typer(trust_app, name="trust")

console = Console()
err = Console(stderr=True)
EXIT_CODES = {"CLEAN": 0, "UNVERIFIED": 1, "REVIEW": 1, "SUSPICIOUS": 2}


def _options(ai: bool, model: str, fallback_model: str | None, ollama_host: str | None, max_ai: int,
             previous: bool, quiet: bool) -> AnalyzeOptions:
    client = OllamaClient(model=model, fallback_model=fallback_model, host=ollama_host) if ai else None

    def progress(message: str) -> None:
        if not quiet:
            err.print(f"[dim]> {message}[/dim]")

    return AnalyzeOptions(use_previous=previous, ai=client, max_ai=max_ai, progress=progress)


def _emit(report: Report, json_out: Path | None, md_out: Path | None, show_all: bool, quiet: bool,
          exit_zero: bool) -> None:
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(report.model_dump_json(indent=2))
    if md_out:
        md_out.parent.mkdir(parents=True, exist_ok=True)
        md_out.write_text(to_markdown(report))
    if not quiet:
        render_terminal(report, console, show_all=show_all)
    else:
        console.print(f"{report.verdict} {report.risk_score} {report.ecosystem}:{report.package}@{report.version}")
    raise typer.Exit(0 if exit_zero else EXIT_CODES.get(report.verdict, 1))


AiOpt = typer.Option(True, "--ai/--no-ai", help="Ask the open-weight model to explain findings.")
ModelOpt = typer.Option(DEFAULT_MODEL, "--model", help="Ollama model for explanations (env WTMT_MODEL).")
FallbackOpt = typer.Option(DEFAULT_FALLBACK, "--fallback-model",
                           help="Local Ollama model used if the main model fails (env WTMT_FALLBACK_MODEL).")
HostOpt = typer.Option(None, "--ollama-host", help="Ollama URL (env OLLAMA_HOST, default http://localhost:11434).")
MaxAiOpt = typer.Option(12, "--max-ai", help="Maximum number of findings sent to the model.")
JsonOpt = typer.Option(None, "--json", help="Write the full report as JSON.")
MdOpt = typer.Option(None, "--md", help="Write the report as Markdown.")
AllOpt = typer.Option(False, "--all", help="Show informational findings too.")
QuietOpt = typer.Option(False, "--quiet", "-q", help="Only print the verdict line.")
ExitZeroOpt = typer.Option(False, "--exit-zero", help="Always exit 0 (by default 1 = review, 2 = suspicious).")


@app.command()
def check(
    ecosystem: str = typer.Argument(..., help="npm or pypi"),
    package: str = typer.Argument(..., help="Package name, e.g. debug or requests"),
    version: str | None = typer.Argument(None, help="Version (default: latest)"),
    dist: str = typer.Option("auto", "--dist", help="PyPI only: auto, sdist or wheel"),
    source: str | None = typer.Option(None, "--source", help="Override source: local directory or repository URL"),
    ref: str | None = typer.Option(None, "--ref", help="Git tag/branch/commit to compare against"),
    previous: bool = typer.Option(True, "--previous/--no-previous", help="Use the previous release as a baseline"),
    ai: bool = AiOpt, model: str = ModelOpt, fallback_model: str | None = FallbackOpt,
    ollama_host: str | None = HostOpt, max_ai: int = MaxAiOpt,
    json_out: Path | None = JsonOpt, md_out: Path | None = MdOpt, show_all: bool = AllOpt,
    quiet: bool = QuietOpt, exit_zero: bool = ExitZeroOpt,
) -> None:
    """Download a release from npm or PyPI and compare it with its source repository."""
    opts = _options(ai, model, fallback_model, ollama_host, max_ai, previous, quiet)
    try:
        report = analyze_release(ecosystem, package, version, dist=dist, source=source, ref=ref, opts=opts)
    except (RegistryError, UnsafeArchiveError, UnsupportedArchiveError) as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(3) from exc
    _emit(report, json_out, md_out, show_all, quiet, exit_zero)


@app.command()
def diff(
    artifact: Path = typer.Argument(..., exists=True, help="Package file (.tgz, .tar.gz, .whl, .zip) or directory"),
    source: str | None = typer.Argument(None, help="Source directory or repository URL"),
    ecosystem: str | None = typer.Option(None, "--ecosystem", help="npm or pypi (guessed if omitted)"),
    ref: str | None = typer.Option(None, "--ref", help="Git ref when SOURCE is a URL"),
    previous_artifact: Path | None = typer.Option(None, "--previous", exists=True,
                                                  help="Previous release file to use as a baseline"),
    name: str | None = typer.Option(None, "--name", help="Package name for the report"),
    version: str | None = typer.Option(None, "--version", help="Version for the report"),
    ai: bool = AiOpt, model: str = ModelOpt, fallback_model: str | None = FallbackOpt,
    ollama_host: str | None = HostOpt, max_ai: int = MaxAiOpt,
    json_out: Path | None = JsonOpt, md_out: Path | None = MdOpt, show_all: bool = AllOpt,
    quiet: bool = QuietOpt, exit_zero: bool = ExitZeroOpt,
) -> None:
    """Compare a local package file (for example a suspicious copy) with a source tree."""
    opts = _options(ai, model, fallback_model, ollama_host, max_ai, True, quiet)
    try:
        report = analyze_local(artifact, source, ecosystem=ecosystem, ref=ref, package=name, version=version,
                               previous_artifact=previous_artifact, opts=opts)
    except (UnsafeArchiveError, UnsupportedArchiveError) as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(3) from exc
    _emit(report, json_out, md_out, show_all, quiet, exit_zero)


def _attack_table(attacks) -> None:
    from rich.table import Table

    table = Table(title="Modelled attacks (all payloads are inert)", show_lines=False)
    table.add_column("Attack", no_wrap=True)
    for col in ("Formats", "What it does", "Modelled on"):
        table.add_column(col)
    for a in attacks:
        table.add_row(a.id, ", ".join(a.formats), a.title, a.incident)
    console.print(table)


@app.command("tamper")
def tamper_cmd(
    ecosystem: str | None = typer.Argument(None, help="npm or pypi (omit with --file)"),
    package: str | None = typer.Argument(None, help="Package name"),
    version: str | None = typer.Argument(None, help="Version (default: latest)"),
    attack: str | None = typer.Option(None, "--attack", "-a", help="Attack id (default: every attack that fits)"),
    file: Path | None = typer.Option(None, "--file", exists=True, help="Tamper a local package file instead"),
    dist: str = typer.Option("auto", "--dist", help="PyPI only: auto, sdist or wheel"),
    out: Path = typer.Option(Path("wtmt-redteam"), "--out", help="Directory for tampered copies"),
    list_attacks: bool = typer.Option(False, "--list", help="List the modelled attacks and exit"),
) -> None:
    """Make tampered copies of a real release for detection testing (DO NOT INSTALL them)."""
    import tempfile

    from .redteam import ATTACKS, NotApplicable, applicable_attacks, tamper
    from .redteam.registry import download_release

    if list_attacks:
        _attack_table(ATTACKS.values())
        raise typer.Exit(0)
    try:
        with tempfile.TemporaryDirectory(prefix="wtmt-") as tmp:
            if file is None:
                if not (ecosystem and package):
                    err.print("[red]error:[/red] give ECOSYSTEM PACKAGE [VERSION] or --file PATH")
                    raise typer.Exit(3)
                _, base, _ = download_release(ecosystem, package, version, dist, Path(tmp), with_previous=False)
            else:
                base = file
            ids = [attack] if attack else [a.id for a in applicable_attacks(base)]
            for attack_id in ids:
                result = tamper(base, attack_id, out)
                console.print(f"[bold]{attack_id}[/bold] -> {result.artifact}  (changed: {', '.join(result.changed_files)})")
    except KeyError as exc:
        err.print(f"[red]error:[/red] unknown attack {exc}; see `wtmt tamper --list`")
        raise typer.Exit(3) from exc
    except (NotApplicable, RegistryError, UnsafeArchiveError, UnsupportedArchiveError) as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(3) from exc
    console.print("[yellow]These copies are deliberately tampered. Do not install or publish them.[/yellow]")


@app.command("redteam")
def redteam_cmd(
    ecosystem: str | None = typer.Argument(None, help="npm or pypi (omit with --file)"),
    package: str | None = typer.Argument(None, help="Package name"),
    version: str | None = typer.Argument(None, help="Version (default: latest)"),
    file: Path | None = typer.Option(None, "--file", exists=True, help="Red-team a local package file"),
    source: str | None = typer.Option(None, "--source", help="With --file: source directory or repository URL"),
    ref: str | None = typer.Option(None, "--ref", help="With --file: git ref when --source is a URL"),
    previous_artifact: Path | None = typer.Option(None, "--previous", exists=True,
                                                  help="With --file: previous release file used as a baseline"),
    dist: str = typer.Option("auto", "--dist", help="PyPI only: auto, sdist or wheel"),
    attack: list[str] | None = typer.Option(None, "--attack", "-a", help="Only these attacks (repeatable)"),
    keep: Path | None = typer.Option(None, "--keep", help="Keep the tampered copies in this directory"),
    ai: bool = typer.Option(False, "--ai/--no-ai", help="Also ask the model (slow: one pass per attack)."),
    model: str = ModelOpt, fallback_model: str | None = FallbackOpt, ollama_host: str | None = HostOpt,
    max_ai: int = MaxAiOpt, json_out: Path | None = JsonOpt, quiet: bool = QuietOpt,
) -> None:
    """Attack a real release with every modelled attack and show which ones wtmt catches."""
    import tempfile

    from rich.table import Table

    from .redteam import run_campaign
    from .redteam.registry import download_release

    opts = _options(ai, model, fallback_model, ollama_host, max_ai, True, quiet)
    try:
        with tempfile.TemporaryDirectory(prefix="wtmt-redteam-") as tmp:
            work = keep or Path(tmp)
            if file is not None:
                result = run_campaign(file, source, workdir=work, ref=ref, previous=previous_artifact,
                                      attacks=attack, opts=opts)
            else:
                if not (ecosystem and package):
                    err.print("[red]error:[/red] give ECOSYSTEM PACKAGE [VERSION] or --file PATH --source SRC")
                    raise typer.Exit(3)
                release, artifact, previous = download_release(ecosystem, package, version, dist, Path(tmp))
                baseline = analyze_release(ecosystem, package, release.version, dist=dist, opts=opts)
                if not baseline.source or not baseline.source.commit:
                    err.print("[red]error:[/red] no source revision found for this release; red-teaming needs one "
                              "(try `wtmt redteam --file ... --source ...`)")
                    raise typer.Exit(3)
                result = run_campaign(artifact, baseline.source.repository, workdir=work,
                                      ecosystem=get_ecosystem(ecosystem).name, ref=baseline.source.commit,
                                      previous=previous, attacks=attack, opts=opts, baseline_report=baseline,
                                      package=release.name, version=release.version)
    except KeyError as exc:
        err.print(f"[red]error:[/red] unknown attack {exc}; see `wtmt tamper --list`")
        raise typer.Exit(3) from exc
    except (RegistryError, UnsafeArchiveError, UnsupportedArchiveError) as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(3) from exc

    if json_out:
        import json

        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(result.to_dict(), indent=2))
    caught = sum(r.caught for r in result.rows)
    if not quiet:
        table = Table(title=f"Red team: {result.package}", show_lines=True)
        for col in ("Attack", "Modelled on", "Verdict", "Result", "Evidence"):
            table.add_column(col, overflow="fold")
        b = result.baseline
        table.add_row(b.attack, "-", b.verdict, "[green]not flagged[/green]" if result.baseline_ok
                      else "[red]flagged before tampering[/red]", "\n".join(b.evidence))
        for r in result.rows:
            table.add_row(r.attack, r.incident, f"{r.verdict} ({r.risk_score})",
                          "[green]caught[/green]" if r.caught else "[red]MISSED[/red]", "\n".join(r.evidence))
        console.print(table)
    console.print(f"Caught {caught}/{len(result.rows)} attacks ({result.detection_rate:.0%}); "
                  f"original release: {result.baseline.verdict}")
    raise typer.Exit(0 if caught == len(result.rows) and result.baseline_ok else 1)


@watch_app.command("add")
def watch_add(ecosystem: str, package: str,
              baseline: str | None = typer.Option(None, help="Treat this version as already reviewed")) -> None:
    """Start watching a package."""
    from .monitor import add, connect

    add(connect(), ecosystem, package, baseline)
    console.print(f"Watching {ecosystem}:{package}")


@watch_app.command("remove")
def watch_remove(ecosystem: str, package: str) -> None:
    """Stop watching a package."""
    from .monitor import connect, remove

    console.print("Removed" if remove(connect(), ecosystem, package) else "Not watched")


@watch_app.command("list")
def watch_list() -> None:
    """List watched packages."""
    from .monitor import connect, list_watched

    rows = list_watched(connect())
    if not rows:
        console.print("Nothing is being watched. Add one with `wtmt watch add npm debug`.")
    for eco, name, version, verdict, checked in rows:
        console.print(f"{eco}:{name}  last={version or '-'}  verdict={verdict or '-'}  checked={checked or '-'}")


@watch_app.command("run")
def watch_run(
    out_dir: Path = typer.Option(Path("wtmt-reports"), "--out", help="Directory for reports"),
    interval: int = typer.Option(0, "--interval", help="Seconds between polls; 0 = run once"),
    ai: bool = AiOpt, model: str = ModelOpt, fallback_model: str | None = FallbackOpt,
    ollama_host: str | None = HostOpt, max_ai: int = MaxAiOpt,
) -> None:
    """Check watched packages for new releases and analyze them."""
    from .monitor import connect, run_once

    opts = _options(ai, model, fallback_model, ollama_host, max_ai, True, False)
    conn = connect()
    while True:
        for r in run_once(conn, out_dir, opts):
            detail = r.error or (str(r.report_path) if r.report_path else "")
            console.print(f"{r.ecosystem}:{r.name}@{r.version or '?'}  {r.verdict}  {detail}")
        if interval <= 0:
            break
        time.sleep(interval)


@app.command("verify-build")
def verify_build_cmd(
    ecosystem: str = typer.Argument(..., help="npm or pypi"),
    spec: str = typer.Argument(..., help="Package spec: npm <name>@<version> or pypi <name>==<version>"),
    timeout: int = typer.Option(600, "--timeout", help="Build timeout in seconds"),
    memory_limit: int = typer.Option(2048, "--memory-limit", help="Memory limit in MB"),
    cpu_limit: float = typer.Option(2.0, "--cpu-limit", help="CPU limit"),
    network_policy: str = typer.Option("none", "--network-policy", help="none, limited, or full"),
    output: Path | None = typer.Option(None, "--output", help="Write verification result JSON to this path"),
    keep_build_artifacts: bool = typer.Option(False, "--keep-build-artifacts", help="Keep rebuilt artifacts"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose output"),
    source: str | None = typer.Option(None, "--source", help="Override source repository/path"),
    ref: str | None = typer.Option(None, "--ref", help="Git ref to build from"),
) -> None:
    """Independently rebuild a published package and compare it with the registry artifact."""
    # Parse spec
    if ecosystem.lower() == "npm":
        if "@" in spec and not spec.startswith("@"):
            # name@version (handle scoped by last @)
            idx = spec.rfind("@")
            package, version = spec[:idx], spec[idx + 1:]
        elif "@" in spec and spec.startswith("@"):
            # scoped: @scope/pkg@version
            idx = spec.rfind("@")
            package, version = spec[:idx], spec[idx + 1:]
        else:
            package, version = spec, None
    else:
        if "==" in spec:
            package, version = spec.split("==", 1)
        elif "@" in spec:
            package, version = spec.split("@", 1)
        else:
            package, version = spec, None

    try:
        np = NetworkPolicy(network_policy)
    except ValueError:
        err.print(f"[red]error:[/red] invalid network policy: {network_policy}")
        raise typer.Exit(3) from None

    try:
        result = verify_build(
            ecosystem, package, version, source=source, ref=ref, timeout=timeout,
            memory_limit=memory_limit, cpu_limit=cpu_limit, network_policy=np,
            keep_build_artifacts=keep_build_artifacts, progress=(lambda m: err.print(f"[dim]> {m}[/dim]") if verbose or True else None),
        )
    except Exception as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(3) from exc


    data = result.as_dict()
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        import json as _json
        output.write_text(_json.dumps(data, indent=2))
    console.print(f"Verification status: {result.status.value}")
    console.print(f"Files matched: {result.files_matched}, mismatched: {result.files_mismatched}")
    if result.missing_files:
        console.print(f"Missing: {', '.join(result.missing_files)}")
    if result.unexpected_files:
        console.print(f"Unexpected: {', '.join(result.unexpected_files)}")
    if result.notes:
        for n in result.notes:
            console.print(f"note: {n}")
    # exit codes: build/environment issues => 1, mismatches => 2? Keep 0 only exact/normalized.
    if result.status.value in ("EXACT_MATCH", "NORMALIZED_MATCH"):
        raise typer.Exit(0)
    if result.status.value in ("ENVIRONMENT_UNAVAILABLE", "BUILD_FAILURE", "VERIFICATION_ERROR",
                              "INSUFFICIENT_BUILD_INFORMATION", "UNSUPPORTED_BUILD_SYSTEM",
                              "SOURCE_REVISION_MISMATCH"):
        raise typer.Exit(1)
    raise typer.Exit(2)



@app.command("verify-provenance")
def verify_provenance_cmd(
    ecosystem: str = typer.Argument(..., help="npm or pypi"),
    spec: str = typer.Argument(..., help="Package spec: npm <name>@<version> or pypi <name>==<version>"),
    expected_repository: str | None = typer.Option(None, "--expected-repository", help="Expected source repository URL"),
    expected_commit: str | None = typer.Option(None, "--expected-commit", help="Expected source commit"),
    expected_workflow: str | None = typer.Option(None, "--expected-workflow", help="Expected build workflow"),
    output: Path | None = typer.Option(None, "--output", help="Write JSON result to path"),
    json_out: bool = typer.Option(False, "--json", help="Print result as JSON"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable attestation cache"),
    strict: bool = typer.Option(False, "--strict", help="Fail unless VERIFIED"),
) -> None:
    """Independently verify cryptographic provenance of a published package."""
    if ecosystem.lower() == "npm":
        idx = spec.rfind("@")
        package, version = (spec[:idx], spec[idx+1:]) if "@" in spec and idx > 0 else (spec, None)
    else:
        if "==" in spec:
            package, version = spec.split("==", 1)
        elif "@" in spec:
            package, version = spec.split("@", 1)
        else:
            package, version = spec, None
    try:
        result = verify_provenance(ecosystem, package, version, expected_repository=expected_repository,
                                   expected_commit=expected_commit, expected_workflow=expected_workflow,
                                   no_cache=no_cache, progress=(lambda m: err.print(f"[dim]> {m}[/dim]") if verbose else None))
    except Exception as exc:
        err.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(3) from exc
    data = result.as_dict()
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        import json as _json
        output.write_text(_json.dumps(data, indent=2))
    if json_out or verbose:
        err.print(_json.dumps(data, indent=2) if False else "")
    import json as _json
    console.print(f"Provenance status: {result.status.value}")
    console.print(f"Trust status: {result.trust_status.value}")
    console.print("")
    console.print("Cryptographic Provenance Verification")
    console.print("Attestation Retrieval       AVAILABLE")
    console.print("in-toto Parsing             AVAILABLE")
    console.print("SLSA Parsing                AVAILABLE")
    console.print("Artifact Digest Binding     AVAILABLE")
    try:
        from .provenance.sigstore import SIGSTORE_AVAILABLE
        sig = "AVAILABLE" if SIGSTORE_AVAILABLE else "UNAVAILABLE"
    except Exception:
        sig = "UNAVAILABLE"
    console.print(f"Sigstore Verification       {sig}")
    console.print(f"Certificate Validation     {sig}")
    console.print(f"Rekor Verification          {sig}")
    if result.verification_errors:
        for e in result.verification_errors:
            err.print(f"error: {e}")
    if strict and result.status.value != "VERIFIED":
        raise typer.Exit(2)
    if result.status.value in ("VERIFIED", "VERIFIED_UNTRUSTED"):
        raise typer.Exit(0)
    if result.status.value in ("MISSING_PROVENANCE", "VERIFICATION_UNAVAILABLE", "RETRIEVAL_ERROR"):
        raise typer.Exit(1)
    raise typer.Exit(2)





@trust_app.command("show")
def trust_show(ecosystem: str, package: str) -> None:
    from .monitor import connect, get_active_baseline
    conn = connect()
    row = get_active_baseline(conn, get_ecosystem(ecosystem).name, package)
    console.print(row if row else "No baseline found")


@trust_app.command("history")
def trust_history(ecosystem: str, package: str) -> None:
    from .monitor import connect, list_baselines
    conn = connect()
    for row in list_baselines(conn, get_ecosystem(ecosystem).name, package):
        console.print(row)


@trust_app.command("changes")
def trust_changes(ecosystem: str, package: str) -> None:
    from .monitor import connect
    conn = connect()
    eco = get_ecosystem(ecosystem).name
    rows = conn.execute(
        "SELECT id,field,previous_value,current_value,severity,category,first_detected_at,status FROM trust_changes WHERE ecosystem=? AND package_name=?",
        (eco, package),
    ).fetchall()
    for row in rows:
        console.print(row)


@trust_app.command("baseline")
def trust_baseline(ecosystem: str, package: str) -> None:
    from .monitor import connect, list_baselines
    conn = connect()
    eco = get_ecosystem(ecosystem).name
    rows = list_baselines(conn, eco, package)
    if not rows:
        console.print("No baseline records.")
    for row in rows:
        console.print(row)



@trust_app.command("approve")
def trust_approve(ecosystem: str, package: str, change_id: int = typer.Option(..., "--change-id")) -> None:
    from .monitor import approve_change, connect
    conn = connect()
    approve_change(conn, get_ecosystem(ecosystem).name, package, change_id)
    console.print(f"Approved change {change_id}")


@trust_app.command("reject")
def trust_reject(ecosystem: str, package: str, change_id: int = typer.Option(..., "--change-id")) -> None:
    from .monitor import connect, reject_change
    conn = connect()
    reject_change(conn, get_ecosystem(ecosystem).name, package, change_id)
    console.print(f"Rejected change {change_id}")


@trust_app.command("acknowledge")
def trust_acknowledge(ecosystem: str, package: str, change_id: int = typer.Option(..., "--change-id")) -> None:
    from .monitor import acknowledge_change, connect
    conn = connect()
    acknowledge_change(conn, get_ecosystem(ecosystem).name, package, change_id)
    console.print(f"Acknowledged change {change_id}")




@benchmark_app.command("run")
def benchmark_run(output: Path | None = typer.Option(None, "--output"),
                  scenario: str | None = typer.Option(None, "--scenario")) -> None:
    import datetime
    import uuid

    from .benchmark.dataset import default_scenarios
    from .benchmark.metrics import compute
    from .benchmark.models import RunSummary
    from .benchmark.reporter import render_terminal, write_json
    from .benchmark.runner import run_scenarios
    scenarios = default_scenarios()
    if scenario:
        scenarios = [s for s in scenarios if s.scenario_id == scenario]
    results = run_scenarios(scenarios)
    tp, tn, fp, fn, inc, precision, recall, specificity, f1, accuracy, fpr, fnr = compute(results)
    summary = RunSummary(
        run_id=str(uuid.uuid4()),
        dataset_version=__import__("whotouchedmytarball.benchmark.dataset", fromlist=["DATASET_VERSION"]).DATASET_VERSION,
        started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        total=len(results),
        malicious=sum(1 for r in results if r.label == "malicious"),
        benign=sum(1 for r in results if r.label == "benign"),
        tp=tp, tn=tn, fp=fp, fn=fn, inconclusive=inc,
        precision=precision, recall=recall, specificity=specificity, f1=f1,
        accuracy=accuracy, fpr=fpr, fnr=fnr, results=results,
    )
    from .benchmark.history import save_run
    path = save_run(summary)
    render_terminal(summary, console)
    console.print(f"Run ID: {summary.run_id}")
    console.print(f"Saved: {path}")
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        write_json(output, summary)
        console.print(f"Wrote {output}")


@benchmark_app.command("list")
def benchmark_list() -> None:
    from .benchmark.dataset import default_scenarios
    for s in default_scenarios():
        console.print(f"{s.scenario_id}  {s.ecosystem}  {s.label}  {s.category}")



@benchmark_app.command("list")
def benchmark_list_cmd() -> None:
    from .benchmark.history import list_runs
    for rid in list_runs():
        console.print(rid)


@benchmark_app.command("compare")
def benchmark_compare(baseline: str = typer.Option(..., "--baseline"),
                     current: str = typer.Option(..., "--current")) -> None:
    from .benchmark.history import load_run
    b = load_run(baseline)
    c = load_run(current)
    console.print(f"Baseline recall={b.get('recall'):.3f} precision={b.get('precision'):.3f} fpr={b.get('fpr'):.3f}")
    console.print(f"Current  recall={c.get('recall'):.3f} precision={c.get('precision'):.3f} fpr={c.get('fpr'):.3f}")
    console.print(f"Recall delta: {c.get('recall',0)-b.get('recall',0):+.3f}")
    console.print(f"Precision delta: {c.get('precision',0)-b.get('precision',0):+.3f}")
    console.print(f"FPR delta: {c.get('fpr',0)-b.get('fpr',0):+.3f}")
    # critical FN check
    b_ids = {r["scenario_id"] for r in b.get("results",[]) if r.get("label")=="malicious" and not r.get("predicted_malicious")}
    c_ids = {r["scenario_id"] for r in c.get("results",[]) if r.get("label")=="malicious" and not r.get("predicted_malicious")}
    new_fn = c_ids - b_ids
    if new_fn:
        console.print(f"NEW CRITICAL FALSE NEGATIVES: {', '.join(sorted(new_fn))}")

@app.command()
def version() -> None:
    """Print the tool version."""
    console.print(f"whotouchedmytarball {__version__}")


if __name__ == "__main__":
    app()
