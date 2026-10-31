"""Command line interface: ``wtmt``."""

from __future__ import annotations

import time
from pathlib import Path

import typer
from rich.console import Console

from . import __version__
from .analyzer import AnalyzeOptions, analyze_local, analyze_release
from .archive import UnsafeArchiveError, UnsupportedArchiveError
from .ecosystems import RegistryError
from .llm import DEFAULT_FALLBACK, DEFAULT_MODEL, OllamaClient
from .models import Report
from .report import render_terminal, to_markdown

app = typer.Typer(
    help="WhoTouchedMyTarball: check whether a published npm/PyPI package matches its source code.",
    no_args_is_help=True,
    add_completion=False,
)
watch_app = typer.Typer(help="Monitor packages and analyze every new release.", no_args_is_help=True)
app.add_typer(watch_app, name="watch")

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


@app.command()
def version() -> None:
    """Print the tool version."""
    console.print(f"whotouchedmytarball {__version__}")


if __name__ == "__main__":
    app()
