"""Render reports for the terminal, Markdown and JSON."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import Report, Severity

VERDICT_STYLE = {"CLEAN": "bold green", "REVIEW": "bold yellow", "SUSPICIOUS": "bold red", "UNVERIFIED": "bold cyan"}
SEVERITY_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "cyan",
                  "info": "dim"}
VERDICT_ICON = {"CLEAN": "OK", "REVIEW": "!!", "SUSPICIOUS": "XX", "UNVERIFIED": "??"}


def render_terminal(report: Report, console: Console, show_all: bool = False, max_findings: int = 25) -> None:
    style = VERDICT_STYLE.get(report.verdict, "bold")
    header = (
        f"[{style}]{report.verdict}[/{style}]  risk {report.risk_score}/100\n"
        f"[bold]{report.ecosystem}:{report.package}@{report.version}[/bold]\n{report.summary}"
    )
    console.print(Panel(header, title="WhoTouchedMyTarball", border_style=style.split()[-1]))

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="bold")
    meta.add_column()
    meta.add_row("Artifact", report.artifact)
    meta.add_row("Integrity", report.artifact_integrity)
    if report.source:
        src = report.source
        where = src.repository or "-"
        if src.ref:
            where += f" @ {src.ref}"
        if src.commit and src.commit != src.ref:
            where += f" ({src.commit[:12]})"
        meta.add_row("Source", where)
        meta.add_row("Resolved by", src.resolved_by + (f", package root = {src.root_prefix}" if src.root_prefix else ""))
    else:
        meta.add_row("Source", "not available")
    prov = report.provenance
    if prov.available:
        match = {True: "[green]matches source[/green]", False: "[red]DOES NOT match source[/red]",
                 None: "not compared"}[prov.matches_source]
        meta.add_row("Provenance", f"{prov.kind}: {prov.repository or '?'} {(prov.commit or '')[:12]} ({match})")
    else:
        meta.add_row("Provenance", prov.note or "none")
    if report.previous_version:
        meta.add_row("Baseline", f"previous release {report.previous_version}")
    s = report.stats
    meta.add_row("Files", f"{s.get('package_files', 0)} in package, {s.get('identical', 0)} identical, "
                          f"{s.get('modified', 0)} modified, {s.get('package_only', 0)} package-only, "
                          f"{s.get('source_only', 0)} source-only (not published)")
    console.print(meta)

    shown = [f for f in report.findings if show_all or f.severity != Severity.INFO]
    hidden = len(report.findings) - len(shown)
    if shown:
        table = Table(title="Differences", show_lines=True, expand=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("File", overflow="fold", ratio=2)
        table.add_column("Why", ratio=4)
        for f in shown[:max_findings]:
            why = [f"[bold]{f.category.value}[/bold] ({f.kind.value}): {f.reason}"]
            for sig in f.signals[:6]:
                line = f" L{sig.line}" if sig.line else ""
                tag = f" [dim](explained: {sig.explained_by})[/dim]" if sig.explained_by else ""
                why.append(f"  - [{SEVERITY_STYLE[sig.severity.value]}]{sig.severity.value}[/] {sig.description}{line}{tag}")
            for note in f.notes[:3]:
                why.append(f"  [dim]{note}[/dim]")
            if f.ai:
                why.append(f"  [magenta]AI ({f.ai.model}, {f.ai.verdict}, {f.ai.confidence:.0%}):[/magenta] "
                           f"{f.ai.explanation}")
            table.add_row(f"[{SEVERITY_STYLE[f.severity.value]}]{f.severity.value}[/]", f.path, "\n".join(why))
        console.print(table)
        if len(shown) > max_findings:
            console.print(f"[dim]... {len(shown) - max_findings} more findings in the JSON/Markdown report[/dim]")
    if hidden:
        console.print(f"[dim]{hidden} informational differences hidden (use --all to show)[/dim]")
    for note in report.notes:
        console.print(f"[dim]note: {note}[/dim]")


def to_markdown(report: Report, max_findings: int = 100) -> str:
    lines = [
        f"# WhoTouchedMyTarball report: `{report.ecosystem}:{report.package}@{report.version}`",
        "",
        f"**Verdict: {report.verdict}** ({VERDICT_ICON.get(report.verdict, '')}) | risk score {report.risk_score}/100",
        "",
        report.summary,
        "",
        "| | |",
        "|---|---|",
        f"| Artifact | {report.artifact} |",
        f"| Integrity | {report.artifact_integrity} |",
    ]
    if report.source:
        src = report.source
        where = src.repository or "-"
        if src.ref:
            where += f" @ `{src.ref}`"
        if src.commit and src.commit != src.ref:
            where += f" (`{src.commit[:12]}`)"
        lines.append(f"| Source | {where} |")
        lines.append(f"| Resolved by | {src.resolved_by}{', package root `' + src.root_prefix + '`' if src.root_prefix else ''} |")
    prov = report.provenance
    if prov.available:
        lines.append(f"| Provenance | {prov.kind}: {prov.repository or '?'} `{(prov.commit or '')[:12]}` "
                     f"(matches source: {prov.matches_source}) |")
    else:
        lines.append(f"| Provenance | {prov.note or 'none'} |")
    if report.previous_version:
        lines.append(f"| Baseline | previous release {report.previous_version} |")
    s = report.stats
    lines.append(f"| Files | {s.get('package_files', 0)} in package, {s.get('identical', 0)} identical, "
                 f"{s.get('modified', 0)} modified, {s.get('package_only', 0)} package-only, "
                 f"{s.get('source_only', 0)} source-only |")
    lines += ["", "## Findings", ""]
    if not report.findings:
        lines.append("No differences between the package and the source.")
    lines += ["| Severity | File | Category | Reason |", "|---|---|---|---|"]
    for f in report.findings[:max_findings]:
        reason = f.reason.replace("|", "\\|")
        lines.append(f"| {f.severity.value} | `{f.path}` | {f.category.value} ({f.kind.value}) | {reason} |")
    if len(report.findings) > max_findings:
        lines.append(f"\n_{len(report.findings) - max_findings} more findings in the JSON report._")

    detailed = [f for f in report.findings if f.signals or f.ai or f.severity.rank >= Severity.MEDIUM.rank]
    if detailed:
        lines += ["", "## Evidence", ""]
    for f in detailed[:30]:
        lines += [f"### `{f.path}` ({f.severity.value})", "", f.reason, ""]
        for sig in f.signals:
            where = f" (line {sig.line})" if sig.line else ""
            expl = f" _explained: {sig.explained_by}_" if sig.explained_by else ""
            lines.append(f"- **{sig.severity.value}** {sig.description}{where}{expl}")
            if sig.snippet:
                snippet = sig.snippet[:150].replace("`", "'")
                lines.append(f"  `{snippet}`")
        for note in f.notes:
            lines.append(f"- {note}")
        if f.ai:
            lines.append(f"- **AI ({f.ai.model})**: {f.ai.verdict} ({f.ai.confidence:.0%}). {f.ai.explanation}")
        if f.diff_excerpt and f.diff_excerpt != "(binary file differs)":
            excerpt = "\n".join(f.diff_excerpt.splitlines()[:40])
            lines += ["", "```diff", excerpt, "```"]
        lines.append("")
    rb = getattr(report, "reproducible_build", None)
    if rb:
        lines += ["", "## Reproducible Build Verification", ""]
        lines.append(f"- Status: **{rb.get('status', '')}**")
        for key in ("source_repository", "source_commit", "registry_artifact_hash", "rebuilt_artifact_hash",
                    "normalized_artifact_hash", "build_command", "build_duration_seconds", "files_matched",
                    "files_mismatched"):
            if rb.get(key) is not None and rb.get(key) != "":
                lines.append(f"- {key.replace('_', ' ').title()}: `{rb.get(key)}`")
        if rb.get("missing_files"):
            lines.append(f"- Missing files: {', '.join(rb['missing_files'])}")
        if rb.get("unexpected_files"):
            lines.append(f"- Unexpected files: {', '.join(rb['unexpected_files'])}")
        if rb.get("limitations"):
            lines += ["- Limitations:"] + [f"  - {x}" for x in rb["limitations"]]
        if rb.get("notes"):
            lines += ["- Notes:"] + [f"  - {x}" for x in rb["notes"]]
    if report.notes:
        lines += ["## Notes", ""] + [f"- {n}" for n in report.notes]
    lines += ["", f"_Generated by WhoTouchedMyTarball {report.tool_version}_", ""]
    return "\n".join(lines)
