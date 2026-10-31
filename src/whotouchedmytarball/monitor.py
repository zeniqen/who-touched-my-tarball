"""Watch selected packages and analyze every new release automatically."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import AnalyzeOptions, analyze_release
from .ecosystems import RegistryError, get_ecosystem, make_client
from .models import Report
from .report import to_markdown


def db_path() -> Path:
    base = Path(os.environ.get("WTMT_HOME") or Path.home() / ".wtmt")
    base.mkdir(parents=True, exist_ok=True)
    return base / "watch.db"


def connect(path: Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or db_path())
    conn.execute(
        """CREATE TABLE IF NOT EXISTS watched (
            ecosystem TEXT NOT NULL,
            name TEXT NOT NULL,
            last_version TEXT,
            last_verdict TEXT,
            last_checked TEXT,
            PRIMARY KEY (ecosystem, name)
        )"""
    )
    return conn


@dataclass
class WatchResult:
    ecosystem: str
    name: str
    version: str | None
    verdict: str
    report_path: Path | None = None
    error: str | None = None


def add(conn: sqlite3.Connection, ecosystem: str, name: str, baseline: str | None = None) -> None:
    eco = get_ecosystem(ecosystem)
    conn.execute("INSERT OR IGNORE INTO watched (ecosystem, name, last_version) VALUES (?, ?, ?)",
                 (eco.name, name, baseline))
    conn.commit()


def remove(conn: sqlite3.Connection, ecosystem: str, name: str) -> bool:
    cur = conn.execute("DELETE FROM watched WHERE ecosystem = ? AND name = ?", (get_ecosystem(ecosystem).name, name))
    conn.commit()
    return cur.rowcount > 0


def list_watched(conn: sqlite3.Connection) -> list[tuple]:
    return conn.execute(
        "SELECT ecosystem, name, last_version, last_verdict, last_checked FROM watched ORDER BY ecosystem, name"
    ).fetchall()


def run_once(conn: sqlite3.Connection, out_dir: Path, opts: AnalyzeOptions | None = None) -> list[WatchResult]:
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[WatchResult] = []
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with make_client() as client:
        rows = list_watched(conn)
        latest: dict[tuple[str, str], str] = {}
        for eco_name, name, *_ in rows:
            try:
                latest[(eco_name, name)] = get_ecosystem(eco_name).latest_version(client, name)
            except Exception as exc:  # noqa: BLE001 - keep watching other packages
                results.append(WatchResult(eco_name, name, None, "ERROR", error=str(exc)))

    for eco_name, name, last_version, *_ in rows:
        version = latest.get((eco_name, name))
        if version is None:
            continue
        if version == last_version:
            results.append(WatchResult(eco_name, name, version, "UNCHANGED"))
            conn.execute("UPDATE watched SET last_checked = ? WHERE ecosystem = ? AND name = ?",
                         (now, eco_name, name))
            continue
        try:
            report: Report = analyze_release(eco_name, name, version, opts=opts)
        except (RegistryError, OSError, ValueError) as exc:
            results.append(WatchResult(eco_name, name, version, "ERROR", error=str(exc)))
            continue
        safe = name.replace("/", "__").replace("@", "")
        stem = out_dir / f"{eco_name}-{safe}-{version}"
        stem.with_suffix(".json").write_text(report.model_dump_json(indent=2))
        stem.with_suffix(".md").write_text(to_markdown(report))
        conn.execute(
            "UPDATE watched SET last_version = ?, last_verdict = ?, last_checked = ? WHERE ecosystem = ? AND name = ?",
            (version, report.verdict, now, eco_name, name),
        )
        results.append(WatchResult(eco_name, name, version, report.verdict, report_path=stem.with_suffix(".md")))
    conn.commit()
    return results
