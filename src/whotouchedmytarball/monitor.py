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
from .trust.models import TrustBaseline, IdentityObservation, BaselineStatus
from .trust.identity import repo_identity
from .trust.compare import detect_changes
from datetime import datetime, timezone as _tz
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
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS trust_baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ecosystem TEXT NOT NULL,
            package_name TEXT NOT NULL,
            repository_url TEXT,
            repository_owner TEXT,
            repository_name TEXT,
            source_commit TEXT,
            source_ref TEXT,
            publisher_identity TEXT,
            issuer TEXT,
            signer_identity TEXT,
            build_workflow TEXT,
            builder_identity TEXT,
            provenance_status TEXT,
            artifact_digest TEXT,
            first_observed_at TEXT NOT NULL,
            last_observed_at TEXT NOT NULL,
            baseline_status TEXT NOT NULL,
            approved_at TEXT,
            approved_by TEXT,
            superseded_by INTEGER
        );
        CREATE TABLE IF NOT EXISTS identity_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ecosystem TEXT NOT NULL,
            package_name TEXT NOT NULL,
            version TEXT NOT NULL,
            repository_url TEXT,
            repository_owner TEXT,
            repository_name TEXT,
            source_commit TEXT,
            source_ref TEXT,
            publisher_identity TEXT,
            issuer TEXT,
            signer_identity TEXT,
            build_workflow TEXT,
            builder_identity TEXT,
            provenance_status TEXT,
            artifact_digest TEXT,
            observed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS trust_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ecosystem TEXT NOT NULL,
            package_name TEXT NOT NULL,
            field TEXT NOT NULL,
            previous_value TEXT,
            current_value TEXT,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            explanation TEXT NOT NULL,
            evidence TEXT NOT NULL,
            first_detected_at TEXT NOT NULL,
            status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS trust_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ecosystem TEXT NOT NULL,
            package_name TEXT NOT NULL,
            change_id INTEGER,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            created_at TEXT NOT NULL,
            note TEXT
        );
        """
    )
    conn.commit()
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

        # Trust continuity observation and change detection.
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            source_repo = None
            source_commit = None
            source_ref = None
            if report.source:
                source_repo = report.source.repository
                source_commit = report.source.commit
                source_ref = report.source.ref
            if report.provenance and report.provenance.repository:
                source_repo = source_repo or report.provenance.repository
                source_commit = source_commit or report.provenance.commit
            nu, owner, rname = repo_identity(source_repo)
            obs = IdentityObservation(
                ecosystem=eco_name, package_name=name, version=version,
                repository_url=nu, repository_owner=owner, repository_name=rname,
                source_commit=source_commit, source_ref=source_ref,
                build_workflow=report.provenance.workflow if report.provenance else None,
                provenance_status=report.provenance_verification.get("status") if report.provenance_verification else None,
                observed_at=now_iso,
            )
            # version previously seen?
            cur = conn.execute(
                "SELECT 1 FROM identity_observations WHERE ecosystem=? AND package_name=? AND version=?",
                (eco_name, name, version),
            )
            version_seen = cur.fetchone() is not None
            active = get_active_baseline(conn, eco_name, name)
            # Baseline conversion helpers
            baseline_obj = None
            if active:
                import sqlite3 as _sq
                # map row -> TrustBaseline by column names
                cols = [c[0] for c in conn.execute("PRAGMA table_info(trust_baselines)").fetchall()]
                d = dict(zip(cols, active))
                baseline_obj = TrustBaseline(
                    ecosystem=d["ecosystem"], package_name=d["package_name"],
                    repository_url=d["repository_url"], repository_owner=d["repository_owner"],
                    repository_name=d["repository_name"], source_commit=d["source_commit"],
                    source_ref=d["source_ref"], publisher_identity=d["publisher_identity"],
                    issuer=d["issuer"], signer_identity=d["signer_identity"],
                    build_workflow=d["build_workflow"], builder_identity=d["builder_identity"],
                    provenance_status=d["provenance_status"], artifact_digest=d["artifact_digest"],
                    first_observed_at=d["first_observed_at"], last_observed_at=d["last_observed_at"],
                    baseline_status=d["baseline_status"], approved_at=d["approved_at"],
                    approved_by=d["approved_by"], baseline_id=d["id"],
                )
            changes = detect_changes(baseline_obj, obs, version_previously_seen=version_seen) if baseline_obj else []
            # deduplicate identical NEW alerts
            new_changes = []
            for ch in changes:
                ch.ecosystem = eco_name
                ch.package_name = name
                if has_same_change(conn, eco_name, name, ch.field, ch.current_value):
                    continue
                new_changes.append(ch)
            # create baseline if none (initial observed, not trusted)
            if baseline_obj is None:
                b = TrustBaseline(
                    ecosystem=eco_name, package_name=name,
                    repository_url=nu, repository_owner=owner, repository_name=rname,
                    source_commit=source_commit, source_ref=source_ref,
                    build_workflow=obs.build_workflow,
                    provenance_status=obs.provenance_status,
                    artifact_digest=None,
                    first_observed_at=now_iso, last_observed_at=now_iso,
                    baseline_status=BaselineStatus.OBSERVED,
                )
                create_baseline(conn, b)
            else:
                # update last_observed_at best-effort
                conn.execute(
                    "UPDATE trust_baselines SET last_observed_at=? WHERE id=?",
                    (now_iso, baseline_obj.baseline_id),
                )
                conn.commit()
            # persist changes
            for ch in new_changes:
                add_change(conn, ch)
            # persist observation
            add_observation(conn, obs)
            report.trust_continuity = {
                "baseline_status": baseline_obj.baseline_status.value if baseline_obj else "OBSERVED",
                "changes": [c.__dict__ for c in new_changes],
                "observed_at": now_iso,
            }
        except Exception as exc:  # noqa: BLE001
            report.notes.append(f"Trust continuity processing failed: {exc}")

        conn.execute(
            "UPDATE watched SET last_version = ?, last_verdict = ?, last_checked = ? WHERE ecosystem = ? AND name = ?",
            (version, report.verdict, now, eco_name, name),
        )
        results.append(WatchResult(eco_name, name, version, report.verdict, report_path=stem.with_suffix(".md")))
    conn.commit()
    return results


def list_baselines(conn, ecosystem=None, name=None):
    q="SELECT * FROM trust_baselines WHERE 1=1"
    params=[]
    if ecosystem:
        q+=" AND ecosystem=?"; params.append(ecosystem)
    if name:
        q+=" AND package_name=?"; params.append(name)
    q+=" ORDER BY id"
    return conn.execute(q, params).fetchall()


def add_observation(conn, obs):
    conn.execute(
        """INSERT INTO identity_observations
        (ecosystem,package_name,version,repository_url,repository_owner,repository_name,
         source_commit,source_ref,publisher_identity,issuer,signer_identity,build_workflow,
         builder_identity,provenance_status,artifact_digest,observed_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (obs.ecosystem, obs.package_name, obs.version, obs.repository_url, obs.repository_owner,
         obs.repository_name, obs.source_commit, obs.source_ref, obs.publisher_identity, obs.issuer,
         obs.signer_identity, obs.build_workflow, obs.builder_identity, obs.provenance_status,
         obs.artifact_digest, obs.observed_at),
    )
    conn.commit()


def get_active_baseline(conn, ecosystem, name):
    cur = conn.execute(
        """SELECT * FROM trust_baselines WHERE ecosystem=? AND package_name=? AND baseline_status IN ('OBSERVED','TRUSTED','PENDING_APPROVAL')
        ORDER BY id DESC LIMIT 1""",
        (ecosystem, name),
    )
    row = cur.fetchone()
    return row


def create_baseline(conn, baseline) -> int:
    cur = conn.execute(
        """INSERT INTO trust_baselines
        (ecosystem,package_name,repository_url,repository_owner,repository_name,source_commit,
         source_ref,publisher_identity,issuer,signer_identity,build_workflow,builder_identity,
         provenance_status,artifact_digest,first_observed_at,last_observed_at,baseline_status,
         approved_at,approved_by)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (baseline.ecosystem, baseline.package_name, baseline.repository_url, baseline.repository_owner,
         baseline.repository_name, baseline.source_commit, baseline.source_ref, baseline.publisher_identity,
         baseline.issuer, baseline.signer_identity, baseline.build_workflow, baseline.builder_identity,
         baseline.provenance_status, baseline.artifact_digest, baseline.first_observed_at,
         baseline.last_observed_at, baseline.baseline_status.value if hasattr(baseline.baseline_status,'value') else str(baseline.baseline_status),
         baseline.approved_at, baseline.approved_by),
    )
    conn.commit()
    return cur.lastrowid


def add_change(conn, change) -> int:
    import json
    cur = conn.execute(
        """INSERT INTO trust_changes
        (ecosystem,package_name,field,previous_value,current_value,severity,category,explanation,evidence,first_detected_at,status)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (change.ecosystem, change.package_name, change.field, change.previous_value, change.current_value,
         change.severity, change.category, change.explanation, json.dumps(change.evidence), change.first_detected_at,
         change.status.value if hasattr(change.status,'value') else str(change.status)),
    )
    conn.commit()
    return cur.lastrowid


def has_same_change(conn, ecosystem, name, field, current_value) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM trust_changes WHERE ecosystem=? AND package_name=? AND field=? AND current_value=? AND status IN ('NEW','ACKNOWLEDGED')",
        (ecosystem, name, field, current_value),
    )
    return cur.fetchone() is not None


def approve_change(conn, ecosystem, package, change_id, actor="local-operator", note=None):
    conn.execute("UPDATE trust_changes SET status='APPROVED' WHERE id=? AND ecosystem=? AND package_name=?", (change_id, ecosystem, package))
    conn.execute("INSERT INTO trust_approvals (ecosystem,package_name,change_id,action,actor,created_at,note) VALUES (?,?,?,?,?,?,?)",
                 (ecosystem, package, change_id, "APPROVE", actor, datetime.now(timezone.utc).isoformat() if False else __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(), note))
    conn.commit()


def reject_change(conn, ecosystem, package, change_id, actor="local-operator", note=None):
    conn.execute("UPDATE trust_changes SET status='REJECTED' WHERE id=? AND ecosystem=? AND package_name=?", (change_id, ecosystem, package))
    conn.execute("INSERT INTO trust_approvals (ecosystem,package_name,change_id,action,actor,created_at,note) VALUES (?,?,?,?,?,?,?)",
                 (ecosystem, package, change_id, "REJECT", actor, __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(), note))
    conn.commit()


def acknowledge_change(conn, ecosystem, package, change_id, actor="local-operator", note=None):
    conn.execute("UPDATE trust_changes SET status='ACKNOWLEDGED' WHERE id=? AND ecosystem=? AND package_name=?", (change_id, ecosystem, package))
    conn.execute("INSERT INTO trust_approvals (ecosystem,package_name,change_id,action,actor,created_at,note) VALUES (?,?,?,?,?,?,?)",
                 (ecosystem, package, change_id, "ACKNOWLEDGE", actor, __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(), note))
    conn.commit()
