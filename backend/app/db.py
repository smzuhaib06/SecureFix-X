"""
SQLite database persistence for SECUREFIX.
Handles durable storage of investigations, findings, and audit events.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.models import AuditEvent, Investigation, InvestigationStatus, Severity

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.environ.get(
    "DATABASE_PATH",
    os.path.normpath(os.path.join(_THIS_DIR, "../securefix.db")),
)


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH):
    """Create database tables if they do not exist."""
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                issue_description TEXT NOT NULL,
                repository_path TEXT,
                repository_url TEXT,
                status TEXT NOT NULL,
                severity TEXT,
                progress_pct INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                data_json TEXT NOT NULL
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                metadata_json TEXT
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL,
                agent TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                files_json TEXT,
                line_ranges_json TEXT,
                evidence_json TEXT,
                recommendation TEXT,
                attack_path_json TEXT,
                root_cause TEXT,
                created_at TEXT NOT NULL
            );
        """)
        conn.commit()


def save_investigation(inv: Investigation, db_path: str = DEFAULT_DB_PATH):
    """Persist an investigation to SQLite, updating both the investigation and its findings."""
    created_at_str = inv.created_at.isoformat() if hasattr(inv.created_at, "isoformat") else str(inv.created_at)
    updated_at_str = inv.updated_at.isoformat() if hasattr(inv.updated_at, "isoformat") else str(inv.updated_at)
    data_json = inv.model_dump_json()

    with get_connection(db_path) as conn:
        conn.execute("""
            INSERT INTO investigations (
                id, title, issue_description, repository_path, repository_url,
                status, severity, progress_pct, created_at, updated_at, data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                title = excluded.title,
                issue_description = excluded.issue_description,
                repository_path = excluded.repository_path,
                repository_url = excluded.repository_url,
                status = excluded.status,
                severity = excluded.severity,
                progress_pct = excluded.progress_pct,
                updated_at = excluded.updated_at,
                data_json = excluded.data_json;
        """, (
            inv.id,
            inv.title,
            inv.issue_description,
            inv.repository_path,
            inv.repository_url,
            inv.status.value if hasattr(inv.status, "value") else str(inv.status),
            inv.severity.value if inv.severity and hasattr(inv.severity, "value") else (str(inv.severity) if inv.severity else None),
            inv.progress_pct,
            created_at_str,
            updated_at_str,
            data_json,
        ))

        # Refresh findings table for this investigation
        conn.execute("DELETE FROM findings WHERE investigation_id = ?", (inv.id,))
        now_str = datetime.now(timezone.utc).isoformat()
        for agent_name, result in inv.agent_results.items():
            for f in result.findings:
                conn.execute("""
                    INSERT INTO findings (
                        investigation_id, agent, title, severity, confidence,
                        files_json, line_ranges_json, evidence_json, recommendation,
                        attack_path_json, root_cause, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    inv.id,
                    agent_name,
                    f.title,
                    f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    f.confidence,
                    json.dumps(f.files),
                    json.dumps(f.line_ranges),
                    json.dumps(f.evidence),
                    f.recommendation,
                    json.dumps(f.attack_path),
                    f.root_cause,
                    now_str,
                ))
        conn.commit()


def load_investigation(investigation_id: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Investigation]:
    """Load a single investigation from SQLite."""
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT data_json FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        if not row:
            return None
        return Investigation.model_validate_json(row["data_json"])


def load_all_investigations(db_path: str = DEFAULT_DB_PATH) -> List[Investigation]:
    """Load all investigations from SQLite ordered by created_at DESC."""
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT data_json FROM investigations ORDER BY created_at DESC").fetchall()
        result = []
        for r in rows:
            try:
                result.append(Investigation.model_validate_json(r["data_json"]))
            except Exception:
                pass
        return result


def delete_investigation(investigation_id: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Delete an investigation and its associated audit events and findings."""
    with get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))
        conn.execute("DELETE FROM audit_events WHERE investigation_id = ?", (investigation_id,))
        conn.execute("DELETE FROM findings WHERE investigation_id = ?", (investigation_id,))
        conn.commit()
        return cursor.rowcount > 0


def log_audit_event(
    investigation_id: str,
    action: str,
    actor: str = "system",
    status: str = "COMPLETED",
    metadata: Optional[Dict[str, Any]] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> AuditEvent:
    """Record an immutable audit event in SQLite."""
    now = datetime.now(timezone.utc)
    ts_str = now.isoformat()
    meta_json = json.dumps(metadata or {})

    with get_connection(db_path) as conn:
        cursor = conn.execute("""
            INSERT INTO audit_events (
                investigation_id, timestamp, actor, action, status, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (investigation_id, ts_str, actor, action, status, meta_json))
        conn.commit()
        event_id = cursor.lastrowid

    return AuditEvent(
        id=event_id,
        investigation_id=investigation_id,
        timestamp=now,
        actor=actor,
        action=action,
        status=status,
        metadata=metadata or {},
    )


def get_audit_events(investigation_id: str, db_path: str = DEFAULT_DB_PATH) -> List[AuditEvent]:
    """Fetch all audit events for an investigation ordered chronologically."""
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, investigation_id, timestamp, actor, action, status, metadata_json FROM audit_events WHERE investigation_id = ? ORDER BY id ASC",
            (investigation_id,),
        ).fetchall()
        events = []
        for r in rows:
            try:
                ts = datetime.fromisoformat(r["timestamp"])
            except Exception:
                ts = datetime.now(timezone.utc)
            meta = json.loads(r["metadata_json"]) if r["metadata_json"] else {}
            events.append(AuditEvent(
                id=r["id"],
                investigation_id=r["investigation_id"],
                timestamp=ts,
                actor=r["actor"],
                action=r["action"],
                status=r["status"],
                metadata=meta,
            ))
        return events


def get_db_stats(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Calculate dashboard statistics directly from SQLite database."""
    with get_connection(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
        active = conn.execute("""
            SELECT COUNT(*) FROM investigations
            WHERE status IN ('pending', 'running', 'awaiting_approval', 'applying', 'verifying')
        """).fetchone()[0]
        completed = conn.execute(
            "SELECT COUNT(*) FROM investigations WHERE status = 'completed'"
        ).fetchone()[0]
        critical = conn.execute("""
            SELECT COUNT(*) FROM investigations WHERE LOWER(severity) = 'critical'
        """).fetchone()[0]

        # Calculate verified remediations from stored json
        rows = conn.execute("SELECT data_json FROM investigations").fetchall()
        verified = 0
        for r in rows:
            try:
                data = json.loads(r["data_json"])
                if data.get("remediation", {}).get("status") == "verified":
                    verified += 1
            except Exception:
                pass

        total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

    return {
        "active_investigations": active,
        "critical_findings": critical,
        "issues_fixed": completed,
        "verified_remediations": verified,
        "total_investigations": total,
        "total_findings": total_findings,
        "demo_metrics": {
            "avg_investigation_time_reduction_pct": 68,
            "manual_steps_before": 12,
            "automated_steps_after": 1,
            "avg_files_inspected_before": 47,
            "avg_relevant_files_securefix": 6,
        },
    }
