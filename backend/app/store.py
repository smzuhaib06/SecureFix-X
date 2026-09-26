"""
Investigation Store with SQLite persistence and real-time SSE pub/sub.
Ensures investigations, findings, and audit logs persist across restarts.
"""
import asyncio
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from app.models import AuditEvent, Investigation, ProgressEvent
from app.db import (
    DEFAULT_DB_PATH,
    delete_investigation,
    get_audit_events,
    get_db_stats,
    init_db,
    load_all_investigations,
    load_investigation,
    log_audit_event,
    save_investigation,
)


class InvestigationStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._investigations: Dict[str, Investigation] = {}
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}

        # Initialize SQLite database and load existing investigations
        init_db(self.db_path)
        persisted = load_all_investigations(self.db_path)
        for inv in persisted:
            self._investigations[inv.id] = inv

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def create(self, investigation: Investigation) -> Investigation:
        self._investigations[investigation.id] = investigation
        save_investigation(investigation, self.db_path)
        self.log_audit(
            investigation.id,
            action="INVESTIGATION_CREATED",
            actor="system",
            status=investigation.status.value if hasattr(investigation.status, "value") else str(investigation.status),
            metadata={
                "title": investigation.title,
                "repository_path": investigation.repository_path,
                "repository_url": investigation.repository_url,
            },
        )
        return investigation

    def get(self, investigation_id: str) -> Optional[Investigation]:
        if investigation_id in self._investigations:
            return self._investigations[investigation_id]
        # Fallback to SQLite
        inv = load_investigation(investigation_id, self.db_path)
        if inv:
            self._investigations[inv.id] = inv
        return inv

    def list_all(self) -> List[Investigation]:
        # Return sorted by created_at DESC
        return sorted(
            self._investigations.values(),
            key=lambda i: i.created_at,
            reverse=True,
        )

    def update(self, investigation: Investigation) -> Investigation:
        investigation.updated_at = datetime.now(timezone.utc)
        self._investigations[investigation.id] = investigation
        save_investigation(investigation, self.db_path)
        return investigation

    def delete(self, investigation_id: str) -> bool:
        deleted = delete_investigation(investigation_id, self.db_path)
        if investigation_id in self._investigations:
            del self._investigations[investigation_id]
            return True
        return deleted

    # ── Audit Logging ─────────────────────────────────────────────────────────

    def log_audit(
        self,
        investigation_id: str,
        action: str,
        actor: str = "system",
        status: str = "COMPLETED",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        return log_audit_event(
            investigation_id=investigation_id,
            action=action,
            actor=actor,
            status=status,
            metadata=metadata or {},
            db_path=self.db_path,
        )

    def get_audit(self, investigation_id: str) -> List[AuditEvent]:
        return get_audit_events(investigation_id, self.db_path)

    # ── Dashboard Statistics ──────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        return get_db_stats(self.db_path)

    # ── SSE pub/sub ───────────────────────────────────────────────────────────

    def subscribe(self, investigation_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(investigation_id, []).append(q)
        return q

    def unsubscribe(self, investigation_id: str, queue: asyncio.Queue):
        subs = self._subscribers.get(investigation_id, [])
        if queue in subs:
            subs.remove(queue)

    async def publish(self, event: ProgressEvent):
        for q in self._subscribers.get(event.investigation_id, []):
            await q.put(event)


# Singleton
store = InvestigationStore()
