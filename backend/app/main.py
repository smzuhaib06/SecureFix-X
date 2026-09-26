"""
SECUREFIX Backend API
FastAPI application serving the investigation workflow.
"""
import asyncio
import json
import os
from typing import List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.models import (
    ApprovalDecision,
    AuditEvent,
    Investigation,
    InvestigationCreate,
    InvestigationStatus,
    InvestigationSummary,
    RemediationStatus,
)
from app.orchestrator import AgentOrchestrator
from app.store import store
from app.report import generate_markdown_report
from app.repository import connector as repo_connector

app = FastAPI(
    title="SECUREFIX API",
    description="Autonomous AI security investigation and remediation system",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = AgentOrchestrator()

# ── Demo repo path (resolved relative to this file) ──────────────────────────
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DEMO_REPO_PATH = os.environ.get(
    "DEMO_REPO_PATH",
    os.path.normpath(os.path.join(_THIS_DIR, "../../../demo-app")),
)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "healthy", "service": "securefix-api"}


# ── Investigations ────────────────────────────────────────────────────────────

@app.post("/api/investigations", response_model=Investigation, status_code=201)
async def create_investigation(
    payload: InvestigationCreate,
    background_tasks: BackgroundTasks,
):
    # Resolve repo path — local path takes priority, then GitHub URL, then demo default
    repo_path = payload.repository_path

    if not repo_path and payload.repository_url:
        try:
            repo_path = repo_connector.resolve(payload.repository_url)
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    if not repo_path:
        repo_path = DEMO_REPO_PATH

    if not os.path.isdir(repo_path):
        raise HTTPException(
            status_code=400,
            detail=f"Repository path not found: {repo_path}",
        )

    inv = Investigation(
        title=payload.title,
        issue_description=payload.issue_description,
        repository_path=repo_path,
        repository_url=payload.repository_url,
        severity=payload.severity_hint,
        status=InvestigationStatus.PENDING,
    )
    store.create(inv)

    # Start investigation in background
    background_tasks.add_task(orchestrator.run_investigation, inv)

    return inv


@app.get("/api/investigations", response_model=List[InvestigationSummary])
def list_investigations():
    return [
        InvestigationSummary(
            id=inv.id,
            title=inv.title,
            status=inv.status,
            severity=inv.severity,
            created_at=inv.created_at,
            progress_pct=inv.progress_pct,
        )
        for inv in store.list_all()
    ]


@app.get("/api/investigations/{investigation_id}", response_model=Investigation)
def get_investigation(investigation_id: str):
    inv = store.get(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


@app.delete("/api/investigations/{investigation_id}", status_code=204)
def delete_investigation(investigation_id: str):
    if not store.delete(investigation_id):
        raise HTTPException(status_code=404, detail="Investigation not found")


# ── SSE progress stream ───────────────────────────────────────────────────────

@app.get("/api/investigations/{investigation_id}/stream")
async def stream_investigation(investigation_id: str):
    inv = store.get(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    queue = store.subscribe(investigation_id)

    async def event_generator():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    data = json.dumps(event.model_dump())
                    yield f"data: {data}\n\n"

                    # Stop streaming once terminal state reached
                    if event.progress_pct >= 100 or event.event_type in ("error",):
                        break
                except asyncio.TimeoutError:
                    # Heartbeat
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
        finally:
            store.unsubscribe(investigation_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Approval ──────────────────────────────────────────────────────────────────

@app.post("/api/investigations/{investigation_id}/approve", response_model=Investigation)
async def approve_remediation(
    investigation_id: str,
    decision: ApprovalDecision,
    background_tasks: BackgroundTasks,
):
    inv = store.get(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if inv.status != InvestigationStatus.AWAITING_APPROVAL:
        raise HTTPException(
            status_code=400,
            detail=f"Investigation is not awaiting approval (status: {inv.status})",
        )

    if not inv.remediation:
        raise HTTPException(status_code=400, detail="No remediation proposal to approve")

    if decision.approved:
        inv.remediation.status = RemediationStatus.APPROVED
        store.update(inv)
        store.log_audit(
            investigation_id,
            action="PATCH_APPROVED",
            actor="user",
            status="APPROVED",
            metadata={"comment": decision.comment or "User approved remediation patch"},
        )
        background_tasks.add_task(orchestrator.apply_patch_and_verify, inv)
    else:
        inv.remediation.status = RemediationStatus.REJECTED
        inv.status = InvestigationStatus.COMPLETED
        store.log_audit(
            investigation_id,
            action="PATCH_REJECTED",
            actor="user",
            status="REJECTED",
            metadata={"comment": decision.comment or "No reason provided"},
        )
        from app.models import TimelineEvent
        inv.timeline.append(TimelineEvent(
            event="Patch rejected by user",
            detail=decision.comment or "No reason provided",
            actor="user",
        ))
        store.update(inv)

    return inv


# ── Audit Log ─────────────────────────────────────────────────────────────────

@app.get("/api/investigations/{investigation_id}/audit", response_model=List[AuditEvent])
def get_investigation_audit(investigation_id: str):
    """Retrieve immutable audit events for an investigation from the database."""
    inv = store.get(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return store.get_audit(investigation_id)


# ── Dashboard stats ───────────────────────────────────────────────────────────

@app.get("/api/dashboard/stats")
def dashboard_stats():
    return store.get_stats()


# ── Demo shortcut ─────────────────────────────────────────────────────────────

@app.post("/api/demo/create-investigation", response_model=Investigation, status_code=201)
async def create_demo_investigation(background_tasks: BackgroundTasks):
    """Create the standard BOLA demo investigation with one click."""
    inv = Investigation(
        title="Broken Access Control in Account API",
        issue_description=(
            "Authenticated users may be able to access another user's account data "
            "by modifying the account_id parameter in the GET /api/accounts/{account_id} endpoint. "
            "Alice can access Bob's account by requesting /api/accounts/2."
        ),
        repository_path=DEMO_REPO_PATH,
        status=InvestigationStatus.PENDING,
    )
    store.create(inv)
    background_tasks.add_task(orchestrator.run_investigation, inv)
    return inv


# ── Report export ─────────────────────────────────────────────────────────────

@app.get("/api/investigations/{investigation_id}/report")
def get_investigation_report(investigation_id: str):
    """Export a completed investigation as a Markdown report."""
    inv = store.get(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    report_md = generate_markdown_report(inv)

    filename = f"securefix-report-{investigation_id}.md"
    return Response(
        content=report_md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
