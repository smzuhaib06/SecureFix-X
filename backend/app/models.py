"""
Pydantic models for SECUREFIX backend.
"""
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import uuid


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ── Enums ──────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class InvestigationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    APPLYING = "applying"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class RemediationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"
    VERIFIED = "verified"
    FAILED = "failed"


# ── Repository ─────────────────────────────────────────────────────────────────

class RepositoryInfo(BaseModel):
    project_type: str = ""
    languages: List[str] = []
    frameworks: List[str] = []
    entry_points: List[str] = []
    api_routes: List[str] = []
    auth_components: List[str] = []
    database_components: List[str] = []
    test_framework: str = ""
    deployment_files: List[str] = []
    total_files: int = 0
    relevant_files: List[str] = []


# ── Agent Outputs ──────────────────────────────────────────────────────────────

class AgentFinding(BaseModel):
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    files: List[str] = []
    line_ranges: List[str] = []
    evidence: List[str] = []
    recommendation: str = ""
    attack_path: List[str] = []
    root_cause: str = ""


class AgentResult(BaseModel):
    agent: str
    status: AgentStatus
    duration_ms: int = 0
    findings: List[AgentFinding] = []
    summary: str = ""
    error: Optional[str] = None
    raw_output: Optional[Dict[str, Any]] = None


# ── Evidence Correlation ───────────────────────────────────────────────────────

class EvidenceItem(BaseModel):
    source: str          # which agent produced this
    type: str            # code | config | dependency | runtime | test
    description: str
    file: Optional[str] = None
    line_range: Optional[str] = None
    severity: Optional[Severity] = None


class CorrelationResult(BaseModel):
    primary_finding: str
    corroborating_evidence: List[EvidenceItem] = []
    contradicting_evidence: List[EvidenceItem] = []
    affected_files: List[str] = []
    attack_path: List[str] = []
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_graph: Dict[str, Any] = {}


# ── Root Cause ─────────────────────────────────────────────────────────────────

class RootCauseAnalysis(BaseModel):
    symptom: str
    root_cause: str
    why_it_happens: str
    impact: str
    affected_components: List[str] = []
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_reasoning: Optional[str] = None


# ── Remediation ────────────────────────────────────────────────────────────────

class FilePatch(BaseModel):
    file_path: str
    before: str
    after: str
    diff: str
    explanation: str


class RemediationProposal(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: RemediationStatus = RemediationStatus.PENDING
    summary: str
    files_changed: List[str] = []
    patches: List[FilePatch] = []
    risk_level: str = "low"
    risk_explanation: str = ""
    regression_test: Optional[str] = None
    regression_test_file: Optional[str] = None


# ── Verification ───────────────────────────────────────────────────────────────

class VerificationCheck(BaseModel):
    name: str
    status: str          # passed | failed | skipped
    detail: str = ""


class VerificationResult(BaseModel):
    overall_status: str   # verified | failed | partial
    checks: List[VerificationCheck] = []
    exploit_blocked: bool = False
    regression_passed: bool = False
    summary: str = ""


# ── Timeline ───────────────────────────────────────────────────────────────────

class TimelineEvent(BaseModel):
    timestamp: datetime = Field(default_factory=utc_now)
    event: str
    detail: str = ""
    actor: str = "system"   # system | user | agent name


# ── Investigation ──────────────────────────────────────────────────────────────

class InvestigationCreate(BaseModel):
    title: str
    issue_description: str
    repository_path: Optional[str] = None   # local path for demo
    repository_url: Optional[str] = None    # GitHub URL
    severity_hint: Optional[Severity] = None


class Investigation(BaseModel):
    id: str = Field(default_factory=lambda: f"SF-{str(uuid.uuid4())[:8].upper()}")
    title: str
    issue_description: str
    repository_path: Optional[str] = None
    repository_url: Optional[str] = None
    status: InvestigationStatus = InvestigationStatus.PENDING
    severity: Optional[Severity] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    # Populated as investigation progresses
    repository_info: Optional[RepositoryInfo] = None
    agent_results: Dict[str, AgentResult] = {}
    correlation: Optional[CorrelationResult] = None
    root_cause: Optional[RootCauseAnalysis] = None
    remediation: Optional[RemediationProposal] = None
    verification: Optional[VerificationResult] = None
    timeline: List[TimelineEvent] = []
    progress_pct: int = 0


class InvestigationSummary(BaseModel):
    id: str
    title: str
    status: InvestigationStatus
    severity: Optional[Severity]
    created_at: datetime
    progress_pct: int


# ── SSE Progress Event ─────────────────────────────────────────────────────────

class ProgressEvent(BaseModel):
    investigation_id: str
    event_type: str     # agent_started | agent_completed | agent_failed |
                        # correlation_done | root_cause_done | patch_ready |
                        # verification_done | status_change
    agent: Optional[str] = None
    message: str
    progress_pct: int
    data: Optional[Dict[str, Any]] = None


# ── Approval ───────────────────────────────────────────────────────────────────

class ApprovalDecision(BaseModel):
    approved: bool
    comment: Optional[str] = None


# ── Audit Log ──────────────────────────────────────────────────────────────────

class AuditEvent(BaseModel):
    id: Optional[int] = None
    investigation_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    actor: str = "system"
    action: str
    status: str = "COMPLETED"
    metadata: Dict[str, Any] = {}

