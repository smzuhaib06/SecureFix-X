"""
Pydantic models for SECUREFIX backend.
"""
from enum import Enum
from typing import Any, Dict, List, Optional, Union
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


class ExploitCheckOutcome(str, Enum):
    """
    Structured outcome of a single security oracle check.

    PASS        — observed behavior satisfies the invariant oracle
    BYPASS      — the application violates the security invariant
    ERROR       — verification could not be executed reliably
                  (app unavailable, auth failure, subprocess failure)
    UNSUPPORTED — the invariant lacks enough information to check safely
    """
    PASS = "pass"
    BYPASS = "bypass"
    ERROR = "error"
    UNSUPPORTED = "unsupported"


class VulnerabilityClass(str, Enum):
    """Canonical vulnerability class identifiers used in SecurityInvariant."""
    BOLA = "BOLA"                         # Broken Object Level Authorization (CWE-639)
    SQL_INJECTION = "SQL_INJECTION"        # CWE-89
    NOSQL_INJECTION = "NOSQL_INJECTION"    # CWE-943 — NoSQL query operator injection
    PATH_TRAVERSAL = "PATH_TRAVERSAL"      # CWE-22
    COMMAND_INJECTION = "COMMAND_INJECTION"  # CWE-78
    MISSING_AUTH = "MISSING_AUTH"          # CWE-306
    HARDCODED_SECRET = "HARDCODED_SECRET"  # CWE-798
    UNKNOWN = "UNKNOWN"


class RemediationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"
    VERIFIED = "verified"
    FAILED = "failed"


# ── Finding status ─────────────────────────────────────────────────────────────

class FindingStatus(str, Enum):
    """
    Evidence-grounded status for every finding.

    CONFIRMED   — finding has real repository evidence (file + line + excerpt).
    HYPOTHESIS  — finding identifies missing evidence explicitly.
    UNSUPPORTED — analyzer cannot establish the claim for documented reason.
    """
    CONFIRMED   = "CONFIRMED"
    HYPOTHESIS  = "HYPOTHESIS"
    UNSUPPORTED = "UNSUPPORTED"


class DependencyAdvisoryStatus(str, Enum):
    """Status of a dependency advisory lookup."""
    CONFIRMED        = "CONFIRMED"       # CVE confirmed, version matches
    NO_KNOWN_ADVISORY = "NO_KNOWN_ADVISORY"  # Not in advisory DB
    UNSCANNED        = "UNSCANNED"       # Not attempted (no manifest)
    UNSUPPORTED      = "UNSUPPORTED"     # Package manager not supported


# ── Technology Profile ─────────────────────────────────────────────────────────

class VerificationStrategyType(str, Enum):
    """How to verify a finding for this technology stack."""
    FASTAPI_TESTCLIENT = "fastapi_testclient"   # Python/FastAPI: use TestClient
    EXPRESS_HTTP       = "express_http"          # Node.js/Express: local HTTP
    STATIC_ONLY        = "static_only"           # Static code inspection only
    UNSUPPORTED        = "unsupported"           # Cannot verify


class TechnologyProfile(BaseModel):
    """
    Repository-scoped technology profile derived purely from repository evidence.
    Never hardcoded. Must be derived during RepositoryAgent analysis.
    """
    language: str = ""                   # primary language (e.g. "python", "javascript")
    languages: List[str] = []            # all detected languages
    runtime: str = ""                    # e.g. "python", "node"
    framework: str = ""                  # primary framework (e.g. "fastapi", "express")
    frameworks: List[str] = []           # all detected frameworks
    package_manager: str = ""            # e.g. "pip", "npm"
    database: str = ""                   # e.g. "postgresql", "mongodb", "sqlite"
    application_type: str = ""           # e.g. "web_api", "web_app", "cli"
    test_framework: str = ""             # e.g. "pytest", "jest", "mocha", "unknown"
    test_file_patterns: List[str] = []   # e.g. ["test_*.py"] or ["*.test.js", "*.spec.js"]
    entry_points: List[str] = []         # discovered entry point files
    build_command: str = ""              # e.g. "npm run build"
    run_command: str = ""                # e.g. "uvicorn app.main:app"
    verification_strategy: VerificationStrategyType = VerificationStrategyType.UNSUPPORTED
    detection_evidence: List[str] = []   # what was inspected to derive this profile


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
    technology_profile: Optional["TechnologyProfile"] = None


# ── Agent Outputs ──────────────────────────────────────────────────────────────

class AgentFinding(BaseModel):
    title: str
    severity: Severity
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    files: List[str] = []
    line_ranges: List[str] = []
    evidence: List[str] = []
    recommendation: str = ""
    attack_path: List[str] = []
    root_cause: str = ""
    # Evidence-grounded status (required for EvidenceValidator)
    finding_status: "FindingStatus" = FindingStatus.HYPOTHESIS
    missing_evidence: str = ""       # required when finding_status=HYPOTHESIS
    unsupported_reason: str = ""     # required when finding_status=UNSUPPORTED
    # Source traceability
    vulnerability_class: Optional[str] = None
    file_line_start: Optional[int] = None
    file_line_end: Optional[int] = None
    evidence_excerpt: str = ""       # actual source code snippet
    source: str = ""                 # input source (e.g. "req.body.username")
    sink: str = ""                   # vulnerable sink (e.g. "User.findOne()")
    route: str = ""                  # route where this was found
    technology: str = ""             # technology this applies to
    provenance: str = ""             # how this finding was derived


class AgentResult(BaseModel):
    agent: str
    status: AgentStatus
    duration_ms: int = 0
    findings: List[AgentFinding] = []
    summary: str = ""
    error: Optional[str] = None
    raw_output: Optional[Dict[str, Any]] = None


# ── Evidence Validator ─────────────────────────────────────────────────────────

class EvidenceValidationResult(BaseModel):
    """Result of validating a single AgentFinding against evidence rules."""
    valid: bool
    finding_title: str
    finding_status: "FindingStatus"
    rejection_reason: str = ""


class EvidenceValidator:
    """
    Central validation layer that runs before a finding enters Evidence Correlation.

    Rules enforced:
    - CONFIRMED findings MUST have: non-empty files, non-empty evidence_excerpt or
      evidence list containing actual source text (not generic descriptions).
    - HYPOTHESIS findings MUST have a non-empty missing_evidence explanation.
    - UNSUPPORTED findings MUST have a non-empty unsupported_reason.
    - Generic fallback text is rejected from CONFIRMED status.
    - Empty file references are rejected from CONFIRMED status.
    """

    # Generic fallback phrases that cannot constitute CONFIRMED evidence
    _GENERIC_PHRASES = frozenset([
        "insufficient security control",
        "potential unauthorized access",
        "security vulnerability detected",
        "add a test suite",
        "no test files found",
        "issue description indicates",
        "issue describes",
        "arbitrary confidence",
        "see agent findings for specific details",
    ])

    def validate(self, finding: "AgentFinding") -> "EvidenceValidationResult":
        """Validate one finding. Returns EvidenceValidationResult."""
        status = finding.finding_status

        if status == FindingStatus.CONFIRMED:
            return self._validate_confirmed(finding)
        elif status == FindingStatus.HYPOTHESIS:
            return self._validate_hypothesis(finding)
        else:  # UNSUPPORTED
            return self._validate_unsupported(finding)

    def _validate_confirmed(self, finding: "AgentFinding") -> "EvidenceValidationResult":
        """CONFIRMED requires real repository evidence."""
        # Must have at least one file reference
        if not finding.files:
            return EvidenceValidationResult(
                valid=False,
                finding_title=finding.title,
                finding_status=FindingStatus.CONFIRMED,
                rejection_reason="CONFIRMED finding has no file references",
            )

        # Must have at least one evidence item that looks like actual source
        has_real_evidence = bool(finding.evidence_excerpt)
        if not has_real_evidence and finding.evidence:
            # Check that evidence is not purely generic
            for ev in finding.evidence:
                ev_lower = ev.lower()
                if not any(phrase in ev_lower for phrase in self._GENERIC_PHRASES):
                    has_real_evidence = True
                    break

        if not has_real_evidence:
            return EvidenceValidationResult(
                valid=False,
                finding_title=finding.title,
                finding_status=FindingStatus.CONFIRMED,
                rejection_reason=(
                    "CONFIRMED finding lacks real repository evidence "
                    "(only generic descriptions present)"
                ),
            )

        # Must have a line reference or excerpt
        if not finding.line_ranges and finding.file_line_start is None and not finding.evidence_excerpt:
            return EvidenceValidationResult(
                valid=False,
                finding_title=finding.title,
                finding_status=FindingStatus.CONFIRMED,
                rejection_reason=(
                    "CONFIRMED finding has no line reference or code excerpt"
                ),
            )

        return EvidenceValidationResult(
            valid=True,
            finding_title=finding.title,
            finding_status=FindingStatus.CONFIRMED,
        )

    def _validate_hypothesis(self, finding: "AgentFinding") -> "EvidenceValidationResult":
        """HYPOTHESIS requires missing_evidence to be documented."""
        if not finding.missing_evidence and not finding.evidence:
            return EvidenceValidationResult(
                valid=False,
                finding_title=finding.title,
                finding_status=FindingStatus.HYPOTHESIS,
                rejection_reason="HYPOTHESIS finding must document what evidence is missing",
            )
        return EvidenceValidationResult(
            valid=True,
            finding_title=finding.title,
            finding_status=FindingStatus.HYPOTHESIS,
        )

    def _validate_unsupported(self, finding: "AgentFinding") -> "EvidenceValidationResult":
        """UNSUPPORTED requires unsupported_reason to be documented."""
        if not finding.unsupported_reason:
            return EvidenceValidationResult(
                valid=False,
                finding_title=finding.title,
                finding_status=FindingStatus.UNSUPPORTED,
                rejection_reason="UNSUPPORTED finding must document why analysis cannot be done",
            )
        return EvidenceValidationResult(
            valid=True,
            finding_title=finding.title,
            finding_status=FindingStatus.UNSUPPORTED,
        )

    def filter_to_confirmed(
        self, findings: "List[AgentFinding]"
    ) -> "List[AgentFinding]":
        """Return only findings that pass validation and have CONFIRMED status."""
        return [
            f for f in findings
            if f.finding_status == FindingStatus.CONFIRMED
            and self.validate(f).valid
        ]


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
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_graph: Dict[str, Any] = {}
    # Overall investigation outcome
    # NO_CONFIRMED_FINDING | CONFIRMED | PARTIAL | UNSUPPORTED
    investigation_outcome: str = "UNKNOWN"
    confirmed_finding_count: int = 0
    hypothesis_count: int = 0
    unsupported_count: int = 0


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


# ── Security Invariant ─────────────────────────────────────────────────────────

class InvariantScope(BaseModel):
    """Defines the scope to which the invariant applies."""
    routes: List[str] = Field(
        default=[],
        description="URL route patterns covered by this invariant (e.g. ['/api/accounts/{account_id}'])",
    )
    resources: List[str] = Field(
        default=[],
        description="Logical resource types involved (e.g. ['account', 'transaction'])",
    )
    actor_roles: List[str] = Field(
        default=[],
        description="Roles of principals involved (e.g. ['authenticated_user', 'resource_owner', 'non_owner'])",
    )
    relevant_files: List[str] = Field(
        default=[],
        description="Repository-relative file paths where the invariant is enforced (or should be)",
    )


class AttackScenario(BaseModel):
    """
    Parameterized representation of the attack — instance values, not hardcoded globals.
    For SecureBank/BOLA these would be filled with Alice, account_id=2, etc.
    For a different repository they would carry that system's values.
    """
    method: str = Field(
        default="GET",
        description="HTTP method used in the attack (GET, POST, …)",
    )
    route_template: str = Field(
        default="",
        description="Route template with placeholders (e.g. '/api/accounts/{account_id}')",
    )
    route_example: str = Field(
        default="",
        description="Concrete example URL used in the attack scenario (scenario data)",
    )
    actor_credential_hint: str = Field(
        default="",
        description="Description of attacker identity (scenario data, e.g. 'authenticated as non-owner user')",
    )
    # ── Executable credentials (scenario data) ──────────────────────────────
    auth_endpoint: str = Field(
        default="",
        description=(
            "Login endpoint used to obtain a bearer token before the attack request. "
            "Scenario data.  Example: '/api/auth/login'"
        ),
    )
    auth_credentials: Dict[str, str] = Field(
        default={},
        description=(
            "Credential key/value pairs posted to auth_endpoint.  Scenario data. "
            "Example: {'username': 'alice', 'password': 'alice123'}.  "
            "Do NOT expose in reports — sanitize before logging."
        ),
    )
    auth_token_path: str = Field(
        default="access_token",
        description=(
            "JSON key path in the auth response that contains the bearer token.  "
            "Scenario data.  Example: 'access_token'"
        ),
    )
    parameters: Dict[str, Any] = Field(
        default={},
        description="Scenario-specific parameters (scenario data — not global assumptions)",
    )


class OracleExpectedOutcome(BaseModel):
    """A single expected outcome of the security oracle."""
    label: str = Field(description="Human-readable label (e.g. 'attack_blocked', 'exploit_active')")
    allowed_status_codes: List[int] = Field(
        default=[],
        description="HTTP status codes that indicate this outcome (e.g. [403, 404] for blocked)",
    )
    forbidden_status_codes: List[int] = Field(
        default=[],
        description="HTTP status codes that indicate a failure (e.g. [200] for BOLA attack that succeeded)",
    )
    protected_data_indicators: List[str] = Field(
        default=[],
        description="Field names or response body patterns that must NOT appear if the oracle passes",
    )


class SecurityOracle(BaseModel):
    """
    Machine-readable specification for verifying that the invariant holds.
    Designed to be consumed by a future generalised VerificationEngine.
    """
    description: str = Field(
        default="",
        description="Human-readable summary of what the oracle checks",
    )
    outcomes: List[OracleExpectedOutcome] = Field(
        default=[],
        description="All expected outcomes (typically: attack_blocked + attack_active)",
    )

    # Convenience: the primary 'invariant holds' outcome
    @property
    def blocked_outcome(self) -> Optional[OracleExpectedOutcome]:
        for o in self.outcomes:
            if "block" in o.label.lower() or "secure" in o.label.lower() or "pass" in o.label.lower():
                return o
        return None

    # Convenience: the primary 'invariant violated' outcome
    @property
    def violated_outcome(self) -> Optional[OracleExpectedOutcome]:
        for o in self.outcomes:
            if "active" in o.label.lower() or "bypass" in o.label.lower() or "fail" in o.label.lower() or "vuln" in o.label.lower():
                return o
        return None


class LegitimateUseCase(BaseModel):
    """
    One valid usage pattern that must continue to work after the fix.
    Represents the 'legitimate-use contract' for this invariant.
    """
    description: str = Field(description="Human-readable description of the valid use case")
    method: str = Field(default="GET", description="HTTP method")
    route_example: str = Field(default="", description="Concrete URL (scenario data)")
    actor_credential_hint: str = Field(
        default="",
        description="Description of the legitimate actor (scenario data)",
    )
    # ── Executable credentials (scenario data) ──────────────────────────────
    auth_endpoint: str = Field(
        default="",
        description="Login endpoint for this use case.  Scenario data.",
    )
    auth_credentials: Dict[str, str] = Field(
        default={},
        description=(
            "Credential key/value pairs for this use case.  Scenario data.  "
            "Do NOT expose in reports."
        ),
    )
    auth_token_path: str = Field(
        default="access_token",
        description="JSON key in auth response containing the bearer token.",
    )
    expected_status_codes: List[int] = Field(
        default=[200],
        description="HTTP status codes expected for a legitimate call",
    )
    parameters: Dict[str, Any] = Field(
        default={},
        description="Scenario-specific parameters for this use case (scenario data)",
    )


class InvariantProvenance(BaseModel):
    """Records where the invariant was derived from."""
    investigation_id: str
    source_agents: List[str] = Field(
        default=[],
        description="Agent names that contributed findings used to derive this invariant",
    )
    root_cause_cwe: Optional[str] = Field(
        default=None,
        description="CWE identifier that anchors this invariant",
    )
    derived_at: datetime = Field(default_factory=utc_now)


class SecurityInvariant(BaseModel):
    """
    Machine-readable Security Invariant for a SECUREFIX investigation.

    Represents WHAT must always be true about the system — independent of
    implementation details.  The invariant is the source of truth for:

    * executable security oracle verification
    * legitimate-use contract testing
    * adversarial variant generation (Phase 2)
    * controlled security patch mutation testing (Phase 3)
    * evidence bundle assembly

    Instance values (specific users, account IDs, route examples) are
    carried in AttackScenario and LegitimateUseCase as *scenario data*,
    never as global assumptions.  The invariant abstraction itself is
    repository-agnostic.
    """
    id: str = Field(
        default_factory=lambda: f"INV-{str(uuid.uuid4())[:8].upper()}",
        description="Stable identifier for this invariant instance",
    )
    vulnerability_class: VulnerabilityClass = Field(
        description="Canonical vulnerability class",
    )
    cwe: Optional[str] = Field(
        default=None,
        description="CWE identifier (e.g. 'CWE-639')",
    )
    statement: str = Field(
        description=(
            "Human-readable invariant statement expressing the security property "
            "in terms of roles, not specific users.  "
            "Example: 'An authenticated user may only access resources they own.'"
        ),
    )
    scope: InvariantScope = Field(default_factory=InvariantScope)
    attack: AttackScenario = Field(default_factory=AttackScenario)
    oracle: SecurityOracle = Field(default_factory=SecurityOracle)
    legitimate_use: List[LegitimateUseCase] = Field(
        default=[],
        description="One or more legitimate-use cases that must remain functional after a fix",
    )
    provenance: Optional[InvariantProvenance] = None
    limitations: str = Field(
        default="",
        description=(
            "Known limitations of this invariant — e.g. which scenarios it does NOT cover, "
            "which attack variants require separate invariants, and what context was unavailable."
        ),
    )
    supported: bool = Field(
        default=True,
        description=(
            "False when the vulnerability class does not yet have enough structured context "
            "to produce a meaningful invariant.  When False, the other fields may be sparse."
        ),
    )
    unsupported_reason: Optional[str] = Field(
        default=None,
        description="When supported=False, explains why a full invariant could not be derived.",
    )


# ── Adversarial Variants (Phase 3) ────────────────────────────────────────────

class VariantType(str, Enum):
    """
    Bounded set of variant dimensions that the VariantGenerator can produce.

    ORIGINAL_ATTACK   — the attack scenario from the invariant itself (baseline)
    IDENTITY          — same route, different actor (alternate non-owner, etc.)
    IDENTIFIER        — same route/actor, different resource identifier
    SIBLING_ROUTE     — related route discovered from repository API metadata
    REQUEST_VARIANT   — alternate request representation (safe mutations only)
    """
    ORIGINAL_ATTACK = "original_attack"
    IDENTITY        = "identity"
    IDENTIFIER      = "identifier"
    SIBLING_ROUTE   = "sibling_route"
    REQUEST_VARIANT = "request_variant"


class VariantProvenance(BaseModel):
    """
    Records exactly why a variant was generated.

    source        — where the generating information came from
                    (e.g. 'security_invariant', 'repository_api_routes',
                     'identity_dimension', 'identifier_dimension')
    parent_route  — the invariant's primary attack route, when the variant
                    is derived from it
    reason        — human-readable explanation of the derivation step
    invariant_id  — the SecurityInvariant.id that anchors this variant
    """
    source: str = Field(description="Origin of the generating information")
    parent_route: str = Field(
        default="",
        description="Primary route from which this variant was derived",
    )
    reason: str = Field(description="Why this variant was generated")
    invariant_id: str = Field(description="ID of the source SecurityInvariant")


class AdversarialVariant(BaseModel):
    """
    One bounded, provenance-rich verification scenario derived from a SecurityInvariant.

    Every field must be traceable to:
        SecurityInvariant → VariantGenerator → AdversarialVariant → VerificationEngine result

    Credentials are NEVER stored here.  They must be resolved at execution time
    from the SecurityInvariant that is passed alongside the variant to the
    VerificationEngine.

    The variant carries:
    - invariant-derived information (source_invariant_id, expected_oracle)
    - scenario-specific values (actor, target, route, method)
    - the generated mutation/variation (variant_type + description)
    - expected verification behaviour (expected_oracle label)
    - provenance (why it exists)
    - limitations (what it does NOT test)
    """
    variant_id: str = Field(
        default_factory=lambda: f"VAR-{str(uuid.uuid4())[:8].upper()}",
        description="Stable identifier for this variant instance",
    )
    source_invariant_id: str = Field(
        description="ID of the SecurityInvariant this variant was derived from",
    )
    variant_type: VariantType = Field(
        description="Which generation dimension produced this variant",
    )
    description: str = Field(
        description="Human-readable explanation of what this variant tests",
    )
    # ── Request parameters ────────────────────────────────────────────────────
    actor_role: str = Field(
        default="",
        description=(
            "Role of the principal in this scenario (e.g. 'non_owner', "
            "'alternate_non_owner', 'resource_owner').  Never a literal username."
        ),
    )
    actor_credential_hint: str = Field(
        default="",
        description=(
            "Human-readable description of which credential set to use.  "
            "Literal credentials are NOT stored here — they must come from "
            "the SecurityInvariant's attack/legitimate_use scenario data."
        ),
    )
    route: str = Field(
        description="Concrete URL for this variant (scenario data)",
    )
    method: str = Field(
        default="GET",
        description="HTTP method (read-only by default; destructive methods require explicit justification)",
    )
    parameters: Dict[str, Any] = Field(
        default={},
        description="Additional scenario parameters (scenario data — not global assumptions)",
    )
    # ── Oracle ────────────────────────────────────────────────────────────────
    expected_oracle: Optional["OracleExpectedOutcome"] = Field(
        default=None,
        description=(
            "Expected oracle outcome for this variant.  "
            "Derived from SecurityInvariant.oracle — never fabricated by the generator."
        ),
    )
    expected_oracle_label: str = Field(
        default="",
        description="Label of the expected oracle outcome (e.g. 'attack_blocked')",
    )
    # ── Provenance ────────────────────────────────────────────────────────────
    provenance: VariantProvenance = Field(
        description="Traceability record — why this variant was generated",
    )
    # ── Metadata ──────────────────────────────────────────────────────────────
    limitations: str = Field(
        default="",
        description="What this variant does NOT test or where its coverage ends",
    )
    supported: bool = Field(
        default=True,
        description="False when the variant cannot be safely executed",
    )
    unsupported_reason: Optional[str] = Field(
        default=None,
        description="When supported=False, explains why execution was skipped",
    )


class VariantGenerationResult(BaseModel):
    """
    The complete output of VariantGenerator.generate().

    Carries all produced variants plus generation metadata for auditability.
    """
    source_invariant_id: str = Field(
        description="ID of the SecurityInvariant used as the generation source",
    )
    variants: List["AdversarialVariant"] = Field(
        default=[],
        description="Generated variants (supported and unsupported)",
    )
    supported_count: int = Field(
        default=0,
        description="Number of variants that can be executed (supported=True)",
    )
    skipped_count: int = Field(
        default=0,
        description="Number of variants that were skipped (supported=False)",
    )
    skipped_reasons: List[str] = Field(
        default=[],
        description="Reasons why variants were skipped (for audit trail)",
    )
    unsupported_dimensions: List[str] = Field(
        default=[],
        description=(
            "Variant dimensions that the generator chose not to produce for "
            "this particular invariant (e.g. 'identifier — no numeric ID in route')"
        ),
    )
    generation_note: str = Field(
        default="",
        description="Free-text note about the generation context",
    )


# ── Mutation Testing (Phase 4) ────────────────────────────────────────────────

class MutationType(str, Enum):
    """
    Allowlisted mutation types for controlled security-patch mutation testing.

    Only these four types are supported in Phase 4.
    No arbitrary mutations are permitted.

    REMOVE_OWNERSHIP_CHECK      — removes the ownership authorization check
                                  Expected: adversarial variant detects BYPASS
    INVERT_OWNERSHIP_COMPARISON — inverts the ownership comparison (wrong direction)
                                  Expected: security or legitimate-use dimension detects it
    SIBLING_ROUTE_UNPROTECTED   — primary route is protected; sibling route is not
                                  Expected: sibling-route variant detects BYPASS
    UNCONDITIONAL_DENIAL        — endpoint denies all requests including owner
                                  Expected: legitimate-use check detects regression
    """
    REMOVE_OWNERSHIP_CHECK      = "remove_ownership_check"
    INVERT_OWNERSHIP_COMPARISON = "invert_ownership_comparison"
    SIBLING_ROUTE_UNPROTECTED   = "sibling_route_unprotected"
    UNCONDITIONAL_DENIAL        = "unconditional_denial"


class MutationExecutionStatus(str, Enum):
    """Execution lifecycle status of a mutation trial."""
    PENDING     = "pending"
    APPLIED     = "applied"
    EXECUTED    = "executed"
    CLEANED_UP  = "cleaned_up"
    ERROR       = "error"
    UNSUPPORTED = "unsupported"


class MutationDetectionState(str, Enum):
    """
    Outcome classification for a mutation trial.

    DETECTED    — at least one assurance dimension identified the faulty patch
    SURVIVED    — all verification checks passed; faulty patch was not detected
    ERROR       — execution error (crash, timeout, env failure, mutation not applied)
    UNSUPPORTED — mutation target not found or mutation not applicable
    """
    DETECTED    = "detected"
    SURVIVED    = "survived"
    ERROR       = "error"
    UNSUPPORTED = "unsupported"


class SecurityMutant(BaseModel):
    """
    A single controlled security-patch mutation trial definition.

    Records what mutation to apply and to which isolated copy.

    SAFETY: Must never store credentials, arbitrary shell commands, or
    absolute filesystem paths outside the isolated copy.
    """
    mutant_id: str = Field(
        default_factory=lambda: f"MUT-{str(uuid.uuid4())[:8].upper()}",
        description="Stable identifier for this mutation trial",
    )
    mutation_type: MutationType = Field(
        description="Allowlisted mutation type applied in this trial",
    )
    description: str = Field(
        description="Human-readable explanation of what this mutation does",
    )
    source_finding: str = Field(
        default="",
        description="Description of the security finding that motivates this mutant",
    )
    source_invariant_id: str = Field(
        default="",
        description="SecurityInvariant.id that this mutant tests against",
    )
    affected_file: str = Field(
        default="",
        description=(
            "Repository-relative path of the file being mutated.  "
            "Path is relative to the isolated copy root — not an absolute path."
        ),
    )
    mutation_metadata: Dict[str, Any] = Field(
        default={},
        description=(
            "Mutation-specific metadata (e.g. which code pattern was targeted).  "
            "Must not contain credentials, shell commands, or absolute paths."
        ),
    )
    isolation_reference: str = Field(
        default="",
        description=(
            "Sanitized reference to the isolated copy (e.g. a hash or temp dir name).  "
            "Not the full absolute filesystem path."
        ),
    )
    expected_detection: Dict[str, str] = Field(
        default={},
        description=(
            "Expected detection per assurance dimension: "
            "{'security_resistance': 'bypass', 'legitimate_behavior': 'pass', "
            "'verification_sensitivity': 'detected'}"
        ),
    )


class MutationAssuranceDimension(BaseModel):
    """Result for one assurance dimension within a MutationResult."""
    dimension: str = Field(
        description="'security_resistance' | 'legitimate_behavior' | 'verification_sensitivity'",
    )
    outcome: ExploitCheckOutcome = Field(description="PASS / BYPASS / ERROR / UNSUPPORTED")
    detail: str = Field(default="", description="Human-readable explanation")
    check_names: List[str] = Field(
        default=[],
        description="Which VerificationCheck names contributed to this dimension",
    )


class MutationResult(BaseModel):
    """
    Complete outcome of executing one SecurityMutant trial.

    Records all three assurance dimensions separately.
    Must never be collapsed into a single score.
    """
    mutant_id: str = Field(description="ID of the SecurityMutant that was executed")
    mutation_type: MutationType = Field(description="Mutation type that was applied")
    execution_status: MutationExecutionStatus = Field(
        default=MutationExecutionStatus.PENDING,
        description="Lifecycle status of this trial",
    )
    detected: bool = Field(
        default=False,
        description="True when at least one assurance dimension identified the faulty patch",
    )
    detection_state: MutationDetectionState = Field(
        default=MutationDetectionState.UNSUPPORTED,
        description="DETECTED | SURVIVED | ERROR | UNSUPPORTED",
    )
    # ── Three assurance dimensions (never collapsed) ──────────────────────────
    security_resistance: Optional["MutationAssuranceDimension"] = Field(
        default=None,
        description="Does the faulty patch still resist the adversarial attack?",
    )
    legitimate_behavior: Optional["MutationAssuranceDimension"] = Field(
        default=None,
        description="Does the faulty patch still allow legitimate owner access?",
    )
    verification_sensitivity: Optional["MutationAssuranceDimension"] = Field(
        default=None,
        description="Did the verification suite detect the faulty patch?",
    )
    # ── Evidence ──────────────────────────────────────────────────────────────
    verification_checks: List["VerificationCheck"] = Field(
        default=[],
        description="Verification checks executed against this mutant",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message when execution_status=ERROR",
    )
    evidence: Dict[str, Any] = Field(
        default={},
        description="Sanitized evidence record (no credentials, no absolute paths)",
    )
    timestamp: datetime = Field(default_factory=utc_now)
    cleanup_completed: bool = Field(
        default=False,
        description="True when the isolated copy was successfully destroyed",
    )
    survived_detail: Optional[str] = Field(
        default=None,
        description=(
            "When detection_state=SURVIVED: which check was expected to detect "
            "the mutant but did not, and which assurance dimension is affected."
        ),
    )


class MutationAssessment(BaseModel):
    """
    Aggregate assessment of all mutation trials for one investigation.

    Does NOT produce a single security score.
    Reports each dimension separately.
    """
    investigation_id: str
    invariant_id: str = Field(default="")
    total_mutants: int = Field(default=0)
    detected_count: int = Field(default=0)
    survived_count: int = Field(default=0)
    error_count: int = Field(default=0)
    unsupported_count: int = Field(default=0)
    results: List["MutationResult"] = Field(default=[])
    assessment_note: str = Field(
        default="",
        description=(
            "Narrative summary.  Must not claim 'complete security assurance' "
            "or '100% coverage'."
        ),
    )
    scope_limitations: List[str] = Field(
        default=[],
        description="Explicit list of what this assessment does NOT cover",
    )
    timestamp: datetime = Field(default_factory=utc_now)


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
    status: str = ""    # passed | failed | skipped  (legacy — kept for backward compat)
    detail: str = ""
    # ── Phase 2: structured oracle evidence ──────────────────────────────────
    outcome: Optional[ExploitCheckOutcome] = Field(
        default=None,
        description=(
            "Structured oracle outcome.  None means this check does not use the "
            "oracle (e.g. pytest runner or static scan)."
        ),
    )
    route: str = Field(default="", description="Route exercised in this check")
    http_method: str = Field(default="", description="HTTP method used")
    observed_status_code: Optional[int] = Field(
        default=None, description="HTTP status code returned by the application"
    )
    expected_outcome_label: str = Field(
        default="", description="Label of the oracle outcome that was expected"
    )
    response_evidence: str = Field(
        default="",
        description="Sanitized/truncated response evidence (no credentials)",
    )
    execution_error: Optional[str] = Field(
        default=None,
        description="Exception message when outcome==ERROR; None otherwise",
    )

    def set_outcome_fields(
        self,
        outcome: ExploitCheckOutcome,
        route: str = "",
        http_method: str = "",
        observed_status_code: Optional[int] = None,
        expected_outcome_label: str = "",
        response_evidence: str = "",
        execution_error: Optional[str] = None,
    ) -> None:
        """
        Convenience mutator that sets all oracle evidence fields and keeps the
        legacy `status` string in sync.
        """
        self.outcome = outcome
        self.route = route
        self.http_method = http_method
        self.observed_status_code = observed_status_code
        self.expected_outcome_label = expected_outcome_label
        self.response_evidence = response_evidence
        self.execution_error = execution_error
        # Sync legacy status
        if outcome == ExploitCheckOutcome.PASS:
            self.status = "passed"
        elif outcome == ExploitCheckOutcome.BYPASS:
            self.status = "failed"
        elif outcome == ExploitCheckOutcome.UNSUPPORTED:
            self.status = "skipped"
        else:  # ERROR
            self.status = "failed"


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
    technology_profile: Optional["TechnologyProfile"] = None   # derived by RepositoryAgent
    agent_results: Dict[str, AgentResult] = {}
    correlation: Optional[CorrelationResult] = None
    root_cause: Optional[RootCauseAnalysis] = None
    security_invariant: Optional[SecurityInvariant] = None
    remediation: Optional[RemediationProposal] = None
    verification: Optional[VerificationResult] = None
    ai_reasoning: Optional[Dict[str, Any]] = None
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

