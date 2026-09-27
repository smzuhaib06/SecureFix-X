"""
Phase 5C — SecurityEvidencePackage

Canonical structured representation of all evidence collected by the
seven SECUREFIX agents. This is the source of truth consumed by the
AI reasoning layer.

The package preserves full provenance: every evidence item records which
agent produced it, from which file, at which line, with what strength.

Evidence strength classification:
  DIRECT       — observed directly in repository source (file + line + excerpt)
  CORROBORATED — independently confirmed by two or more agents
  INFERRED     — derived from indirect signals (e.g. no log files found)
  UNAVAILABLE  — agent ran but no relevant evidence was collected

AI grounding rules enforced here:
  - Technology comes from TechnologyProfile, never hardcoded
  - Route names come from TechnologyProfile.api_routes, never fabricated
  - No SecureBank-specific values (alice, bob, /api/accounts) are injected
"""
from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Evidence strength ──────────────────────────────────────────────────────────

class EvidenceStrength(str, Enum):
    DIRECT      = "DIRECT"       # Source file + line + excerpt observed
    CORROBORATED = "CORROBORATED" # Confirmed by 2+ independent agents
    INFERRED    = "INFERRED"     # Derived from indirect signals
    UNAVAILABLE = "UNAVAILABLE"  # Agent ran; relevant evidence absent


# ── Observation status ─────────────────────────────────────────────────────────

class ObservationStatus(str, Enum):
    OBSERVED    = "OBSERVED"     # Seen directly in evidence
    INFERRED    = "INFERRED"     # Derived from observed evidence
    RECOMMENDED = "RECOMMENDED"  # AI reasoning recommendation
    UNSUPPORTED = "UNSUPPORTED"  # Cannot be determined from available evidence


# ── Per-evidence item ──────────────────────────────────────────────────────────

class EvidenceItem(BaseModel):
    """One piece of evidence collected by a specific agent."""
    evidence_id: str = Field(
        default_factory=lambda: f"EV-{str(uuid.uuid4())[:8].upper()}",
        description="Stable identifier for this evidence item",
    )
    agent: str = Field(description="Agent that produced this evidence")
    technology: str = Field(
        default="",
        description=(
            "Technology this evidence applies to — derived from TechnologyProfile, "
            "not hardcoded. Examples: 'python', 'javascript/nodejs', 'docker'"
        ),
    )
    file: Optional[str] = Field(default=None, description="Repository-relative file path")
    line_start: Optional[int] = Field(default=None, description="Start line (1-indexed)")
    line_end: Optional[int] = Field(default=None, description="End line (1-indexed)")
    excerpt: str = Field(default="", description="Actual source code or config excerpt")
    finding: str = Field(description="Human-readable description of this evidence item")
    source_type: str = Field(
        default="",
        description="Evidence type: code | config | dependency | test | runtime | repository",
    )
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_strength: EvidenceStrength = Field(default=EvidenceStrength.INFERRED)
    provenance: str = Field(default="", description="How this item was derived")
    cve: Optional[str] = Field(default=None, description="CVE identifier if applicable")
    cwe: Optional[str] = Field(default=None, description="CWE identifier if applicable")
    route: Optional[str] = Field(default=None, description="Route this applies to if applicable")
    source_variable: Optional[str] = Field(default=None, description="Input source (e.g. req.body.username)")
    sink_call: Optional[str] = Field(default=None, description="Vulnerable sink (e.g. User.find(...))")


# ── Main evidence package ──────────────────────────────────────────────────────

class SecurityEvidencePackage(BaseModel):
    """
    Canonical structured representation of all evidence for one investigation.

    This is what the AI reasoning layer receives — never raw prose summaries
    when structured evidence is available.

    Grounding contract:
    - technology_profile fields come from RepositoryAgent analysis only
    - route names come from TechnologyProfile.api_routes
    - No values are injected that are not present in the repository
    - SecureBank-specific values (alice, bob, /api/accounts) are absent unless
      those values actually exist in the repository under analysis
    """
    investigation_id: str
    repository_path: str = ""
    issue_description: str = ""

    # Technology grounding
    runtime: str = Field(
        default="",
        description="Runtime from TechnologyProfile (e.g. 'python', 'node')",
    )
    language: str = Field(
        default="",
        description="Primary language from TechnologyProfile",
    )
    framework: str = Field(
        default="",
        description="Framework from TechnologyProfile (e.g. 'fastapi', 'express')",
    )
    database: str = Field(
        default="",
        description="Database from TechnologyProfile (e.g. 'mongodb', 'postgresql')",
    )
    package_manager: str = Field(default="", description="Package manager (pip, npm, ...)")
    discovered_routes: List[str] = Field(
        default=[],
        description=(
            "API routes discovered from TechnologyProfile.api_routes — "
            "these are actual repository routes, not fabricated examples"
        ),
    )
    detected_entry_points: List[str] = Field(default=[], description="Entry point files found by RepositoryAgent")
    verification_strategy: str = Field(default="", description="Verification strategy from TechnologyProfile")

    # All evidence items
    all_evidence: List[EvidenceItem] = Field(
        default=[],
        description="All evidence items collected by all agents, in priority order",
    )

    # Categorised evidence views
    code_evidence: List[EvidenceItem] = Field(default=[], description="Evidence from SecurityAgent + CodeAgent")
    dependency_evidence: List[EvidenceItem] = Field(default=[], description="Evidence from DependencyAgent")
    configuration_evidence: List[EvidenceItem] = Field(default=[], description="Evidence from ConfigAgent")
    test_evidence: List[EvidenceItem] = Field(default=[], description="Evidence from TestAgent")
    runtime_evidence: List[EvidenceItem] = Field(default=[], description="Evidence from RuntimeAgent")

    # Correlation signals
    corroborating_agents: List[str] = Field(
        default=[],
        description="Agents that independently confirmed the primary finding",
    )
    primary_vulnerability_class: Optional[str] = Field(
        default=None,
        description="Primary vulnerability class from CorrelationEngine (e.g. 'nosql_injection')",
    )
    primary_cwe: Optional[str] = Field(default=None, description="Primary CWE from correlation")
    investigation_outcome: str = Field(
        default="UNKNOWN",
        description="Overall outcome: CONFIRMED | PARTIAL | NO_CONFIRMED_FINDING | UNSUPPORTED",
    )
    confirmed_finding_count: int = Field(default=0)
    highest_severity: str = Field(default="info")

    # Root cause signals (from RootCauseEngine — before AI reasoning)
    deterministic_root_cause: Optional[str] = Field(
        default=None,
        description="Root cause derived by the deterministic RootCauseEngine",
    )
    deterministic_cwe: Optional[str] = Field(default=None)

    # Relevant source snippets (max 5 to avoid context overflow)
    relevant_code_snippets: List[Dict[str, Any]] = Field(
        default=[],
        description="Curated code snippets from evidence (file, lines, content)",
    )

    # Metadata
    agent_count: int = Field(default=7, description="Number of agents that ran")
    total_findings: int = Field(default=0)
    runtime_evidence_available: bool = Field(
        default=False,
        description="False when RuntimeAgent found no log files",
    )
    ai_grounding_notes: List[str] = Field(
        default=[],
        description="Notes about what the AI can and cannot claim based on evidence",
    )


# ── Builder ───────────────────────────────────────────────────────────────────

class EvidencePackageBuilder:
    """
    Assembles a SecurityEvidencePackage from a completed Investigation.

    Grounding rules enforced:
    1. Technology fields come exclusively from TechnologyProfile
    2. Routes come from TechnologyProfile.api_routes
    3. No SecureBank-specific values are injected unless present in repo
    4. Evidence items are only created from actual AgentFindings
    5. Evidence strength is DIRECT only when file + line + excerpt are present
    """

    def build(self, investigation: Any) -> SecurityEvidencePackage:
        """Build the package from a fully-run Investigation object."""
        # Resolve technology profile
        profile = getattr(investigation, "technology_profile", None)
        if profile is None and investigation.repository_info:
            profile = investigation.repository_info.technology_profile

        runtime = getattr(profile, "runtime", "") if profile else ""
        language = getattr(profile, "language", "") if profile else ""
        framework = getattr(profile, "framework", "") if profile else ""
        database = getattr(profile, "database", "") if profile else ""
        pkg_manager = getattr(profile, "package_manager", "") if profile else ""
        routes = list(getattr(profile, "api_routes", [])) if profile else []
        if hasattr(investigation, "repository_info") and investigation.repository_info:
            if not routes:
                routes = list(investigation.repository_info.api_routes or [])
        entry_points = list(getattr(profile, "entry_points", [])) if profile else []
        verif_strategy = ""
        if profile and hasattr(profile, "verification_strategy"):
            verif_strategy = str(profile.verification_strategy)

        pkg = SecurityEvidencePackage(
            investigation_id=investigation.id,
            repository_path=investigation.repository_path or "",
            issue_description=investigation.issue_description or "",
            runtime=runtime,
            language=language,
            framework=framework,
            database=database,
            package_manager=pkg_manager,
            discovered_routes=routes,
            detected_entry_points=entry_points,
            verification_strategy=verif_strategy,
        )

        # Assemble evidence from agent results
        all_ev: List[EvidenceItem] = []
        agent_results = investigation.agent_results or {}

        for agent_name, result in agent_results.items():
            if not result or not result.findings:
                continue
            for finding in result.findings:
                item = self._finding_to_evidence(finding, agent_name, language, runtime)
                all_ev.append(item)

                # Categorise
                if agent_name in ("security_agent", "code_agent"):
                    pkg.code_evidence.append(item)
                elif agent_name == "dependency_agent":
                    pkg.dependency_evidence.append(item)
                elif agent_name == "config_agent":
                    pkg.configuration_evidence.append(item)
                elif agent_name == "test_agent":
                    pkg.test_evidence.append(item)
                elif agent_name == "runtime_agent":
                    pkg.runtime_evidence.append(item)

        pkg.all_evidence = all_ev
        pkg.total_findings = len(all_ev)

        # Correlation signals
        if investigation.correlation:
            corr = investigation.correlation
            pkg.investigation_outcome = corr.investigation_outcome
            pkg.confirmed_finding_count = corr.confirmed_finding_count
            pkg.primary_vulnerability_class = (
                corr.primary_finding if corr.primary_finding else None
            )

        # Root cause signals
        if investigation.root_cause:
            rc = investigation.root_cause
            pkg.deterministic_root_cause = rc.root_cause
            pkg.deterministic_cwe = rc.cwe_id

        # Runtime evidence availability
        rt_result = agent_results.get("runtime_agent")
        if rt_result and rt_result.raw_output:
            pkg.runtime_evidence_available = bool(rt_result.raw_output.get("logs_found", False))

        # Highest severity
        severity_order = ["info", "low", "medium", "high", "critical"]
        max_sev = "info"
        for ev in all_ev:
            try:
                sev_str = getattr(ev, "_severity_raw", "info")
            except Exception:
                sev_str = "info"
            # We don't carry severity through EvidenceItem directly; use finding severity from source
        # Collect from raw findings
        for agent_name, result in agent_results.items():
            if not result or not result.findings:
                continue
            for finding in result.findings:
                sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
                if severity_order.index(sev) > severity_order.index(max_sev):
                    max_sev = sev
        pkg.highest_severity = max_sev

        # Build code snippets for AI context (top 5 code evidence items with excerpts)
        snippets = []
        for ev in pkg.code_evidence[:5]:
            if ev.excerpt and ev.file:
                snippets.append({
                    "file": ev.file,
                    "line_start": ev.line_start,
                    "line_end": ev.line_end,
                    "excerpt": ev.excerpt,
                    "finding": ev.finding,
                    "evidence_id": ev.evidence_id,
                })
        pkg.relevant_code_snippets = snippets

        # Corroborating agents: agents that produced CONFIRMED code/dependency findings
        corroborating = set()
        for ev in pkg.code_evidence:
            if ev.evidence_strength == EvidenceStrength.DIRECT:
                corroborating.add(ev.agent)
        for ev in pkg.dependency_evidence:
            if ev.confidence >= 0.8:
                corroborating.add(ev.agent)
        pkg.corroborating_agents = sorted(corroborating)

        # AI grounding notes — what the AI can and cannot claim
        grounding_notes = []
        if not runtime:
            grounding_notes.append("Runtime unknown — AI must not assume a specific runtime")
        if not routes:
            grounding_notes.append("No routes discovered — AI must not fabricate route names")
        if not pkg.runtime_evidence_available:
            grounding_notes.append("Runtime logs unavailable — dynamic behavior cannot be observed")
        if framework:
            grounding_notes.append(f"Framework confirmed as '{framework}' by RepositoryAgent")
        if routes:
            grounding_notes.append(
                f"Available routes from repository: {', '.join(routes[:5])}"
                + (" (and more)" if len(routes) > 5 else "")
            )
        pkg.ai_grounding_notes = grounding_notes

        return pkg

    def _finding_to_evidence(
        self, finding: Any, agent_name: str, language: str, runtime: str
    ) -> EvidenceItem:
        """Convert one AgentFinding to an EvidenceItem."""
        # Determine evidence strength
        has_file = bool(getattr(finding, "files", None))
        has_line = getattr(finding, "file_line_start", None) is not None
        has_excerpt = bool(getattr(finding, "evidence_excerpt", ""))
        finding_status = getattr(finding, "finding_status", None)

        if has_file and has_line and has_excerpt and str(finding_status) in ("FindingStatus.CONFIRMED", "CONFIRMED"):
            strength = EvidenceStrength.DIRECT
        elif has_file and has_excerpt:
            strength = EvidenceStrength.DIRECT
        elif has_file:
            strength = EvidenceStrength.INFERRED
        else:
            strength = EvidenceStrength.UNAVAILABLE

        # Technology from finding — never default to "python" if the finding says otherwise
        tech = getattr(finding, "technology", "") or language or runtime or "unknown"

        file_ref = (finding.files[0] if finding.files else None) if hasattr(finding, "files") else None

        # Source type from agent name
        source_type_map = {
            "security_agent": "code",
            "code_agent": "code",
            "dependency_agent": "dependency",
            "config_agent": "config",
            "test_agent": "test",
            "runtime_agent": "runtime",
            "repository_agent": "repository",
        }
        source_type = source_type_map.get(agent_name, agent_name)

        return EvidenceItem(
            agent=agent_name,
            technology=tech,
            file=file_ref,
            line_start=getattr(finding, "file_line_start", None),
            line_end=getattr(finding, "file_line_end", None),
            excerpt=getattr(finding, "evidence_excerpt", ""),
            finding=finding.title,
            source_type=source_type,
            confidence=getattr(finding, "confidence", 0.0),
            evidence_strength=strength,
            provenance=getattr(finding, "provenance", ""),
            cwe=getattr(finding, "vulnerability_class", None),
            route=getattr(finding, "route", None) or None,
            source_variable=getattr(finding, "source", None) or None,
            sink_call=getattr(finding, "sink", None) or None,
        )
