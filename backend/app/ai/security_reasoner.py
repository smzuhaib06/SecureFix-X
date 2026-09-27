"""
Phase 5F/5H — AI Security Reasoner

The AI reasoning layer sits between the deterministic evidence pipeline and
the deterministic verification engine.

Architecture:
  EvidencePackage + RAG passages
          ↓
  AISecurityReasoner
          ↓
  AIReasoningResult (structured Pydantic output)
          ↓
  Deterministic VerificationEngine (reasoning result informs, doesn't control)

Grounding rules (HARD):
  - The AI receives the full structured EvidencePackage — never only prose
  - The AI must NEVER fabricate evidence not present in the package
  - Every claim must be classified as OBSERVED, INFERRED, or RECOMMENDED
  - Deterministic findings always win when they conflict with AI reasoning
  - The AI must acknowledge evidence gaps (runtime_evidence_available=False, etc.)
  - SecureBank-specific values must not appear unless present in the repository
  - The output is always validated by AIGroundingValidator before use

Note: When no AI provider is configured, the reasoner runs in deterministic mode
(evidence summary only, no LLM inference). The system is fully functional without
an AI provider.
"""
from __future__ import annotations

import json
import re
import time
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.ai.evidence_package import (
    SecurityEvidencePackage,
    EvidenceStrength,
    ObservationStatus,
)
from app.ai.rag import RetrievedDocument, retrieve_for_investigation
from app.ai.provider import get_provider, BaseAIProvider


# ── Output models ──────────────────────────────────────────────────────────────

class ObservationStatus(str, Enum):  # noqa: F811
    OBSERVED    = "OBSERVED"
    INFERRED    = "INFERRED"
    RECOMMENDED = "RECOMMENDED"
    UNSUPPORTED = "UNSUPPORTED"


class GroundedClaim(BaseModel):
    """A single claim made by the AI, with its observation status."""
    claim: str = Field(description="The specific security claim")
    status: ObservationStatus = Field(
        description="OBSERVED (from evidence), INFERRED (reasoned), RECOMMENDED (suggestion)"
    )
    supporting_evidence_ids: List[str] = Field(
        default=[],
        description="Evidence item IDs from the EvidencePackage that support this claim",
    )
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    limitation: Optional[str] = Field(
        default=None,
        description="Known limitation of this claim — what evidence would strengthen it",
    )


class AttackPathStep(BaseModel):
    """One step in the reasoned attack path."""
    step: int
    description: str
    evidence_basis: str = ""          # which evidence supports this step
    observation_status: ObservationStatus = ObservationStatus.INFERRED


class RecommendedTest(BaseModel):
    """A specific test case the AI recommends writing."""
    title: str
    description: str
    test_type: str = ""               # unit | integration | security
    expected_assertion: str = ""
    rag_source: str = ""              # which knowledge document suggested this


class AIReasoningResult(BaseModel):
    """
    Structured output of the AI Security Reasoner.

    Every field is either:
    - Observed (directly present in evidence)
    - Inferred (reasoned from evidence)
    - Recommended (AI suggestion for investigation/remediation)

    This output is consumed by the UI and (indirectly) by the
    VerificationEngine. Deterministic verification results always
    override AI inference when they conflict.
    """
    investigation_id: str
    provider_used: str = ""
    model_used: str = ""
    reasoning_latency_ms: int = 0
    ran_in_deterministic_mode: bool = False

    # ── Vulnerability assessment ───────────────────────────────────────────────
    vulnerability_title: str = Field(default="", description="Concise title for the vulnerability")
    primary_cwe: Optional[str] = Field(default=None, description="Primary CWE from AI reasoning")
    primary_owasp: Optional[str] = Field(default=None, description="Closest OWASP category")
    severity_assessment: str = Field(
        default="",
        description="Severity assessment with explicit observation_status",
    )
    severity_observation_status: ObservationStatus = ObservationStatus.INFERRED

    # ── Root cause ─────────────────────────────────────────────────────────────
    root_cause_summary: str = Field(
        default="",
        description="Grounded root cause — must reference specific evidence",
    )
    root_cause_observation_status: ObservationStatus = ObservationStatus.INFERRED

    # ── Attack path ────────────────────────────────────────────────────────────
    attack_path: List[AttackPathStep] = Field(
        default=[],
        description="Step-by-step attack path with evidence basis for each step",
    )

    # ── Grounded claims ────────────────────────────────────────────────────────
    grounded_claims: List[GroundedClaim] = Field(
        default=[],
        description="All specific claims made, each with observation status",
    )

    # ── Remediation guidance ───────────────────────────────────────────────────
    primary_remediation: str = Field(
        default="",
        description="Primary fix recommendation",
    )
    remediation_code_example: str = Field(
        default="",
        description="Concrete code example for the fix (from knowledge base or evidence)",
    )

    # ── Test recommendations ───────────────────────────────────────────────────
    recommended_tests: List[RecommendedTest] = Field(
        default=[],
        description="Specific test cases to add, grounded in the evidence",
    )

    # ── Knowledge base citations ───────────────────────────────────────────────
    rag_citations: List[Dict[str, Any]] = Field(
        default=[],
        description="Knowledge documents retrieved and used in reasoning",
    )

    # ── Evidence gaps ──────────────────────────────────────────────────────────
    evidence_gaps: List[str] = Field(
        default=[],
        description="Evidence that is missing and would strengthen the analysis",
    )
    cannot_determine: List[str] = Field(
        default=[],
        description="Claims the AI explicitly cannot make due to insufficient evidence",
    )

    # ── Grounding metadata ─────────────────────────────────────────────────────
    grounding_confidence: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Overall confidence in AI output grounding (0=fully speculative, 1=all OBSERVED)",
    )
    evidence_sufficiency: str = Field(
        default="",
        description="SUFFICIENT | PARTIAL | INSUFFICIENT",
    )
    deterministic_override_applied: bool = Field(
        default=False,
        description="True when deterministic results corrected an AI inference",
    )
    deterministic_override_note: str = Field(default="")


# ── System instruction ─────────────────────────────────────────────────────────

_SYSTEM_INSTRUCTION = """You are a security analysis assistant for the SECUREFIX vulnerability investigation system.

GROUNDING RULES (MANDATORY — non-negotiable):
1. Base every claim on the structured evidence provided. Never fabricate evidence.
2. Label each claim: OBSERVED (seen in evidence), INFERRED (reasoned), or RECOMMENDED (suggestion).
3. Do NOT convert an inference into an observed fact. If you have not seen it, say so.
4. When the evidence package shows runtime_evidence_available=false, do NOT make claims about runtime behavior.
5. If no routes are discovered, do NOT invent example route paths.
6. Technology is fixed: use only what the TechnologyProfile says.
7. Do NOT include SecureBank-specific values (alice, bob, /api/accounts, FastAPI TestClient) unless those values appear in the evidence.
8. The deterministic SECUREFIX pipeline is authoritative. Your role is to reason over evidence, not to replace the pipeline.
9. Acknowledge all evidence gaps explicitly in evidence_gaps.
10. If you cannot determine something from the evidence, list it in cannot_determine.

OUTPUT FORMAT: Return valid JSON matching the AIReasoningResult schema. No markdown code fences.
No prose before or after the JSON. Structure all output within the JSON fields."""


# ── Prompt builder ─────────────────────────────────────────────────────────────

def _build_reasoning_prompt(
    pkg: SecurityEvidencePackage,
    rag_docs: List[RetrievedDocument],
) -> str:
    """Build the structured reasoning prompt from evidence package + RAG passages."""

    # Technology context
    tech_ctx = f"""TECHNOLOGY PROFILE (from RepositoryAgent — authoritative):
Runtime: {pkg.runtime or 'UNKNOWN'}
Language: {pkg.language or 'UNKNOWN'}
Framework: {pkg.framework or 'UNKNOWN'}
Database: {pkg.database or 'UNKNOWN'}
Package Manager: {pkg.package_manager or 'UNKNOWN'}
Discovered Routes: {', '.join(pkg.discovered_routes) if pkg.discovered_routes else 'NONE DISCOVERED'}
Entry Points: {', '.join(pkg.detected_entry_points) if pkg.detected_entry_points else 'NONE DISCOVERED'}
Verification Strategy: {pkg.verification_strategy or 'NONE'}"""

    # Issue context
    issue_ctx = f"""REPORTED ISSUE:
{pkg.issue_description}"""

    # Evidence summary
    ev_lines = []
    for ev in pkg.all_evidence[:30]:
        strength = ev.evidence_strength.value if hasattr(ev.evidence_strength, "value") else str(ev.evidence_strength)
        ev_lines.append(
            f"  [{ev.agent}] [{strength}] {ev.finding}"
            + (f" (file: {ev.file}:{ev.line_start})" if ev.file and ev.line_start else "")
            + (f" excerpt: {ev.excerpt[:80]}" if ev.excerpt else "")
            + (f" [source: {ev.source_variable}]" if ev.source_variable else "")
            + (f" [sink: {ev.sink_call}]" if ev.sink_call else "")
        )

    evidence_ctx = f"""COLLECTED EVIDENCE ({len(pkg.all_evidence)} items):
{chr(10).join(ev_lines) if ev_lines else '  No confirmed evidence collected.'}"""

    # Code snippets
    snippets_ctx = ""
    if pkg.relevant_code_snippets:
        snippets_ctx = "\nRELEVANT CODE SNIPPETS (from evidence):\n"
        for s in pkg.relevant_code_snippets[:3]:
            snippets_ctx += (
                f"  File: {s['file']}:{s.get('line_start', '?')}\n"
                f"  Excerpt: {s['excerpt'][:200]}\n"
                f"  Finding: {s['finding']}\n\n"
            )

    # Deterministic results
    det_ctx = f"""DETERMINISTIC PIPELINE RESULTS (authoritative — do not contradict):
Investigation outcome: {pkg.investigation_outcome}
Confirmed findings: {pkg.confirmed_finding_count}
Highest severity: {pkg.highest_severity}
Root cause (deterministic): {pkg.deterministic_root_cause or 'Not determined'}
Primary CWE (deterministic): {pkg.deterministic_cwe or 'Not determined'}
Primary vulnerability class: {pkg.primary_vulnerability_class or 'Not determined'}
Runtime logs available: {pkg.runtime_evidence_available}"""

    # Grounding notes
    grounding_ctx = f"""GROUNDING CONSTRAINTS:
{chr(10).join('  - ' + n for n in pkg.ai_grounding_notes) if pkg.ai_grounding_notes else '  None'}"""

    # RAG passages
    rag_ctx = ""
    if rag_docs:
        rag_ctx = "\nKNOWLEDGE BASE (curated — use for explanations and remediation guidance):\n"
        for rd in rag_docs:
            doc = rd.document
            rag_ctx += (
                f"  [{doc.identifier}] {doc.title} — {doc.section} (score: {rd.score:.3f})\n"
                f"  {doc.content[:500]}\n\n"
            )

    # Output schema hint
    schema_hint = """OUTPUT SCHEMA (return valid JSON matching this structure):
{
  "vulnerability_title": "...",
  "primary_cwe": "CWE-...",
  "primary_owasp": "OWASP-A0X-2021",
  "severity_assessment": "...",
  "severity_observation_status": "OBSERVED|INFERRED",
  "root_cause_summary": "...",
  "root_cause_observation_status": "OBSERVED|INFERRED",
  "attack_path": [
    {"step": 1, "description": "...", "evidence_basis": "...", "observation_status": "OBSERVED|INFERRED"}
  ],
  "grounded_claims": [
    {"claim": "...", "status": "OBSERVED|INFERRED|RECOMMENDED", "confidence": 0.0, "limitation": "..."}
  ],
  "primary_remediation": "...",
  "remediation_code_example": "...",
  "recommended_tests": [
    {"title": "...", "description": "...", "test_type": "...", "expected_assertion": "..."}
  ],
  "rag_citations": [{"identifier": "...", "title": "...", "section": "..."}],
  "evidence_gaps": ["..."],
  "cannot_determine": ["..."],
  "grounding_confidence": 0.0,
  "evidence_sufficiency": "SUFFICIENT|PARTIAL|INSUFFICIENT"
}"""

    return "\n\n".join(filter(None, [
        tech_ctx, issue_ctx, evidence_ctx, snippets_ctx, det_ctx,
        grounding_ctx, rag_ctx, schema_hint,
    ]))


# ── Grounding validator ────────────────────────────────────────────────────────

class AIGroundingValidator:
    """
    Post-generation grounding validator.

    Verifies that AI output does not violate grounding rules.
    Applies corrections when deterministic results conflict with AI inference.
    """

    FORBIDDEN_NAMES = {
        "alice", "bob", "charlie", "alice123", "bob456",
        "testclient", "fasttestclient",
    }
    FORBIDDEN_IMPORTS = {"fastapi.testclient", "app.main", "securebank"}

    def validate_and_correct(
        self,
        result: AIReasoningResult,
        pkg: SecurityEvidencePackage,
    ) -> AIReasoningResult:
        """Validate and correct AI output against the evidence package."""
        overrides: List[str] = []

        # Rule 1: Deterministic CWE overrides AI CWE when they conflict, or populates if missing
        if pkg.deterministic_cwe:
            if not result.primary_cwe:
                result.primary_cwe = pkg.deterministic_cwe
            elif result.primary_cwe != pkg.deterministic_cwe:
                overrides.append(
                    f"AI CWE '{result.primary_cwe}' overridden by deterministic CWE '{pkg.deterministic_cwe}'"
                )
                result.primary_cwe = pkg.deterministic_cwe
                result.deterministic_override_applied = True

        # Rule 2: Forbid SecureBank-specific values unless in repo evidence
        repo_context = (
            pkg.issue_description.lower() + " "
            + pkg.repository_path.lower() + " "
            + " ".join(pkg.discovered_routes).lower()
        )
        for forbidden in self.FORBIDDEN_NAMES:
            if forbidden not in repo_context:
                for field_name in ("root_cause_summary", "severity_assessment", "primary_remediation"):
                    val = getattr(result, field_name, "")
                    if val and forbidden in val.lower():
                        overrides.append(
                            f"Removed SecureBank-specific value '{forbidden}' from {field_name}"
                        )
                        setattr(result, field_name, val.replace(forbidden, "<actor>").replace(forbidden.title(), "<Actor>"))
                        result.deterministic_override_applied = True

        # Rule 3: Runtime claims without evidence
        if not pkg.runtime_evidence_available:
            for claim in result.grounded_claims:
                if "runtime" in claim.claim.lower() and claim.status == "OBSERVED":
                    claim.status = ObservationStatus.INFERRED
                    if claim.limitation:
                        claim.limitation += " [corrected: runtime logs unavailable]"
                    else:
                        claim.limitation = "Runtime logs were unavailable — this is an inference, not an observation"
                    result.deterministic_override_applied = True

        # Rule 4: Route claims without discovered routes
        if not pkg.discovered_routes:
            for step in result.attack_path:
                if re.search(r'/api/|/v\d/', step.description):
                    if step.observation_status == ObservationStatus.OBSERVED:
                        step.observation_status = ObservationStatus.INFERRED
                        step.evidence_basis += " [corrected: no routes discovered from repository]"
                        result.deterministic_override_applied = True

        # Rule 5: Grounding confidence — anchor to evidence
        observed_count = sum(
            1 for c in result.grounded_claims
            if c.status == ObservationStatus.OBSERVED or c.status == "OBSERVED"
        )
        total_claims = max(len(result.grounded_claims), 1)
        direct_evidence = sum(
            1 for ev in pkg.all_evidence
            if ev.evidence_strength == EvidenceStrength.DIRECT
        )
        evidence_factor = min(direct_evidence / 3.0, 1.0)
        claim_factor = observed_count / total_claims
        result.grounding_confidence = round((evidence_factor * 0.6 + claim_factor * 0.4), 2)

        if overrides:
            result.deterministic_override_note = "; ".join(overrides)

        return result


# ── Main reasoner ──────────────────────────────────────────────────────────────

class AISecurityReasoner:
    """
    The AI security reasoning layer.

    Flow:
    1. Receive structured EvidencePackage
    2. Retrieve relevant knowledge from RAG
    3. Build grounded prompt
    4. Call AI provider (or deterministic fallback)
    5. Parse structured output
    6. Validate + correct against grounding rules
    7. Return AIReasoningResult
    """

    def __init__(self, provider: Optional[BaseAIProvider] = None):
        self._provider = provider or get_provider()
        self._validator = AIGroundingValidator()

    def reason(self, pkg: SecurityEvidencePackage) -> AIReasoningResult:
        """
        Run AI reasoning over the evidence package.

        Returns a fully validated, grounding-checked AIReasoningResult.
        Never raises — if reasoning fails, returns a minimal result with error noted.
        """
        t0 = time.time()
        investigation_id = pkg.investigation_id

        # Retrieve relevant knowledge
        rag_docs = retrieve_for_investigation(
            issue_description=pkg.issue_description,
            vulnerability_class=pkg.primary_vulnerability_class,
            cwe=pkg.deterministic_cwe,
            framework=pkg.framework,
            top_k=6,
        )

        # Check if provider is actually an AI (not deterministic fallback)
        ran_deterministic = (self._provider.name == "deterministic")

        if not pkg.all_evidence and not pkg.issue_description:
            return AIReasoningResult(
                investigation_id=investigation_id,
                provider_used=self._provider.name,
                ran_in_deterministic_mode=True,
                evidence_sufficiency="INSUFFICIENT",
                evidence_gaps=["No evidence collected — investigation may not have run"],
                cannot_determine=["All aspects — no evidence available"],
                grounding_confidence=0.0,
            )

        # Build prompt
        prompt = _build_reasoning_prompt(pkg, rag_docs)

        # Call provider
        response = self._provider.generate(
            prompt=prompt,
            system_instruction=_SYSTEM_INSTRUCTION,
            temperature=0.15,
            max_output_tokens=4096,
        )

        latency = int((time.time() - t0) * 1000)

        # Parse response into structured result
        result = self._parse_response(response.text, investigation_id, rag_docs)
        result.provider_used = self._provider.name
        result.model_used = response.model
        result.reasoning_latency_ms = latency
        result.ran_in_deterministic_mode = ran_deterministic or not response.succeeded

        if response.error:
            result.evidence_gaps.append(f"AI provider error: {response.error}")
            result.evidence_sufficiency = "INSUFFICIENT"

        # Validate and correct
        result = self._validator.validate_and_correct(result, pkg)

        # Add RAG citations
        result.rag_citations = [
            {
                "identifier": rd.document.identifier,
                "source": rd.document.source,
                "title": rd.document.title,
                "section": rd.document.section,
                "score": rd.score,
            }
            for rd in rag_docs[:4]
        ]

        return result

    def _parse_response(
        self,
        text: str,
        investigation_id: str,
        rag_docs: List[RetrievedDocument],
    ) -> AIReasoningResult:
        """Parse AI response text into AIReasoningResult, with robust fallback."""
        if not text:
            return self._fallback_result(investigation_id)

        # Strip markdown fences if present
        text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
        text = re.sub(r'\s*```\s*$', '', text, flags=re.MULTILINE)
        text = text.strip()

        # Try JSON parsing
        try:
            data = json.loads(text)
            return self._dict_to_result(data, investigation_id)
        except json.JSONDecodeError:
            pass

        # Try extracting JSON block
        json_match = re.search(r'\{.*\}', text, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(0))
                return self._dict_to_result(data, investigation_id)
            except json.JSONDecodeError:
                pass

        # Fallback: extract what we can from text
        return self._text_fallback(text, investigation_id)

    def _dict_to_result(self, data: Dict[str, Any], investigation_id: str) -> AIReasoningResult:
        """Convert parsed JSON dict to AIReasoningResult."""
        result = AIReasoningResult(investigation_id=investigation_id)

        result.vulnerability_title = data.get("vulnerability_title", "")
        result.primary_cwe = data.get("primary_cwe")
        result.primary_owasp = data.get("primary_owasp")
        result.severity_assessment = data.get("severity_assessment", "")
        result.root_cause_summary = data.get("root_cause_summary", "")
        result.primary_remediation = data.get("primary_remediation", "")
        result.remediation_code_example = data.get("remediation_code_example", "")
        result.evidence_gaps = data.get("evidence_gaps", [])
        result.cannot_determine = data.get("cannot_determine", [])
        result.grounding_confidence = float(data.get("grounding_confidence", 0.0))
        result.evidence_sufficiency = data.get("evidence_sufficiency", "PARTIAL")

        # Severity observation status
        sos = data.get("severity_observation_status", "INFERRED")
        try:
            result.severity_observation_status = ObservationStatus(sos)
        except ValueError:
            result.severity_observation_status = ObservationStatus.INFERRED

        # Root cause observation status
        ros = data.get("root_cause_observation_status", "INFERRED")
        try:
            result.root_cause_observation_status = ObservationStatus(ros)
        except ValueError:
            result.root_cause_observation_status = ObservationStatus.INFERRED

        # Attack path
        for step_data in data.get("attack_path", []):
            if isinstance(step_data, dict):
                obs_status = ObservationStatus.INFERRED
                try:
                    obs_status = ObservationStatus(step_data.get("observation_status", "INFERRED"))
                except ValueError:
                    pass
                result.attack_path.append(AttackPathStep(
                    step=int(step_data.get("step", 0)),
                    description=str(step_data.get("description", "")),
                    evidence_basis=str(step_data.get("evidence_basis", "")),
                    observation_status=obs_status,
                ))

        # Grounded claims
        for claim_data in data.get("grounded_claims", []):
            if isinstance(claim_data, dict):
                status = ObservationStatus.INFERRED
                try:
                    status = ObservationStatus(claim_data.get("status", "INFERRED"))
                except ValueError:
                    pass
                result.grounded_claims.append(GroundedClaim(
                    claim=str(claim_data.get("claim", "")),
                    status=status,
                    confidence=float(claim_data.get("confidence", 0.5)),
                    supporting_evidence_ids=claim_data.get("supporting_evidence_ids", []),
                    limitation=claim_data.get("limitation"),
                ))

        # Recommended tests
        for test_data in data.get("recommended_tests", []):
            if isinstance(test_data, dict):
                result.recommended_tests.append(RecommendedTest(
                    title=str(test_data.get("title", "")),
                    description=str(test_data.get("description", "")),
                    test_type=str(test_data.get("test_type", "")),
                    expected_assertion=str(test_data.get("expected_assertion", "")),
                    rag_source=str(test_data.get("rag_source", "")),
                ))

        return result

    def _text_fallback(self, text: str, investigation_id: str) -> AIReasoningResult:
        """Minimal result when JSON parsing fails."""
        result = AIReasoningResult(
            investigation_id=investigation_id,
            evidence_sufficiency="PARTIAL",
            grounding_confidence=0.3,
        )
        # Extract any useful content
        lines = text.splitlines()
        for line in lines[:20]:
            line = line.strip()
            if line and not line.startswith("#"):
                result.root_cause_summary = line[:500]
                break
        result.evidence_gaps.append("AI response was not valid JSON — structured parsing failed")
        return result

    def _fallback_result(self, investigation_id: str) -> AIReasoningResult:
        return AIReasoningResult(
            investigation_id=investigation_id,
            evidence_sufficiency="INSUFFICIENT",
            grounding_confidence=0.0,
            evidence_gaps=["No response from AI provider"],
            cannot_determine=["All aspects — AI provider returned empty response"],
        )

    def explain_verification(self, investigation: Any) -> str:
        """
        Phase 5L — AI Explanation of Verification
        Produces a grounded, human-readable explanation from:
          SecurityInvariant + attack result + legitimate-use result +
          adversarial variants + mutation results + evidence

        Rules:
        - Must reference actual observed verification facts and checks.
        - Cannot override deterministic verification results.
        - Must never claim absolute proof; uses 'VERIFIED WITHIN TESTED SCOPE'
          or explicit reason why verification failed.
        """
        verification = getattr(investigation, "verification", None)
        if not verification:
            return "Deterministic verification has not been executed."

        overall = getattr(verification, "overall_status", "unknown").lower()
        exploit_blocked = getattr(verification, "exploit_blocked", False)
        regression_passed = getattr(verification, "regression_passed", False)
        checks = getattr(verification, "checks", []) or []

        invariant = getattr(investigation, "security_invariant", None)
        inv_stmt = invariant.statement if invariant and invariant.statement else "Security invariant"
        inv_class = invariant.vulnerability_class.value if invariant and hasattr(invariant, "vulnerability_class") and invariant.vulnerability_class else ""

        # Summarize check outcomes
        passed_checks = [c for c in checks if getattr(c, "status", "") == "passed" or getattr(c, "outcome", "") == "pass"]
        failed_checks = [c for c in checks if getattr(c, "status", "") == "failed" or getattr(c, "outcome", "") in ("bypass", "error")]
        bypass_checks = [c for c in checks if getattr(c, "outcome", "") == "bypass"]

        # Check for adversarial variants & mutations
        variant_checks = [c for c in checks if "variant" in getattr(c, "name", "").lower() or getattr(c, "name", "").startswith("VAR-")]
        mutation_checks = [c for c in checks if "mutation" in getattr(c, "name", "").lower() or getattr(c, "name", "").startswith("MUT-")]

        # If LLM provider is active, ask LLM for grounded explanation
        if self._provider.name != "deterministic" and self._provider.is_available():
            prompt = (
                f"Explain this deterministic verification result for SECUREFIX:\n"
                f"Overall status: {overall}\n"
                f"Exploit blocked: {exploit_blocked}\n"
                f"Regression passed: {regression_passed}\n"
                f"Security Invariant: {inv_stmt} (Class: {inv_class})\n"
                f"Total checks: {len(checks)}, Passed: {len(passed_checks)}, Failed: {len(failed_checks)}\n"
                f"Bypass checks: {[getattr(c, 'name', '') for c in bypass_checks]}\n"
                f"Summary: {getattr(verification, 'summary', '')}\n\n"
                f"Rules: Write 2-3 concise sentences explaining the verification outcome. "
                f"Reference the specific observed outcomes. Never claim absolute security. "
                f"If verified, state 'VERIFIED WITHIN TESTED SCOPE'. If not, state what failed."
            )
            resp = self._provider.generate(prompt=prompt, system_instruction="You are a security verification analyst. Be grounded and factual.")
            if resp.succeeded and resp.text:
                return resp.text.strip()

        # Deterministic grounded explanation
        if overall == "verified":
            parts = [
                f"The proposed remediation was VERIFIED WITHIN TESTED SCOPE.",
                f"The security invariant ('{inv_stmt}') held under testing:",
                f"the attack scenario was confirmed blocked, and all {len(passed_checks)} verification check(s) passed (including legitimate-use regression tests)."
            ]
            if variant_checks:
                parts.append(f"{len(variant_checks)} adversarial variant(s) were tested and successfully defended.")
            if mutation_checks:
                parts.append(f"Controlled mutation testing confirmed that weakened patch variants were properly detected.")
            return " ".join(parts)
        elif bypass_checks:
            failed_names = ", ".join(getattr(c, "name", "check") for c in bypass_checks[:3])
            return (
                f"Remediation was NOT VERIFIED within tested scope. "
                f"The security invariant ('{inv_stmt}') was bypassed: "
                f"verification check(s) [{failed_names}] observed unauthorized access or bypass. "
                f"The patch does not fully defend against the vulnerability."
            )
        elif not exploit_blocked:
            return (
                f"Remediation was NOT VERIFIED within tested scope. "
                f"The attack scenario was NOT blocked after patch application. "
                f"The security invariant ('{inv_stmt}') remains violated."
            )
        elif not regression_passed:
            return (
                f"Remediation blocked the exploit but FAILED regression testing. "
                f"Legitimate application functionality was broken by the patch. "
                f"Fix rejected to prevent functional breakage."
            )
        else:
            return (
                f"Verification completed with status: {overall.upper()}. "
                f"{len(passed_checks)} of {len(checks)} check(s) passed. "
                f"Status: NOT VERIFIED within tested scope."
            )

