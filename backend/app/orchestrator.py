"""
Agent Orchestrator
Coordinates parallel agent execution, evidence correlation,
root-cause analysis, and patch generation.
"""
import asyncio
from datetime import datetime
from typing import List

from app.agents.repository_agent import RepositoryAgent
from app.agents.security_agent import SecurityAgent
from app.agents.code_agent import CodeAgent
from app.agents.dependency_agent import DependencyAgent
from app.agents.config_agent import ConfigAgent
from app.agents.test_agent import TestAgent, generate_regression_test
from app.agents.runtime_agent import RuntimeAgent
from app.correlation.engine import CorrelationEngine
from app.remediation.root_cause import RootCauseEngine
from app.remediation.engine import RemediationEngine
from app.store import store
from app.models import (
    AgentStatus, Investigation, InvestigationStatus,
    ProgressEvent, RemediationStatus, TimelineEvent,
)


class AgentOrchestrator:
    def __init__(self):
        self.correlation_engine = CorrelationEngine()
        self.root_cause_engine = RootCauseEngine()
        self.remediation_engine = RemediationEngine()

    async def run_investigation(self, investigation: Investigation):
        """Full investigation pipeline."""
        try:
            await self._update_status(investigation, InvestigationStatus.RUNNING, 5)
            await self._add_timeline(investigation, "Investigation started", "Pipeline initiated")

            # Phase 1: Repository Intelligence (sequential — others depend on it)
            await self._run_agent(investigation, RepositoryAgent(), 15)

            # Phase 2: Parallel agent execution
            await self._add_timeline(investigation, "Parallel agent analysis started",
                                     "6 specialized agents running concurrently")

            parallel_agents = [
                (SecurityAgent(), 40),
                (CodeAgent(), 45),
                (DependencyAgent(), 50),
                (ConfigAgent(), 55),
                (TestAgent(), 60),
                (RuntimeAgent(), 65),
            ]

            tasks = [
                self._run_agent(investigation, agent, pct)
                for agent, pct in parallel_agents
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

            await self._add_timeline(investigation, "All agents completed", "Evidence collected")

            # Phase 3: Evidence Correlation
            await self._publish_progress(investigation, "correlation_started",
                                         "Correlating evidence across agents", 70)
            correlation = self.correlation_engine.correlate(investigation)
            investigation.correlation = correlation
            await self._add_timeline(investigation, "Evidence correlated",
                                     f"Primary finding: {correlation.primary_finding}")
            store.update(investigation)

            await self._publish_progress(investigation, "correlation_done",
                                         "Evidence correlated", 75)

            # Phase 4: Root Cause
            await self._publish_progress(investigation, "root_cause_started",
                                         "Analyzing root cause", 78)
            root_cause = self.root_cause_engine.analyze(investigation)
            investigation.root_cause = root_cause
            await self._add_timeline(investigation, "Root cause identified",
                                     root_cause.root_cause[:100])
            store.update(investigation)

            await self._publish_progress(investigation, "root_cause_done",
                                         "Root cause identified", 83)

            # Phase 4b: Security Invariant derivation (additive — does not alter root cause)
            await self._publish_progress(investigation, "invariant_started",
                                         "Deriving security invariant", 84)
            invariant = self.root_cause_engine.derive_invariant(investigation)
            investigation.security_invariant = invariant
            store.update(investigation)
            invariant_status = "derived" if invariant.supported else "unsupported"
            await self._add_timeline(
                investigation,
                f"Security invariant {invariant_status}",
                (
                    f"Class: {invariant.vulnerability_class.value}, CWE: {invariant.cwe}"
                    if invariant.supported
                    else f"Unsupported: {invariant.unsupported_reason[:80] if invariant.unsupported_reason else ''}"
                ),
            )
            await self._publish_progress(
                investigation,
                "invariant_done",
                f"Security invariant {invariant_status}: {invariant.vulnerability_class.value}",
                85,
                data={"supported": invariant.supported, "cwe": invariant.cwe},
            )

            # ── Phase 5: AI Security Reasoning (additive — never blocks pipeline) ──
            await self._publish_progress(investigation, "ai_reasoning_started",
                                         "AI reasoning over evidence (grounded)", 86)
            try:
                from app.ai.evidence_package import EvidencePackageBuilder
                from app.ai.security_reasoner import AISecurityReasoner

                builder = EvidencePackageBuilder()
                evidence_pkg = builder.build(investigation)

                reasoner = AISecurityReasoner()
                ai_result = reasoner.reason(evidence_pkg)

                # Store result on investigation for API/UI access
                investigation.ai_reasoning = ai_result.model_dump()
                store.update(investigation)

                ai_status = (
                    f"AI reasoning complete (provider: {ai_result.provider_used}, "
                    f"grounding: {ai_result.grounding_confidence:.0%})"
                )
            except Exception as ai_exc:
                ai_status = f"AI reasoning skipped: {ai_exc}"
                investigation.ai_reasoning = {"error": str(ai_exc), "skipped": True}
                store.update(investigation)

            await self._add_timeline(investigation, "AI reasoning complete", ai_status)
            await self._publish_progress(investigation, "ai_reasoning_done",
                                         ai_status, 87)
            await self._publish_progress(investigation, "patch_started",
                                         "Generating remediation patch", 87)
            proposal = self.remediation_engine.propose(investigation)

            # Generate regression test
            regression_src = generate_regression_test(investigation)
            proposal.regression_test = regression_src
            proposal.regression_test_file = f"tests/test_securefix_regression_{investigation.id.lower().replace('-','_')}.py"

            investigation.remediation = proposal
            await self._add_timeline(investigation, "Patch proposed",
                                     f"{len(proposal.patches)} file(s) to modify")
            store.update(investigation)

            # Move to awaiting approval
            await self._update_status(investigation, InvestigationStatus.AWAITING_APPROVAL, 90)
            await self._add_timeline(investigation, "Awaiting human approval",
                                     "Review proposed patch before applying")

            await self._publish_progress(investigation, "patch_ready",
                                         "Patch ready for review", 90,
                                         data={
                                             "files_changed": proposal.files_changed,
                                             "risk_level": proposal.risk_level,
                                         })

        except Exception as exc:
            investigation.status = InvestigationStatus.FAILED
            await self._add_timeline(investigation, "Investigation failed", str(exc))
            store.update(investigation)
            await self._publish_progress(investigation, "error", f"Error: {exc}", investigation.progress_pct)

    async def apply_patch_and_verify(self, investigation: Investigation):
        """Apply approved patch and run verification."""
        try:
            await self._update_status(investigation, InvestigationStatus.APPLYING, 92)
            await self._add_timeline(investigation, "Applying patch", "Human approved")

            success = self.remediation_engine.apply(investigation)

            if not success:
                await self._add_timeline(investigation, "Patch application failed",
                                         "Could not apply patch to repository files")
                investigation.remediation.status = RemediationStatus.FAILED
                store.update(investigation)
                return

            investigation.remediation.status = RemediationStatus.APPLIED
            await self._add_timeline(investigation, "Patch applied successfully",
                                     f"Modified: {', '.join(investigation.remediation.files_changed)}")
            store.update(investigation)

            # Verification
            await self._update_status(investigation, InvestigationStatus.VERIFYING, 95)
            await self._add_timeline(investigation, "Running verification",
                                     "Executing tests and security re-scan")

            from app.verification.engine import VerificationEngine
            verifier = VerificationEngine()
            result = verifier.verify(investigation)
            investigation.verification = result

            await self._add_timeline(
                investigation,
                "Verification completed",
                result.summary,
            )

            # Phase 5L: AI explanation of verification (grounded, non-overriding)
            try:
                from app.ai.security_reasoner import AISecurityReasoner
                reasoner = AISecurityReasoner()
                explanation = reasoner.explain_verification(investigation)
                if explanation:
                    if investigation.ai_reasoning:
                        investigation.ai_reasoning["verification_explanation"] = explanation
                    else:
                        investigation.ai_reasoning = {"verification_explanation": explanation}
                    await self._add_timeline(
                        investigation,
                        "AI verification explanation",
                        explanation[:120],
                    )
            except Exception:
                pass

            if result.overall_status == "verified":
                investigation.remediation.status = RemediationStatus.VERIFIED
                await self._update_status(investigation, InvestigationStatus.COMPLETED, 100)
                await self._add_timeline(investigation, "Investigation resolved",
                                         "Finding remediated and verified")
            else:
                await self._update_status(investigation, InvestigationStatus.COMPLETED, 100)

            store.update(investigation)

            await self._publish_progress(
                investigation,
                "verification_done",
                f"Verification: {result.overall_status.upper()}",
                100,
                data={"overall_status": result.overall_status},
            )

        except Exception as exc:
            investigation.status = InvestigationStatus.FAILED
            await self._add_timeline(investigation, "Apply/verify failed", str(exc))
            store.update(investigation)

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _run_agent(self, investigation: Investigation, agent, progress_pct: int):
        await self._publish_progress(
            investigation, "agent_started", f"{agent.name} started", progress_pct - 2,
            agent=agent.name,
        )
        store.log_audit(
            investigation.id,
            action=f"AGENT_STARTED_{agent.name.upper()}",
            actor=agent.name,
            status="RUNNING",
        )
        result = await agent.run(investigation)
        investigation.agent_results[agent.name] = result
        store.update(investigation)

        status_label = "completed" if result.status == AgentStatus.COMPLETED else "failed"
        await self._publish_progress(
            investigation,
            f"agent_{status_label}",
            f"{agent.name} {status_label}: {result.summary[:80]}",
            progress_pct,
            agent=agent.name,
            data={"findings_count": len(result.findings), "duration_ms": result.duration_ms},
        )
        store.log_audit(
            investigation.id,
            action=f"AGENT_COMPLETED_{agent.name.upper()}",
            actor=agent.name,
            status=status_label.upper(),
            metadata={"findings_count": len(result.findings), "duration_ms": result.duration_ms},
        )

        name_label = agent.name.replace("_", " ").title()
        await self._add_timeline(
            investigation,
            f"{name_label} completed",
            result.summary[:120],
            actor=agent.name,
        )

    async def _update_status(
        self, investigation: Investigation, status: InvestigationStatus, pct: int
    ):
        investigation.status = status
        investigation.progress_pct = pct
        store.update(investigation)
        await self._publish_progress(
            investigation, "status_change", f"Status: {status.value}", pct,
        )

    async def _add_timeline(
        self,
        investigation: Investigation,
        event: str,
        detail: str = "",
        actor: str = "system",
    ):
        investigation.timeline.append(TimelineEvent(
            event=event,
            detail=detail,
            actor=actor,
        ))
        store.update(investigation)
        store.log_audit(
            investigation.id,
            action=event.upper().replace(" ", "_"),
            actor=actor,
            status="COMPLETED",
            metadata={"detail": detail},
        )

    async def _publish_progress(
        self,
        investigation: Investigation,
        event_type: str,
        message: str,
        pct: int,
        agent: str = None,
        data: dict = None,
    ):
        event = ProgressEvent(
            investigation_id=investigation.id,
            event_type=event_type,
            agent=agent,
            message=message,
            progress_pct=pct,
            data=data or {},
        )
        await store.publish(event)
