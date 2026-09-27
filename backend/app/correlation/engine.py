"""
Evidence Correlation Engine
Correlates findings from all agents into a unified picture.

KEY RULES:
- Primary finding MUST come from a CONFIRMED finding with real evidence.
- If no CONFIRMED findings exist: investigation_outcome = NO_CONFIRMED_FINDING
- Generic fallback text cannot become the primary finding.
- Confidence is only computed from CONFIRMED findings; arbitrary percentages are rejected.
- Attack path is taken from actual findings, never fabricated.
"""
from typing import Dict, List, Any, Optional
from app.models import (
    AgentFinding, AgentResult, CorrelationResult, EvidenceItem,
    EvidenceValidator, FindingStatus, Investigation, Severity,
)


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_validator = EvidenceValidator()


class CorrelationEngine:
    def correlate(self, investigation: Investigation) -> CorrelationResult:
        results: Dict[str, AgentResult] = investigation.agent_results
        issue = investigation.issue_description

        evidence_items: List[EvidenceItem] = []
        all_files: List[str] = []
        confirmed_findings: List[AgentFinding] = []
        hypothesis_findings: List[AgentFinding] = []
        unsupported_findings: List[AgentFinding] = []

        # ── Gather and classify findings ───────────────────────────────────
        for agent_name, result in results.items():
            if result.status.value not in ("completed",):
                continue
            for finding in result.findings:
                # Classify by status
                if finding.finding_status == FindingStatus.CONFIRMED:
                    # Validate before accepting
                    vr = _validator.validate(finding)
                    if vr.valid:
                        confirmed_findings.append(finding)
                    # Still collect evidence items even for invalid findings
                elif finding.finding_status == FindingStatus.HYPOTHESIS:
                    hypothesis_findings.append(finding)
                else:  # UNSUPPORTED
                    unsupported_findings.append(finding)

                # Collect evidence items from all completed findings
                for ev_text in finding.evidence:
                    evidence_items.append(EvidenceItem(
                        source=agent_name,
                        type=self._classify_evidence_type(agent_name),
                        description=ev_text,
                        file=finding.files[0] if finding.files else None,
                        line_range=finding.line_ranges[0] if finding.line_ranges else None,
                        severity=finding.severity,
                    ))
                all_files.extend(self._normalise_paths(finding.files))

        # ── Determine investigation outcome ────────────────────────────────
        if confirmed_findings:
            investigation_outcome = "CONFIRMED"
        elif hypothesis_findings:
            investigation_outcome = "PARTIAL"
        elif unsupported_findings:
            investigation_outcome = "UNSUPPORTED"
        else:
            investigation_outcome = "NO_CONFIRMED_FINDING"

        # ── Primary finding: MUST come from a CONFIRMED finding ────────────
        primary = self._identify_primary_finding_from_confirmed(
            confirmed_findings, investigation_outcome, issue
        )

        # ── Attack path: only from actual findings ─────────────────────────
        attack_path = self._build_attack_path(results, confirmed_findings)

        # ── Confidence: derived from CONFIRMED findings only ───────────────
        # No arbitrary percentage — derived from evidence count and corroboration
        confidence = self._compute_confidence(confirmed_findings, results)

        # ── Evidence graph ─────────────────────────────────────────────────
        evidence_graph = self._build_evidence_graph(results, primary)

        return CorrelationResult(
            primary_finding=primary,
            corroborating_evidence=evidence_items,
            affected_files=list(dict.fromkeys(all_files)),
            attack_path=attack_path,
            confidence=round(confidence, 2),
            evidence_graph=evidence_graph,
            investigation_outcome=investigation_outcome,
            confirmed_finding_count=len(confirmed_findings),
            hypothesis_count=len(hypothesis_findings),
            unsupported_count=len(unsupported_findings),
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _normalise_paths(self, files: List[str]) -> List[str]:
        """Strip absolute path prefixes, keeping only repo-relative paths."""
        result = []
        for f in files:
            p = f.replace("\\", "/")
            if p.startswith("/"):
                for anchor in ("app/", "tests/", "src/", "routes/"):
                    idx = p.find("/" + anchor)
                    if idx != -1:
                        p = p[idx + 1:]
                        break
                else:
                    p = p.split("/")[-1]
            result.append(p)
        return result

    def _classify_evidence_type(self, agent_name: str) -> str:
        mapping = {
            "security_agent": "code",
            "code_agent": "code",
            "dependency_agent": "dependency",
            "config_agent": "config",
            "test_agent": "test",
            "runtime_agent": "runtime",
            "repository_agent": "repository",
        }
        return mapping.get(agent_name, "unknown")

    def _identify_primary_finding_from_confirmed(
        self,
        confirmed_findings: List[AgentFinding],
        investigation_outcome: str,
        issue: str,
    ) -> str:
        """
        Primary finding MUST come from a CONFIRMED, evidence-backed finding.

        If no confirmed findings exist, returns a structured outcome string
        that accurately reflects the investigation state — never a fabricated
        vulnerability name.
        """
        if not confirmed_findings:
            if investigation_outcome == "NO_CONFIRMED_FINDING":
                return "NO_CONFIRMED_FINDING: No agent produced a confirmed evidence-backed finding"
            elif investigation_outcome == "PARTIAL":
                return "PARTIAL: Hypothesis-level findings only — no confirmed evidence-backed finding"
            elif investigation_outcome == "UNSUPPORTED":
                return "UNSUPPORTED: Analysis capability is insufficient for this repository"
            else:
                return "NO_CONFIRMED_FINDING: Investigation produced no actionable findings"

        # Find the highest-severity confirmed finding
        best = max(
            confirmed_findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity.value)
            if f.severity.value in SEVERITY_ORDER else 0,
        )
        return best.title

    def _build_attack_path(
        self,
        results: Dict[str, AgentResult],
        confirmed_findings: List[AgentFinding],
    ) -> List[str]:
        """
        Attack path comes from the highest-confidence CONFIRMED finding only.
        Returns empty list (not a generic fabricated path) if none available.
        """
        # First preference: confirmed findings with attack paths
        for finding in confirmed_findings:
            if finding.attack_path:
                return finding.attack_path

        # Second preference: any finding from security/code agents with attack path
        for agent_name in ("security_agent", "code_agent"):
            result = results.get(agent_name)
            if not result:
                continue
            for finding in result.findings:
                if (
                    finding.finding_status == FindingStatus.CONFIRMED
                    and finding.attack_path
                ):
                    return finding.attack_path

        # No confirmed attack path — return empty, not fabricated
        return []

    def _compute_confidence(
        self,
        confirmed_findings: List[AgentFinding],
        results: Dict[str, AgentResult],
    ) -> float:
        """
        Confidence is derived from:
        - How many agents produced CONFIRMED findings (corroboration)
        - Average confidence of confirmed findings

        Never produces an arbitrary percentage.
        Returns 0.0 if no confirmed findings.
        """
        if not confirmed_findings:
            return 0.0

        # Count agents with confirmed findings
        agent_confirmed_count = sum(
            1 for result in results.values()
            if result.status.value == "completed"
            and any(
                f.finding_status == FindingStatus.CONFIRMED and _validator.validate(f).valid
                for f in result.findings
            )
        )

        # Average confidence across confirmed findings that have it set
        findings_with_confidence = [
            f.confidence for f in confirmed_findings if f.confidence > 0.0
        ]
        avg_confidence = (
            sum(findings_with_confidence) / len(findings_with_confidence)
            if findings_with_confidence else 0.5
        )

        # Corroboration boost: each additional corroborating agent adds a small boost
        corroboration_boost = min(0.15, (agent_confirmed_count - 1) * 0.05)

        return min(0.99, avg_confidence + corroboration_boost)

    def _build_evidence_graph(
        self, results: Dict[str, AgentResult], primary: str
    ) -> Dict[str, Any]:
        graph: Dict[str, Any] = {
            "finding": primary,
            "nodes": [],
            "edges": [],
        }

        node_id = 0
        finding_node = node_id
        graph["nodes"].append({"id": node_id, "label": primary, "type": "finding"})

        agent_node_map: Dict[str, int] = {}
        for agent_name, result in results.items():
            if result.status.value != "completed":
                continue
            node_id += 1
            agent_node_map[agent_name] = node_id
            label = agent_name.replace("_", " ").title()
            graph["nodes"].append({"id": node_id, "label": label, "type": "agent"})
            graph["edges"].append({
                "from": finding_node,
                "to": node_id,
                "label": f"{len(result.findings)} finding(s)",
            })

            for finding in result.findings[:2]:
                for ffile in finding.files[:2]:
                    node_id += 1
                    graph["nodes"].append({"id": node_id, "label": ffile, "type": "file"})
                    graph["edges"].append({
                        "from": agent_node_map[agent_name],
                        "to": node_id,
                        "label": finding.title[:30],
                    })

        return graph
