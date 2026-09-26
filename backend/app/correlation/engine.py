"""
Evidence Correlation Engine
Correlates findings from all agents into a unified picture.
Identifies when multiple agents point to the same underlying issue.
"""
from typing import Dict, List, Any
from app.models import (
    AgentResult, CorrelationResult, EvidenceItem,
    Investigation, Severity,
)


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


class CorrelationEngine:
    def correlate(self, investigation: Investigation) -> CorrelationResult:
        results: Dict[str, AgentResult] = investigation.agent_results
        issue = investigation.issue_description

        evidence_items: List[EvidenceItem] = []
        all_files: List[str] = []
        total_confidence = 0.0
        confidence_count = 0

        # Gather all evidence across agents
        for agent_name, result in results.items():
            if result.status.value not in ("completed",):
                continue
            for finding in result.findings:
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
                if finding.confidence:
                    total_confidence += finding.confidence
                    confidence_count += 1

        # Identify primary finding
        primary = self._identify_primary_finding(results, issue)
        attack_path = self._build_attack_path(results)

        # Compute aggregate confidence
        base_confidence = (total_confidence / confidence_count) if confidence_count else 0.5
        # Boost confidence when multiple agents corroborate
        agents_with_findings = sum(
            1 for r in results.values()
            if r.status.value == "completed" and r.findings
        )
        corroboration_boost = min(0.15, agents_with_findings * 0.03)
        final_confidence = min(0.99, base_confidence + corroboration_boost)

        # Build evidence graph
        evidence_graph = self._build_evidence_graph(results, primary)

        return CorrelationResult(
            primary_finding=primary,
            corroborating_evidence=evidence_items,
            affected_files=list(dict.fromkeys(all_files)),
            attack_path=attack_path,
            confidence=round(final_confidence, 2),
            evidence_graph=evidence_graph,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _normalise_paths(self, files: List[str]) -> List[str]:
        """Strip absolute path prefixes, keeping only repo-relative paths."""
        result = []
        for f in files:
            p = f.replace("\\", "/")
            # If it looks absolute, find the first known anchor dir
            if p.startswith("/"):
                for anchor in ("app/", "tests/", "src/"):
                    idx = p.find("/" + anchor)
                    if idx != -1:
                        p = p[idx + 1:]
                        break
                else:
                    # Last resort — keep only the basename
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

    def _identify_primary_finding(
        self, results: Dict[str, AgentResult], issue: str
    ) -> str:
        # Find the highest-severity finding across all agents
        best_title = ""
        best_sev = -1

        for result in results.values():
            for finding in result.findings:
                sev_idx = SEVERITY_ORDER.index(finding.severity.value) if finding.severity.value in SEVERITY_ORDER else 0
                if sev_idx > best_sev:
                    best_sev = sev_idx
                    best_title = finding.title

        if best_title:
            return best_title

        # Fallback: derive from issue description
        issue_lower = issue.lower()
        if "traversal" in issue_lower or "path" in issue_lower:
            return "Path Traversal"
        if "command" in issue_lower or "shell" in issue_lower or "rce" in issue_lower:
            return "Command Injection"
        if "authorization" in issue_lower or "access" in issue_lower or "account" in issue_lower:
            return "Broken Object Level Authorization (BOLA)"
        if "sql" in issue_lower or "injection" in issue_lower:
            return "SQL Injection"
        if "auth" in issue_lower:
            return "Authentication Failure"
        return "Security Vulnerability Detected"

    def _build_attack_path(self, results: Dict[str, AgentResult]) -> List[str]:
        # Use the attack path from the highest-confidence security finding
        for agent_name in ("security_agent", "code_agent"):
            result = results.get(agent_name)
            if not result:
                continue
            for finding in result.findings:
                if finding.attack_path:
                    return finding.attack_path

        # Contextual fallback
        return [
            "Attacker submits crafted request targeting vulnerable endpoint",
            "Server processes input without adequate security controls",
            "Security boundary is bypassed",
            "Attacker gains unauthorized access, executes commands, or reads sensitive data",
        ]

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
