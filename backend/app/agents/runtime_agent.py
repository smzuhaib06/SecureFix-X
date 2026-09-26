"""
Runtime / Log Agent
Analyzes application logs if available.
Clearly states when log evidence is unavailable.
Never fabricates log data.
"""
import os
import re
from pathlib import Path
from typing import List, Optional

from app.agents.base import BaseAgent
from app.models import AgentFinding, AgentResult, AgentStatus, Investigation, Severity

LOG_EXTENSIONS = {".log", ".txt"}
LOG_DIRS = {"logs", "log", "var/log", ".logs"}
LOG_FILENAMES = {"app.log", "error.log", "access.log", "server.log", "debug.log"}


class RuntimeAgent(BaseAgent):
    name = "runtime_agent"

    async def _execute(self, investigation: Investigation) -> AgentResult:
        repo_path = investigation.repository_path

        log_files = self._find_logs(repo_path) if repo_path else []

        if not log_files:
            return AgentResult(
                agent=self.name,
                status=AgentStatus.COMPLETED,
                findings=[],
                summary=(
                    "Runtime evidence unavailable. "
                    "No log files found in repository. "
                    "Analysis based on repository source code only."
                ),
                raw_output={"logs_found": False, "log_files": []},
            )

        findings = []
        issue = investigation.issue_description.lower()

        for log_path in log_files[:5]:
            rel = os.path.relpath(log_path, repo_path) if repo_path else log_path
            try:
                content = Path(log_path).read_text(errors="ignore")
            except Exception:
                continue
            findings.extend(self._analyze_log(rel, content, issue))

        return AgentResult(
            agent=self.name,
            status=AgentStatus.COMPLETED,
            findings=findings,
            summary=(
                f"Analyzed {len(log_files)} log file(s). "
                f"Found {len(findings)} runtime indicator(s)."
            ),
            raw_output={"logs_found": True, "log_files": [
                os.path.relpath(lf, repo_path) if repo_path else lf
                for lf in log_files
            ]},
        )

    def _find_logs(self, repo_path: str) -> List[str]:
        found = []
        if not repo_path:
            return found

        # Check common log directories
        for log_dir in LOG_DIRS:
            full_dir = os.path.join(repo_path, log_dir)
            if os.path.isdir(full_dir):
                for fname in os.listdir(full_dir):
                    fpath = os.path.join(full_dir, fname)
                    if os.path.isfile(fpath) and (
                        fname in LOG_FILENAMES
                        or Path(fname).suffix in LOG_EXTENSIONS
                    ):
                        found.append(fpath)

        # Check root for log files
        for fname in os.listdir(repo_path):
            if fname in LOG_FILENAMES or (
                Path(fname).suffix in LOG_EXTENSIONS and "log" in fname.lower()
            ):
                found.append(os.path.join(repo_path, fname))

        return found

    def _analyze_log(self, rel_path: str, content: str, issue: str) -> List[AgentFinding]:
        findings = []
        lines = content.splitlines()

        # Detect repeated access to same endpoint pattern (enumeration)
        if any(w in issue for w in ["authorization", "access", "account", "bola"]):
            # Look for sequential ID probing patterns
            account_accesses = re.findall(
                r'GET /api/(?:accounts|profile|transactions)/(\d+)',
                content,
            )
            if len(account_accesses) > 3:
                ids = sorted(set(account_accesses))
                findings.append(AgentFinding(
                    title="Potential resource enumeration detected in logs",
                    severity=Severity.HIGH,
                    confidence=0.77,
                    files=[rel_path],
                    evidence=[
                        f"Multiple resource IDs accessed: {ids[:10]}",
                        f"Total distinct resource IDs: {len(ids)}",
                        "Pattern consistent with BOLA enumeration attack",
                    ],
                    recommendation="Implement rate limiting and ownership checks on resource endpoints.",
                ))

        # Detect 500 errors (potential exploitation causing errors)
        error_lines = [
            (i + 1, line) for i, line in enumerate(lines)
            if "500" in line or "Internal Server Error" in line
        ]
        if error_lines:
            findings.append(AgentFinding(
                title="Server errors detected in application logs",
                severity=Severity.MEDIUM,
                confidence=0.65,
                files=[rel_path],
                line_ranges=[f"{el[0]}" for el in error_lines[:3]],
                evidence=[f"Line {el[0]}: {el[1].strip()}" for el in error_lines[:3]],
                recommendation="Investigate server errors; may indicate exploitation attempts.",
            ))

        # Detect unauthorized 401/403 responses
        auth_errors = [
            line for line in lines
            if re.search(r'\b(401|403)\b', line)
        ]
        if len(auth_errors) > 5:
            findings.append(AgentFinding(
                title="High rate of authorization failures in logs",
                severity=Severity.MEDIUM,
                confidence=0.70,
                files=[rel_path],
                evidence=[
                    f"{len(auth_errors)} auth failure log entries found",
                    "May indicate probing or misconfigured clients",
                ],
                recommendation="Review auth failure patterns and consider alerting on thresholds.",
            ))

        return findings
