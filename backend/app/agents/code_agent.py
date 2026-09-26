"""
Code Analysis Agent
Performs data-flow and control-flow analysis on files relevant
to the reported security issue.
"""
import os
import re
from pathlib import Path
from typing import List, Dict

from app.agents.base import BaseAgent
from app.models import (
    AgentFinding, AgentResult, AgentStatus,
    Investigation, Severity,
)

IGNORE_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}


class CodeAgent(BaseAgent):
    name = "code_agent"

    async def _execute(self, investigation: Investigation) -> AgentResult:
        repo_path = investigation.repository_path
        if not repo_path:
            return AgentResult(
                agent=self.name,
                status=AgentStatus.FAILED,
                error="No repository path",
                summary="Cannot analyze — no repository.",
            )

        relevant = (
            investigation.repository_info.relevant_files
            if investigation.repository_info
            else []
        )
        if not relevant:
            relevant = self._find_code_files(repo_path)

        findings = []
        analyzed = 0

        for rel_path in relevant[:25]:
            fpath = os.path.join(repo_path, rel_path)
            if not os.path.isfile(fpath):
                continue
            try:
                content = Path(fpath).read_text(errors="ignore")
            except Exception:
                continue
            analyzed += 1
            findings.extend(self._analyze(rel_path, content, investigation.issue_description))

        return AgentResult(
            agent=self.name,
            status=AgentStatus.COMPLETED,
            findings=findings,
            summary=(
                f"Analyzed {analyzed} files for data/control-flow issues. "
                f"Found {len(findings)} code-level finding(s)."
            ),
        )

    # ── Core analysis ─────────────────────────────────────────────────────────

    def _analyze(self, rel_path: str, content: str, issue: str) -> List[AgentFinding]:
        findings = []
        lines = content.split("\n")
        issue_lower = issue.lower()

        # 1. User-controlled IDs flowing into database queries without ownership check
        if any(w in issue_lower for w in ["authorization", "account", "access", "ownership", "bola", "idor"]):
            findings.extend(self._check_unverified_id_flow(rel_path, content, lines))

        # 2. Path traversal data flows
        findings.extend(self._check_path_traversal_flow(rel_path, content, lines))

        # 3. Command injection data flows
        findings.extend(self._check_command_injection_flow(rel_path, content, lines))

        # 4. SQL injection data flows
        findings.extend(self._check_sql_injection_flow(rel_path, content, lines))

        # 5. Missing error handling around sensitive operations
        findings.extend(self._check_missing_error_handling(rel_path, content, lines))

        # 6. Dangerous direct object references in route params
        findings.extend(self._check_direct_object_ref(rel_path, content, lines))

        return findings

    def _check_unverified_id_flow(
        self, rel_path: str, content: str, lines: List[str]
    ) -> List[AgentFinding]:
        # Find functions that take an ID from path/query AND do a db lookup
        # but DON'T include an ownership assertion
        func_pattern = re.compile(
            r'def\s+(\w+)\s*\(([^)]*)\)',
        )
        findings = []

        for m in func_pattern.finditer(content):
            func_name = m.group(1)
            params = m.group(2)

            # Function takes an id-like parameter
            if not re.search(r'\b\w*_?id\b', params, re.IGNORECASE):
                continue

            # Extract function body (crude: next 40 lines)
            start_line = content[:m.start()].count("\n")
            body_lines = lines[start_line: start_line + 40]
            body = "\n".join(body_lines)

            has_db_query = bool(re.search(r'execute|fetchone|fetchall|filter|query', body))
            has_ownership = bool(re.search(
                r'user_id.*current_user|current_user.*user_id|verif|owner|403|FORBIDDEN',
                body, re.IGNORECASE,
            ))

            if has_db_query and not has_ownership:
                findings.append(AgentFinding(
                    title="Unverified direct object reference in function",
                    severity=Severity.HIGH,
                    confidence=0.82,
                    files=[rel_path],
                    line_ranges=[f"{start_line+1}-{start_line+40}"],
                    evidence=[
                        f"Function `{func_name}` accepts an ID parameter",
                        "Function performs a database query using that ID",
                        "No ownership verification found in function body",
                        f"Params: {params.strip()}",
                    ],
                    recommendation=(
                        f"In `{func_name}`, after fetching the resource verify that "
                        "resource.user_id equals current_user['id'] and raise HTTP 403 if not."
                    ),
                    root_cause=(
                        "ID-parameterized function queries database without verifying "
                        "the calling user owns the returned resource."
                    ),
                ))

        return findings

    def _check_missing_error_handling(
        self, rel_path: str, content: str, lines: List[str]
    ) -> List[AgentFinding]:
        findings = []
        # Look for db calls outside try/except blocks
        db_lines = [
            i for i, line in enumerate(lines, 1)
            if re.search(r'\.execute\(|\.fetchone\(|\.fetchall\(', line)
        ]
        for lineno in db_lines:
            # Check surrounding 10 lines for try/except
            context = "\n".join(lines[max(0, lineno-10): lineno+5])
            if "try:" not in context and "except" not in context:
                findings.append(AgentFinding(
                    title="Database operation without error handling",
                    severity=Severity.LOW,
                    confidence=0.6,
                    files=[rel_path],
                    line_ranges=[f"{lineno}"],
                    evidence=[f"Line {lineno}: {lines[lineno-1].strip()}"],
                    recommendation="Wrap database operations in try/except to handle connection and query failures.",
                ))
                break  # One finding per file is enough

        return findings

    def _check_direct_object_ref(
        self, rel_path: str, content: str, lines: List[str]
    ) -> List[AgentFinding]:
        findings = []
        # Look for route decorators with {id} placeholders
        route_pattern = re.compile(
            r'@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']*\{(\w*id\w*)\}',
            re.IGNORECASE,
        )
        for m in route_pattern.finditer(content):
            lineno = content[:m.start()].count("\n") + 1
            method = m.group(1).upper()
            param = m.group(2)

            # Check if the route function has an ownership check
            # Look ahead 50 lines
            ahead = "\n".join(lines[lineno: lineno + 50])
            if not re.search(
                r'user_id.*current_user|current_user.*user_id|403|FORBIDDEN|verif|owner',
                ahead, re.IGNORECASE,
            ):
                findings.append(AgentFinding(
                    title=f"Route with direct object reference — ownership unchecked",
                    severity=Severity.HIGH,
                    confidence=0.79,
                    files=[rel_path],
                    line_ranges=[f"{lineno}"],
                    evidence=[
                        f"{method} route uses `{{{param}}}` from path",
                        "No ownership check found in next 50 lines of route handler",
                        f"Line {lineno}: {lines[lineno-1].strip()}",
                    ],
                    recommendation=(
                        "Add ownership verification: compare fetched resource owner ID "
                        "with current_user ID before returning the response."
                    ),
                    root_cause=(
                        "Route handler accepts caller-controlled resource identifier "
                        "and accesses database without confirming caller is the resource owner."
                    ),
                ))

        return findings

    def _check_path_traversal_flow(
        self, rel_path: str, content: str, lines: List[str]
    ) -> List[AgentFinding]:
        findings = []
        func_pattern = re.compile(r'def\s+(\w+)\s*\(([^)]*)\)')
        for m in func_pattern.finditer(content):
            func_name = m.group(1)
            params = m.group(2)
            # Param looks like a path or filename
            if not re.search(r'\b(?:filename|file_name|filepath|file_path|file|path)\b', params, re.IGNORECASE):
                continue

            start_line = content[:m.start()].count("\n")
            body_lines = lines[start_line: start_line + 40]
            body = "\n".join(body_lines)

            # Checks if parameter is used in open, os.path.join, Path without sanitization
            uses_file_sink = bool(re.search(r'open\s*\(|os\.path\.join|Path\(|FileResponse\(', body))
            has_sanitization = bool(re.search(
                r'os\.path\.basename|commonpath|startswith\s*\(.*base|\.resolve\(\)\.is_relative_to|403|400',
                body,
            ))

            if uses_file_sink and not has_sanitization:
                findings.append(AgentFinding(
                    title="Path traversal vulnerability in file handler",
                    severity=Severity.HIGH,
                    confidence=0.88,
                    files=[rel_path],
                    line_ranges=[f"{start_line+1}-{start_line+len(body_lines)}"],
                    evidence=[
                        f"Function `{func_name}` accepts user path parameter: {params.strip()}",
                        "Parameter flows into file system operations without canonical path validation",
                        "Missing commonpath or os.path.basename check to prevent directory escape",
                    ],
                    recommendation=(
                        f"In `{func_name}`, resolve the absolute path and verify it starts with "
                        "the allowed base directory or enforce os.path.basename(). Raise HTTP 403 on violation."
                    ),
                    root_cause=(
                        "Filesystem path is constructed from caller input without verifying that "
                        "the canonical path remains within the restricted directory."
                    ),
                ))
        return findings

    def _check_command_injection_flow(
        self, rel_path: str, content: str, lines: List[str]
    ) -> List[AgentFinding]:
        findings = []
        func_pattern = re.compile(r'def\s+(\w+)\s*\(([^)]*)\)')
        for m in func_pattern.finditer(content):
            func_name = m.group(1)
            params = m.group(2)
            start_line = content[:m.start()].count("\n")
            body_lines = lines[start_line: start_line + 40]
            body = "\n".join(body_lines)

            has_shell_exec = bool(re.search(r'shell\s*=\s*True|os\.system|os\.popen', body))
            if has_shell_exec:
                findings.append(AgentFinding(
                    title="Command injection sink executed with shell=True",
                    severity=Severity.CRITICAL,
                    confidence=0.92,
                    files=[rel_path],
                    line_ranges=[f"{start_line+1}-{start_line+len(body_lines)}"],
                    evidence=[
                        f"Function `{func_name}` executes shell command with shell=True or os.system",
                        "User parameters may chain shell commands via metacharacters (; | &)",
                    ],
                    recommendation="Avoid shell=True. Use subprocess.run with argument lists (shell=False).",
                    root_cause="User input is concatenated into shell command strings without escaping.",
                ))
        return findings

    def _check_sql_injection_flow(
        self, rel_path: str, content: str, lines: List[str]
    ) -> List[AgentFinding]:
        findings = []
        for i, line in enumerate(lines, 1):
            if re.search(r'\.execute\(\s*f["\']|\.execute\(\s*["\'].*%|\.execute\(.*\+', line):
                findings.append(AgentFinding(
                    title="SQL injection via string interpolation",
                    severity=Severity.CRITICAL,
                    confidence=0.90,
                    files=[rel_path],
                    line_ranges=[f"{i}"],
                    evidence=[f"Line {i}: {line.strip()}"],
                    recommendation="Use parameterized query placeholders (?, %s, :param) instead of string formatting.",
                    root_cause="Dynamic SQL string concatenation creates injection vulnerabilities.",
                ))
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_code_files(self, repo_path: str) -> List[str]:
        result = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for f in files:
                if f.endswith((".py", ".js", ".ts")):
                    result.append(os.path.relpath(os.path.join(root, f), repo_path))
        return result
