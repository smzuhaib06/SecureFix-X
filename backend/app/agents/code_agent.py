"""
Code Analysis Agent
Performs data-flow and control-flow analysis on files relevant
to the reported security issue.

Supports:
  Python   — existing analysis preserved (def-based patterns)
  JavaScript / Node.js / Express — Phase 5A addition

Every finding contains:
  technology, file, line, excerpt, source, sink, route (where available),
  reasoning, confidence, evidence classification.

Never fabricates evidence.
SecureBank isolation: no references to alice, bob, /api/accounts,
FastAPI TestClient, or any SecureBank-specific value.
"""
import os
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from app.agents.base import BaseAgent
from app.models import (
    AgentFinding, AgentResult, AgentStatus,
    FindingStatus, Investigation, Severity,
)

IGNORE_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}

# ── JavaScript request source patterns ────────────────────────────────────────
_JS_REQ_SRC = re.compile(
    r'\breq\.(body|query|params|headers|cookies)(?:\.\w+)?',
    re.IGNORECASE,
)

# ── JavaScript security-sensitive sink patterns ────────────────────────────────
_JS_NOSQL_SINK = re.compile(
    r'\.\s*(?:find|findOne|findById|findOneAndUpdate|updateOne|deleteOne|countDocuments)'
    r'\s*\(\s*\{',
    re.IGNORECASE,
)
_JS_SQL_SINK = re.compile(
    r'(?:query|execute)\s*\(\s*(?:`[^`]*\$\{|["\'][^"\']*\s*\+)',
    re.IGNORECASE | re.DOTALL,
)
_JS_FS_SINK = re.compile(
    r'(?:fs\.(?:readFile|writeFile|createReadStream|open|stat|access)|'
    r'path\.join\s*\([^)]*req\.\w)',
    re.IGNORECASE,
)
_JS_EXEC_SINK = re.compile(
    r'(?:exec|execSync|spawn|spawnSync|execFile|fork)\s*\(',
    re.IGNORECASE,
)
_JS_EVAL_SINK = re.compile(
    r'\beval\s*\(|\bnew\s+Function\s*\(',
    re.IGNORECASE,
)
_JS_REDIRECT_SINK = re.compile(
    r'res\s*\.\s*(?:redirect|location)\s*\(',
    re.IGNORECASE,
)

# ── Sanitization / mitigation patterns (JS) ───────────────────────────────────
_JS_SANITIZATION = re.compile(
    r'mongo(?:db)?-sanitize|mongoSanitize|express-mongo-sanitize'
    r'|typeof\s+\w+\s*===?\s*[\'"]string[\'"]'
    r'|parseInt\s*\(|Number\s*\('
    r'|path\.resolve\s*\(|path\.normalize\s*\(',
    re.IGNORECASE,
)


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

        findings: List[AgentFinding] = []
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

            if rel_path.endswith((".js", ".ts", ".mjs")):
                findings.extend(
                    self._analyze_js(rel_path, content, investigation.issue_description)
                )
            elif rel_path.endswith(".py"):
                findings.extend(
                    self._analyze_py(rel_path, content, investigation.issue_description)
                )

        return AgentResult(
            agent=self.name,
            status=AgentStatus.COMPLETED,
            findings=findings,
            summary=(
                f"Analyzed {analyzed} files for data/control-flow issues. "
                f"Found {len(findings)} code-level finding(s)."
            ),
        )

    # ══════════════════════════════════════════════════════════════════════════
    # JavaScript / Node.js / Express analysis  (Phase 5A)
    # ══════════════════════════════════════════════════════════════════════════

    def _analyze_js(self, rel_path: str, content: str, issue: str) -> List[AgentFinding]:
        """
        Bounded source->sink data-flow analysis for JavaScript/Express files.

        Sources: req.body / req.query / req.params / req.headers / req.cookies
        Sinks:   Mongoose queries, SQL queries, fs ops,
                 child_process exec/spawn, eval/Function(), res.redirect()

        Every finding carries:
        - A real source excerpt (line + content)
        - A real sink excerpt (line + content)
        - Technology: javascript/nodejs
        Never fabricates lines or routes not in the file.
        """
        lines = content.splitlines()
        handler_map = self._extract_js_handlers(content, lines)
        return self._check_js_source_sink_flows(rel_path, content, lines, handler_map, issue)

    def _extract_js_handlers(self, content: str, lines: List[str]) -> Dict[int, Tuple[str, str]]:
        """Extract Express route registrations. Returns {line_number: (method, route)}."""
        result: Dict[int, Tuple[str, str]] = {}
        route_pat = re.compile(
            r'(?:router|app)\s*\.\s*(get|post|put|delete|patch|use)\s*\(\s*[\'"]([^\'"]*)[\'"]',
            re.IGNORECASE,
        )
        for m in route_pat.finditer(content):
            lineno = content[: m.start()].count("\n") + 1
            result[lineno] = (m.group(1).upper(), m.group(2))
        return result

    def _nearest_route(self, lineno: int, handler_map: Dict[int, Tuple[str, str]], window: int = 60) -> Tuple[str, str]:
        best = (0, ("", ""))
        for hline, (method, route) in handler_map.items():
            if hline <= lineno <= hline + window:
                if hline > best[0]:
                    best = (hline, (method, route))
        return best[1]

    def _check_js_source_sink_flows(
        self,
        rel_path: str,
        content: str,
        lines: List[str],
        handler_map: Dict[int, Tuple[str, str]],
        issue: str,
    ) -> List[AgentFinding]:
        """
        For each security-sensitive sink, check whether user-controlled sources
        appear within a context window. Produce a finding only when both exist.
        """
        findings: List[AgentFinding] = []
        issue_lower = issue.lower()
        has_sanitization = bool(_JS_SANITIZATION.search(content))

        SINK_SPECS = [
            ("NoSQL Injection (Mongoose)", _JS_NOSQL_SINK,
             ["nosql", "injection", "mongo", "mongoose", "auth", "login", "query"],
             "CWE-943", Severity.CRITICAL),
            ("Command Injection via child_process", _JS_EXEC_SINK,
             ["command", "exec", "shell", "rce", "injection"],
             "CWE-78", Severity.CRITICAL),
            ("JavaScript Code Injection via eval/Function", _JS_EVAL_SINK,
             ["eval", "injection", "script", "code"],
             "CWE-95", Severity.CRITICAL),
            ("Path Traversal via filesystem operation", _JS_FS_SINK,
             ["file", "path", "traversal", "directory", "download", "read", "upload"],
             "CWE-22", Severity.HIGH),
            ("Open Redirect", _JS_REDIRECT_SINK,
             ["redirect", "url", "location", "open"],
             "CWE-601", Severity.MEDIUM),
            ("SQL Injection", _JS_SQL_SINK,
             ["sql", "injection", "query", "database"],
             "CWE-89", Severity.CRITICAL),
        ]

        seen_sinks: set = set()

        for sink_label, sink_pat, relevant_kws, cwe, severity in SINK_SPECS:
            if not any(kw in issue_lower for kw in relevant_kws):
                continue

            for sink_match in sink_pat.finditer(content):
                sink_lineno = content[: sink_match.start()].count("\n") + 1
                sink_key = (rel_path, sink_lineno, sink_label)
                if sink_key in seen_sinks:
                    continue

                ctx_start = max(0, sink_lineno - 15)
                ctx_end = min(len(lines), sink_lineno + 5)
                context_content = "\n".join(lines[ctx_start:ctx_end])

                src_match = _JS_REQ_SRC.search(context_content)
                if not src_match:
                    continue

                seen_sinks.add(sink_key)
                source_field = src_match.group(0)

                source_lineno: Optional[int] = None
                for i, line in enumerate(lines[ctx_start:ctx_end], start=ctx_start + 1):
                    if _JS_REQ_SRC.search(line):
                        source_lineno = i
                        break

                sink_line_content = lines[sink_lineno - 1].strip() if sink_lineno <= len(lines) else ""
                source_line_content = (
                    lines[source_lineno - 1].strip() if source_lineno and source_lineno <= len(lines) else ""
                )

                method, route = self._nearest_route(sink_lineno, handler_map)
                route_label = f"{method} {route}" if method else "(route unknown)"

                evidence = [
                    f"Sink line {sink_lineno}: {sink_line_content}",
                    f"Source: {source_field} reaches sink without sanitization",
                ]
                if source_lineno:
                    evidence.append(f"Source line {source_lineno}: {source_line_content}")
                if route:
                    evidence.append(f"Route handler: {route_label}")
                evidence.append(
                    "NOTE: Sanitization detected in file — verify this specific path is covered"
                    if has_sanitization
                    else "No input sanitization library detected in this file"
                )
                ctx_lines = [
                    f"  {ctx_start + i + 1}: {lines[ctx_start + i]}"
                    for i in range(min(8, ctx_end - ctx_start))
                ]
                evidence.extend(ctx_lines)

                if has_sanitization:
                    finding_severity = Severity.INFO
                    confidence = 0.35
                    title = f"{sink_label} — input appears sanitized"
                else:
                    finding_severity = severity
                    confidence = 0.82
                    title = f"{sink_label} — user input reaches sink"

                findings.append(AgentFinding(
                    title=title,
                    severity=finding_severity,
                    confidence=confidence,
                    files=[rel_path],
                    line_ranges=[
                        f"{source_lineno}" if source_lineno else "unknown",
                        f"{sink_lineno}",
                    ],
                    evidence=evidence,
                    recommendation=self._js_recommendation(cwe),
                    root_cause=self._js_root_cause(cwe, rel_path, sink_lineno),
                    finding_status=FindingStatus.CONFIRMED,
                    file_line_start=source_lineno or sink_lineno,
                    file_line_end=sink_lineno,
                    evidence_excerpt=sink_line_content,
                    source=source_field,
                    sink=sink_line_content[:100],
                    route=route_label,
                    technology="javascript/nodejs",
                    vulnerability_class=cwe,
                    provenance=(
                        f"CodeAgent: JS {sink_label} source->sink at {rel_path}:{sink_lineno} "
                        f"(source: {source_field})"
                    ),
                ))

        return findings

    @staticmethod
    def _js_recommendation(cwe: str) -> str:
        recs = {
            "CWE-943": (
                "Validate input fields are plain strings (typeof checks) or use "
                "mongo-sanitize / express-mongo-sanitize to strip MongoDB operators."
            ),
            "CWE-78": (
                "Avoid passing user input to exec/spawn. Use argument arrays and "
                "prefer child_process.execFile() with an allowlist-validated command."
            ),
            "CWE-95": "Never pass user input to eval() or new Function().",
            "CWE-22": (
                "Resolve absolute path and verify it starts within the base directory: "
                "path.resolve(base, userInput).startsWith(path.resolve(base))."
            ),
            "CWE-601": "Validate redirect targets against an allowlist before redirecting.",
            "CWE-89": "Use parameterized queries. Never concatenate user input into SQL.",
        }
        return recs.get(cwe, "Sanitize user input before passing to security-sensitive operations.")

    @staticmethod
    def _js_root_cause(cwe: str, rel_path: str, lineno: int) -> str:
        causes = {
            "CWE-943": (
                f"User request fields are passed directly into a MongoDB query filter at "
                f"{rel_path}:{lineno} without verifying they are plain strings. "
                "MongoDB interprets JSON objects as operators, enabling authentication bypass."
            ),
            "CWE-78": (
                f"User input flows into a shell command at {rel_path}:{lineno} without "
                "escaping or argument separation, enabling command injection."
            ),
            "CWE-95": (
                f"User input reaches eval/Function at {rel_path}:{lineno}, "
                "enabling execution of arbitrary attacker-controlled JavaScript."
            ),
            "CWE-22": (
                f"A filesystem path at {rel_path}:{lineno} is constructed from user input "
                "without canonical path boundary verification, enabling directory traversal."
            ),
            "CWE-601": (
                f"A redirect target at {rel_path}:{lineno} is derived from user input "
                "without allowlist validation."
            ),
            "CWE-89": (
                f"User input is concatenated into a SQL query at {rel_path}:{lineno} "
                "instead of being passed as a parameterized value."
            ),
        }
        return causes.get(cwe, "User input reaches a security-sensitive operation without validation.")

    # ══════════════════════════════════════════════════════════════════════════
    # Python analysis  (existing — preserved)
    # ══════════════════════════════════════════════════════════════════════════

    def _analyze_py(self, rel_path: str, content: str, issue: str) -> List[AgentFinding]:
        findings = []
        lines = content.split("\n")
        issue_lower = issue.lower()

        if any(w in issue_lower for w in ["authorization", "account", "access", "ownership", "bola", "idor"]):
            findings.extend(self._check_unverified_id_flow(rel_path, content, lines))

        findings.extend(self._check_path_traversal_flow(rel_path, content, lines))
        findings.extend(self._check_command_injection_flow(rel_path, content, lines))
        findings.extend(self._check_sql_injection_flow(rel_path, content, lines))
        findings.extend(self._check_missing_error_handling(rel_path, content, lines))
        findings.extend(self._check_direct_object_ref(rel_path, content, lines))

        return findings

    def _check_unverified_id_flow(self, rel_path: str, content: str, lines: List[str]) -> List[AgentFinding]:
        func_pattern = re.compile(r'def\s+(\w+)\s*\(([^)]*)\)')
        findings = []
        for m in func_pattern.finditer(content):
            func_name = m.group(1)
            params = m.group(2)
            if not re.search(r'\b\w*_?id\b', params, re.IGNORECASE):
                continue
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
                    finding_status=FindingStatus.CONFIRMED,
                    file_line_start=start_line + 1,
                    evidence_excerpt=f"def {func_name}({params.strip()})",
                    technology="python",
                ))
        return findings

    def _check_missing_error_handling(self, rel_path: str, content: str, lines: List[str]) -> List[AgentFinding]:
        findings = []
        db_lines = [
            i for i, line in enumerate(lines, 1)
            if re.search(r'\.execute\(|\.fetchone\(|\.fetchall\(', line)
        ]
        for lineno in db_lines:
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
                    finding_status=FindingStatus.CONFIRMED,
                    file_line_start=lineno,
                    evidence_excerpt=lines[lineno-1].strip(),
                    technology="python",
                ))
                break
        return findings

    def _check_direct_object_ref(self, rel_path: str, content: str, lines: List[str]) -> List[AgentFinding]:
        findings = []
        route_pattern = re.compile(
            r'@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']*\{(\w*id\w*)\}',
            re.IGNORECASE,
        )
        for m in route_pattern.finditer(content):
            lineno = content[:m.start()].count("\n") + 1
            method = m.group(1).upper()
            param = m.group(2)
            ahead = "\n".join(lines[lineno: lineno + 50])
            if not re.search(
                r'user_id.*current_user|current_user.*user_id|403|FORBIDDEN|verif|owner',
                ahead, re.IGNORECASE,
            ):
                findings.append(AgentFinding(
                    title="Route with direct object reference — ownership unchecked",
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
                    finding_status=FindingStatus.CONFIRMED,
                    file_line_start=lineno,
                    evidence_excerpt=lines[lineno-1].strip(),
                    technology="python",
                ))
        return findings

    def _check_path_traversal_flow(self, rel_path: str, content: str, lines: List[str]) -> List[AgentFinding]:
        findings = []
        func_pattern = re.compile(r'def\s+(\w+)\s*\(([^)]*)\)')
        for m in func_pattern.finditer(content):
            func_name = m.group(1)
            params = m.group(2)
            if not re.search(r'\b(?:filename|file_name|filepath|file_path|file|path)\b', params, re.IGNORECASE):
                continue
            start_line = content[:m.start()].count("\n")
            body_lines = lines[start_line: start_line + 40]
            body = "\n".join(body_lines)
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
                    finding_status=FindingStatus.CONFIRMED,
                    file_line_start=start_line + 1,
                    evidence_excerpt=f"def {func_name}({params.strip()})",
                    technology="python",
                ))
        return findings

    def _check_command_injection_flow(self, rel_path: str, content: str, lines: List[str]) -> List[AgentFinding]:
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
                    finding_status=FindingStatus.CONFIRMED,
                    file_line_start=start_line + 1,
                    evidence_excerpt=f"def {func_name}({params.strip()})",
                    technology="python",
                ))
        return findings

    def _check_sql_injection_flow(self, rel_path: str, content: str, lines: List[str]) -> List[AgentFinding]:
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
                    finding_status=FindingStatus.CONFIRMED,
                    file_line_start=i,
                    evidence_excerpt=line.strip(),
                    technology="python",
                ))
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_code_files(self, repo_path: str) -> List[str]:
        result = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for f in files:
                if f.endswith((".py", ".js", ".ts", ".mjs")):
                    result.append(os.path.relpath(os.path.join(root, f), repo_path))
        return result
