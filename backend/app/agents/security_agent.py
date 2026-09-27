"""
Security Investigation Agent
Analyzes the reported security issue against the repository source code.
Identifies vulnerable data flows, missing checks, attack paths, and root causes.

Every finding is annotated with FindingStatus:
- CONFIRMED: has file + line + evidence excerpt from actual source
- HYPOTHESIS: pattern suggests vulnerability but missing definitive evidence
- UNSUPPORTED: analysis cannot be performed for this technology/pattern
"""
import os
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional

from app.agents.base import BaseAgent
from app.models import (
    AgentFinding, AgentResult, AgentStatus,
    FindingStatus, Investigation, Severity,
)

# ── Vulnerability pattern library ─────────────────────────────────────────────
VULN_PATTERNS = {
    "bola_missing_ownership": {
        "patterns": [
            r"def\s+get_\w+\s*\(.*?(?:_id|Id)\s*:.*?current_user",
            r"WHERE\s+id\s*=\s*\?",
            r"\.fetchone\(\)",
        ],
        "anti_patterns": [
            r"user_id.*current_user",
            r"verif\w+.*owner",
            r"if.*user_id\s*!=\s*current",
        ],
        "severity": Severity.CRITICAL,
        "title": "Broken Object Level Authorization (BOLA)",
        "cwe": "CWE-639",
    },
    "sql_injection": {
        "patterns": [
            r'execute\s*\(\s*[f"\']\s*SELECT.*\{',
            r'execute\s*\(\s*".*"\s*%\s*',
            r"cursor\.execute\(.*\+",
        ],
        "anti_patterns": [r"execute\(.*,\s*\(", r"execute\(.*,\s*\["],
        "severity": Severity.CRITICAL,
        "title": "SQL Injection",
        "cwe": "CWE-89",
    },
    "missing_auth": {
        "patterns": [
            r"@router\.(get|post|put|delete)\(",
            r"@app\.(get|post|put|delete)\(",
        ],
        "anti_patterns": [
            r"Depends\(get_current_user\)",
            r"Depends\(.*auth",
            r"@login_required",
            r"@jwt_required",
        ],
        "severity": Severity.HIGH,
        "title": "Missing Authentication",
        "cwe": "CWE-306",
    },
    "hardcoded_secret": {
        "patterns": [
            r'(?:secret|password|api_key|token)\s*=\s*["\'][^"\']{8,}["\']',
            r'SECRET_KEY\s*=\s*["\'][^"\']+["\']',
        ],
        "anti_patterns": [r"os\.environ", r"os\.getenv", r"config\["],
        "severity": Severity.HIGH,
        "title": "Hardcoded Secret",
        "cwe": "CWE-798",
    },
    "path_traversal": {
        "patterns": [
            r'open\s*\(.*(?:filename|file_name|path|file_path|target)',
            r'os\.path\.join\s*\(.*(?:filename|file_name|filepath|file_path|file|path)',
            r'Path\s*\(.*(?:filename|file_name|file_path|path)',
            r'FileResponse\s*\(.*(?:filename|file_name|path)',
        ],
        "anti_patterns": [
            r"os\.path\.basename",
            r"commonpath",
            r"startswith\s*\(.*base",
            r"\.resolve\(\)\.is_relative_to",
            r"sanitize",
        ],
        "severity": Severity.HIGH,
        "title": "Path Traversal",
        "cwe": "CWE-22",
    },
    "command_injection": {
        "patterns": [
            r'subprocess\.(?:run|Popen|call|check_output)\s*\(.*shell\s*=\s*True',
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
        ],
        "anti_patterns": [
            r'shlex\.quote',
            r'shell\s*=\s*False',
            r'isinstance\(.*list\)',
        ],
        "severity": Severity.CRITICAL,
        "title": "Command Injection",
        "cwe": "CWE-78",
    },
}

IGNORE_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}

# ── JavaScript / Node.js / Express supplemental rules ────────────────────────
# Applied only when the file is .js and the investigation involves NoSQL/injection.

JS_NOSQL_PATTERNS = [
    # Model.find({ field: req.body.x })  — no sanitization wrapper
    re.compile(
        r'\w+\s*\.\s*(?:find|findOne|findById|countDocuments)\s*\(\s*\{[^}]*req\.(body|query|params)',
        re.DOTALL,
    ),
]

JS_NOSQL_ANTI_PATTERNS = [
    re.compile(r"mongo(?:db)?-sanitize|mongoSanitize|express-mongo-sanitize", re.IGNORECASE),
    re.compile(r"typeof\s+req\.(body|query)\.\w+\s*===?\s*['\"]string['\"]", re.IGNORECASE),
]


class SecurityAgent(BaseAgent):
    name = "security_agent"

    async def _execute(self, investigation: Investigation) -> AgentResult:
        repo_path = investigation.repository_path
        if not repo_path or not os.path.isdir(repo_path):
            return AgentResult(
                agent=self.name,
                status=AgentStatus.FAILED,
                error="Repository path not available",
                summary="Cannot analyze — repository not found.",
            )

        issue = investigation.issue_description.lower()
        relevant_files = self._get_relevant_files(repo_path, issue)
        findings = []

        for rel_path in relevant_files:
            fpath = os.path.join(repo_path, rel_path)
            try:
                content = Path(fpath).read_text(errors="ignore")
            except Exception:
                continue

            file_findings = self._analyze_file(rel_path, content, issue)
            findings.extend(file_findings)

        # Deduplicate by title
        seen = set()
        unique = []
        for f in findings:
            key = (f.title, tuple(f.files))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        # Do NOT fall through to heuristic analysis — if no pattern-based findings exist,
        # the result is 0 findings, not a fabricated fallback.
        # The heuristic analysis was removed in the evidence-first redesign.

        severity = max(
            (f.severity for f in unique),
            key=lambda s: ["info","low","medium","high","critical"].index(s),
            default=Severity.INFO,
        )
        investigation.severity = severity

        return AgentResult(
            agent=self.name,
            status=AgentStatus.COMPLETED,
            findings=unique,
            summary=(
                f"Analyzed {len(relevant_files)} relevant files. "
                f"Found {len(unique)} security finding(s). "
                f"Highest severity: {severity}."
            ),
        )

    # ── File relevance scoring ────────────────────────────────────────────────

    def _get_relevant_files(self, repo_path: str, issue: str) -> List[str]:
        keywords = self._extract_keywords(issue)
        scored: List[Tuple[str, int]] = []

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for fname in files:
                if not fname.endswith((".py", ".js", ".ts", ".java", ".go", ".rb")):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, repo_path)
                score = 0

                # Filename relevance
                for kw in keywords:
                    if kw in fname.lower():
                        score += 3
                    if kw in rel_path.lower():
                        score += 2

                # Content relevance (quick scan)
                try:
                    snippet = Path(fpath).read_text(errors="ignore")[:5000]
                    for kw in keywords:
                        score += snippet.lower().count(kw)
                except Exception:
                    pass

                if score > 0:
                    scored.append((rel_path, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [p for p, _ in scored[:20]]

    def _extract_keywords(self, issue: str) -> List[str]:
        stop = {"a", "an", "the", "is", "in", "of", "to", "and", "or",
                "that", "may", "can", "be", "with", "by", "for", "on"}
        words = re.findall(r'\b[a-z_]+\b', issue.lower())
        kws = [w for w in words if w not in stop and len(w) > 2]
        # Add domain-specific expansions
        expansions = {
            "authorization": ["auth", "ownership", "access"],
            "authentication": ["login", "token", "jwt"],
            "account": ["accounts", "balance", "user_id"],
            "injection": ["sql", "query", "execute"],
        }
        extra = []
        for kw in kws:
            extra.extend(expansions.get(kw, []))
        return list(dict.fromkeys(kws + extra))

    # ── Pattern-based analysis ────────────────────────────────────────────────

    def _analyze_file(
        self, rel_path: str, content: str, issue: str
    ) -> List[AgentFinding]:
        findings = []
        lines = content.split("\n")

        for vuln_id, vuln in VULN_PATTERNS.items():
            if not self._is_relevant_to_issue(vuln_id, issue):
                continue

            hit_lines = []
            for i, line in enumerate(lines, 1):
                for pat in vuln["patterns"]:
                    if re.search(pat, line, re.IGNORECASE):
                        hit_lines.append(i)

            if not hit_lines:
                continue

            # Check for mitigating patterns
            mitigated = any(
                re.search(ap, content, re.IGNORECASE)
                for ap in vuln.get("anti_patterns", [])
            )
            if mitigated:
                continue

            evidence = self._build_evidence(vuln_id, content, lines, hit_lines)
            attack_path = self._build_attack_path(vuln_id, rel_path, content)

            # Derive evidence_excerpt from first hit line
            first_hit_line = lines[hit_lines[0] - 1].strip() if hit_lines else ""
            findings.append(AgentFinding(
                title=vuln["title"],
                severity=vuln["severity"],
                confidence=0.91 if hit_lines else 0.5,
                files=[rel_path],
                line_ranges=[f"{min(hit_lines)}-{max(hit_lines)}"],
                evidence=evidence,
                recommendation=self._get_recommendation(vuln_id),
                attack_path=attack_path,
                root_cause=self._get_root_cause(vuln_id),
                # Evidence-grounded status
                finding_status=FindingStatus.CONFIRMED,
                file_line_start=min(hit_lines),
                file_line_end=max(hit_lines),
                evidence_excerpt=first_hit_line,
                technology=self._tech_from_path(rel_path),
                vulnerability_class=vuln_id,
                provenance=f"SecurityAgent: pattern '{vuln_id}' matched at {rel_path}:{min(hit_lines)}-{max(hit_lines)}",
            ))

        # ── JavaScript-specific NoSQL injection analysis ──────────────────
        if rel_path.endswith(".js") or rel_path.endswith(".ts"):
            findings.extend(self._analyze_js_nosql(rel_path, content, lines, issue))

        return findings

    def _analyze_js_nosql(
        self, rel_path: str, content: str, lines: list, issue: str
    ) -> "List[AgentFinding]":
        """
        Detect NoSQL injection patterns in JavaScript files.
        Only produces a finding when both:
        1. A Mongoose query receives req.body/query/params in the filter object.
        2. No operator-sanitization library is detected in the file.
        """
        nosql_keywords = ["nosql", "injection", "mongo", "authentication", "login", "query"]
        if not any(kw in issue.lower() for kw in nosql_keywords):
            return []

        # Check mitigations at file level
        if any(p.search(content) for p in JS_NOSQL_ANTI_PATTERNS):
            return []

        findings = []
        for pat in JS_NOSQL_PATTERNS:
            for m in pat.finditer(content):
                line_number = content[: m.start()].count("\n") + 1
                raw = lines[line_number - 1].strip() if line_number <= len(lines) else ""

                # Extract what req source is used (body/query/params)
                req_source = m.group(1) if m.lastindex and m.lastindex >= 1 else "body/query"

                # Gather surrounding context for evidence (up to 4 lines)
                ctx_start = max(0, line_number - 2)
                ctx_end = min(len(lines), line_number + 3)
                context = [
                    f"  {ctx_start + i + 1}: {lines[ctx_start + i]}"
                    for i in range(ctx_end - ctx_start)
                ]

                findings.append(AgentFinding(
                    title="NoSQL Injection — Mongoose query receives unsanitized request input",
                    severity=Severity.CRITICAL,
                    files=[rel_path],
                    line_ranges=[f"{line_number}"],
                    evidence=[
                        f"Line {line_number}: {raw}",
                        f"Request source: req.{req_source} passed directly into Mongoose filter object",
                        "MongoDB operator injection possible: attacker can supply "
                        '{"$gt": ""} or {"$ne": null} instead of a string value',
                        "No operator-sanitization library (mongo-sanitize / express-mongo-sanitize) detected",
                    ] + context,
                    recommendation=(
                        "Validate that authentication inputs are plain strings before passing to "
                        "Mongoose queries.  Use mongo-sanitize or express-mongo-sanitize to strip "
                        "MongoDB operators from request objects.  "
                        "Example: const clean = sanitize(req.body); User.find({username: clean.username, ...})"
                    ),
                    attack_path=[
                        f"Attacker sends JSON body to POST route in {rel_path}",
                        f'Payload: {{"username": "victim@example.com", "password": {{"$gt": ""}}}}',
                        f"req.{req_source} is passed directly to Mongoose .find() filter",
                        "MongoDB evaluates $gt operator: all non-empty passwords match",
                        "Authentication succeeds without valid credentials",
                    ],
                    root_cause=(
                        f"The Mongoose query in {rel_path} line {line_number} accepts "
                        f"req.{req_source} fields as filter values without ensuring they are "
                        "plain strings.  MongoDB interprets JSON objects as query operators "
                        "(e.g. $gt, $ne, $regex), allowing an attacker to bypass string comparison."
                    ),
                    # Evidence-grounded status
                    finding_status=FindingStatus.CONFIRMED,
                    file_line_start=line_number,
                    evidence_excerpt=raw,
                    source=f"req.{req_source}",
                    sink="Mongoose.findOne({})",
                    technology="javascript/nodejs",
                    provenance=f"SecurityAgent: JS NoSQL injection pattern at {rel_path}:{line_number}",
                ))

        return findings

    def _is_relevant_to_issue(self, vuln_id: str, issue: str) -> bool:
        relevance = {
            "bola_missing_ownership": ["authorization", "access", "account", "profile", "ownership", "idor", "bola"],
            "sql_injection": ["sql", "injection", "query", "database"],
            "missing_auth": ["authentication", "unauthorized", "unauthenticated"],
            "hardcoded_secret": ["secret", "credential", "key", "password", "token"],
            "path_traversal": ["path", "file", "traversal", "directory", "download", "read"],
            "command_injection": ["command", "exec", "shell", "rce", "subprocess", "os.system"],
        }
        keywords = relevance.get(vuln_id, [])
        return any(kw in issue for kw in keywords) or not keywords

    def _build_evidence(
        self, vuln_id: str, content: str, lines: List[str], hit_lines: List[int]
    ) -> List[str]:
        evidence = []
        for lineno in hit_lines[:5]:
            evidence.append(f"Line {lineno}: {lines[lineno-1].strip()}")

        if vuln_id == "bola_missing_ownership":
            if re.search(r"WHERE\s+id\s*=", content, re.IGNORECASE):
                evidence.append("Database query uses externally-controlled ID without ownership filter")
            if not re.search(r"user_id.*current_user|current_user.*user_id", content):
                evidence.append("No user_id cross-check against current_user found in function scope")
        elif vuln_id == "path_traversal":
            evidence.append("File path constructed with user-controlled input without canonical path boundary verification")
        elif vuln_id == "command_injection":
            evidence.append("Operating system command executed with shell=True using user-controlled parameters")

        return evidence

    def _build_attack_path(self, vuln_id: str, rel_path: str, content: str) -> List[str]:
        paths = {
            "bola_missing_ownership": [
                "Attacker authenticates with valid credentials",
                f"Attacker sends request to endpoint in {rel_path}",
                "Request carries victim's resource ID in path/query",
                "Authentication check ✓ — token is valid",
                "Authorization check ✗ — ownership NOT verified",
                "Database returns victim's resource",
                "Attacker receives unauthorized data",
            ],
            "sql_injection": [
                "Attacker submits malicious SQL payload in input field",
                f"Input reaches database query in {rel_path}",
                "Input is concatenated/formatted directly into query string",
                "Database executes attacker-controlled SQL",
                "Attacker extracts, modifies, or deletes data",
            ],
            "missing_auth": [
                f"Endpoint in {rel_path} is publicly accessible",
                "No authentication dependency declared on route",
                "Any unauthenticated caller can invoke endpoint",
                "Sensitive data returned without identity check",
            ],
            "path_traversal": [
                f"Attacker submits path traversal sequence (e.g. `../../etc/passwd`) to endpoint in {rel_path}",
                "Endpoint constructs file path using user input without boundary enforcement",
                "Path resolution escapes the intended base directory",
                "Application reads and returns arbitrary server files to attacker",
            ],
            "command_injection": [
                f"Attacker submits command metacharacters (e.g. `; id` or `& whoami`) to endpoint in {rel_path}",
                "Input reaches shell command formatted with shell=True",
                "Shell executes arbitrary attacker-supplied commands with server privileges",
                "Attacker obtains full remote command execution",
            ],
        }
        return paths.get(vuln_id, ["Vulnerability exploited via crafted request"])

    def _get_recommendation(self, vuln_id: str) -> str:
        recs = {
            "bola_missing_ownership": (
                "After fetching the resource, verify that resource.user_id == current_user.id. "
                "If not, raise HTTP 403 Forbidden."
            ),
            "sql_injection": (
                "Use parameterized queries (cursor.execute(sql, (param,))) instead of string formatting."
            ),
            "missing_auth": (
                "Add Depends(get_current_user) to the route function signature."
            ),
            "hardcoded_secret": (
                "Move secret to environment variable and load with os.environ.get()."
            ),
            "path_traversal": (
                "Validate that the resolved path is within the allowed base directory using "
                "os.path.commonpath([base_dir, resolved_path]) == base_dir, or restrict to os.path.basename(). "
                "Raise HTTP 403 Forbidden if traversal is attempted."
            ),
            "command_injection": (
                "Avoid shell=True. Pass arguments as a list to subprocess.run(..., shell=False) and validate input."
            ),
        }
        return recs.get(vuln_id, "Review and remediate the identified vulnerability.")

    def _get_root_cause(self, vuln_id: str) -> str:
        causes = {
            "bola_missing_ownership": (
                "The API verifies that the requester is authenticated (token validation) but does not "
                "verify that the authenticated user is the owner of the requested resource. "
                "The resource ID is fully controlled by the caller."
            ),
            "sql_injection": (
                "User-controlled input is directly interpolated into a SQL query string "
                "rather than being passed as a parameterized value, allowing SQL syntax injection."
            ),
            "missing_auth": (
                "The route handler does not declare an authentication dependency, "
                "making the endpoint accessible to unauthenticated callers."
            ),
            "path_traversal": (
                "The endpoint constructs filesystem paths using user-supplied parameters without verifying "
                "that the canonical path remains within the designated directory boundary."
            ),
            "command_injection": (
                "User input is concatenated into an operating system command and passed to a shell interpreter, "
                "allowing shell command chaining and arbitrary execution."
            ),
        }
        return causes.get(vuln_id, "Insufficient input validation or access control.")

    # Heuristic fallback REMOVED in evidence-first redesign.
    # Generic keyword-based findings cannot be CONFIRMED without actual source evidence.
    # If pattern analysis finds nothing, the result is 0 confirmed findings.

    @staticmethod
    def _tech_from_path(rel_path: str) -> str:
        """Derive the technology label from the file extension.

        Rules:
        - .py  → python
        - .js  → javascript/nodejs
        - .ts  → typescript/nodejs
        - .rb  → ruby
        - .go  → go
        - .java → java
        Never hardcoded to a single language.
        """
        if rel_path.endswith(".py"):
            return "python"
        if rel_path.endswith(".js"):
            return "javascript/nodejs"
        if rel_path.endswith(".ts"):
            return "typescript/nodejs"
        if rel_path.endswith(".rb"):
            return "ruby"
        if rel_path.endswith(".go"):
            return "go"
        if rel_path.endswith(".java"):
            return "java"
        return "unknown"
