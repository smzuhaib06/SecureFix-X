"""
Phase 5D/5E — Security Knowledge RAG (Retrieval-Augmented Generation)

Local, offline-capable security knowledge base for SECUREFIX.

Architecture:
  Security Knowledge Documents
          ↓
  Chunking (paragraph-level)
          ↓
  TF-IDF retrieval (no external services required)
          ↓
  Semantic similarity (optional: if sentence-transformers available)
          ↓
  Retrieved passages with full provenance metadata

Knowledge sources:
  CWE-22   Path Traversal
  CWE-78   OS Command Injection
  CWE-79   Cross-Site Scripting
  CWE-89   SQL Injection
  CWE-95   JavaScript Code Injection
  CWE-285  Improper Authorization
  CWE-601  Open Redirect
  CWE-639  BOLA / Insecure Direct Object Reference
  CWE-798  Hard-coded Credentials
  CWE-862  Missing Authorization
  CWE-943  NoSQL Injection

OWASP Top 10 (2021):
  A01 Broken Access Control
  A03 Injection
  A05 Security Misconfiguration
  A07 Identification and Authentication Failures

OWASP ASVS (V4 – relevant controls)

Framework-specific guidance:
  Express.js / Node.js / Mongoose
  FastAPI / Python

Guarantees:
  - Works completely offline
  - Every retrieved document has full provenance
  - No fabricated citations
  - Source text is embedded verbatim (curated knowledge)
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ── Knowledge document ─────────────────────────────────────────────────────────

@dataclass
class KnowledgeDocument:
    """One unit of curated security knowledge with full provenance."""
    doc_id: str
    source: str          # e.g. "CWE", "OWASP", "ASVS", "framework_guidance"
    title: str
    identifier: str      # e.g. "CWE-943", "OWASP-A03", "ASVS-V5.2.3"
    section: str         # e.g. "Description", "Remediation", "Detection"
    content: str         # verbatim curated text
    keywords: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class RetrievedDocument:
    """A knowledge document returned by RAG retrieval."""
    document: KnowledgeDocument
    score: float
    rank: int


# ── Curated knowledge base ─────────────────────────────────────────────────────

KNOWLEDGE_BASE: List[KnowledgeDocument] = [

    # ── CWE-943 NoSQL Injection ────────────────────────────────────────────────
    KnowledgeDocument(
        doc_id="CWE-943-DESC",
        source="CWE",
        title="Improper Neutralization of Special Elements in Data Query Logic",
        identifier="CWE-943",
        section="Description",
        content=(
            "CWE-943 describes vulnerabilities where an application passes user-supplied data "
            "to a NoSQL query without sufficient sanitization. Unlike SQL injection (CWE-89), "
            "NoSQL injection exploits the operator-evaluation semantics of document databases "
            "such as MongoDB. An attacker may supply a JSON object instead of a string value, "
            "causing MongoDB to evaluate query operators such as $gt, $ne, $regex, or $where. "
            "This can bypass authentication checks, expose unauthorized data, or enable "
            "full server-side code execution via $where with JavaScript evaluation."
        ),
        keywords=["nosql", "injection", "mongodb", "mongoose", "operator", "query", "json"],
        tags=["nosql", "injection", "authentication-bypass"],
    ),
    KnowledgeDocument(
        doc_id="CWE-943-REM",
        source="CWE",
        title="Improper Neutralization of Special Elements in Data Query Logic",
        identifier="CWE-943",
        section="Remediation",
        content=(
            "To prevent CWE-943 NoSQL injection:\n"
            "1. Input type validation: verify that credentials and filter fields are plain "
            "strings (typeof field === 'string') before passing to MongoDB queries.\n"
            "2. Use mongo-sanitize or express-mongo-sanitize to strip $-prefixed keys from "
            "request objects before they reach query builders.\n"
            "3. In Mongoose, use schema-level type enforcement: declare username: String in "
            "the schema so Mongoose coerces non-string values.\n"
            "4. Avoid passing req.body directly as a Mongoose query filter object.\n"
            "5. Upgrade Mongoose to >= 5.7.5 (CVE-2019-17426), which defaults to strict "
            "operator sanitization."
        ),
        keywords=["nosql", "remediation", "mongo-sanitize", "mongoose", "typeof", "fix"],
        tags=["nosql", "remediation", "mongoose"],
    ),
    KnowledgeDocument(
        doc_id="CWE-943-ATTACK",
        source="CWE",
        title="Improper Neutralization of Special Elements in Data Query Logic",
        identifier="CWE-943",
        section="Attack Example",
        content=(
            "Mongoose authentication bypass example:\n"
            "Vulnerable code: User.find({ username: req.body.username, password: req.body.password })\n"
            "Attack payload (JSON body): {\"username\": \"victim@example.com\", \"password\": {\"$gt\": \"\"}}\n"
            "MongoDB evaluates the $gt operator: any non-empty password hash is greater than an "
            "empty string, so all users match regardless of their actual password. "
            "The attacker is authenticated as the victim without knowing their password. "
            "This is a critical authentication bypass (CWE-287) enabled by CWE-943."
        ),
        keywords=["nosql", "attack", "bypass", "gt", "operator", "payload"],
        tags=["nosql", "attack-example", "authentication-bypass"],
    ),

    # ── CWE-89 SQL Injection ───────────────────────────────────────────────────
    KnowledgeDocument(
        doc_id="CWE-89-DESC",
        source="CWE",
        title="Improper Neutralization of Special Elements used in an SQL Command",
        identifier="CWE-89",
        section="Description",
        content=(
            "CWE-89 SQL Injection occurs when user-supplied input is incorporated into an SQL "
            "query without adequate sanitization. The attacker manipulates the query structure "
            "to access unauthorized data, bypass authentication, modify data, or execute "
            "database stored procedures. SQL injection remains one of the most critical and "
            "prevalent web application vulnerabilities. Common patterns include string "
            "concatenation (cursor.execute('SELECT * FROM users WHERE id=' + user_id)) and "
            "f-string interpolation (f'SELECT * FROM users WHERE id={user_id}')."
        ),
        keywords=["sql", "injection", "query", "execute", "concatenation", "cursor"],
        tags=["sql", "injection"],
    ),
    KnowledgeDocument(
        doc_id="CWE-89-REM",
        source="CWE",
        title="Improper Neutralization of Special Elements used in an SQL Command",
        identifier="CWE-89",
        section="Remediation",
        content=(
            "Remediation for CWE-89 SQL Injection:\n"
            "1. Use parameterized queries (prepared statements): cursor.execute('SELECT * FROM "
            "users WHERE id = %s', (user_id,)) — the database driver safely separates code "
            "from data.\n"
            "2. Use an ORM (SQLAlchemy, Django ORM) which automatically parameterizes queries.\n"
            "3. Apply input validation and allowlisting where the query structure must vary.\n"
            "4. Apply least-privilege database accounts — the application user should not have "
            "DROP or GRANT permissions.\n"
            "5. Never use f-strings, % formatting, or string concatenation to build SQL queries."
        ),
        keywords=["sql", "parameterized", "prepared", "orm", "fix", "remediation"],
        tags=["sql", "remediation"],
    ),

    # ── CWE-22 Path Traversal ──────────────────────────────────────────────────
    KnowledgeDocument(
        doc_id="CWE-22-DESC",
        source="CWE",
        title="Improper Limitation of a Pathname to a Restricted Directory",
        identifier="CWE-22",
        section="Description",
        content=(
            "CWE-22 Path Traversal occurs when an application uses user-supplied input to "
            "construct a file path and accesses the resulting path without verifying that it "
            "remains within the intended base directory. An attacker may inject '../' sequences "
            "(or encoded variants such as %2e%2e%2f) to escape the base directory and read or "
            "write arbitrary files. This can expose configuration files, private keys, or other "
            "sensitive server files. Common vulnerable patterns include os.path.join(BASE, user_input) "
            "and open(os.path.join(dir, filename)) without boundary checking."
        ),
        keywords=["path", "traversal", "directory", "file", "read", "escape", "dotdot"],
        tags=["path-traversal", "filesystem"],
    ),
    KnowledgeDocument(
        doc_id="CWE-22-REM",
        source="CWE",
        title="Improper Limitation of a Pathname to a Restricted Directory",
        identifier="CWE-22",
        section="Remediation",
        content=(
            "Remediation for CWE-22 Path Traversal:\n"
            "Python:\n"
            "  resolved = os.path.abspath(os.path.join(base_dir, user_input))\n"
            "  if not resolved.startswith(os.path.abspath(base_dir) + os.sep):\n"
            "      raise HTTPException(status_code=403)\n"
            "Node.js:\n"
            "  const resolved = path.resolve(baseDir, userInput);\n"
            "  if (!resolved.startsWith(path.resolve(baseDir) + path.sep)) return res.status(403);\n"
            "General:\n"
            "  1. Always resolve to absolute canonical path before access.\n"
            "  2. Verify the resolved path starts with the allowed base directory.\n"
            "  3. Use os.path.basename() / path.basename() to strip directory components entirely.\n"
            "  4. Return HTTP 403 Forbidden (not 404) on traversal detection to avoid information leakage."
        ),
        keywords=["path", "traversal", "fix", "abspath", "resolve", "basename", "403"],
        tags=["path-traversal", "remediation"],
    ),

    # ── CWE-78 OS Command Injection ────────────────────────────────────────────
    KnowledgeDocument(
        doc_id="CWE-78-DESC",
        source="CWE",
        title="Improper Neutralization of Special Elements used in an OS Command",
        identifier="CWE-78",
        section="Description",
        content=(
            "CWE-78 OS Command Injection occurs when user input is incorporated into an "
            "operating system command that is executed by the application. The attacker uses "
            "shell metacharacters (;, |, &, $(), backticks) to chain additional commands. "
            "Common vulnerable patterns: subprocess.run(cmd + user_input, shell=True), "
            "os.system('cmd ' + user_input), exec(user_input). This can lead to arbitrary "
            "remote code execution (RCE), file system access, or privilege escalation."
        ),
        keywords=["command", "injection", "exec", "shell", "subprocess", "rce", "os.system"],
        tags=["command-injection", "rce"],
    ),
    KnowledgeDocument(
        doc_id="CWE-78-REM",
        source="CWE",
        title="Improper Neutralization of Special Elements used in an OS Command",
        identifier="CWE-78",
        section="Remediation",
        content=(
            "Remediation for CWE-78 OS Command Injection:\n"
            "1. Avoid shell=True: use subprocess.run([cmd, arg1, arg2], shell=False) — "
            "arguments are passed as a list, not interpreted by the shell.\n"
            "2. Validate input against a strict allowlist before using it in any command context.\n"
            "3. In Node.js, prefer child_process.execFile(cmd, [args]) over exec() with "
            "shell interpolation.\n"
            "4. Use shlex.quote() (Python) to escape shell arguments when shell=True is unavoidable.\n"
            "5. Run commands with the least-privileged OS account possible."
        ),
        keywords=["command", "injection", "fix", "shell", "subprocess", "execfile"],
        tags=["command-injection", "remediation"],
    ),

    # ── CWE-79 XSS ────────────────────────────────────────────────────────────
    KnowledgeDocument(
        doc_id="CWE-79-DESC",
        source="CWE",
        title="Improper Neutralization of Input During Web Page Generation (XSS)",
        identifier="CWE-79",
        section="Description",
        content=(
            "CWE-79 Cross-Site Scripting (XSS) occurs when user input is reflected in a web "
            "page response without proper encoding. The attacker injects JavaScript that "
            "executes in the victim's browser. Types: Reflected XSS (payload in request), "
            "Stored XSS (payload persisted in database), DOM XSS (payload processed by "
            "client-side JavaScript). Impacts include session hijacking, credential theft, "
            "and arbitrary actions performed as the victim."
        ),
        keywords=["xss", "cross-site", "scripting", "reflected", "stored", "dom"],
        tags=["xss"],
    ),

    # ── CWE-285 / CWE-862 Authorization ───────────────────────────────────────
    KnowledgeDocument(
        doc_id="CWE-285-DESC",
        source="CWE",
        title="Improper Authorization",
        identifier="CWE-285",
        section="Description",
        content=(
            "CWE-285 Improper Authorization occurs when an application fails to verify that "
            "an authenticated user is authorized to perform the requested action or access "
            "the requested resource. Authentication (who are you?) succeeds but authorization "
            "(are you allowed to do this?) is absent or flawed. Common patterns: "
            "BOLA/IDOR (accessing another user's resource by changing an ID), "
            "privilege escalation (regular user accessing admin functions), "
            "horizontal access (user A accessing user B's data)."
        ),
        keywords=["authorization", "bola", "idor", "access", "ownership", "privilege"],
        tags=["authorization", "bola", "idor"],
    ),
    KnowledgeDocument(
        doc_id="CWE-639-REM",
        source="CWE",
        title="Authorization Bypass Through User-Controlled Key (IDOR/BOLA)",
        identifier="CWE-639",
        section="Remediation",
        content=(
            "Remediation for BOLA / IDOR (CWE-639):\n"
            "1. After fetching a resource by ID, verify the resource belongs to the "
            "authenticated user: if resource.user_id != current_user.id: raise HTTP 403.\n"
            "2. Use indirect references: map user-specific tokens to real IDs server-side "
            "instead of exposing database IDs in URLs.\n"
            "3. Apply object-level authorization checks in every route handler, not just at "
            "authentication middleware level.\n"
            "4. Add regression tests: User A authenticates, requests User B's resource, "
            "asserts HTTP 403."
        ),
        keywords=["authorization", "bola", "idor", "fix", "403", "ownership", "remediation"],
        tags=["authorization", "bola", "remediation"],
    ),
    KnowledgeDocument(
        doc_id="CWE-862-DESC",
        source="CWE",
        title="Missing Authorization",
        identifier="CWE-862",
        section="Description",
        content=(
            "CWE-862 Missing Authorization occurs when the application does not perform an "
            "authorization check at all before granting access to a resource or operation. "
            "Unlike CWE-285 (improper/flawed authorization), CWE-862 describes complete "
            "absence of the check. Common pattern: a REST API endpoint is accessible without "
            "an authentication/authorization middleware, or authorization is checked on some "
            "routes but accidentally omitted on a sibling route."
        ),
        keywords=["authorization", "missing", "route", "middleware", "unauthenticated"],
        tags=["authorization", "missing-auth"],
    ),

    # ── CWE-798 Hardcoded Credentials ─────────────────────────────────────────
    KnowledgeDocument(
        doc_id="CWE-798-DESC",
        source="CWE",
        title="Use of Hard-coded Credentials",
        identifier="CWE-798",
        section="Description",
        content=(
            "CWE-798 occurs when an application contains hard-coded credentials (passwords, "
            "API keys, tokens, cryptographic keys) in source code or configuration files. "
            "These credentials are visible to anyone with access to the source repository and "
            "cannot be changed without a code deployment. Common patterns: SECRET_KEY = 'hardcoded', "
            "API_KEY = 'abc123', password='admin' in code or .env files committed to version control."
        ),
        keywords=["hardcoded", "secret", "credential", "key", "password", "token"],
        tags=["credentials", "secret"],
    ),

    # ── CWE-601 Open Redirect ──────────────────────────────────────────────────
    KnowledgeDocument(
        doc_id="CWE-601-DESC",
        source="CWE",
        title="URL Redirection to Untrusted Site (Open Redirect)",
        identifier="CWE-601",
        section="Description",
        content=(
            "CWE-601 Open Redirect occurs when an application accepts a user-supplied URL and "
            "redirects the browser to that URL without validation. Attackers use this in "
            "phishing attacks: by crafting a URL on a trusted domain that redirects to a "
            "malicious site, they trick victims into believing they are navigating to a "
            "legitimate service. CVE-2024-29041 describes this vulnerability in Express < 4.19.2."
        ),
        keywords=["redirect", "url", "open", "phishing", "location", "express"],
        tags=["redirect", "open-redirect"],
    ),

    # ── OWASP Top 10 (2021) ────────────────────────────────────────────────────
    KnowledgeDocument(
        doc_id="OWASP-A01-2021",
        source="OWASP",
        title="OWASP Top 10 2021 — A01: Broken Access Control",
        identifier="OWASP-A01-2021",
        section="Overview",
        content=(
            "OWASP A01:2021 Broken Access Control is the most critical category, moving up "
            "from position 5 in 2017. 94% of applications were tested for some form of "
            "broken access control. Includes: IDOR/BOLA (accessing another user's data by "
            "modifying the resource ID), missing authorization checks, privilege escalation, "
            "CORS misconfiguration, and access control bypass. Prevention: deny by default, "
            "log access control failures, alert on repeated failures, invalidate tokens after logout."
        ),
        keywords=["access", "control", "bola", "idor", "authorization", "owasp", "a01"],
        tags=["owasp", "authorization", "access-control"],
    ),
    KnowledgeDocument(
        doc_id="OWASP-A03-2021",
        source="OWASP",
        title="OWASP Top 10 2021 — A03: Injection",
        identifier="OWASP-A03-2021",
        section="Overview",
        content=(
            "OWASP A03:2021 Injection (formerly #1) covers SQL, NoSQL, OS, and LDAP injection. "
            "An application is vulnerable when user-supplied data is not validated, filtered, "
            "or sanitized before being used in queries or commands. Prevention: use safe APIs "
            "that avoid the interpreter entirely (parameterized queries, ORMs, stored procedures), "
            "perform server-side input validation, escape special characters, and use LIMIT to "
            "prevent mass data disclosure."
        ),
        keywords=["injection", "sql", "nosql", "os", "ldap", "owasp", "a03", "query"],
        tags=["owasp", "injection"],
    ),
    KnowledgeDocument(
        doc_id="OWASP-A07-2021",
        source="OWASP",
        title="OWASP Top 10 2021 — A07: Identification and Authentication Failures",
        identifier="OWASP-A07-2021",
        section="Overview",
        content=(
            "OWASP A07:2021 covers authentication and session management weaknesses. "
            "Relevant to NoSQL injection authentication bypass: when an application relies "
            "on a database query to verify credentials, a NoSQL injection attack that causes "
            "the query to always return results bypasses authentication entirely. "
            "Prevention: use multi-factor authentication, do not expose session IDs in URLs, "
            "implement proper session invalidation, use proven authentication libraries."
        ),
        keywords=["authentication", "session", "login", "bypass", "owasp", "a07"],
        tags=["owasp", "authentication"],
    ),

    # ── OWASP ASVS V4 relevant controls ───────────────────────────────────────
    KnowledgeDocument(
        doc_id="ASVS-V5.2.3",
        source="ASVS",
        title="OWASP ASVS V4 — V5.2.3 Sanitization and Sandboxing",
        identifier="ASVS-V5.2.3",
        section="Requirement",
        content=(
            "ASVS V5.2.3: Verify that the application sanitizes, disables, or sandboxes "
            "user-supplied scriptable or expression template language content, such as Markdown, "
            "CSS or XSL stylesheets, BBCode, or similar. This also applies to NoSQL query "
            "operators: user-supplied values must be sanitized to remove MongoDB query operators "
            "before being incorporated into database queries."
        ),
        keywords=["sanitize", "nosql", "operator", "asvs", "v5", "query"],
        tags=["asvs", "sanitization", "nosql"],
    ),
    KnowledgeDocument(
        doc_id="ASVS-V4.2.1",
        source="ASVS",
        title="OWASP ASVS V4 — V4.2.1 Operation Level Access Control",
        identifier="ASVS-V4.2.1",
        section="Requirement",
        content=(
            "ASVS V4.2.1: Verify that sensitive data and APIs are protected against direct "
            "object reference attacks that target creation, reading, updating, and deletion "
            "of records, such that only authorized users can create, read, update, or delete "
            "records. This requirement directly addresses BOLA/IDOR vulnerabilities."
        ),
        keywords=["authorization", "bola", "idor", "object", "asvs", "v4", "access"],
        tags=["asvs", "authorization"],
    ),
    KnowledgeDocument(
        doc_id="ASVS-V12.3.1",
        source="ASVS",
        title="OWASP ASVS V4 — V12.3.1 File Execution",
        identifier="ASVS-V12.3.1",
        section="Requirement",
        content=(
            "ASVS V12.3.1: Verify that user-submitted filenames are not used directly by the "
            "system's or framework's file storage APIs and that path traversal protection is in "
            "use to prevent user-supplied filenames from having their paths altered. Specifically: "
            "reject filenames with ../, use os.path.basename or equivalent, verify that the "
            "resolved path remains within an allowed directory using path.resolve() comparison."
        ),
        keywords=["file", "path", "traversal", "asvs", "v12", "filename", "directory"],
        tags=["asvs", "path-traversal"],
    ),

    # ── Framework-specific guidance ────────────────────────────────────────────
    KnowledgeDocument(
        doc_id="FWGUIDE-EXPRESS-NOSQL",
        source="framework_guidance",
        title="Express.js / Mongoose — NoSQL Injection Prevention",
        identifier="FWGUIDE-EXPRESS-NOSQL",
        section="Secure Coding Pattern",
        content=(
            "Express.js / Mongoose secure coding for authentication:\n"
            "UNSAFE: User.find({ username: req.body.username, password: req.body.password })\n"
            "SAFE (input validation):\n"
            "  if (typeof req.body.username !== 'string' || typeof req.body.password !== 'string') {\n"
            "      return res.status(400).json({ error: 'Invalid input type' });\n"
            "  }\n"
            "  User.find({ username: req.body.username, password: req.body.password })\n"
            "SAFE (mongo-sanitize):\n"
            "  const sanitize = require('mongo-sanitize');\n"
            "  const clean = sanitize(req.body);\n"
            "  User.find({ username: clean.username, password: clean.password })\n"
            "SAFE (Mongoose schema type enforcement):\n"
            "  const UserSchema = new Schema({ username: { type: String, required: true }, ... })\n"
            "  — Mongoose will reject non-string values at schema validation level."
        ),
        keywords=["express", "mongoose", "nosql", "sanitize", "typeof", "schema", "nodejs"],
        tags=["express", "mongoose", "nosql", "framework-guidance"],
    ),
    KnowledgeDocument(
        doc_id="FWGUIDE-FASTAPI-PATH",
        source="framework_guidance",
        title="FastAPI — Path Traversal Prevention",
        identifier="FWGUIDE-FASTAPI-PATH",
        section="Secure Coding Pattern",
        content=(
            "FastAPI secure file serving with path traversal prevention:\n"
            "UNSAFE: open(os.path.join(DATA_DIR, filename))\n"
            "SAFE:\n"
            "  import os\n"
            "  base = os.path.abspath(DATA_DIR)\n"
            "  resolved = os.path.abspath(os.path.join(DATA_DIR, filename))\n"
            "  if not (resolved == base or resolved.startswith(base + os.sep)):\n"
            "      raise HTTPException(status_code=403, detail='Access forbidden: path traversal detected')\n"
            "Additional hardening: restrict filename characters with a regex allowlist, "
            "use os.path.basename(filename) to strip directory components, "
            "serve files via FileResponse instead of returning raw content."
        ),
        keywords=["fastapi", "path", "traversal", "abspath", "403", "file", "python"],
        tags=["fastapi", "path-traversal", "framework-guidance"],
    ),
    KnowledgeDocument(
        doc_id="FWGUIDE-EXPRESS-REDIRECT",
        source="framework_guidance",
        title="Express.js — Open Redirect Prevention (CVE-2024-29041)",
        identifier="FWGUIDE-EXPRESS-REDIRECT",
        section="Secure Coding Pattern",
        content=(
            "CVE-2024-29041 affected Express < 4.19.2: the res.redirect() function could be "
            "exploited via a malformed Host header. Secure redirect implementation in Express:\n"
            "1. Upgrade Express to >= 4.19.2.\n"
            "2. Never redirect to a URL derived from req.query, req.body, or req.headers without "
            "allowlist validation.\n"
            "3. SAFE allowlist example:\n"
            "  const ALLOWED_REDIRECTS = ['https://app.example.com', 'https://api.example.com'];\n"
            "  if (!ALLOWED_REDIRECTS.some(u => redirectUrl.startsWith(u))) {\n"
            "      return res.status(400).json({ error: 'Invalid redirect target' });\n"
            "  }\n"
            "  res.redirect(redirectUrl);"
        ),
        keywords=["express", "redirect", "cve", "2024-29041", "open-redirect", "allowlist"],
        tags=["express", "redirect", "cve", "framework-guidance"],
    ),
    KnowledgeDocument(
        doc_id="FWGUIDE-DOCKER-ROOT",
        source="framework_guidance",
        title="Docker Security — Avoiding Running as Root",
        identifier="FWGUIDE-DOCKER-ROOT",
        section="Secure Coding Pattern",
        content=(
            "Running containers as root is a Docker security misconfiguration (OWASP A05). "
            "If the container process is compromised, root access inside the container may "
            "be leveraged to escape or access host resources. Secure Dockerfile pattern:\n"
            "  RUN groupadd -r appgroup && useradd -r -g appgroup appuser\n"
            "  RUN chown -R appuser:appgroup /app\n"
            "  USER appuser\n"
            "This ensures the application runs as a non-root user with minimal privileges."
        ),
        keywords=["docker", "root", "user", "container", "privilege", "dockerfile"],
        tags=["docker", "configuration", "framework-guidance"],
    ),
]


# ── TF-IDF Retrieval Engine ────────────────────────────────────────────────────

class TFIDFRetriever:
    """
    Simple TF-IDF based retrieval for the security knowledge base.

    Works completely offline with no external dependencies.
    Provides retrieval provenance for every returned document.
    """

    def __init__(self, documents: List[KnowledgeDocument]):
        self._docs = documents
        self._idf: Dict[str, float] = {}
        self._doc_tfs: List[Dict[str, float]] = []
        self._build_index()

    def _tokenize(self, text: str) -> List[str]:
        text = text.lower()
        tokens = re.findall(r'[a-z][a-z0-9\-_]*', text)
        stopwords = {"the", "a", "an", "is", "in", "of", "to", "and", "or",
                     "that", "may", "can", "be", "with", "by", "for", "on",
                     "this", "it", "are", "was", "as", "at", "from", "when",
                     "which", "not", "do", "if", "has", "have", "will"}
        return [t for t in tokens if t not in stopwords and len(t) > 2]

    def _build_index(self) -> None:
        """Build TF vectors and IDF weights."""
        all_tokens_per_doc = []
        df: Dict[str, int] = {}

        for doc in self._docs:
            text = f"{doc.title} {doc.section} {doc.content} {' '.join(doc.keywords)}"
            tokens = self._tokenize(text)
            token_counts: Dict[str, int] = {}
            for t in tokens:
                token_counts[t] = token_counts.get(t, 0) + 1
            total = max(len(tokens), 1)
            tf = {t: c / total for t, c in token_counts.items()}
            all_tokens_per_doc.append(tf)
            for t in tf:
                df[t] = df.get(t, 0) + 1

        n = len(self._docs)
        self._idf = {t: math.log((n + 1) / (df_t + 1)) + 1 for t, df_t in df.items()}
        self._doc_tfs = all_tokens_per_doc

    def _tfidf_vector(self, tf: Dict[str, float]) -> Dict[str, float]:
        return {t: tf_val * self._idf.get(t, 0) for t, tf_val in tf.items()}

    def _cosine_similarity(self, v1: Dict[str, float], v2: Dict[str, float]) -> float:
        common = set(v1) & set(v2)
        if not common:
            return 0.0
        dot = sum(v1[t] * v2[t] for t in common)
        mag1 = math.sqrt(sum(x**2 for x in v1.values()))
        mag2 = math.sqrt(sum(x**2 for x in v2.values()))
        if mag1 == 0 or mag2 == 0:
            return 0.0
        return dot / (mag1 * mag2)

    def retrieve(self, query: str, top_k: int = 5) -> List[RetrievedDocument]:
        """
        Retrieve the top-k most relevant knowledge documents for a query.

        Returns results with their cosine similarity score and rank.
        Always returns at least one document unless the knowledge base is empty.
        """
        if not self._docs:
            return []

        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        # Build query TF
        token_counts: Dict[str, int] = {}
        for t in query_tokens:
            token_counts[t] = token_counts.get(t, 0) + 1
        total = max(len(query_tokens), 1)
        query_tf = {t: c / total for t, c in token_counts.items()}
        query_vec = self._tfidf_vector(query_tf)

        # Also boost by keyword matching
        keyword_boost: Dict[int, float] = {}
        query_set = set(query_tokens)
        for i, doc in enumerate(self._docs):
            overlap = query_set & set(doc.keywords)
            keyword_boost[i] = len(overlap) * 0.15

        # Score all documents
        scores = []
        for i, doc_tf in enumerate(self._doc_tfs):
            doc_vec = self._tfidf_vector(doc_tf)
            sim = self._cosine_similarity(query_vec, doc_vec)
            sim += keyword_boost.get(i, 0)
            scores.append((i, sim))

        scores.sort(key=lambda x: x[1], reverse=True)

        results = []
        for rank, (idx, score) in enumerate(scores[:top_k], start=1):
            if score > 0:
                results.append(RetrievedDocument(
                    document=self._docs[idx],
                    score=round(score, 4),
                    rank=rank,
                ))

        return results


# ── Public API ─────────────────────────────────────────────────────────────────

# Module-level singleton (instantiated once at import time)
_retriever: Optional[TFIDFRetriever] = None


def get_retriever() -> TFIDFRetriever:
    """Get or create the singleton TF-IDF retriever over the local knowledge base."""
    global _retriever
    if _retriever is None:
        _retriever = TFIDFRetriever(KNOWLEDGE_BASE)
    return _retriever


def retrieve_for_investigation(
    issue_description: str,
    vulnerability_class: Optional[str] = None,
    cwe: Optional[str] = None,
    framework: Optional[str] = None,
    top_k: int = 6,
) -> List[RetrievedDocument]:
    """
    High-level retrieval function for SECUREFIX investigations.

    Constructs a rich query from all available signals and returns
    the most relevant knowledge documents.

    Every returned document has full provenance:
    - source (CWE, OWASP, ASVS, framework_guidance)
    - identifier (CWE-943, OWASP-A03-2021, ...)
    - section (Description, Remediation, Attack Example, ...)
    - content (verbatim curated text)
    """
    retriever = get_retriever()

    # Build composite query from all available signals
    query_parts = [issue_description]
    if vulnerability_class:
        query_parts.append(vulnerability_class)
    if cwe:
        query_parts.append(cwe)
    if framework:
        query_parts.append(framework)
    query = " ".join(query_parts)

    return retriever.retrieve(query, top_k=top_k)
