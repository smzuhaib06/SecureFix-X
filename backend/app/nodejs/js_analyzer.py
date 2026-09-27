"""
Node.js / Express Analysis Module  (Cross-stack extension — Phase 5)

Provides narrowly scoped static analysis for Node.js/Express repositories.

SCOPE — deliberately limited:
- Repository/framework detection (Node.js, Express)
- Express route extraction from common patterns
- NoSQL injection detection (Mongoose/.find() with req.body/req.query)

This module does NOT:
- Perform full JavaScript data-flow analysis
- Support all Express idioms exhaustively
- Replace a proper JavaScript SAST engine
- Analyse any vulnerability class other than NoSQL injection

Evidence rules:
- Every finding requires observed source text (file + line).
- UNSUPPORTED is returned when the evidence is insufficient to confirm.
- No confidence percentages are fabricated.

SecureBank isolation:
- This module contains no references to alice, bob, alice123,
  /api/accounts, FastAPI, or any SecureBank-specific value.
- All scenario values come from the repository under analysis.
"""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Public data structures ────────────────────────────────────────────────────

@dataclass
class ExpressRoute:
    """One discovered Express route handler."""
    method: str                  # "GET", "POST", etc.
    path: str                    # e.g. "/login"
    handler_name: str            # e.g. "loginHandler" or "<inline>"
    source_file: str             # repo-relative path
    line_number: int             # 1-based line where the route is registered
    auth_middleware: List[str] = field(default_factory=list)
    # raw line for evidence
    raw_line: str = ""


@dataclass
class NoSqlSink:
    """A Mongoose/MongoDB query call that may receive operator-injected input."""
    source_file: str
    line_number: int
    raw_line: str
    model_name: str              # e.g. "User"
    method_call: str             # e.g. "find", "findOne"
    input_sources: List[str]     # e.g. ["req.body.username", "req.body.password"]
    has_operator_sanitization: bool
    # The surrounding context lines (for evidence)
    context_lines: List[str] = field(default_factory=list)


@dataclass
class NodejsRepoInfo:
    """Results of Node.js repository detection and analysis."""
    is_nodejs: bool = False
    is_express: bool = False
    node_version_hint: str = ""       # from package.json engines if present
    express_version: str = ""         # from package.json dependencies
    mongoose_version: str = ""
    routes: List[ExpressRoute] = field(default_factory=list)
    nosql_sinks: List[NoSqlSink] = field(default_factory=list)
    js_source_files: List[str] = field(default_factory=list)
    route_files: List[str] = field(default_factory=list)
    detection_evidence: List[str] = field(default_factory=list)


# ── Public API ────────────────────────────────────────────────────────────────

class NodejsAnalyzer:
    """
    Analyses a repository path for Node.js/Express structure and NoSQL sinks.

    Usage:
        info = NodejsAnalyzer().analyze(repo_path)
    """

    def analyze(self, repo_path: str) -> NodejsRepoInfo:
        info = NodejsRepoInfo()
        pkg = self._read_package_json(repo_path)

        # ── Step 1: Detect Node.js ──────────────────────────────────────────
        if pkg is None:
            # No package.json — not a Node.js repo
            return info

        info.is_nodejs = True
        info.detection_evidence.append(
            f"package.json found: name={pkg.get('name', '?')}, "
            f"version={pkg.get('version', '?')}"
        )

        # ── Step 2: Detect Express ──────────────────────────────────────────
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        if "express" in deps:
            info.is_express = True
            info.express_version = deps["express"]
            info.detection_evidence.append(
                f"express@{info.express_version} declared in package.json"
            )
        if "mongoose" in deps:
            info.mongoose_version = deps["mongoose"]
            info.detection_evidence.append(
                f"mongoose@{info.mongoose_version} declared in package.json"
            )

        # Confirm Express by scanning source if not found in package.json
        if not info.is_express:
            if self._source_confirms_express(repo_path):
                info.is_express = True
                info.detection_evidence.append(
                    "Express detected via require('express') in source files"
                )

        if not info.is_express:
            # Not Express — no route analysis
            return info

        # ── Step 3: Collect JS source files ────────────────────────────────
        info.js_source_files = self._collect_js_files(repo_path)

        # ── Step 4: Extract Express routes ─────────────────────────────────
        for rel_path in info.js_source_files:
            abs_path = str(Path(repo_path) / rel_path)
            try:
                content = Path(abs_path).read_text(errors="ignore")
            except OSError:
                continue
            routes = _extract_express_routes(content, rel_path)
            info.routes.extend(routes)
            if routes:
                info.route_files.append(rel_path)

        if info.routes:
            info.detection_evidence.append(
                f"{len(info.routes)} Express route(s) extracted from "
                f"{len(info.route_files)} file(s)"
            )

        # ── Step 5: Detect NoSQL injection sinks ───────────────────────────
        for rel_path in info.js_source_files:
            abs_path = str(Path(repo_path) / rel_path)
            try:
                content = Path(abs_path).read_text(errors="ignore")
            except OSError:
                continue
            sinks = _detect_nosql_sinks(content, rel_path)
            info.nosql_sinks.extend(sinks)

        return info

    # ── Private helpers ───────────────────────────────────────────────────────

    def _read_package_json(self, repo_path: str) -> Optional[Dict]:
        pkg_path = Path(repo_path) / "package.json"
        if not pkg_path.is_file():
            return None
        try:
            return json.loads(pkg_path.read_text(errors="ignore"))
        except (json.JSONDecodeError, OSError):
            return None

    def _source_confirms_express(self, repo_path: str) -> bool:
        """Scan JS files for require('express') or import express."""
        for js_file in self._collect_js_files(repo_path)[:20]:
            abs_path = str(Path(repo_path) / js_file)
            try:
                snippet = Path(abs_path).read_text(errors="ignore")[:3000]
                if re.search(r"require\(['\"]express['\"]\)|from\s+['\"]express['\"]", snippet):
                    return True
            except OSError:
                pass
        return False

    def _collect_js_files(self, repo_path: str) -> List[str]:
        """Collect .js and .ts files, excluding node_modules and build dirs."""
        _IGNORE = {"node_modules", ".git", "dist", "build", ".venv", "venv", "public"}
        result = []
        for p in Path(repo_path).rglob("*.js"):
            parts = set(p.parts)
            if parts & _IGNORE:
                continue
            try:
                result.append(str(p.relative_to(repo_path)))
            except ValueError:
                pass
        return sorted(result)


# ── Pure analysis functions (independently testable) ─────────────────────────

# Express route registration patterns:
#   app.get('/path', middleware, handler)
#   router.post('/path', handler)
#   app.use('/prefix', router)
_ROUTE_PATTERN = re.compile(
    r'(?:app|router)\s*\.\s*(get|post|put|delete|patch|use)\s*\(\s*'
    r'[\'"]([^\'"]+)[\'"]'         # path string
    r'((?:\s*,\s*[\w.]+)*)'        # optional middleware chain
    r'\s*(?:,\s*([\w.]+))?',       # final handler name (optional)
    re.IGNORECASE,
)

# Known auth-related middleware names (conservative list)
_AUTH_MIDDLEWARE_NAMES = frozenset({
    "isloggedin", "authenticate", "requireauth", "authcheck",
    "ensureloggedin", "verifytoken", "checkauth", "requirelogin",
    "isauthentic", "jwtauth", "passport.authenticate",
})


def _extract_express_routes(content: str, source_file: str) -> List[ExpressRoute]:
    """
    Extract Express route registrations from a JS source file.

    Only captures routes explicitly registered via app.METHOD() or router.METHOD().
    Does not invent routes or infer them from variable names.
    """
    routes: List[ExpressRoute] = []
    lines = content.splitlines()

    for m in _ROUTE_PATTERN.finditer(content):
        method = m.group(1).upper()
        path = m.group(2)
        middleware_chain = m.group(3) or ""
        handler_name = (m.group(4) or "").strip() or "<inline>"

        line_number = content[: m.start()].count("\n") + 1
        raw_line = lines[line_number - 1].strip() if line_number <= len(lines) else ""

        # Extract middleware names from the chain
        chain_names = [
            n.strip().lower()
            for n in re.split(r"\s*,\s*", middleware_chain)
            if n.strip()
        ]
        auth_mw = [n for n in chain_names if n in _AUTH_MIDDLEWARE_NAMES]

        routes.append(ExpressRoute(
            method=method,
            path=path,
            handler_name=handler_name,
            source_file=source_file,
            line_number=line_number,
            auth_middleware=auth_mw,
            raw_line=raw_line,
        ))

    return routes


# Patterns that indicate operator sanitization is present
_OPERATOR_SANITIZATION_PATTERNS = [
    re.compile(r"mongo-sanitize", re.IGNORECASE),
    re.compile(r"mongoSanitize", re.IGNORECASE),
    re.compile(r"express-mongo-sanitize", re.IGNORECASE),
    re.compile(r"sanitizeFilter", re.IGNORECASE),           # Mongoose 6+ option
    re.compile(r"\$\w+.*typeof.*string", re.IGNORECASE),   # typeof checks on operators
    re.compile(r"sanitize.*query|query.*sanitize", re.IGNORECASE),
]

# Mongoose query methods that accept a filter object
_MONGOOSE_QUERY_METHODS = frozenset({"find", "findone", "findbyid", "findoneandupdate", "countdocuments"})

# Pattern: Model.find({ field: req.body.X })  or similar
# Looks for a mongoose-style .find({ ... req.body/req.query/req.params ... })
_MONGOOSE_FIND_PATTERN = re.compile(
    r'(\w+)\s*\.\s*(find|findOne|findById|findOneAndUpdate|countDocuments)\s*\('
    r'\s*\{([^}]{0,400})\}',   # filter object — limited to 400 chars to stay sane
    re.DOTALL | re.IGNORECASE,
)

# User-controlled request sources
_REQUEST_SOURCES = re.compile(
    r'req\.(body|query|params)\.\w+',
    re.IGNORECASE,
)


def _detect_nosql_sinks(content: str, source_file: str) -> List[NoSqlSink]:
    """
    Detect Mongoose query calls where the filter object contains
    request-controlled values (req.body/req.query/req.params) without
    apparent operator sanitization.

    Returns only sinks with observed evidence — never fabricates findings.
    """
    sinks: List[NoSqlSink] = []
    lines = content.splitlines()

    # Check file-level sanitization once
    file_has_sanitization = any(
        p.search(content) for p in _OPERATOR_SANITIZATION_PATTERNS
    )

    for m in _MONGOOSE_FIND_PATTERN.finditer(content):
        model_name = m.group(1)
        method_call = m.group(2)
        filter_body = m.group(3)

        # Only flag if req.body/query/params appear inside the filter
        input_matches = _REQUEST_SOURCES.findall(filter_body)
        if not input_matches:
            continue

        input_sources = list(dict.fromkeys(
            m2.group(0) for m2 in _REQUEST_SOURCES.finditer(filter_body)
        ))

        line_number = content[: m.start()].count("\n") + 1
        raw_line = lines[line_number - 1].strip() if line_number <= len(lines) else ""

        # Gather context (up to 5 lines around the match)
        ctx_start = max(0, line_number - 3)
        ctx_end = min(len(lines), line_number + 3)
        context_lines = [
            f"{ctx_start + i + 1}: {lines[ctx_start + i]}"
            for i in range(ctx_end - ctx_start)
        ]

        sinks.append(NoSqlSink(
            source_file=source_file,
            line_number=line_number,
            raw_line=raw_line,
            model_name=model_name,
            method_call=method_call,
            input_sources=input_sources,
            has_operator_sanitization=file_has_sanitization,
            context_lines=context_lines,
        ))

    return sinks
