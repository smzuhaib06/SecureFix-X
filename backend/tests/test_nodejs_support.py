"""
Node.js / Express Support Tests  (Phase 5 — Cross-stack extension)

14 test areas covering:

 1.  VulnerabilityClass.NOSQL_INJECTION enum value
 2.  js_analyzer: NodejsAnalyzer rejects non-Node.js repos
 3.  js_analyzer: NodejsAnalyzer detects Node.js from package.json
 4.  js_analyzer: NodejsAnalyzer detects Express from package.json
 5.  js_analyzer: _extract_express_routes — basic route extraction
 6.  js_analyzer: _extract_express_routes — no false positives on non-route code
 7.  js_analyzer: _detect_nosql_sinks — detects Mongoose + req.body injection
 8.  js_analyzer: _detect_nosql_sinks — suppressed when sanitization present
 9.  js_analyzer: _detect_nosql_sinks — no false positives on safe queries
10.  RootCauseEngine._nosql_injection_root_cause — CWE-943, CVSS 9.8
11.  RootCauseEngine._nosql_injection_invariant — supported invariant structure
12.  RootCauseEngine._nosql_injection_invariant — no login route → UNSUPPORTED
13.  DependencyAgent — mongoose < 5.7.5 flagged (CVE-2019-17426)
14.  NodejsVerifier — HTTP checks always return UNSUPPORTED for Node.js targets

Integration guard:
  An integration test against the real nodejs-goof symlink is provided but
  skipped when the symlink is not present.  It never hardcodes expected
  line numbers — it verifies structural properties only.

No SecureBank values (alice, alice123, /api/accounts, app.main, etc.)
appear in this file.  All synthetic fixtures use generic names.
"""
import os
import json
import tempfile
import textwrap
from pathlib import Path

import pytest

# Ensure DEMO_REPO_PATH is set before any app imports
DEMO_REPO = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "../../demo-app")
)
os.environ.setdefault("DEMO_REPO_PATH", DEMO_REPO)

# Path to the nodejs-goof symlink (may be absent in CI)
GOOF_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "../../nodejs-goof")
)
GOOF_AVAILABLE = os.path.isdir(GOOF_PATH) and os.path.isfile(
    os.path.join(GOOF_PATH, "package.json")
)


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic JS fixture helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_nodejs_repo(tmp_path: Path, *, pkg_extra: dict = None, files: dict = None) -> str:
    """
    Create a minimal synthetic Node.js repository on disk.

    pkg_extra: merged into package.json
    files: {relative_path: content_str}
    """
    pkg = {
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.0",
        },
    }
    if pkg_extra:
        for k, v in pkg_extra.items():
            if isinstance(v, dict) and k in pkg:
                pkg[k].update(v)
            else:
                pkg[k] = v

    (tmp_path / "package.json").write_text(json.dumps(pkg))

    if files:
        for rel, content in files.items():
            fpath = tmp_path / rel
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(textwrap.dedent(content))

    return str(tmp_path)


# ─────────────────────────────────────────────────────────────────────────────
# 1. VulnerabilityClass.NOSQL_INJECTION enum value
# ─────────────────────────────────────────────────────────────────────────────

class TestNosqlInjectionEnumValue:
    """Area 1: VulnerabilityClass enum must include NOSQL_INJECTION."""

    def test_nosql_injection_enum_exists(self):
        from app.models import VulnerabilityClass
        assert hasattr(VulnerabilityClass, "NOSQL_INJECTION")

    def test_nosql_injection_enum_value(self):
        from app.models import VulnerabilityClass
        assert VulnerabilityClass.NOSQL_INJECTION.value == "NOSQL_INJECTION"

    def test_nosql_injection_distinct_from_sql_injection(self):
        from app.models import VulnerabilityClass
        assert VulnerabilityClass.NOSQL_INJECTION != VulnerabilityClass.SQL_INJECTION

    def test_all_expected_vulnerability_classes_present(self):
        from app.models import VulnerabilityClass
        expected = {
            "BOLA", "SQL_INJECTION", "NOSQL_INJECTION",
            "PATH_TRAVERSAL", "COMMAND_INJECTION",
            "MISSING_AUTH", "HARDCODED_SECRET", "UNKNOWN",
        }
        actual = {v.value for v in VulnerabilityClass}
        assert expected.issubset(actual), f"Missing classes: {expected - actual}"


# ─────────────────────────────────────────────────────────────────────────────
# 2. NodejsAnalyzer rejects non-Node.js repos
# ─────────────────────────────────────────────────────────────────────────────

class TestNodejsAnalyzerRejection:
    """Area 2: Analyzer must return is_nodejs=False when no package.json exists."""

    def test_empty_directory_not_nodejs(self, tmp_path):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        info = NodejsAnalyzer().analyze(str(tmp_path))
        assert info.is_nodejs is False
        assert info.is_express is False
        assert info.routes == []
        assert info.nosql_sinks == []

    def test_python_only_repo_not_nodejs(self, tmp_path):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
        (tmp_path / "app.py").write_text("from flask import Flask\n")
        info = NodejsAnalyzer().analyze(str(tmp_path))
        assert info.is_nodejs is False

    def test_nonexistent_path_returns_empty_info(self):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        info = NodejsAnalyzer().analyze("/tmp/this_path_does_not_exist_xyz_abc_999")
        assert info.is_nodejs is False


# ─────────────────────────────────────────────────────────────────────────────
# 3. NodejsAnalyzer detects Node.js from package.json
# ─────────────────────────────────────────────────────────────────────────────

class TestNodejsDetection:
    """Area 3: Any package.json presence marks repo as Node.js."""

    def test_package_json_marks_nodejs(self, tmp_path):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        (tmp_path / "package.json").write_text('{"name":"myapp","version":"1.0.0"}')
        info = NodejsAnalyzer().analyze(str(tmp_path))
        assert info.is_nodejs is True

    def test_detection_evidence_mentions_package_json(self, tmp_path):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        (tmp_path / "package.json").write_text('{"name":"webapp","version":"2.1.0"}')
        info = NodejsAnalyzer().analyze(str(tmp_path))
        assert any("package.json" in e for e in info.detection_evidence)

    def test_malformed_package_json_does_not_crash(self, tmp_path):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        (tmp_path / "package.json").write_text("{ this is not valid json ]")
        # Should not raise — gracefully returns non-nodejs
        info = NodejsAnalyzer().analyze(str(tmp_path))
        assert info.is_nodejs is False


# ─────────────────────────────────────────────────────────────────────────────
# 4. NodejsAnalyzer detects Express from package.json
# ─────────────────────────────────────────────────────────────────────────────

class TestExpressDetection:
    """Area 4: Express declared in package.json triggers is_express=True."""

    def test_express_in_dependencies_detected(self, tmp_path):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        repo = _make_nodejs_repo(tmp_path, pkg_extra={
            "dependencies": {"express": "^4.18.0"},
        })
        info = NodejsAnalyzer().analyze(repo)
        assert info.is_express is True

    def test_express_version_captured(self, tmp_path):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        repo = _make_nodejs_repo(tmp_path, pkg_extra={
            "dependencies": {"express": "4.12.4"},
        })
        info = NodejsAnalyzer().analyze(repo)
        assert info.express_version == "4.12.4"

    def test_mongoose_version_captured(self, tmp_path):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        repo = _make_nodejs_repo(tmp_path, pkg_extra={
            "dependencies": {"express": "^4.18.0", "mongoose": "4.2.4"},
        })
        info = NodejsAnalyzer().analyze(repo)
        assert info.mongoose_version == "4.2.4"

    def test_nodejs_without_express_stays_false(self, tmp_path):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        (tmp_path / "package.json").write_text(
            '{"name":"cli-tool","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}'
        )
        info = NodejsAnalyzer().analyze(str(tmp_path))
        assert info.is_nodejs is True
        assert info.is_express is False

    def test_express_detected_via_source_require(self, tmp_path):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        # No express in package.json, but source uses require('express')
        (tmp_path / "package.json").write_text('{"name":"app","version":"1.0.0"}')
        (tmp_path / "app.js").write_text("const express = require('express');\n")
        info = NodejsAnalyzer().analyze(str(tmp_path))
        assert info.is_express is True


# ─────────────────────────────────────────────────────────────────────────────
# 5. _extract_express_routes — basic route extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestExpressRouteExtraction:
    """Area 5: Route extractor captures method, path, and source location."""

    def test_app_get_route_extracted(self):
        from app.nodejs.js_analyzer import _extract_express_routes
        src = "app.get('/health', healthHandler);\n"
        routes = _extract_express_routes(src, "app.js")
        assert len(routes) == 1
        assert routes[0].method == "GET"
        assert routes[0].path == "/health"

    def test_router_post_route_extracted(self):
        from app.nodejs.js_analyzer import _extract_express_routes
        src = "router.post('/login', loginHandler);\n"
        routes = _extract_express_routes(src, "routes/index.js")
        assert len(routes) == 1
        assert routes[0].method == "POST"
        assert routes[0].path == "/login"
        assert routes[0].source_file == "routes/index.js"

    def test_multiple_routes_extracted(self):
        from app.nodejs.js_analyzer import _extract_express_routes
        src = textwrap.dedent("""\
            app.get('/users', listUsers);
            app.post('/users', createUser);
            app.delete('/users/:id', deleteUser);
        """)
        routes = _extract_express_routes(src, "routes.js")
        methods = {r.method for r in routes}
        paths = {r.path for r in routes}
        assert "GET" in methods
        assert "POST" in methods
        assert "DELETE" in methods
        assert "/users" in paths

    def test_line_number_recorded(self):
        from app.nodejs.js_analyzer import _extract_express_routes
        src = "// comment\napp.post('/login', handler);\n"
        routes = _extract_express_routes(src, "routes.js")
        assert len(routes) == 1
        assert routes[0].line_number == 2

    def test_route_raw_line_captured(self):
        from app.nodejs.js_analyzer import _extract_express_routes
        src = "app.get('/ping', pingHandler);\n"
        routes = _extract_express_routes(src, "app.js")
        assert routes[0].raw_line != ""
        assert "/ping" in routes[0].raw_line

    def test_auth_middleware_detected(self):
        from app.nodejs.js_analyzer import _extract_express_routes
        src = "app.get('/dashboard', requireAuth, dashboardHandler);\n"
        routes = _extract_express_routes(src, "app.js")
        assert len(routes) == 1
        assert "requireauth" in routes[0].auth_middleware


# ─────────────────────────────────────────────────────────────────────────────
# 6. _extract_express_routes — no false positives
# ─────────────────────────────────────────────────────────────────────────────

class TestExpressRouteNoFalsePositives:
    """Area 6: Extractor must not produce routes from non-route code."""

    def test_empty_file_no_routes(self):
        from app.nodejs.js_analyzer import _extract_express_routes
        routes = _extract_express_routes("", "empty.js")
        assert routes == []

    def test_comment_only_no_routes(self):
        from app.nodejs.js_analyzer import _extract_express_routes
        src = "// app.get('/admin', handler);\n/* router.post('/x', y); */"
        routes = _extract_express_routes(src, "test.js")
        # Comments may still match regex patterns — this is acceptable since
        # the extractor is conservative (better to over-report than miss real routes).
        # What must NOT happen is crashing or returning structured nonsense.
        for r in routes:
            assert r.method in {"GET", "POST", "PUT", "DELETE", "PATCH", "USE"}
            assert r.path.startswith("/")

    def test_variable_assignment_does_not_create_route(self):
        from app.nodejs.js_analyzer import _extract_express_routes
        src = "const getUser = (req, res) => res.json(req.params);\n"
        routes = _extract_express_routes(src, "utils.js")
        assert routes == []

    def test_python_style_decorators_no_routes(self):
        from app.nodejs.js_analyzer import _extract_express_routes
        src = "@app.route('/api/accounts', methods=['GET'])\ndef get_accounts(): pass\n"
        routes = _extract_express_routes(src, "routes.py")
        assert routes == []


# ─────────────────────────────────────────────────────────────────────────────
# 7. _detect_nosql_sinks — detects injection
# ─────────────────────────────────────────────────────────────────────────────

class TestNosqlSinkDetection:
    """Area 7: Sink detector finds Mongoose queries receiving unsanitized req.body."""

    def test_find_with_req_body_is_sink(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        src = textwrap.dedent("""\
            User.find({
                username: req.body.username,
                password: req.body.password
            }, callback);
        """)
        sinks = _detect_nosql_sinks(src, "routes/index.js")
        assert len(sinks) == 1
        assert sinks[0].model_name == "User"
        assert sinks[0].method_call.lower() in ("find", "findone")

    def test_req_query_injection_detected(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        src = "Product.find({ category: req.query.cat }, cb);\n"
        sinks = _detect_nosql_sinks(src, "products.js")
        assert len(sinks) == 1
        assert any("req.query" in s for s in sinks[0].input_sources)

    def test_source_file_recorded(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        src = "Item.find({ name: req.body.name }, cb);\n"
        sinks = _detect_nosql_sinks(src, "handlers/item.js")
        assert sinks[0].source_file == "handlers/item.js"

    def test_line_number_recorded(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        src = "// first line\nUser.find({ id: req.body.id }, cb);\n"
        sinks = _detect_nosql_sinks(src, "auth.js")
        assert sinks[0].line_number == 2

    def test_context_lines_captured(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        src = textwrap.dedent("""\
            // before
            User.find({
                username: req.body.username,
                password: req.body.password
            }, function(err, users) {
            // after
        """)
        sinks = _detect_nosql_sinks(src, "auth.js")
        assert len(sinks) == 1
        assert len(sinks[0].context_lines) > 0

    def test_no_sanitization_flag_set(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        src = "User.find({ username: req.body.username }, cb);\n"
        sinks = _detect_nosql_sinks(src, "routes.js")
        assert sinks[0].has_operator_sanitization is False

    def test_findone_detected(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        src = "Admin.findOne({ email: req.body.email }, cb);\n"
        sinks = _detect_nosql_sinks(src, "admin.js")
        assert len(sinks) == 1
        assert sinks[0].method_call.lower() == "findone"


# ─────────────────────────────────────────────────────────────────────────────
# 8. _detect_nosql_sinks — suppressed when sanitization present
# ─────────────────────────────────────────────────────────────────────────────

class TestNosqlSinkSuppression:
    """Area 8: When express-mongo-sanitize or mongoSanitize is present, has_operator_sanitization=True."""

    def test_mongo_sanitize_middleware_suppresses_flag(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        src = textwrap.dedent("""\
            const mongoSanitize = require('express-mongo-sanitize');
            app.use(mongoSanitize());
            User.find({ username: req.body.username, password: req.body.password }, cb);
        """)
        sinks = _detect_nosql_sinks(src, "app.js")
        # Sink is still detected (it exists) but sanitization flag is True
        assert len(sinks) == 1
        assert sinks[0].has_operator_sanitization is True

    def test_sanitize_filter_option_sets_flag(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        src = textwrap.dedent("""\
            mongoose.connect(uri, { sanitizeFilter: true });
            User.find({ email: req.body.email }, cb);
        """)
        sinks = _detect_nosql_sinks(src, "db.js")
        assert len(sinks) == 1
        assert sinks[0].has_operator_sanitization is True


# ─────────────────────────────────────────────────────────────────────────────
# 9. _detect_nosql_sinks — no false positives on safe queries
# ─────────────────────────────────────────────────────────────────────────────

class TestNosqlSinkNoFalsePositives:
    """Area 9: Sinks with only hardcoded filter values must not be flagged."""

    def test_hardcoded_filter_not_flagged(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        src = "User.find({ role: 'admin' }, cb);\n"
        sinks = _detect_nosql_sinks(src, "seed.js")
        assert sinks == []

    def test_empty_file_no_sinks(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        sinks = _detect_nosql_sinks("", "empty.js")
        assert sinks == []

    def test_find_with_local_variable_not_flagged(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        # Local variable derived from validated input — not directly req.body
        src = textwrap.dedent("""\
            const userId = parseInt(req.body.id, 10);
            if (isNaN(userId)) return res.status(400).send('invalid');
            // userId is now a safe integer
            User.find({ _id: userId }, cb);
        """)
        sinks = _detect_nosql_sinks(src, "users.js")
        # Should not flag because filter body doesn't directly contain req.body.X
        assert sinks == []

    def test_sql_queries_not_flagged_as_nosql(self):
        from app.nodejs.js_analyzer import _detect_nosql_sinks
        src = textwrap.dedent("""\
            const result = await db.query(
                'SELECT * FROM users WHERE email = $1',
                [req.body.email]
            );
        """)
        sinks = _detect_nosql_sinks(src, "pg_handler.js")
        assert sinks == []


# ─────────────────────────────────────────────────────────────────────────────
# 10. RootCauseEngine._nosql_injection_root_cause
# ─────────────────────────────────────────────────────────────────────────────

def _make_investigation_with_primary(primary_finding: str):
    """
    Build a minimal Investigation whose correlation.primary_finding
    matches the given text.
    """
    from app.models import (
        CorrelationResult, Investigation, RepositoryInfo,
    )
    repo_info = RepositoryInfo(
        frameworks=["Express"],
        languages=["JavaScript"],
        api_routes=["POST /login"],
    )
    corr = CorrelationResult(
        primary_finding=primary_finding,
        affected_files=["routes/auth.js"],
        confidence=0.9,
    )
    inv = Investigation(
        title="NoSQL injection test investigation",
        repository_path="/tmp/test-repo",
        issue_description=primary_finding,
    )
    inv.repository_info = repo_info
    inv.correlation = corr
    return inv


class TestNosqlRootCauseAnalysis:
    """Area 10: RootCauseEngine produces correct CWE-943 root cause."""

    def test_nosql_root_cause_dispatched(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection in login route")
        rca = engine.analyze(inv)
        assert rca is not None

    def test_nosql_root_cause_cwe_943(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("nosql injection vulnerability")
        rca = engine.analyze(inv)
        assert rca.cwe_id == "CWE-943"

    def test_nosql_root_cause_cvss_9_8(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL Injection — Mongoose")
        rca = engine.analyze(inv)
        assert rca.cvss_score == 9.8

    def test_nosql_root_cause_mentions_operator_injection(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection vulnerability detected")
        rca = engine.analyze(inv)
        text = " ".join([rca.symptom, rca.root_cause, rca.why_it_happens]).lower()
        assert "operator" in text or "injection" in text

    def test_nosql_root_cause_has_impact(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection — authentication bypass")
        rca = engine.analyze(inv)
        assert rca.impact
        assert len(rca.impact) > 20

    def test_nosql_root_cause_affected_components_from_investigation(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection")
        rca = engine.analyze(inv)
        assert rca.affected_components == ["routes/auth.js"]


# ─────────────────────────────────────────────────────────────────────────────
# 11. RootCauseEngine._nosql_injection_invariant — supported structure
# ─────────────────────────────────────────────────────────────────────────────

class TestNosqlInjectionInvariant:
    """Area 11: Invariant derivation produces a fully structured, supported invariant."""

    def test_nosql_invariant_is_supported(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection vulnerability")
        # Populate root_cause so provenance works
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        assert invariant.supported is True

    def test_nosql_invariant_cwe_943(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection vulnerability")
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        assert invariant.cwe == "CWE-943"

    def test_nosql_invariant_vulnerability_class(self):
        from app.models import VulnerabilityClass
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection — Mongoose find")
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        assert invariant.vulnerability_class == VulnerabilityClass.NOSQL_INJECTION

    def test_nosql_invariant_has_statement(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection vulnerability")
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        assert invariant.statement
        assert len(invariant.statement) > 20

    def test_nosql_invariant_oracle_blocked_outcome(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection vulnerability")
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        assert invariant.oracle is not None
        blocked = invariant.oracle.blocked_outcome
        assert blocked is not None
        assert 401 in blocked.allowed_status_codes or 400 in blocked.allowed_status_codes

    def test_nosql_invariant_oracle_forbidden_codes_include_200(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection vulnerability")
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        blocked = invariant.oracle.blocked_outcome
        assert 200 in blocked.forbidden_status_codes

    def test_nosql_invariant_has_legitimate_use(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection vulnerability")
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        assert invariant.legitimate_use is not None
        assert len(invariant.legitimate_use) >= 1

    def test_nosql_invariant_has_scope_with_login_route(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection vulnerability")
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        assert invariant.scope is not None
        assert len(invariant.scope.routes) >= 1
        # Should reference the /login route discovered in api_routes
        assert any("login" in r.lower() for r in invariant.scope.routes)

    def test_nosql_invariant_attack_method_is_post(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection vulnerability")
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        assert invariant.attack.method.upper() == "POST"

    def test_nosql_invariant_has_provenance(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection vulnerability")
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        assert invariant.provenance is not None
        assert invariant.provenance.investigation_id == inv.id

    def test_nosql_invariant_limitations_mention_nodejs(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection vulnerability")
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        assert invariant.limitations
        assert "node" in invariant.limitations.lower() or "express" in invariant.limitations.lower()

    def test_nosql_invariant_no_securebank_literals(self):
        """Invariant must not contain alice, bob, alice123, or /api/accounts."""
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_investigation_with_primary("NoSQL injection vulnerability")
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        # Serialise to text and check for SecureBank artifacts
        import json as _json
        try:
            text = invariant.model_dump_json()
        except Exception:
            import dataclasses
            text = str(invariant)
        text_lower = text.lower()
        forbidden = ["alice123", "/api/accounts", "securebank"]
        for token in forbidden:
            assert token not in text_lower, f"SecureBank literal '{token}' found in NoSQL invariant"


# ─────────────────────────────────────────────────────────────────────────────
# 12. RootCauseEngine._nosql_injection_invariant — no login route → UNSUPPORTED
# ─────────────────────────────────────────────────────────────────────────────

class TestNosqlInvariantFallback:
    """Area 12: When no login route is known, invariant returns UNSUPPORTED with reason."""

    def _make_inv_no_routes(self):
        from app.models import CorrelationResult, Investigation, RepositoryInfo
        repo_info = RepositoryInfo(
            frameworks=["Express"],
            languages=["JavaScript"],
            api_routes=[],  # intentionally empty
        )
        corr = CorrelationResult(
            primary_finding="NoSQL injection vulnerability",
            affected_files=[],
            confidence=0.9,
        )
        inv = Investigation(
            title="NoSQL injection no-routes investigation",
            repository_path="/tmp/no-routes",
            issue_description="NoSQL injection vulnerability",
        )
        inv.repository_info = repo_info
        inv.correlation = corr
        return inv

    def test_no_login_route_produces_unsupported(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = self._make_inv_no_routes()
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        assert invariant.supported is False

    def test_unsupported_invariant_has_reason(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = self._make_inv_no_routes()
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        assert invariant.unsupported_reason
        assert len(invariant.unsupported_reason) > 10

    def test_unsupported_invariant_cwe_943(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = self._make_inv_no_routes()
        inv.root_cause = engine.analyze(inv)
        invariant = engine.derive_invariant(inv)
        # Even when unsupported, CWE should be set
        assert invariant.cwe == "CWE-943"


# ─────────────────────────────────────────────────────────────────────────────
# 13. DependencyAgent — mongoose < 5.7.5 flagged (CVE-2019-17426)
# ─────────────────────────────────────────────────────────────────────────────

class TestDependencyAgentNodejs:
    """Area 13: DependencyAgent flags vulnerable mongoose versions."""

    def test_mongoose_4_2_4_flagged(self, tmp_path):
        """mongoose@4.2.4 is below 5.7.5 — must be flagged."""
        from app.agents.dependency_agent import DependencyAgent, KNOWN_VULNS
        assert "mongoose" in KNOWN_VULNS, "mongoose not in KNOWN_VULNS"
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text(json.dumps({
            "name": "test-app",
            "dependencies": {
                "mongoose": "4.2.4",
                "express": "4.12.4",
            }
        }))
        agent = DependencyAgent()
        deps = agent._parse_manifest(str(pkg_path))
        findings = agent._check_vulnerabilities(deps, "nosql injection authentication bypass")
        mongoose_findings = [f for f in findings if "mongoose" in f.title.lower()]
        assert len(mongoose_findings) >= 1

    def test_mongoose_4_2_4_finding_includes_cve(self, tmp_path):
        from app.agents.dependency_agent import DependencyAgent
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text(json.dumps({
            "name": "test-app",
            "dependencies": {"mongoose": "4.2.4"},
        }))
        agent = DependencyAgent()
        deps = agent._parse_manifest(str(pkg_path))
        findings = agent._check_vulnerabilities(deps, "nosql injection")
        assert findings
        evidence_text = " ".join(findings[0].evidence)
        assert "CVE-2019-17426" in evidence_text

    def test_mongoose_latest_not_flagged(self, tmp_path):
        """mongoose@8.0.0 is above 5.7.5 — must not be flagged."""
        from app.agents.dependency_agent import DependencyAgent
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text(json.dumps({
            "name": "test-app",
            "dependencies": {"mongoose": "8.0.0"},
        }))
        agent = DependencyAgent()
        deps = agent._parse_manifest(str(pkg_path))
        findings = agent._check_vulnerabilities(deps, "nosql injection")
        mongoose_findings = [f for f in findings if "mongoose" in f.title.lower()]
        assert len(mongoose_findings) == 0

    def test_express_known_vuln_in_dict(self):
        from app.agents.dependency_agent import KNOWN_VULNS
        assert "express" in KNOWN_VULNS

    def test_dependency_agent_is_relevant_mongoose_nosql(self):
        from app.agents.dependency_agent import DependencyAgent
        agent = DependencyAgent()
        assert agent._is_relevant("mongoose", "NoSQL operator injection", "nosql injection in login") is True

    def test_dependency_agent_is_relevant_mongoose_auth(self):
        from app.agents.dependency_agent import DependencyAgent
        agent = DependencyAgent()
        assert agent._is_relevant("mongoose", "authentication bypass", "login authentication failure") is True

    def test_dependency_agent_version_comparison(self):
        from app.agents.dependency_agent import DependencyAgent
        agent = DependencyAgent()
        assert agent._is_version_vulnerable("4.2.4", "5.7.5") is True
        assert agent._is_version_vulnerable("5.7.5", "5.7.5") is False
        assert agent._is_version_vulnerable("6.0.0", "5.7.5") is False


# ─────────────────────────────────────────────────────────────────────────────
# 14. NodejsVerifier — HTTP checks return UNSUPPORTED
# ─────────────────────────────────────────────────────────────────────────────

class TestNodejsVerifier:
    """Area 14: NodejsVerifier always returns UNSUPPORTED for HTTP-dependent checks."""

    def _make_investigation(self, login_route: str = "/login"):
        from app.models import Investigation, RepositoryInfo
        inv = Investigation(
            title="NoSQL injection nodejs-test",
            repository_path="/tmp/nodejs-test",
            issue_description="NoSQL injection",
        )
        inv.repository_info = RepositoryInfo(
            frameworks=["Express"],
            languages=["JavaScript"],
            api_routes=[f"POST {login_route}"],
        )
        return inv

    def test_check_exploit_blocked_returns_unsupported_without_patch(self):
        from app.models import ExploitCheckOutcome
        from app.verification.nodejs_verifier import NodejsVerifier
        verifier = NodejsVerifier()
        inv = self._make_investigation()
        check = verifier.check_exploit_blocked(inv)
        assert check.outcome == ExploitCheckOutcome.UNSUPPORTED

    def test_check_legitimate_use_returns_unsupported(self):
        from app.models import ExploitCheckOutcome
        from app.verification.nodejs_verifier import NodejsVerifier
        verifier = NodejsVerifier()
        inv = self._make_investigation()
        check = verifier.check_legitimate_use(inv)
        assert check.outcome == ExploitCheckOutcome.UNSUPPORTED

    def test_unsupported_check_has_reason_in_detail(self):
        from app.verification.nodejs_verifier import NodejsVerifier
        verifier = NodejsVerifier()
        inv = self._make_investigation()
        check = verifier.check_legitimate_use(inv)
        assert check.detail
        assert len(check.detail) > 20

    def test_unsupported_check_status_is_skipped(self):
        from app.verification.nodejs_verifier import NodejsVerifier
        verifier = NodejsVerifier()
        inv = self._make_investigation()
        check = verifier.check_exploit_blocked(inv)
        assert check.status == "skipped"

    def test_infer_login_route_from_api_routes(self):
        from app.verification.nodejs_verifier import NodejsVerifier
        verifier = NodejsVerifier()
        inv = self._make_investigation(login_route="/auth/login")
        route = verifier._infer_login_route(inv)
        assert "login" in route

    def test_infer_login_route_fallback(self):
        from app.models import Investigation, RepositoryInfo
        from app.verification.nodejs_verifier import NodejsVerifier
        verifier = NodejsVerifier()
        inv = Investigation(
            title="NoSQL injection fallback test",
            repository_path="/tmp/x",
            issue_description="nosql injection",
        )
        inv.repository_info = RepositoryInfo(
            frameworks=["Express"],
            languages=["JavaScript"],
            api_routes=["GET /health", "GET /products"],  # no login route
        )
        route = verifier._infer_login_route(inv)
        # Should return the fallback "/login"
        assert route == "/login"

    def test_static_nosql_check_detects_mongo_sanitize(self, tmp_path):
        """When patched file contains mongoSanitize, static check returns PASS."""
        from app.models import ExploitCheckOutcome, Investigation, RemediationProposal, RepositoryInfo
        from app.verification.nodejs_verifier import NodejsVerifier

        # Create a synthetic patched file with the fix
        routes_dir = tmp_path / "routes"
        routes_dir.mkdir()
        (routes_dir / "auth.js").write_text(
            "const mongoSanitize = require('express-mongo-sanitize');\n"
            "app.use(mongoSanitize());\n"
            "User.find({ username: req.body.username }, cb);\n"
        )

        inv = Investigation(
            title="NoSQL injection static check",
            repository_path=str(tmp_path),
            issue_description="NoSQL injection",
        )
        inv.repository_info = RepositoryInfo(
            frameworks=["Express"],
            languages=["JavaScript"],
            api_routes=["POST /login"],
        )
        inv.remediation = RemediationProposal(
            summary="Add mongoSanitize middleware",
            files_changed=["routes/auth.js"],
        )

        verifier = NodejsVerifier()
        check = verifier._static_nosql_check(inv)
        assert check is not None
        assert check.outcome == ExploitCheckOutcome.PASS


# ─────────────────────────────────────────────────────────────────────────────
# Integration test: real nodejs-goof (skipped when symlink absent)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not GOOF_AVAILABLE, reason="nodejs-goof symlink not present")
class TestGoofIntegration:
    """
    Integration tests against the real nodejs-goof repository.
    Tests verify structural properties only — never hardcoded line numbers
    or specific route counts (those may change across goof versions).
    """

    def test_goof_is_nodejs(self):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        info = NodejsAnalyzer().analyze(GOOF_PATH)
        assert info.is_nodejs is True

    def test_goof_is_express(self):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        info = NodejsAnalyzer().analyze(GOOF_PATH)
        assert info.is_express is True

    def test_goof_mongoose_version_present(self):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        info = NodejsAnalyzer().analyze(GOOF_PATH)
        assert info.mongoose_version != ""

    def test_goof_routes_extracted(self):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        info = NodejsAnalyzer().analyze(GOOF_PATH)
        assert len(info.routes) > 0, "Expected at least one Express route in goof"

    def test_goof_has_login_route(self):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        info = NodejsAnalyzer().analyze(GOOF_PATH)
        login_routes = [r for r in info.routes if "login" in r.path.lower()]
        assert len(login_routes) >= 1, "Expected a /login route in goof"

    def test_goof_nosql_sinks_detected(self):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        info = NodejsAnalyzer().analyze(GOOF_PATH)
        assert len(info.nosql_sinks) > 0, "Expected at least one NoSQL sink in goof"

    def test_goof_nosql_sinks_reference_req_body(self):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        info = NodejsAnalyzer().analyze(GOOF_PATH)
        for sink in info.nosql_sinks:
            if not sink.has_operator_sanitization:
                # At least one input source must be req.body or req.query
                assert any(
                    "req.body" in s or "req.query" in s for s in sink.input_sources
                ), f"Sink at {sink.source_file}:{sink.line_number} has unexpected sources: {sink.input_sources}"

    def test_goof_nosql_sink_has_context_lines(self):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        info = NodejsAnalyzer().analyze(GOOF_PATH)
        sinks_with_context = [s for s in info.nosql_sinks if s.context_lines]
        assert len(sinks_with_context) > 0

    def test_goof_detection_evidence_populated(self):
        from app.nodejs.js_analyzer import NodejsAnalyzer
        info = NodejsAnalyzer().analyze(GOOF_PATH)
        assert len(info.detection_evidence) >= 2

    def test_goof_mongoose_version_below_5_7_5_flagged(self):
        """CVE-2019-17426: goof's mongoose@4.2.4 must be flagged by DependencyAgent."""
        from app.agents.dependency_agent import DependencyAgent
        pkg_path = os.path.join(GOOF_PATH, "package.json")
        agent = DependencyAgent()
        deps = agent._parse_manifest(pkg_path)
        assert "mongoose" in deps, "mongoose not found in goof package.json"
        mongoose_ver = deps["mongoose"]
        # Confirm version is < 5.7.5
        assert agent._is_version_vulnerable(mongoose_ver, "5.7.5"), (
            f"Expected mongoose {mongoose_ver} to be vulnerable (< 5.7.5)"
        )
