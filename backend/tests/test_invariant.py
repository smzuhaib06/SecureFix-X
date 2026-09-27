"""
Tests for the SecurityInvariant model and RootCauseEngine.derive_invariant().

Coverage:
  1. Valid BOLA invariant creation from model constructors
  2. Nested scope/oracle validation
  3. Legitimate-use contract representation
  4. Provenance fields
  5. SecureBank scenario values are instance data, not global assumptions
  6. Unsupported vulnerability class does not fabricate an invariant
  7. All existing 21 backend tests still pass (verified by separate run)
  8. Demo-app BOLA state unchanged (not tested here — see demo-app/tests)
"""
import os
import pytest

# Ensure the demo-app path env var is available before importing app
DEMO_REPO = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "../../demo-app")
)
os.environ.setdefault("DEMO_REPO_PATH", DEMO_REPO)


# ── Model construction tests ──────────────────────────────────────────────────

class TestSecurityInvariantModel:
    """Unit tests for the SecurityInvariant Pydantic model family."""

    def test_invariant_id_auto_generated(self):
        from app.models import SecurityInvariant, VulnerabilityClass
        inv = SecurityInvariant(
            vulnerability_class=VulnerabilityClass.BOLA,
            statement="test statement",
        )
        assert inv.id.startswith("INV-")
        assert len(inv.id) > 4

    def test_invariant_two_instances_have_different_ids(self):
        from app.models import SecurityInvariant, VulnerabilityClass
        a = SecurityInvariant(vulnerability_class=VulnerabilityClass.BOLA, statement="s")
        b = SecurityInvariant(vulnerability_class=VulnerabilityClass.BOLA, statement="s")
        assert a.id != b.id

    def test_invariant_supported_default(self):
        from app.models import SecurityInvariant, VulnerabilityClass
        inv = SecurityInvariant(
            vulnerability_class=VulnerabilityClass.BOLA,
            statement="An owner may access their own resource.",
        )
        assert inv.supported is True
        assert inv.unsupported_reason is None

    def test_unsupported_invariant_fields(self):
        from app.models import SecurityInvariant, VulnerabilityClass
        inv = SecurityInvariant(
            vulnerability_class=VulnerabilityClass.SQL_INJECTION,
            statement="",
            supported=False,
            unsupported_reason="Requires parameterised query analysis",
        )
        assert inv.supported is False
        assert "parameterised" in inv.unsupported_reason
        assert inv.statement == ""

    def test_vulnerability_class_enum_values(self):
        from app.models import VulnerabilityClass
        assert VulnerabilityClass.BOLA.value == "BOLA"
        assert VulnerabilityClass.SQL_INJECTION.value == "SQL_INJECTION"
        assert VulnerabilityClass.PATH_TRAVERSAL.value == "PATH_TRAVERSAL"
        assert VulnerabilityClass.COMMAND_INJECTION.value == "COMMAND_INJECTION"
        assert VulnerabilityClass.MISSING_AUTH.value == "MISSING_AUTH"
        assert VulnerabilityClass.HARDCODED_SECRET.value == "HARDCODED_SECRET"
        assert VulnerabilityClass.UNKNOWN.value == "UNKNOWN"

    def test_invariant_cwe_optional(self):
        from app.models import SecurityInvariant, VulnerabilityClass
        inv = SecurityInvariant(
            vulnerability_class=VulnerabilityClass.UNKNOWN,
            statement="",
            supported=False,
        )
        assert inv.cwe is None


class TestInvariantScope:
    def test_scope_defaults(self):
        from app.models import InvariantScope
        scope = InvariantScope()
        assert scope.routes == []
        assert scope.resources == []
        assert scope.actor_roles == []
        assert scope.relevant_files == []

    def test_scope_bola_roles(self):
        from app.models import InvariantScope
        scope = InvariantScope(
            routes=["/api/accounts/{account_id}"],
            resources=["account"],
            actor_roles=["authenticated_user", "resource_owner", "non_owner"],
            relevant_files=["app/routes/accounts.py"],
        )
        assert "non_owner" in scope.actor_roles
        assert "resource_owner" in scope.actor_roles
        assert "/api/accounts/{account_id}" in scope.routes
        assert "app/routes/accounts.py" in scope.relevant_files


class TestAttackScenario:
    def test_attack_scenario_parameters_are_scenario_data(self):
        """
        Verify that nothing in the AttackScenario model enforces specific
        usernames, account IDs, or routes as global constants.
        Any values are stored as mutable scenario data.
        """
        from app.models import AttackScenario
        attack = AttackScenario(
            method="GET",
            route_template="/api/accounts/{account_id}",
            route_example="/api/accounts/2",
            actor_credential_hint="Authenticated as alice (non-owner)",
            parameters={"attacker": "alice", "victim_id": 2},
        )
        # These are instance values — should be settable to anything
        assert attack.route_example == "/api/accounts/2"
        assert attack.parameters["attacker"] == "alice"

        # Mutate to prove no global assumption
        attack.route_example = "/api/orders/99"
        attack.parameters["attacker"] = "eve"
        assert attack.route_example == "/api/orders/99"
        assert attack.parameters["attacker"] == "eve"


class TestSecurityOracle:
    def test_oracle_outcomes(self):
        from app.models import OracleExpectedOutcome, SecurityOracle
        oracle = SecurityOracle(
            description="Access control check",
            outcomes=[
                OracleExpectedOutcome(
                    label="attack_blocked",
                    allowed_status_codes=[403],
                    forbidden_status_codes=[200],
                    protected_data_indicators=["balance"],
                ),
                OracleExpectedOutcome(
                    label="exploit_active",
                    allowed_status_codes=[200],
                    forbidden_status_codes=[403],
                ),
            ],
        )
        assert len(oracle.outcomes) == 2
        blocked = oracle.blocked_outcome
        assert blocked is not None
        assert 403 in blocked.allowed_status_codes
        assert 200 in blocked.forbidden_status_codes
        assert "balance" in blocked.protected_data_indicators

    def test_oracle_violated_outcome(self):
        from app.models import OracleExpectedOutcome, SecurityOracle
        oracle = SecurityOracle(
            outcomes=[
                OracleExpectedOutcome(label="attack_blocked", allowed_status_codes=[403]),
                OracleExpectedOutcome(label="exploit_active", allowed_status_codes=[200]),
            ],
        )
        violated = oracle.violated_outcome
        assert violated is not None
        assert violated.label == "exploit_active"

    def test_oracle_status_codes_are_not_globally_fixed(self):
        """
        HTTP 403 is not universally 'secure' — for a different vulnerability
        class the blocked response might be 400, 404, or 401.
        The model must support arbitrary code lists.
        """
        from app.models import OracleExpectedOutcome, SecurityOracle
        # Path traversal might use 400
        oracle = SecurityOracle(
            outcomes=[
                OracleExpectedOutcome(
                    label="traversal_blocked",
                    allowed_status_codes=[400, 403],
                    forbidden_status_codes=[200],
                ),
            ],
        )
        outcome = oracle.outcomes[0]
        assert 400 in outcome.allowed_status_codes
        assert 403 in outcome.allowed_status_codes


class TestLegitimateUseCase:
    def test_legitimate_use_contract(self):
        from app.models import LegitimateUseCase
        uc = LegitimateUseCase(
            description="Owner accesses own resource",
            method="GET",
            route_example="/api/accounts/1",
            actor_credential_hint="Authenticated as alice (owner)",
            expected_status_codes=[200],
            parameters={"owner": "alice", "resource_id": 1},
        )
        assert 200 in uc.expected_status_codes
        assert uc.parameters["owner"] == "alice"
        # Route is scenario data — can be any path
        uc.route_example = "/api/orders/5"
        assert uc.route_example == "/api/orders/5"


class TestInvariantProvenance:
    def test_provenance_fields(self):
        from app.models import InvariantProvenance
        prov = InvariantProvenance(
            investigation_id="SF-ABCD1234",
            source_agents=["security_agent", "code_agent"],
            root_cause_cwe="CWE-639",
        )
        assert prov.investigation_id == "SF-ABCD1234"
        assert "security_agent" in prov.source_agents
        assert prov.root_cause_cwe == "CWE-639"
        assert prov.derived_at is not None

    def test_provenance_cwe_optional(self):
        from app.models import InvariantProvenance
        prov = InvariantProvenance(investigation_id="SF-TEST")
        assert prov.root_cause_cwe is None


# ── RootCauseEngine.derive_invariant() tests ──────────────────────────────────

def _make_bola_investigation():
    """
    Build a minimal Investigation in the state just after root cause analysis,
    matching the BOLA/SecureBank scenario — without depending on running agents.
    """
    import tempfile
    from app.models import (
        AgentFinding, AgentResult, AgentStatus,
        CorrelationResult, Investigation, InvestigationStatus,
        RepositoryInfo, RootCauseAnalysis, Severity,
    )

    repo_info = RepositoryInfo(
        project_type="FastAPI",
        languages=["Python"],
        frameworks=["FastAPI"],
        api_routes=[
            "GET /api/accounts/",
            "GET /api/accounts/{account_id}",
            "GET /api/transactions/{transaction_id}",
            "GET /api/profile/{profile_id}",
        ],
        auth_components=["app/auth.py"],
        database_components=["app/database.py"],
        total_files=20,
        relevant_files=["app/routes/accounts.py"],
    )

    correlation = CorrelationResult(
        primary_finding="Broken Object Level Authorization (BOLA)",
        affected_files=["app/routes/accounts.py"],
        attack_path=["Attacker authenticates", "Attacker requests /api/accounts/2"],
        confidence=0.91,
    )

    root_cause = RootCauseAnalysis(
        symptom="Authenticated non-owner can access another user's account.",
        root_cause="Ownership not checked before returning resource.",
        why_it_happens="Authentication and authorization are distinct.",
        impact="Data breach — account balance and details exposed.",
        cwe_id="CWE-639",
        cvss_score=8.1,
    )

    security_finding = AgentFinding(
        title="Broken Object Level Authorization (BOLA)",
        severity=Severity.CRITICAL,
        confidence=0.91,
        files=["app/routes/accounts.py"],
        evidence=["No ownership check found"],
        root_cause="Missing ownership check",
    )
    agent_result = AgentResult(
        agent="security_agent",
        status=AgentStatus.COMPLETED,
        findings=[security_finding],
        summary="BOLA found",
    )

    inv = Investigation(
        title="BOLA on accounts",
        issue_description="Authorization bypass on account endpoint",
        repository_path=DEMO_REPO,
        status=InvestigationStatus.RUNNING,
        repository_info=repo_info,
        correlation=correlation,
        root_cause=root_cause,
        agent_results={"security_agent": agent_result},
    )
    return inv


class TestDeriveInvariantBOLA:
    def test_derive_returns_supported_invariant(self):
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        inv = _make_bola_investigation()
        invariant = engine.derive_invariant(inv)
        assert invariant.supported is True
        assert invariant.unsupported_reason is None

    def test_derive_bola_vulnerability_class(self):
        from app.models import VulnerabilityClass
        from app.remediation.root_cause import RootCauseEngine
        engine = RootCauseEngine()
        invariant = engine.derive_invariant(_make_bola_investigation())
        assert invariant.vulnerability_class == VulnerabilityClass.BOLA

    def test_derive_bola_cwe(self):
        from app.remediation.root_cause import RootCauseEngine
        invariant = RootCauseEngine().derive_invariant(_make_bola_investigation())
        assert invariant.cwe == "CWE-639"

    def test_derive_bola_statement_is_role_based_not_username_based(self):
        """
        The invariant statement must express the property in terms of roles,
        not specific usernames like 'alice' or 'bob'.
        """
        from app.remediation.root_cause import RootCauseEngine
        invariant = RootCauseEngine().derive_invariant(_make_bola_investigation())
        stmt_lower = invariant.statement.lower()
        assert "alice" not in stmt_lower, "Invariant statement must not hardcode 'alice'"
        assert "bob" not in stmt_lower, "Invariant statement must not hardcode 'bob'"
        assert "carol" not in stmt_lower
        assert "account_id" not in stmt_lower
        # Should express ownership concept
        assert any(word in stmt_lower for word in ("owner", "access", "resource", "authenti"))

    def test_derive_bola_scope_contains_route(self):
        from app.remediation.root_cause import RootCauseEngine
        invariant = RootCauseEngine().derive_invariant(_make_bola_investigation())
        assert len(invariant.scope.routes) >= 1
        # Route template must contain a placeholder or be generic
        assert any("{" in r or "/" in r for r in invariant.scope.routes)

    def test_derive_bola_scope_actor_roles(self):
        from app.remediation.root_cause import RootCauseEngine
        invariant = RootCauseEngine().derive_invariant(_make_bola_investigation())
        assert "non_owner" in invariant.scope.actor_roles
        assert "resource_owner" in invariant.scope.actor_roles

    def test_derive_bola_oracle_has_two_outcomes(self):
        from app.remediation.root_cause import RootCauseEngine
        invariant = RootCauseEngine().derive_invariant(_make_bola_investigation())
        assert len(invariant.oracle.outcomes) == 2

    def test_derive_bola_oracle_blocked_outcome_denies_200(self):
        from app.remediation.root_cause import RootCauseEngine
        invariant = RootCauseEngine().derive_invariant(_make_bola_investigation())
        blocked = invariant.oracle.blocked_outcome
        assert blocked is not None
        assert 200 in blocked.forbidden_status_codes
        assert 403 in blocked.allowed_status_codes or 404 in blocked.allowed_status_codes

    def test_derive_bola_oracle_violated_outcome_allows_200(self):
        from app.remediation.root_cause import RootCauseEngine
        invariant = RootCauseEngine().derive_invariant(_make_bola_investigation())
        violated = invariant.oracle.violated_outcome
        assert violated is not None
        assert 200 in violated.allowed_status_codes

    def test_derive_bola_legitimate_use_contract_not_empty(self):
        from app.remediation.root_cause import RootCauseEngine
        invariant = RootCauseEngine().derive_invariant(_make_bola_investigation())
        assert len(invariant.legitimate_use) >= 1
        # At least one contract expects HTTP 200 for owner access
        owner_cases = [uc for uc in invariant.legitimate_use if 200 in uc.expected_status_codes]
        assert len(owner_cases) >= 1

    def test_derive_bola_legitimate_use_case_has_owner_route(self):
        from app.remediation.root_cause import RootCauseEngine
        invariant = RootCauseEngine().derive_invariant(_make_bola_investigation())
        owner_case = next(
            (uc for uc in invariant.legitimate_use if 200 in uc.expected_status_codes), None
        )
        assert owner_case is not None
        # Route example is scenario data — should exist and be a path
        assert owner_case.route_example.startswith("/")

    def test_derive_bola_scenario_data_labelled_as_such(self):
        """
        Any scenario-specific value stored in attack.parameters must carry a
        _note key indicating it is scenario data, not a global assumption.
        """
        from app.remediation.root_cause import RootCauseEngine
        invariant = RootCauseEngine().derive_invariant(_make_bola_investigation())
        assert "_note" in invariant.attack.parameters, (
            "attack.parameters must contain a _note explaining the scenario data nature"
        )

    def test_derive_bola_route_template_not_hardcoded_securebank(self):
        """
        The route template must be inferred from the repository's API routes,
        not hardcoded to '/api/accounts/{account_id}'.
        Verify inference for a different route set.
        """
        from app.models import RepositoryInfo
        from app.remediation.root_cause import RootCauseEngine
        inv = _make_bola_investigation()
        # Override with different routes
        inv.repository_info.api_routes = [
            "GET /api/orders/{order_id}",
            "POST /api/orders/",
        ]
        invariant = RootCauseEngine().derive_invariant(inv)
        assert "/api/orders/{order_id}" in invariant.scope.routes

    def test_derive_bola_provenance_populated(self):
        from app.remediation.root_cause import RootCauseEngine
        inv = _make_bola_investigation()
        invariant = RootCauseEngine().derive_invariant(inv)
        assert invariant.provenance is not None
        assert invariant.provenance.investigation_id == inv.id
        assert invariant.provenance.root_cause_cwe == "CWE-639"
        assert "security_agent" in invariant.provenance.source_agents

    def test_derive_bola_limitations_populated(self):
        from app.remediation.root_cause import RootCauseEngine
        invariant = RootCauseEngine().derive_invariant(_make_bola_investigation())
        assert len(invariant.limitations) > 0
        # Should mention what it does not cover
        assert any(word in invariant.limitations.lower() for word in ("not", "cover", "require", "phase"))

    def test_derive_bola_id_auto_generated(self):
        from app.remediation.root_cause import RootCauseEngine
        invariant = RootCauseEngine().derive_invariant(_make_bola_investigation())
        assert invariant.id.startswith("INV-")


class TestDeriveInvariantUnsupported:
    """Verify that unsupported classes return supported=False and do not fabricate data."""

    def _make_investigation_with_finding(self, finding_title: str):
        from app.models import (
            AgentResult, AgentStatus, CorrelationResult,
            Investigation, InvestigationStatus,
        )
        correlation = CorrelationResult(
            primary_finding=finding_title,
            confidence=0.8,
        )
        inv = Investigation(
            title="test",
            issue_description="test",
            status=InvestigationStatus.RUNNING,
            correlation=correlation,
        )
        return inv

    def test_sql_injection_unsupported(self):
        from app.models import VulnerabilityClass
        from app.remediation.root_cause import RootCauseEngine
        inv = self._make_investigation_with_finding("SQL Injection")
        invariant = RootCauseEngine().derive_invariant(inv)
        assert invariant.supported is False
        assert invariant.vulnerability_class == VulnerabilityClass.SQL_INJECTION
        assert invariant.unsupported_reason is not None and len(invariant.unsupported_reason) > 0
        # Statement must not be fabricated
        assert invariant.statement == ""
        # Oracle outcomes must be empty
        assert invariant.oracle.outcomes == []

    def test_path_traversal_unsupported(self):
        from app.models import VulnerabilityClass
        from app.remediation.root_cause import RootCauseEngine
        inv = self._make_investigation_with_finding("Path Traversal")
        invariant = RootCauseEngine().derive_invariant(inv)
        assert invariant.supported is False
        assert invariant.vulnerability_class == VulnerabilityClass.PATH_TRAVERSAL

    def test_command_injection_unsupported(self):
        from app.models import VulnerabilityClass
        from app.remediation.root_cause import RootCauseEngine
        inv = self._make_investigation_with_finding("Command Injection")
        invariant = RootCauseEngine().derive_invariant(inv)
        assert invariant.supported is False
        assert invariant.vulnerability_class == VulnerabilityClass.COMMAND_INJECTION

    def test_missing_auth_unsupported(self):
        from app.models import VulnerabilityClass
        from app.remediation.root_cause import RootCauseEngine
        inv = self._make_investigation_with_finding("Missing Authentication")
        invariant = RootCauseEngine().derive_invariant(inv)
        assert invariant.supported is False
        assert invariant.vulnerability_class == VulnerabilityClass.MISSING_AUTH

    def test_hardcoded_secret_unsupported(self):
        from app.models import VulnerabilityClass
        from app.remediation.root_cause import RootCauseEngine
        inv = self._make_investigation_with_finding("Hardcoded Secret")
        invariant = RootCauseEngine().derive_invariant(inv)
        assert invariant.supported is False
        assert invariant.vulnerability_class == VulnerabilityClass.HARDCODED_SECRET

    def test_unknown_finding_unsupported(self):
        from app.models import VulnerabilityClass
        from app.remediation.root_cause import RootCauseEngine
        inv = self._make_investigation_with_finding("Some weird obscure vulnerability")
        invariant = RootCauseEngine().derive_invariant(inv)
        assert invariant.supported is False
        assert invariant.vulnerability_class == VulnerabilityClass.UNKNOWN

    def test_unsupported_does_not_fabricate_legitimate_use(self):
        from app.remediation.root_cause import RootCauseEngine
        inv = self._make_investigation_with_finding("SQL Injection")
        invariant = RootCauseEngine().derive_invariant(inv)
        assert invariant.legitimate_use == []

    def test_unsupported_does_not_fabricate_scope_routes(self):
        from app.remediation.root_cause import RootCauseEngine
        inv = self._make_investigation_with_finding("SQL Injection")
        invariant = RootCauseEngine().derive_invariant(inv)
        assert invariant.scope.routes == []


# ── Investigation model integration ──────────────────────────────────────────

class TestInvestigationModelIntegration:
    def test_investigation_has_security_invariant_field(self):
        from app.models import Investigation
        inv = Investigation(title="t", issue_description="d")
        assert hasattr(inv, "security_invariant")
        assert inv.security_invariant is None

    def test_investigation_invariant_persists_through_store(self):
        """
        SecurityInvariant stored in an investigation must survive a save/load
        round-trip through the SQLite store.
        """
        import tempfile
        from app.models import Investigation, SecurityInvariant, VulnerabilityClass
        from app.store import InvestigationStore

        with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
            s = InvestigationStore(db_path=tmp.name)
            inv = Investigation(title="round-trip", issue_description="invariant persistence")

            inv.security_invariant = SecurityInvariant(
                vulnerability_class=VulnerabilityClass.BOLA,
                cwe="CWE-639",
                statement="Owner-only resource access required.",
            )
            s.create(inv)
            s.update(inv)

            loaded = s.get(inv.id)
            assert loaded is not None
            assert loaded.security_invariant is not None
            assert loaded.security_invariant.vulnerability_class == VulnerabilityClass.BOLA
            assert loaded.security_invariant.cwe == "CWE-639"
            assert loaded.security_invariant.statement == "Owner-only resource access required."

    def test_invariant_api_serialises_to_json(self):
        """Investigation containing a SecurityInvariant must round-trip through JSON."""
        import json
        from app.models import Investigation, SecurityInvariant, VulnerabilityClass
        inv = Investigation(title="json-test", issue_description="test")
        inv.security_invariant = SecurityInvariant(
            vulnerability_class=VulnerabilityClass.BOLA,
            statement="test",
        )
        as_json = json.loads(inv.model_dump_json())
        assert as_json["security_invariant"]["vulnerability_class"] == "BOLA"
        assert as_json["security_invariant"]["statement"] == "test"
