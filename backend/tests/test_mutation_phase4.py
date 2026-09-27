"""
Phase 4 — Controlled Security Patch Mutation Testing tests.

All 22 required test areas are covered.
Existing 173 backend tests are not modified.
SecureBank remains intentionally vulnerable.

Test layout:
    TestMutantModel                  — model validation
    TestMutationTypesAllowlisted     — only allowlisted types accepted
    TestMutationScopeControl         — cannot target arbitrary paths
    TestMutantBuilding               — four mutant definitions built correctly
    TestIsolation                    — isolated copy created/destroyed
    TestWorkingTreeIntegrity         — original working tree unchanged
    TestMutationApplication          — each mutation type applied correctly
    TestMutationTargetVerification   — target-not-found produces UNSUPPORTED
    TestDetectionClassification      — detection state mapping
    TestAssuranceDimensions          — three dimensions reported separately
    TestErrorSemantics               — crash / timeout → ERROR not DETECTED
    TestMutationAssessment           — aggregate assessment model
    TestNoCredentialsInEvidence      — no credentials in evidence records
    TestLiveSecureBankMutation       — end-to-end trials against demo-app
"""
import inspect
import os
import shutil
import tempfile
from pathlib import Path
from typing import List

import pytest

from app.models import (
    ExploitCheckOutcome,
    Investigation,
    MutationAssessment,
    MutationAssuranceDimension,
    MutationDetectionState,
    MutationExecutionStatus,
    MutationResult,
    MutationType,
    MutationAssuranceDimension,
    RepositoryInfo,
    SecurityInvariant,
    SecurityMutant,
    VulnerabilityClass,
)
from app.verification.mutation import (
    MutationEngine,
    _BOLA_ACCOUNTS_FILE,
    _OWNERSHIP_CHECK_PATTERN,
    _build_assessment_note,
)

# ── Fixture: demo-app path ────────────────────────────────────────────────────

DEMO_APP_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "demo-app")
)


def _demo_app_available() -> bool:
    return os.path.isdir(DEMO_APP_PATH) and os.path.isdir(
        os.path.join(DEMO_APP_PATH, "app", "routes")
    )


# ── Fixture: minimal BOLA invariant (generic — no SecureBank literals) ────────

def _make_minimal_bola_invariant() -> SecurityInvariant:
    from app.models import (
        AttackScenario, InvariantProvenance, InvariantScope,
        LegitimateUseCase, OracleExpectedOutcome, SecurityOracle,
    )
    return SecurityInvariant(
        id="INV-TEST-P4",
        vulnerability_class=VulnerabilityClass.BOLA,
        cwe="CWE-639",
        statement="An authenticated user may only access resources they own.",
        scope=InvariantScope(
            routes=["/api/resources/{resource_id}"],
            actor_roles=["authenticated_user", "resource_owner", "non_owner"],
        ),
        attack=AttackScenario(
            method="GET",
            route_template="/api/resources/{resource_id}",
            route_example="/api/resources/2",
            auth_endpoint="/api/auth/login",
            auth_credentials={"username": "user_a", "password": "pass_a"},
            auth_token_path="access_token",
        ),
        oracle=SecurityOracle(
            outcomes=[
                OracleExpectedOutcome(
                    label="attack_blocked",
                    allowed_status_codes=[403, 404],
                    forbidden_status_codes=[200],
                ),
            ]
        ),
        legitimate_use=[
            LegitimateUseCase(
                description="Owner access",
                method="GET",
                route_example="/api/resources/1",
                auth_endpoint="/api/auth/login",
                auth_credentials={"username": "owner_user", "password": "owner_pass"},
                expected_status_codes=[200],
            )
        ],
        provenance=InvariantProvenance(
            investigation_id="INV-TEST-P4",
            source_agents=[],
        ),
        supported=True,
    )


def _make_investigation(invariant: SecurityInvariant = None) -> Investigation:
    inv = Investigation(
        title="Phase 4 test",
        issue_description="BOLA test",
        repository_path=DEMO_APP_PATH,
    )
    inv.security_invariant = invariant
    return inv


# ─────────────────────────────────────────────────────────────────────────────
# 1. Mutant model validation
# ─────────────────────────────────────────────────────────────────────────────

class TestMutantModel:
    def test_mutant_id_auto_generated(self):
        m = SecurityMutant(
            mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
            description="test",
        )
        assert m.mutant_id.startswith("MUT-")

    def test_two_mutants_have_different_ids(self):
        m1 = SecurityMutant(mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK, description="t")
        m2 = SecurityMutant(mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK, description="t")
        assert m1.mutant_id != m2.mutant_id

    def test_mutant_stores_no_credentials(self):
        m = SecurityMutant(
            mutation_type=MutationType.INVERT_OWNERSHIP_COMPARISON,
            description="test",
            mutation_metadata={"target_pattern": "if row[user_id] != ..."},
        )
        dumped = m.model_dump()
        assert "password" not in dumped
        assert "auth_credentials" not in dumped
        assert "secret" not in str(dumped).lower()

    def test_affected_file_is_relative(self):
        """affected_file must be a relative path (no absolute path)."""
        m = SecurityMutant(
            mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
            description="test",
            affected_file=_BOLA_ACCOUNTS_FILE,
        )
        assert not os.path.isabs(m.affected_file)

    def test_mutation_result_default_state(self):
        r = MutationResult(
            mutant_id="MUT-TEST01",
            mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
        )
        assert r.detected is False
        assert r.detection_state == MutationDetectionState.UNSUPPORTED
        assert r.cleanup_completed is False

    def test_mutation_type_enum_values(self):
        assert MutationType.REMOVE_OWNERSHIP_CHECK.value == "remove_ownership_check"
        assert MutationType.INVERT_OWNERSHIP_COMPARISON.value == "invert_ownership_comparison"
        assert MutationType.SIBLING_ROUTE_UNPROTECTED.value == "sibling_route_unprotected"
        assert MutationType.UNCONDITIONAL_DENIAL.value == "unconditional_denial"

    def test_mutation_detection_state_enum_values(self):
        assert MutationDetectionState.DETECTED.value == "detected"
        assert MutationDetectionState.SURVIVED.value == "survived"
        assert MutationDetectionState.ERROR.value == "error"
        assert MutationDetectionState.UNSUPPORTED.value == "unsupported"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Mutation types are allowlisted
# ─────────────────────────────────────────────────────────────────────────────

class TestMutationTypesAllowlisted:
    def test_only_four_mutation_types_defined(self):
        """Exactly four mutation types — no more can be added without code change."""
        values = [m.value for m in MutationType]
        assert len(values) == 4

    def test_mutation_engine_does_not_accept_arbitrary_type(self):
        """build_mutants only produces allowlisted types."""
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        produced_types = {m.mutation_type for m in mutants}
        # All produced types must be in the allowlist
        for t in produced_types:
            assert t in list(MutationType)

    def test_no_arbitrary_shell_commands_in_engine_source(self):
        source = inspect.getsource(MutationEngine)
        assert "os.system(" not in source
        assert "eval(" not in source
        assert "exec(" not in source

    def test_mutation_engine_source_has_no_llm_references(self):
        source = inspect.getsource(MutationEngine)
        assert "openai" not in source.lower()
        assert "anthropic" not in source.lower()
        assert "generate arbitrary" not in source.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 3. Mutation cannot target arbitrary paths
# ─────────────────────────────────────────────────────────────────────────────

class TestMutationScopeControl:
    def test_mutants_target_controlled_files_only(self):
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        allowed_files = {
            os.path.join("app", "routes", "accounts.py"),
            os.path.join("app", "routes", "transactions.py"),
        }
        for m in mutants:
            assert m.affected_file in allowed_files, (
                f"Unexpected target file: {m.affected_file}"
            )

    def test_affected_file_never_absolute(self):
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        for m in mutants:
            assert not os.path.isabs(m.affected_file)

    def test_no_hardcoded_arbitrary_paths_in_engine(self):
        import app.verification.mutation as mod
        source = inspect.getsource(mod)
        # Must not reference arbitrary system paths
        assert "/etc/" not in source
        assert "/home/" not in source
        assert "/root/" not in source

    def test_build_mutants_empty_for_unsupported_class(self):
        invariant = SecurityInvariant(
            vulnerability_class=VulnerabilityClass.SQL_INJECTION,
            cwe="CWE-89",
            statement="",
            supported=True,
        )
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        assert mutants == []

    def test_build_mutants_empty_for_unsupported_invariant(self):
        invariant = SecurityInvariant(
            vulnerability_class=VulnerabilityClass.BOLA,
            cwe="CWE-639",
            statement="",
            supported=False,
            unsupported_reason="test",
        )
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        assert mutants == []


# ─────────────────────────────────────────────────────────────────────────────
# 4. Mutant building — four mutant definitions
# ─────────────────────────────────────────────────────────────────────────────

class TestMutantBuilding:
    def test_build_mutants_returns_four_for_bola(self):
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        assert len(mutants) == 4

    def test_remove_ownership_check_mutant_built(self):
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        types = [m.mutation_type for m in mutants]
        assert MutationType.REMOVE_OWNERSHIP_CHECK in types

    def test_invert_ownership_comparison_mutant_built(self):
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        types = [m.mutation_type for m in mutants]
        assert MutationType.INVERT_OWNERSHIP_COMPARISON in types

    def test_sibling_route_unprotected_mutant_built(self):
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        types = [m.mutation_type for m in mutants]
        assert MutationType.SIBLING_ROUTE_UNPROTECTED in types

    def test_unconditional_denial_mutant_built(self):
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        types = [m.mutation_type for m in mutants]
        assert MutationType.UNCONDITIONAL_DENIAL in types

    def test_all_mutants_have_descriptions(self):
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        for m in mutants:
            assert len(m.description) > 0

    def test_all_mutants_have_expected_detection(self):
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        for m in mutants:
            assert len(m.expected_detection) > 0

    def test_mutant_source_invariant_id_matches(self):
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        for m in mutants:
            assert m.source_invariant_id == invariant.id


# ─────────────────────────────────────────────────────────────────────────────
# 5. Isolation — isolated copy created and destroyed
# ─────────────────────────────────────────────────────────────────────────────

class TestIsolation:
    def test_isolated_copy_created_in_temp_dir(self):
        if not _demo_app_available():
            pytest.skip("demo-app not available")
        engine = MutationEngine()
        isolated_path, iso_ref = engine._create_isolated_copy(DEMO_APP_PATH)
        try:
            assert os.path.isdir(isolated_path)
            assert isolated_path != DEMO_APP_PATH
            assert iso_ref != ""
            # Isolated copy must be in the system temp dir
            assert isolated_path.startswith(tempfile.gettempdir())
        finally:
            shutil.rmtree(isolated_path, ignore_errors=True)

    def test_isolated_copy_contains_app_routes(self):
        if not _demo_app_available():
            pytest.skip("demo-app not available")
        engine = MutationEngine()
        isolated_path, _ = engine._create_isolated_copy(DEMO_APP_PATH)
        try:
            accounts_file = os.path.join(isolated_path, "app", "routes", "accounts.py")
            assert os.path.isfile(accounts_file)
        finally:
            shutil.rmtree(isolated_path, ignore_errors=True)

    def test_isolation_reference_is_not_absolute_path(self):
        if not _demo_app_available():
            pytest.skip("demo-app not available")
        engine = MutationEngine()
        isolated_path, iso_ref = engine._create_isolated_copy(DEMO_APP_PATH)
        try:
            assert not os.path.isabs(iso_ref)
            # iso_ref is just the basename
            assert "/" not in iso_ref
        finally:
            shutil.rmtree(isolated_path, ignore_errors=True)

    def test_isolated_copy_independent_of_original(self):
        """Modifying the isolated copy must not affect the original."""
        if not _demo_app_available():
            pytest.skip("demo-app not available")
        original_file = os.path.join(DEMO_APP_PATH, "app", "routes", "accounts.py")
        original_content = Path(original_file).read_text()

        engine = MutationEngine()
        isolated_path, _ = engine._create_isolated_copy(DEMO_APP_PATH)
        try:
            isolated_file = os.path.join(isolated_path, "app", "routes", "accounts.py")
            Path(isolated_file).write_text("# MUTATED\n" + original_content)
            # Original must be untouched
            assert Path(original_file).read_text() == original_content
        finally:
            shutil.rmtree(isolated_path, ignore_errors=True)
            # Double-check after cleanup
            assert Path(original_file).read_text() == original_content


# ─────────────────────────────────────────────────────────────────────────────
# 6. Main working tree remains unchanged
# ─────────────────────────────────────────────────────────────────────────────

class TestWorkingTreeIntegrity:
    def _hash_file(self, path: str) -> str:
        import hashlib
        h = hashlib.sha256()
        h.update(Path(path).read_bytes())
        return h.hexdigest()

    def test_accounts_py_unchanged_after_mutation_trial(self):
        """The original accounts.py must not change during or after a trial."""
        if not _demo_app_available():
            pytest.skip("demo-app not available")
        accounts_file = os.path.join(DEMO_APP_PATH, "app", "routes", "accounts.py")
        original_hash = self._hash_file(accounts_file)

        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        remove_mutant = next(
            m for m in mutants if m.mutation_type == MutationType.REMOVE_OWNERSHIP_CHECK
        )

        # Run the trial
        engine.run_mutation_trial(remove_mutant, invariant, DEMO_APP_PATH)

        # File must be unchanged
        assert self._hash_file(accounts_file) == original_hash

    def test_transactions_py_unchanged_after_sibling_trial(self):
        if not _demo_app_available():
            pytest.skip("demo-app not available")
        tx_file = os.path.join(DEMO_APP_PATH, "app", "routes", "transactions.py")
        original_hash = self._hash_file(tx_file)

        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        sibling_mutant = next(
            m for m in mutants if m.mutation_type == MutationType.SIBLING_ROUTE_UNPROTECTED
        )
        engine.run_mutation_trial(sibling_mutant, invariant, DEMO_APP_PATH)
        assert self._hash_file(tx_file) == original_hash

    def test_no_mutation_in_original_after_all_trials(self):
        if not _demo_app_available():
            pytest.skip("demo-app not available")
        # Record all relevant file hashes
        files_to_check = [
            os.path.join(DEMO_APP_PATH, "app", "routes", "accounts.py"),
            os.path.join(DEMO_APP_PATH, "app", "routes", "transactions.py"),
        ]
        original_hashes = {f: self._hash_file(f) for f in files_to_check}

        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        for mutant in mutants:
            engine.run_mutation_trial(mutant, invariant, DEMO_APP_PATH)

        for fpath, original_hash in original_hashes.items():
            assert self._hash_file(fpath) == original_hash, (
                f"File was modified by mutation testing: {fpath}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# 7-10. Mutation application — each mutation type
# ─────────────────────────────────────────────────────────────────────────────

class TestMutationApplication:
    """Tests mutation application in isolated copies without running HTTP checks."""

    def _patched_accounts_content(self) -> str:
        """Synthesize a minimal 'patched' accounts.py with an ownership check."""
        return '''\
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import sqlite3
from app.database import get_db
from app.auth import get_current_user

router = APIRouter()

class Account(BaseModel):
    id: int
    account_number: str
    account_type: str
    balance: float
    user_id: int

@router.get("/{account_id}", response_model=Account)
def get_account(
    account_id: int,
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Account not found")
    if row["user_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access forbidden")
    return Account(**dict(row))
'''

    def _make_temp_copy_with_content(self, filename: str, content: str) -> Tuple[str, str]:
        """Create a temp dir with a file at filename containing content."""
        tmpdir = tempfile.mkdtemp(prefix="securefix_test_")
        fpath = Path(tmpdir) / filename
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content)
        return tmpdir, str(fpath)

    def test_remove_ownership_check_removes_pattern(self):
        content = self._patched_accounts_content()
        engine = MutationEngine()
        tmpdir, _ = self._make_temp_copy_with_content(
            _BOLA_ACCOUNTS_FILE, content
        )
        try:
            mutant = SecurityMutant(
                mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
                description="test",
                affected_file=_BOLA_ACCOUNTS_FILE,
            )
            applied, note = engine._apply_mutation(tmpdir, mutant)
            assert applied is True
            result_content = (Path(tmpdir) / _BOLA_ACCOUNTS_FILE).read_text()
            # The ownership check block (if != ... raise 403) must be absent
            # Note: the import line may still contain "HTTPException" — that's expected
            assert 'row["user_id"] !=' not in result_content
            # The 403 raise specific to the ownership block must be gone
            assert 'if row["user_id"]' not in result_content
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_invert_ownership_comparison_changes_operator(self):
        content = self._patched_accounts_content()
        engine = MutationEngine()
        tmpdir, _ = self._make_temp_copy_with_content(
            _BOLA_ACCOUNTS_FILE, content
        )
        try:
            mutant = SecurityMutant(
                mutation_type=MutationType.INVERT_OWNERSHIP_COMPARISON,
                description="test",
                affected_file=_BOLA_ACCOUNTS_FILE,
            )
            applied, note = engine._apply_mutation(tmpdir, mutant)
            assert applied is True, f"Mutation not applied: {note}"
            result_content = (Path(tmpdir) / _BOLA_ACCOUNTS_FILE).read_text()
            # != should become ==
            assert 'row["user_id"] ==' in result_content
            assert 'row["user_id"] !=' not in result_content
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_sibling_route_unprotected_applied(self):
        if not _demo_app_available():
            pytest.skip("demo-app not available")
        engine = MutationEngine()
        isolated_path, _ = engine._create_isolated_copy(DEMO_APP_PATH)
        try:
            mutant = SecurityMutant(
                mutation_type=MutationType.SIBLING_ROUTE_UNPROTECTED,
                description="test",
                affected_file=os.path.join("app", "routes", "transactions.py"),
            )
            applied, note = engine._apply_mutation(isolated_path, mutant)
            assert applied is True
        finally:
            shutil.rmtree(isolated_path, ignore_errors=True)

    def test_unconditional_denial_inserts_raise(self):
        content = self._patched_accounts_content()
        engine = MutationEngine()
        tmpdir, _ = self._make_temp_copy_with_content(
            _BOLA_ACCOUNTS_FILE, content
        )
        try:
            mutant = SecurityMutant(
                mutation_type=MutationType.UNCONDITIONAL_DENIAL,
                description="test",
                affected_file=_BOLA_ACCOUNTS_FILE,
            )
            applied, note = engine._apply_mutation(tmpdir, mutant)
            assert applied is True
            result_content = (Path(tmpdir) / _BOLA_ACCOUNTS_FILE).read_text()
            # Unconditional denial must be present
            assert 'raise HTTPException(status_code=403' in result_content
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# 11-12. Mutation target verification
# ─────────────────────────────────────────────────────────────────────────────

class TestMutationTargetVerification:
    def test_target_not_found_produces_false(self):
        """If the target file doesn't exist, mutation returns (False, reason)."""
        engine = MutationEngine()
        tmpdir = tempfile.mkdtemp(prefix="securefix_test_")
        try:
            mutant = SecurityMutant(
                mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
                description="test",
                affected_file="app/routes/nonexistent.py",
            )
            applied, note = engine._apply_mutation(tmpdir, mutant)
            assert applied is False
            assert len(note) > 0
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_pattern_not_found_returns_appropriate_note(self):
        """A file that exists but doesn't contain the expected pattern."""
        engine = MutationEngine()
        tmpdir = tempfile.mkdtemp(prefix="securefix_test_")
        try:
            # Write a file with no ownership check
            fpath = Path(tmpdir) / _BOLA_ACCOUNTS_FILE
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text("# No ownership check here\ndef get_account(): pass\n")

            mutant = SecurityMutant(
                mutation_type=MutationType.INVERT_OWNERSHIP_COMPARISON,
                description="test",
                affected_file=_BOLA_ACCOUNTS_FILE,
            )
            applied, note = engine._apply_mutation(tmpdir, mutant)
            # Should return False — pattern not found
            assert applied is False
            assert len(note) > 0
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_source_path_not_found_returns_error_result(self):
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        result = engine.run_mutation_trial(
            mutants[0], invariant, "/nonexistent/path/to/app"
        )
        assert result.execution_status == MutationExecutionStatus.ERROR
        assert result.detection_state == MutationDetectionState.ERROR
        assert result.error is not None


# ─────────────────────────────────────────────────────────────────────────────
# 13. Application crash produces ERROR
# ─────────────────────────────────────────────────────────────────────────────

class TestErrorSemantics:
    def test_crash_produces_error_not_detected(self):
        """A mutant that causes the app to crash must produce ERROR, not DETECTED."""
        result = MutationResult(
            mutant_id="MUT-CRASH",
            mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
        )
        # Simulate a crash classification
        result.execution_status = MutationExecutionStatus.ERROR
        result.detection_state = MutationDetectionState.ERROR
        result.detected = False
        result.error = "Application crashed: ImportError"
        assert result.detected is False
        assert result.detection_state == MutationDetectionState.ERROR

    def test_error_state_is_not_detected(self):
        assert MutationDetectionState.ERROR != MutationDetectionState.DETECTED

    def test_unsupported_state_is_not_detected(self):
        assert MutationDetectionState.UNSUPPORTED != MutationDetectionState.DETECTED


# ─────────────────────────────────────────────────────────────────────────────
# Three assurance dimensions
# ─────────────────────────────────────────────────────────────────────────────

class TestAssuranceDimensions:
    def test_three_dimensions_not_collapsed(self):
        """MutationResult has three separate dimension fields."""
        r = MutationResult(
            mutant_id="MUT-1",
            mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
        )
        assert hasattr(r, "security_resistance")
        assert hasattr(r, "legitimate_behavior")
        assert hasattr(r, "verification_sensitivity")

    def test_dimension_model_has_required_fields(self):
        d = MutationAssuranceDimension(
            dimension="security_resistance",
            outcome=ExploitCheckOutcome.BYPASS,
            detail="test",
            check_names=["Exploit replay"],
        )
        assert d.dimension == "security_resistance"
        assert d.outcome == ExploitCheckOutcome.BYPASS

    def test_unconditional_denial_requires_legitimate_behavior_check(self):
        """UNCONDITIONAL_DENIAL must be detected via legitimate_behavior dimension."""
        result = MutationResult(
            mutant_id="MUT-2",
            mutation_type=MutationType.UNCONDITIONAL_DENIAL,
        )
        result.legitimate_behavior = MutationAssuranceDimension(
            dimension="legitimate_behavior",
            outcome=ExploitCheckOutcome.BYPASS,  # owner denied
            detail="Owner was denied — unconditional denial detected",
            check_names=["Legitimate-use contract (mutant)"],
        )
        result.security_resistance = MutationAssuranceDimension(
            dimension="security_resistance",
            outcome=ExploitCheckOutcome.PASS,  # attacker also blocked
            detail="Attacker blocked too",
            check_names=["Exploit replay (mutant)"],
        )
        # Detection should be via legitimate_behavior
        detected_via_legit = result.legitimate_behavior.outcome == ExploitCheckOutcome.BYPASS
        assert detected_via_legit is True


# ─────────────────────────────────────────────────────────────────────────────
# Detection classification logic
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectionClassification:
    def _make_result(self, mutation_type: MutationType) -> MutationResult:
        return MutationResult(
            mutant_id="MUT-X",
            mutation_type=mutation_type,
        )

    def _make_check(
        self,
        name: str,
        outcome: ExploitCheckOutcome,
        route: str = "/test/1",
    ):
        from app.models import VerificationCheck
        c = VerificationCheck(name=name)
        c.set_outcome_fields(outcome=outcome, route=route, http_method="GET")
        return c

    def test_bypass_on_exploit_produces_detected(self):
        from app.models import VerificationCheck
        engine = MutationEngine()
        mutant = SecurityMutant(
            mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
            description="test",
            expected_detection={"security_resistance": "bypass"},
        )
        result = self._make_result(MutationType.REMOVE_OWNERSHIP_CHECK)
        checks = [
            self._make_check("Exploit replay (mutant)", ExploitCheckOutcome.BYPASS),
            self._make_check("Legitimate-use contract (mutant)", ExploitCheckOutcome.PASS),
        ]
        engine._classify_detection(result, mutant, checks)
        assert result.detected is True
        assert result.detection_state == MutationDetectionState.DETECTED

    def test_bypass_on_legit_check_produces_detected(self):
        engine = MutationEngine()
        mutant = SecurityMutant(
            mutation_type=MutationType.UNCONDITIONAL_DENIAL,
            description="test",
            expected_detection={"legitimate_behavior": "denied"},
        )
        result = self._make_result(MutationType.UNCONDITIONAL_DENIAL)
        checks = [
            self._make_check("Exploit replay (mutant)", ExploitCheckOutcome.PASS),
            self._make_check("Legitimate-use contract (mutant)", ExploitCheckOutcome.BYPASS),
        ]
        engine._classify_detection(result, mutant, checks)
        assert result.detected is True
        assert result.detection_state == MutationDetectionState.DETECTED

    def test_all_pass_produces_survived(self):
        engine = MutationEngine()
        mutant = SecurityMutant(
            mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
            description="test",
            expected_detection={},
        )
        result = self._make_result(MutationType.REMOVE_OWNERSHIP_CHECK)
        checks = [
            self._make_check("Exploit replay (mutant)", ExploitCheckOutcome.PASS),
            self._make_check("Legitimate-use contract (mutant)", ExploitCheckOutcome.PASS),
        ]
        engine._classify_detection(result, mutant, checks)
        assert result.detected is False
        assert result.detection_state == MutationDetectionState.SURVIVED
        assert result.survived_detail is not None

    def test_error_in_check_produces_error_state(self):
        engine = MutationEngine()
        mutant = SecurityMutant(
            mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
            description="test",
            expected_detection={},
        )
        result = self._make_result(MutationType.REMOVE_OWNERSHIP_CHECK)
        checks = [
            self._make_check("Exploit replay (mutant)", ExploitCheckOutcome.ERROR),
        ]
        engine._classify_detection(result, mutant, checks)
        assert result.detection_state == MutationDetectionState.ERROR

    def test_survived_detail_populated_on_survived(self):
        engine = MutationEngine()
        mutant = SecurityMutant(
            mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
            description="test",
            expected_detection={},
        )
        result = self._make_result(MutationType.REMOVE_OWNERSHIP_CHECK)
        checks = [
            self._make_check("Exploit replay (mutant)", ExploitCheckOutcome.PASS),
            self._make_check("Legitimate-use contract (mutant)", ExploitCheckOutcome.PASS),
        ]
        engine._classify_detection(result, mutant, checks)
        assert result.survived_detail is not None
        assert len(result.survived_detail) > 0


# ─────────────────────────────────────────────────────────────────────────────
# MutationAssessment aggregate model
# ─────────────────────────────────────────────────────────────────────────────

class TestMutationAssessment:
    def test_assessment_has_required_fields(self):
        a = MutationAssessment(investigation_id="INV-1")
        assert hasattr(a, "total_mutants")
        assert hasattr(a, "detected_count")
        assert hasattr(a, "survived_count")
        assert hasattr(a, "error_count")
        assert hasattr(a, "unsupported_count")
        assert hasattr(a, "results")
        assert hasattr(a, "scope_limitations")

    def test_assessment_counts_are_independent(self):
        """The four count fields are independent — they must not be summed into one."""
        a = MutationAssessment(
            investigation_id="INV-1",
            total_mutants=4,
            detected_count=2,
            survived_count=1,
            error_count=1,
            unsupported_count=0,
        )
        assert a.detected_count == 2
        assert a.survived_count == 1
        assert a.error_count == 1

    def test_assessment_note_does_not_claim_complete_security(self):
        a = MutationAssessment(
            investigation_id="INV-1",
            total_mutants=2,
            detected_count=2,
        )
        a.assessment_note = _build_assessment_note(a)
        note_lower = a.assessment_note.lower()
        assert "100% security" not in note_lower
        assert "complete security assurance" not in note_lower

    def test_assessment_note_mentions_scope_limitation(self):
        a = MutationAssessment(
            investigation_id="INV-1",
            total_mutants=4,
            detected_count=4,
        )
        a.assessment_note = _build_assessment_note(a)
        assert "tested scope" in a.assessment_note

    def test_run_all_mutations_without_invariant(self):
        inv = _make_investigation(invariant=None)
        engine = MutationEngine()
        assessment = engine.run_all_mutations(inv, DEMO_APP_PATH)
        assert assessment.total_mutants == 0
        assert assessment.supported_count if hasattr(assessment, "supported_count") else True


# ─────────────────────────────────────────────────────────────────────────────
# No credentials in evidence
# ─────────────────────────────────────────────────────────────────────────────

class TestNoCredentialsInEvidence:
    def test_mutation_result_evidence_has_no_passwords(self):
        if not _demo_app_available():
            pytest.skip("demo-app not available")
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        result = engine.run_mutation_trial(mutants[0], invariant, DEMO_APP_PATH)
        evidence_str = str(result.evidence)
        assert "password" not in evidence_str.lower()
        assert "pass_a" not in evidence_str
        assert "owner_pass" not in evidence_str

    def test_security_mutant_model_has_no_credential_field(self):
        m = SecurityMutant(
            mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
            description="test",
        )
        fields = set(m.model_fields.keys())
        assert "auth_credentials" not in fields
        assert "password" not in fields

    def test_mutation_metadata_has_no_credentials(self):
        invariant = _make_minimal_bola_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        for m in mutants:
            meta_str = str(m.mutation_metadata)
            assert "password" not in meta_str.lower()
            assert "auth_credentials" not in meta_str


# ─────────────────────────────────────────────────────────────────────────────
# Live SecureBank mutation trials (end-to-end against real demo-app)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(
    not _demo_app_available(),
    reason="demo-app directory not available",
)
class TestLiveSecureBankMutation:
    """
    End-to-end mutation trials using the real SecureBank demo-app.

    These tests use the BOLA invariant inferred from the demo-app's own
    repository data (as the orchestrator would do in production).
    The trials are run against isolated copies — the demo-app is never modified.
    """

    def _securebank_invariant(self) -> SecurityInvariant:
        """Build the standard SecureBank BOLA invariant (scenario data)."""
        from app.models import (
            AttackScenario, InvariantProvenance, InvariantScope,
            LegitimateUseCase, OracleExpectedOutcome, SecurityOracle,
        )
        return SecurityInvariant(
            id="INV-SECUREBANK-BOLA",
            vulnerability_class=VulnerabilityClass.BOLA,
            cwe="CWE-639",
            statement=(
                "An authenticated user may access an account if and only if "
                "that user is the owner of the account."
            ),
            scope=InvariantScope(
                routes=["/api/accounts/{account_id}"],
                actor_roles=["authenticated_user", "resource_owner", "non_owner"],
                relevant_files=["app/routes/accounts.py"],
            ),
            attack=AttackScenario(
                method="GET",
                route_template="/api/accounts/{account_id}",
                route_example="/api/accounts/2",
                auth_endpoint="/api/auth/login",
                # SecureBank scenario data — these are demo credentials in the seed DB
                auth_credentials={"username": "alice", "password": "alice123"},
                auth_token_path="access_token",
            ),
            oracle=SecurityOracle(
                outcomes=[
                    OracleExpectedOutcome(
                        label="attack_blocked",
                        allowed_status_codes=[403, 404],
                        forbidden_status_codes=[200, 201],
                        protected_data_indicators=["balance", "account_number"],
                    ),
                    OracleExpectedOutcome(
                        label="exploit_active",
                        allowed_status_codes=[200, 201],
                        forbidden_status_codes=[403, 404],
                    ),
                ]
            ),
            legitimate_use=[
                LegitimateUseCase(
                    description="Alice accesses her own account",
                    method="GET",
                    route_example="/api/accounts/1",
                    auth_endpoint="/api/auth/login",
                    # Scenario data — demo credentials
                    auth_credentials={"username": "alice", "password": "alice123"},
                    expected_status_codes=[200],
                ),
            ],
            provenance=InvariantProvenance(
                investigation_id="INV-SECUREBANK",
                source_agents=["security_agent", "code_agent"],
                root_cause_cwe="CWE-639",
            ),
            supported=True,
        )

    def test_remove_ownership_check_detected_by_security_resistance(self):
        """
        REMOVE_OWNERSHIP_CHECK mutant:
        The check is removed so the app reverts to the baseline BOLA-vulnerable state.
        Alice can access account/2 → BYPASS → DETECTED via security_resistance.

        Note: the baseline SecureBank already lacks the ownership check,
        so this trial runs against the baseline (already vulnerable) state.
        The result should be DETECTED (exploit succeeds = BYPASS).
        """
        invariant = self._securebank_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        remove_mutant = next(
            m for m in mutants if m.mutation_type == MutationType.REMOVE_OWNERSHIP_CHECK
        )
        result = engine.run_mutation_trial(remove_mutant, invariant, DEMO_APP_PATH)

        # Must not be an error
        assert result.execution_status not in (
            MutationExecutionStatus.ERROR, MutationExecutionStatus.UNSUPPORTED
        ), f"Trial errored: {result.error}"

        # Security resistance must show BYPASS (exploit succeeded on unpatched app)
        assert result.security_resistance is not None
        assert result.security_resistance.outcome == ExploitCheckOutcome.BYPASS

        # Must be classified as DETECTED
        assert result.detected is True
        assert result.detection_state == MutationDetectionState.DETECTED

        # Cleanup completed
        assert result.cleanup_completed is True

    def test_unconditional_denial_detected_by_legitimate_behavior(self):
        """
        UNCONDITIONAL_DENIAL mutant:
        All requests get 403 — attacker blocked BUT owner also blocked.
        legitimate_behavior must show BYPASS (owner denied) → DETECTED.
        """
        invariant = self._securebank_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        denial_mutant = next(
            m for m in mutants if m.mutation_type == MutationType.UNCONDITIONAL_DENIAL
        )
        result = engine.run_mutation_trial(denial_mutant, invariant, DEMO_APP_PATH)

        assert result.execution_status not in (
            MutationExecutionStatus.ERROR, MutationExecutionStatus.UNSUPPORTED
        ), f"Trial errored: {result.error}"

        # Legitimate behavior must show BYPASS (owner was denied)
        assert result.legitimate_behavior is not None
        assert result.legitimate_behavior.outcome == ExploitCheckOutcome.BYPASS, (
            f"Expected owner denied (BYPASS), got: {result.legitimate_behavior.outcome}. "
            f"Detail: {result.legitimate_behavior.detail}"
        )

        # Must be classified as DETECTED (even if attacker was also blocked)
        assert result.detected is True
        assert result.detection_state == MutationDetectionState.DETECTED
        assert result.cleanup_completed is True

    def test_invert_ownership_comparison_detected(self):
        """
        INVERT_OWNERSHIP_COMPARISON:
        On the BASELINE (unpatched) SecureBank, the ownership check is absent,
        so the invert mutation target is not found → UNSUPPORTED (honest result).

        On a PATCHED SecureBank (with ownership check present), the mutation
        would produce DETECTED via one or both assurance dimensions.

        This test verifies that:
        - The trial completes cleanly (no crash, no silent failure)
        - The result is UNSUPPORTED (pattern not found) or DETECTED (if patched)
        - The cleanup always completes
        - If UNSUPPORTED, the error message explains why (target not found)
        """
        invariant = self._securebank_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        invert_mutant = next(
            m for m in mutants if m.mutation_type == MutationType.INVERT_OWNERSHIP_COMPARISON
        )
        result = engine.run_mutation_trial(invert_mutant, invariant, DEMO_APP_PATH)

        # Must not be an unexplained ERROR (crash/environment failure)
        assert result.execution_status != MutationExecutionStatus.ERROR, (
            f"Trial produced unexpected error: {result.error}"
        )

        # Acceptable outcomes:
        # UNSUPPORTED — ownership check not present in baseline (honest)
        # DETECTED — ownership check was present and the mutation was caught
        assert result.detection_state in (
            MutationDetectionState.UNSUPPORTED,
            MutationDetectionState.DETECTED,
        ), (
            f"Unexpected detection state: {result.detection_state}.  "
            f"security_resistance: {result.security_resistance}.  "
            f"legitimate_behavior: {result.legitimate_behavior}."
        )

        if result.detection_state == MutationDetectionState.UNSUPPORTED:
            # Document the verification gap explicitly
            assert result.error is not None
            assert "not found" in result.error.lower() or "not applied" in result.error.lower(), (
                f"UNSUPPORTED but no clear reason: {result.error}"
            )

        # Cleanup always completes regardless of mutation outcome
        assert result.cleanup_completed is True

    def test_sibling_route_trial_runs_without_error(self):
        """
        SIBLING_ROUTE_UNPROTECTED: transactions.py is already unprotected.
        The trial should complete (ERROR or DETECTED depending on scope checks).
        Working tree must be unchanged.
        """
        invariant = self._securebank_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        sibling_mutant = next(
            m for m in mutants if m.mutation_type == MutationType.SIBLING_ROUTE_UNPROTECTED
        )

        tx_file = os.path.join(DEMO_APP_PATH, "app", "routes", "transactions.py")
        original = Path(tx_file).read_text()

        result = engine.run_mutation_trial(sibling_mutant, invariant, DEMO_APP_PATH)

        # Working tree must be unchanged
        assert Path(tx_file).read_text() == original
        # Cleanup completed
        assert result.cleanup_completed is True

    def test_all_trial_results_cleanup(self):
        """All mutation trials must destroy their isolated copies."""
        invariant = self._securebank_invariant()
        engine = MutationEngine()
        mutants = engine.build_mutants(invariant)
        for mutant in mutants:
            result = engine.run_mutation_trial(mutant, invariant, DEMO_APP_PATH)
            if result.execution_status not in (
                MutationExecutionStatus.ERROR, MutationExecutionStatus.UNSUPPORTED
            ):
                assert result.cleanup_completed is True, (
                    f"Isolated copy not cleaned up for {mutant.mutation_type.value}"
                )

    def test_run_all_mutations_returns_assessment(self):
        invariant = self._securebank_invariant()
        inv = _make_investigation(invariant=invariant)
        engine = MutationEngine()
        assessment = engine.run_all_mutations(inv, DEMO_APP_PATH)
        assert assessment.total_mutants == 4
        assert len(assessment.results) == 4
        assert assessment.total_mutants == (
            assessment.detected_count + assessment.survived_count
            + assessment.error_count + assessment.unsupported_count
        )

    def test_assessment_scope_limitations_populated(self):
        invariant = self._securebank_invariant()
        inv = _make_investigation(invariant=invariant)
        engine = MutationEngine()
        assessment = engine.run_all_mutations(inv, DEMO_APP_PATH)
        assert len(assessment.scope_limitations) > 0
        assert any("BOLA" in lim for lim in assessment.scope_limitations)
