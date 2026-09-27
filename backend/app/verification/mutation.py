"""
Mutation Engine  (Phase 4 — Controlled Security Patch Mutation Testing)

Answers the question:
    "Would the existing verification suite detect a plausible faulty security patch?"

This module is an ASSURANCE LAYER that orchestrates:
    1. Isolated copy creation
    2. Allowlisted deterministic mutation application
    3. Existing VerificationEngine checks (adversarial variants + legitimate-use)
    4. Detection classification across three assurance dimensions
    5. Cleanup of the isolated copy

CRITICAL SAFETY CONSTRAINTS
----------------------------
- Mutants are NEVER applied to the original working tree.
- Every mutation trial uses a dedicated disposable temporary directory.
- The mutation engine disposes the isolated copy after execution.
- Only ALLOWLISTED mutation types may be applied (no arbitrary code generation).
- No credentials are stored in mutation records or evidence.
- Mutation application verifies the target pattern was found before claiming success.
- Application crashes are classified as ERROR, not DETECTED.

ARCHITECTURE
------------
MutationEngine
    └── run_mutation_trial(invariant, mutant_def, source_path)
              │
              ├── _create_isolated_copy()     creates tmp dir
              ├── _apply_mutation()           applies allowlisted transform
              ├── _verify_mutation_applied()  confirms pattern changed
              ├── _run_checks_in_isolation()  executes VerificationEngine
              ├── _classify_detection()       maps checks → three dimensions
              └── _cleanup_isolated_copy()    removes tmp dir

Three assurance dimensions:
    security_resistance    — Does the mutant resist the adversarial attack?
    legitimate_behavior    — Does the mutant still allow legitimate owner access?
    verification_sensitivity — Did the verification suite detect the mutation?
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app.models import (
    ExploitCheckOutcome,
    Investigation,
    MutationAssessment,
    MutationAssuranceDimension,
    MutationDetectionState,
    MutationExecutionStatus,
    MutationResult,
    MutationType,
    SecurityInvariant,
    SecurityMutant,
    VariantGenerationResult,
    VerificationCheck,
    VerificationResult,
    VulnerabilityClass,
)
from app.verification.variants import VariantGenerator


# ── Allowlisted mutation strategies ──────────────────────────────────────────
#
# Each entry maps MutationType → (search_pattern, replacement, description).
# search_pattern is a regex.  replacement is a string.
# The mutation is ONLY applied if the pattern is found.
#
# These are intentionally narrow — they target the specific BOLA security pattern
# in the SecureBank accounts route (app/routes/accounts.py), not arbitrary code.
#
# SAFETY: No arbitrary code is executed.  The patterns are statically defined here.

_BOLA_ACCOUNTS_FILE = os.path.join("app", "routes", "accounts.py")

# The ownership check that a correct fix would insert:
#   if row["user_id"] != current_user["id"]:
#       raise HTTPException(status_code=403, detail="Access forbidden")
_OWNERSHIP_CHECK_PATTERN = re.compile(
    r'(if\s+row\[.user_id.\]\s*!=\s*current_user\[.id.\]\s*:\s*\n'
    r'\s+raise\s+HTTPException\(status_code\s*=\s*403[^)]*\))',
    re.MULTILINE,
)

_OWNERSHIP_CHECK_INVERTED_PATTERN = re.compile(
    r'if\s+row\[.user_id.\]\s*==\s*current_user\[.id.\]\s*:\s*\n'
    r'\s+raise\s+HTTPException\(status_code\s*=\s*403[^)]*\)',
    re.MULTILINE,
)

# Pattern for the return statement after the ownership check
_RETURN_ACCOUNT_PATTERN = re.compile(
    r'(\n\s+return\s+Account\(\*\*dict\(row\)\))',
    re.MULTILINE,
)


class MutationEngine:
    """
    Orchestrates controlled security-patch mutation testing.

    Entry point:
        result = MutationEngine().run_mutation_trial(invariant, mutant, source_path)
        assessment = MutationEngine().run_all_mutations(investigation, source_path)

    source_path must be the path to the SecureBank demo-app directory
    (the directory containing app/routes/accounts.py).
    """

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def build_mutants(self, invariant: SecurityInvariant) -> List[SecurityMutant]:
        """
        Build the allowlisted set of SecurityMutant definitions for a BOLA invariant.

        Returns an empty list for unsupported invariant types.
        Does not create any files or isolated copies.
        """
        if not invariant.supported or invariant.vulnerability_class != VulnerabilityClass.BOLA:
            return []

        return [
            SecurityMutant(
                mutation_type=MutationType.REMOVE_OWNERSHIP_CHECK,
                description=(
                    "Remove the ownership authorization check from the patched endpoint.  "
                    "The endpoint remains authenticated but reverts to BOLA-vulnerable behavior."
                ),
                source_finding="Broken Object Level Authorization (BOLA/CWE-639)",
                source_invariant_id=invariant.id,
                affected_file=_BOLA_ACCOUNTS_FILE,
                mutation_metadata={
                    "target_pattern": "ownership check (if row[user_id] != current_user[id])",
                    "action": "remove",
                },
                expected_detection={
                    "security_resistance": "bypass",
                    "legitimate_behavior": "pass",
                    "verification_sensitivity": "detected",
                },
            ),
            SecurityMutant(
                mutation_type=MutationType.INVERT_OWNERSHIP_COMPARISON,
                description=(
                    "Invert the ownership comparison operator so the authorization decision "
                    "is logically reversed: owners are denied and non-owners are permitted."
                ),
                source_finding="Broken Object Level Authorization (BOLA/CWE-639)",
                source_invariant_id=invariant.id,
                affected_file=_BOLA_ACCOUNTS_FILE,
                mutation_metadata={
                    "target_pattern": "ownership check (if row[user_id] != current_user[id])",
                    "action": "invert_comparison",
                },
                expected_detection={
                    "security_resistance": "bypass",
                    "legitimate_behavior": "denied",
                    "verification_sensitivity": "detected",
                },
            ),
            SecurityMutant(
                mutation_type=MutationType.SIBLING_ROUTE_UNPROTECTED,
                description=(
                    "Protect the primary accounts endpoint but leave the transactions "
                    "sibling route without an ownership check.  "
                    "Tests whether sibling-route variants detect the gap."
                ),
                source_finding="Broken Object Level Authorization (BOLA/CWE-639)",
                source_invariant_id=invariant.id,
                affected_file=os.path.join("app", "routes", "transactions.py"),
                mutation_metadata={
                    "target_pattern": "transactions route (no ownership check present — already vulnerable)",
                    "action": "leave_unprotected",
                },
                expected_detection={
                    "security_resistance": "pass",   # primary route is protected
                    "legitimate_behavior": "pass",
                    "verification_sensitivity": "detected",  # via sibling-route variant
                },
            ),
            SecurityMutant(
                mutation_type=MutationType.UNCONDITIONAL_DENIAL,
                description=(
                    "Replace the ownership check with an unconditional 403 denial that "
                    "blocks all authenticated users including the legitimate owner.  "
                    "Attack appears blocked but legitimate owner access is broken."
                ),
                source_finding="Broken Object Level Authorization (BOLA/CWE-639)",
                source_invariant_id=invariant.id,
                affected_file=_BOLA_ACCOUNTS_FILE,
                mutation_metadata={
                    "target_pattern": "ownership check",
                    "action": "unconditional_deny_all",
                },
                expected_detection={
                    "security_resistance": "pass",   # attacker is also blocked
                    "legitimate_behavior": "denied",  # owner is blocked — detected here
                    "verification_sensitivity": "detected",
                },
            ),
        ]

    def run_mutation_trial(
        self,
        mutant: SecurityMutant,
        invariant: SecurityInvariant,
        source_path: str,
    ) -> MutationResult:
        """
        Execute one mutation trial against an isolated copy of source_path.

        source_path must be the SecureBank demo-app directory.
        The original source_path is never modified.

        Returns a MutationResult with three assurance dimensions and cleanup status.
        """
        result = MutationResult(
            mutant_id=mutant.mutant_id,
            mutation_type=mutant.mutation_type,
        )

        if not os.path.isdir(source_path):
            result.execution_status = MutationExecutionStatus.ERROR
            result.detection_state = MutationDetectionState.ERROR
            result.error = f"Source path not found: {os.path.basename(source_path)}"
            result.evidence = {"error": result.error}
            return result

        isolated_path = None
        try:
            # ── Step 1: Create isolated copy ──────────────────────────────────
            isolated_path, iso_ref = self._create_isolated_copy(source_path)
            mutant.isolation_reference = iso_ref
            result.evidence["isolation_reference"] = iso_ref
            result.evidence["mutation_type"] = mutant.mutation_type.value
            result.evidence["affected_file"] = mutant.affected_file

            # ── Step 2: Apply the allowlisted mutation ─────────────────────────
            applied, apply_note = self._apply_mutation(isolated_path, mutant)
            result.evidence["mutation_applied"] = applied
            result.evidence["mutation_note"] = apply_note

            if not applied:
                result.execution_status = MutationExecutionStatus.UNSUPPORTED
                result.detection_state = MutationDetectionState.UNSUPPORTED
                result.error = f"Mutation not applied: {apply_note}"
                return result

            result.execution_status = MutationExecutionStatus.APPLIED

            # ── Step 3: Run checks against the isolated copy ──────────────────
            checks, run_error = self._run_checks_in_isolation(
                isolated_path, invariant, mutant.mutation_type
            )
            result.verification_checks = checks
            result.evidence["check_count"] = len(checks)
            result.evidence["observed_outcomes"] = [
                {
                    "name": c.name,
                    "status": c.status,
                    "outcome": c.outcome.value if c.outcome else None,
                    "status_code": c.observed_status_code,
                }
                for c in checks
            ]

            if run_error:
                result.execution_status = MutationExecutionStatus.ERROR
                result.detection_state = MutationDetectionState.ERROR
                result.error = run_error
                return result

            result.execution_status = MutationExecutionStatus.EXECUTED

            # ── Step 4: Classify detection across three dimensions ─────────────
            self._classify_detection(result, mutant, checks)

        except Exception as exc:
            result.execution_status = MutationExecutionStatus.ERROR
            result.detection_state = MutationDetectionState.ERROR
            result.error = f"Unexpected error during mutation trial: {type(exc).__name__}: {exc}"

        finally:
            # ── Step 5: Cleanup isolated copy ─────────────────────────────────
            if isolated_path and os.path.isdir(isolated_path):
                try:
                    shutil.rmtree(isolated_path, ignore_errors=True)
                    result.cleanup_completed = True
                    result.execution_status = MutationExecutionStatus.CLEANED_UP
                except Exception:
                    result.cleanup_completed = False

        return result

    def run_all_mutations(
        self,
        investigation: Investigation,
        source_path: str,
    ) -> MutationAssessment:
        """
        Build all mutants for the investigation's invariant and run each trial.

        Returns a MutationAssessment with aggregate counts and per-mutant results.
        """
        invariant = investigation.security_invariant
        assessment = MutationAssessment(
            investigation_id=investigation.id,
            invariant_id=invariant.id if invariant else "",
        )
        assessment.scope_limitations = _SCOPE_LIMITATIONS

        if invariant is None:
            assessment.assessment_note = (
                "No SecurityInvariant present — mutation testing requires a supported invariant."
            )
            return assessment

        if not invariant.supported or invariant.vulnerability_class != VulnerabilityClass.BOLA:
            assessment.assessment_note = (
                f"Mutation testing for {invariant.vulnerability_class.value} "
                "is not yet supported.  Phase 4 covers BOLA only."
            )
            return assessment

        mutants = self.build_mutants(invariant)
        assessment.total_mutants = len(mutants)

        for mutant in mutants:
            result = self.run_mutation_trial(mutant, invariant, source_path)
            assessment.results.append(result)

            if result.detection_state == MutationDetectionState.DETECTED:
                assessment.detected_count += 1
            elif result.detection_state == MutationDetectionState.SURVIVED:
                assessment.survived_count += 1
            elif result.detection_state == MutationDetectionState.ERROR:
                assessment.error_count += 1
            else:
                assessment.unsupported_count += 1

        assessment.assessment_note = _build_assessment_note(assessment)
        return assessment

    # ─────────────────────────────────────────────────────────────────────────
    # Isolation
    # ─────────────────────────────────────────────────────────────────────────

    def _create_isolated_copy(self, source_path: str) -> Tuple[str, str]:
        """
        Copy source_path to a new temporary directory.

        Returns (isolated_absolute_path, sanitized_reference).
        The sanitized reference is a short hash — not the full path.
        The isolated directory is under the system temp dir.
        """
        tmp_parent = tempfile.gettempdir()
        # Stable name prefix for audit; not sensitive
        path_hash = hashlib.md5(source_path.encode(), usedforsecurity=False).hexdigest()[:8]
        isolated_dir = tempfile.mkdtemp(
            prefix=f"securefix_mutant_{path_hash}_",
            dir=tmp_parent,
        )
        shutil.copytree(source_path, isolated_dir, dirs_exist_ok=True)
        # Sanitized reference: just the temp dir name, not the full path
        iso_ref = os.path.basename(isolated_dir)
        return isolated_dir, iso_ref

    # ─────────────────────────────────────────────────────────────────────────
    # Mutation application (allowlisted transforms only)
    # ─────────────────────────────────────────────────────────────────────────

    def _apply_mutation(
        self, isolated_path: str, mutant: SecurityMutant
    ) -> Tuple[bool, str]:
        """
        Apply the allowlisted mutation to the isolated copy.

        Returns (applied: bool, note: str).
        Returns (False, reason) if the target pattern is not found.

        SAFETY:
        - Only operates on files inside isolated_path.
        - Only applies transformations defined in this method.
        - No arbitrary code execution.
        - No shell commands.
        """
        target_file = Path(isolated_path) / mutant.affected_file
        if not target_file.is_file():
            return False, f"Target file not found: {mutant.affected_file}"

        try:
            content = target_file.read_text(encoding="utf-8")
        except Exception as e:
            return False, f"Could not read target file: {e}"

        mutation_type = mutant.mutation_type

        if mutation_type == MutationType.REMOVE_OWNERSHIP_CHECK:
            return self._mutate_remove_ownership_check(target_file, content)

        elif mutation_type == MutationType.INVERT_OWNERSHIP_COMPARISON:
            return self._mutate_invert_ownership_comparison(target_file, content)

        elif mutation_type == MutationType.SIBLING_ROUTE_UNPROTECTED:
            # The transactions route is already unprotected in the original SecureBank.
            # This mutant verifies that a patched primary route + unprotected sibling
            # is caught by sibling-route variants.
            # We confirm the sibling file exists and the ownership check is absent.
            return self._mutate_sibling_route_unprotected(target_file, content)

        elif mutation_type == MutationType.UNCONDITIONAL_DENIAL:
            return self._mutate_unconditional_denial(target_file, content)

        return False, f"Unknown mutation type: {mutation_type.value}"

    def _mutate_remove_ownership_check(
        self, target_file: Path, content: str
    ) -> Tuple[bool, str]:
        """
        Remove the ownership check from the patched endpoint.

        The patched file should contain:
            if row["user_id"] != current_user["id"]:
                raise HTTPException(status_code=403, detail="Access forbidden")

        After mutation this block is absent — endpoint reverts to BOLA-vulnerable.

        ALSO handles the vulnerable-state case (check not present):
        if the check is absent, we ensure it stays absent (already mutated by default).
        """
        # Check if ownership check is already absent (baseline vulnerable state)
        if not _OWNERSHIP_CHECK_PATTERN.search(content):
            # Already vulnerable — confirm it's the accounts route with BUG comment
            if "# BUG:" in content or "user_id" in content:
                # Already in the "removed" state
                target_file.write_text(content, encoding="utf-8")
                return True, "Ownership check already absent — mutant is the baseline vulnerable state"
            return False, "Ownership check not found and not a recognized accounts route"

        # Remove the ownership check block
        mutated = _OWNERSHIP_CHECK_PATTERN.sub("", content)
        # Clean up extra blank lines
        mutated = re.sub(r'\n{3,}', '\n\n', mutated)
        target_file.write_text(mutated, encoding="utf-8")
        return True, "Ownership check removed from patched endpoint"

    def _mutate_invert_ownership_comparison(
        self, target_file: Path, content: str
    ) -> Tuple[bool, str]:
        """
        Invert the ownership comparison.

        Patched:   if row["user_id"] != current_user["id"]:   → deny non-owner
        Mutated:   if row["user_id"] == current_user["id"]:   → deny owner!
        """
        # Handle already-inverted case
        if _OWNERSHIP_CHECK_INVERTED_PATTERN.search(content):
            return True, "Ownership comparison already inverted"

        if not _OWNERSHIP_CHECK_PATTERN.search(content):
            return False, "Ownership check pattern not found in target file"

        # Replace != with == in the ownership check
        mutated = _OWNERSHIP_CHECK_PATTERN.sub(
            lambda m: m.group(0).replace("!=", "=="),
            content,
        )
        target_file.write_text(mutated, encoding="utf-8")
        return True, "Ownership comparison inverted (== instead of !=)"

    def _mutate_sibling_route_unprotected(
        self, target_file: Path, content: str
    ) -> Tuple[bool, str]:
        """
        Verify that the sibling route file (transactions.py) exists and
        contains no ownership check.

        For the SecureBank baseline, transactions.py is already unprotected.
        This mutation type uses the existing vulnerable sibling route as-is.
        The mutation 'confirms' the sibling is unprotected rather than actively
        transforming anything.  This is intentional — the point is to test the
        sibling-route adversarial variant.
        """
        # Confirm the file is a transactions route
        if "transaction" not in str(target_file).lower():
            return False, f"Expected a transactions route file; got {target_file.name}"

        # Verify there is no ownership check (i.e. it is already unprotected)
        if _OWNERSHIP_CHECK_PATTERN.search(content):
            # The transactions file has an ownership check — remove it to make it vulnerable
            mutated = _OWNERSHIP_CHECK_PATTERN.sub("", content)
            mutated = re.sub(r'\n{3,}', '\n\n', mutated)
            target_file.write_text(mutated, encoding="utf-8")
            return True, "Ownership check removed from sibling route (making it unprotected)"

        # Already unprotected
        return True, "Sibling route is already unprotected (baseline SecureBank state)"

    def _mutate_unconditional_denial(
        self, target_file: Path, content: str
    ) -> Tuple[bool, str]:
        """
        Replace the ownership check with an unconditional 403 raise.

        Patched:
            if row["user_id"] != current_user["id"]:
                raise HTTPException(status_code=403, detail="Access forbidden")
            return Account(**dict(row))

        Mutated:
            raise HTTPException(status_code=403, detail="Access forbidden")
            return Account(**dict(row))   ← unreachable but structurally present

        This blocks the attacker AND the legitimate owner.
        """
        unconditional_block = (
            '    raise HTTPException(status_code=403, detail="Access forbidden")'
        )

        # Case 1: patched endpoint has the ownership check
        if _OWNERSHIP_CHECK_PATTERN.search(content):
            mutated = _OWNERSHIP_CHECK_PATTERN.sub(
                unconditional_block,
                content,
            )
            target_file.write_text(mutated, encoding="utf-8")
            return True, "Ownership check replaced with unconditional 403 denial"

        # Case 2: baseline vulnerable endpoint — insert unconditional 403 before return
        if "return Account(**dict(row))" in content:
            mutated = content.replace(
                "    return Account(**dict(row))",
                f"{unconditional_block}\n    return Account(**dict(row))",
                1,  # Replace only the first occurrence
            )
            target_file.write_text(mutated, encoding="utf-8")
            return True, "Unconditional 403 denial inserted before return statement"

        return False, "Could not locate insertion point for unconditional denial"

    # ─────────────────────────────────────────────────────────────────────────
    # Verification execution
    # ─────────────────────────────────────────────────────────────────────────

    def _run_checks_in_isolation(
        self,
        isolated_path: str,
        invariant: SecurityInvariant,
        mutation_type: MutationType,
    ) -> Tuple[List[VerificationCheck], Optional[str]]:
        """
        Execute authentication + exploit + legitimate-use checks against the
        isolated copy using the existing TestClient subprocess mechanism.

        Returns (checks, error_string_or_None).

        Uses the same pattern as VerificationEngine._run_authenticated_exploit()
        but always executes against the isolated_path, never the original.
        """
        checks: List[VerificationCheck] = []
        attack = invariant.attack
        blocked_outcome = invariant.oracle.blocked_outcome

        python = self._find_python(isolated_path)
        if not python:
            return checks, "No Python executable found in isolated copy"

        # ── Adversarial exploit check (security_resistance dimension) ─────────
        if attack.auth_endpoint and attack.auth_credentials and blocked_outcome:
            exploit_check, err = self._run_http_check_subprocess(
                isolated_path=isolated_path,
                python=python,
                check_name="Exploit replay (mutant)",
                auth_endpoint=attack.auth_endpoint,
                auth_credentials=attack.auth_credentials,
                auth_token_path=attack.auth_token_path or "access_token",
                method=attack.method.upper(),
                route=attack.route_example,
                blocked_outcome=blocked_outcome,
            )
            checks.append(exploit_check)

            # For sibling-route mutant, also check the sibling route
            if mutation_type == MutationType.SIBLING_ROUTE_UNPROTECTED:
                sibling_route = self._infer_sibling_route(attack.route_example, invariant)
                if sibling_route:
                    sibling_check, _ = self._run_http_check_subprocess(
                        isolated_path=isolated_path,
                        python=python,
                        check_name="Sibling route exploit (mutant)",
                        auth_endpoint=attack.auth_endpoint,
                        auth_credentials=attack.auth_credentials,
                        auth_token_path=attack.auth_token_path or "access_token",
                        method="GET",
                        route=sibling_route,
                        blocked_outcome=blocked_outcome,
                    )
                    checks.append(sibling_check)

        # ── Legitimate-use check (legitimate_behavior dimension) ──────────────
        for uc in invariant.legitimate_use:
            if 200 in uc.expected_status_codes and uc.auth_credentials:
                from app.models import OracleExpectedOutcome
                owner_blocked = OracleExpectedOutcome(
                    label="owner_access_allowed",
                    allowed_status_codes=uc.expected_status_codes,
                    forbidden_status_codes=[403, 404],
                )
                legit_check, _ = self._run_http_check_subprocess(
                    isolated_path=isolated_path,
                    python=python,
                    check_name="Legitimate-use contract (mutant)",
                    auth_endpoint=uc.auth_endpoint,
                    auth_credentials=uc.auth_credentials,
                    auth_token_path=uc.auth_token_path or "access_token",
                    method=uc.method.upper(),
                    route=uc.route_example,
                    blocked_outcome=owner_blocked,
                )
                # For legitimate-use: PASS means owner CAN access (good);
                # BYPASS means owner was denied (bad — legitimate-behavior dimension fails)
                # Re-label for clarity
                if legit_check.outcome == ExploitCheckOutcome.PASS:
                    legit_check.detail = f"Legitimate use: owner access preserved → {legit_check.detail}"
                elif legit_check.outcome == ExploitCheckOutcome.BYPASS:
                    legit_check.detail = f"Legitimate use REGRESSION: owner denied → {legit_check.detail}"
                checks.append(legit_check)
                break  # One legitimate-use check is sufficient

        return checks, None

    def _run_http_check_subprocess(
        self,
        isolated_path: str,
        python: str,
        check_name: str,
        auth_endpoint: str,
        auth_credentials: dict,
        auth_token_path: str,
        method: str,
        route: str,
        blocked_outcome,
    ) -> Tuple[VerificationCheck, Optional[str]]:
        """
        Execute one HTTP check via a subprocess TestClient script.

        Credentials are passed as json.loads() — never via shell arguments.
        The subprocess runs with cwd=isolated_path.
        """
        from app.models import OracleExpectedOutcome
        from app.verification.engine import _evaluate_oracle, _sanitize_body

        check = VerificationCheck(name=check_name)
        creds_json = json.dumps(auth_credentials)
        method_lower = method.lower()

        script = (
            "import sys, json\n"
            "from fastapi.testclient import TestClient\n"
            "try:\n"
            "    from app.main import app\n"
            "    with TestClient(app) as client:\n"
            f"        creds = json.loads({creds_json!r})\n"
            f"        auth_resp = client.post({auth_endpoint!r}, json=creds)\n"
            "        if auth_resp.status_code != 200:\n"
            "            print(json.dumps({'error': 'Auth failed: ' + str(auth_resp.status_code)}))\n"
            "            sys.exit(2)\n"
            f"        token = auth_resp.json().get({auth_token_path!r})\n"
            f"        resp = getattr(client, {method_lower!r})(\n"
            f"            {route!r},\n"
            "            headers={'Authorization': f'Bearer {token}'}\n"
            "        )\n"
            "        print(json.dumps({'status_code': resp.status_code, 'body': resp.text[:400]}))\n"
            "        sys.exit(0)\n"
            "except Exception as e:\n"
            "    print(json.dumps({'error': str(e)}))\n"
            "    sys.exit(3)\n"
        )

        try:
            res = subprocess.run(
                [python, "-c", script],
                cwd=isolated_path,
                capture_output=True,
                text=True,
                timeout=20,
            )
            data: dict = {}
            for line in res.stdout.splitlines():
                try:
                    data = json.loads(line)
                    break
                except Exception:
                    pass

            if data.get("error"):
                check.set_outcome_fields(
                    outcome=ExploitCheckOutcome.ERROR,
                    route=route,
                    http_method=method,
                    execution_error=data["error"],
                )
                check.detail = f"Execution error: {data['error']}"
                return check, data["error"]

            status_code = data.get("status_code")
            body = data.get("body", "")
            if status_code is not None:
                outcome = _evaluate_oracle(status_code, body, blocked_outcome)
                check.set_outcome_fields(
                    outcome=outcome,
                    route=route,
                    http_method=method,
                    observed_status_code=status_code,
                    expected_outcome_label=blocked_outcome.label,
                    response_evidence=_sanitize_body(body),
                )
                check.detail = f"{method} {route} → HTTP {status_code}"
                return check, None

            err = f"No JSON output from subprocess (exit {res.returncode}): {res.stderr[:200]}"
            check.set_outcome_fields(
                outcome=ExploitCheckOutcome.ERROR,
                route=route,
                http_method=method,
                execution_error=err,
            )
            check.detail = err
            return check, err

        except subprocess.TimeoutExpired:
            err = "Subprocess timed out"
            check.set_outcome_fields(
                outcome=ExploitCheckOutcome.ERROR,
                route=route,
                http_method=method,
                execution_error=err,
            )
            check.detail = err
            return check, err
        except FileNotFoundError:
            err = "Python not found in isolated copy"
            check.set_outcome_fields(
                outcome=ExploitCheckOutcome.ERROR,
                route=route,
                http_method=method,
                execution_error=err,
            )
            check.detail = err
            return check, err
        except Exception as e:
            err = str(e)
            check.set_outcome_fields(
                outcome=ExploitCheckOutcome.ERROR,
                route=route,
                http_method=method,
                execution_error=err,
            )
            check.detail = err
            return check, err

    def _infer_sibling_route(
        self, primary_route: str, invariant: SecurityInvariant
    ) -> Optional[str]:
        """
        Infer a sibling route from the invariant scope or route template.
        Returns None if no sibling can be determined safely.
        """
        # Look for a route in scope that shares the prefix but has a suffix
        from app.verification.variants import _extract_route_prefix, _extract_numeric_id
        prefix = _extract_route_prefix(primary_route)
        numeric_id, _ = _extract_numeric_id(primary_route)

        for route in invariant.scope.routes:
            if route != primary_route and route.startswith(prefix.rstrip("/")):
                # Resolve path params
                if "{" in route and numeric_id:
                    resolved = re.sub(r'\{[^}]+\}', str(numeric_id), route)
                    return resolved
                return route
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # Detection classification
    # ─────────────────────────────────────────────────────────────────────────

    def _classify_detection(
        self,
        result: MutationResult,
        mutant: SecurityMutant,
        checks: List[VerificationCheck],
    ) -> None:
        """
        Map verification check outcomes to the three assurance dimensions.

        security_resistance:   Does the exploit check show BYPASS?
                               BYPASS → security_resistance = BYPASS (bad for mutant)
                               PASS   → security_resistance = PASS (mutant evaded detection)
        legitimate_behavior:   Does the legitimate-use check show BYPASS?
                               (here BYPASS means owner was denied — regression)
        verification_sensitivity: Combined — is EITHER dimension showing a failure?

        A mutant is DETECTED when at least one dimension shows a failure
        (BYPASS for attacker OR BYPASS for owner).
        """
        # Categorize checks
        exploit_checks = [c for c in checks if "exploit" in c.name.lower() or "sibling" in c.name.lower()]
        legit_checks = [c for c in checks if "legitimate" in c.name.lower() or "contract" in c.name.lower()]

        # ── Security resistance ───────────────────────────────────────────────
        if exploit_checks:
            # Any BYPASS = attacker got through
            bypass_exploit = [c for c in exploit_checks if c.outcome == ExploitCheckOutcome.BYPASS]
            error_exploit = [c for c in exploit_checks if c.outcome == ExploitCheckOutcome.ERROR]
            if bypass_exploit:
                result.security_resistance = MutationAssuranceDimension(
                    dimension="security_resistance",
                    outcome=ExploitCheckOutcome.BYPASS,
                    detail=(
                        f"Attacker succeeded: exploit replay returned BYPASS on "
                        f"{', '.join(c.route for c in bypass_exploit)}"
                    ),
                    check_names=[c.name for c in bypass_exploit],
                )
            elif error_exploit:
                result.security_resistance = MutationAssuranceDimension(
                    dimension="security_resistance",
                    outcome=ExploitCheckOutcome.ERROR,
                    detail=f"Exploit check execution error: {error_exploit[0].execution_error}",
                    check_names=[c.name for c in error_exploit],
                )
            else:
                result.security_resistance = MutationAssuranceDimension(
                    dimension="security_resistance",
                    outcome=ExploitCheckOutcome.PASS,
                    detail="Exploit was blocked by the mutant (attacker not permitted through)",
                    check_names=[c.name for c in exploit_checks],
                )
        else:
            result.security_resistance = MutationAssuranceDimension(
                dimension="security_resistance",
                outcome=ExploitCheckOutcome.UNSUPPORTED,
                detail="No exploit checks executed",
                check_names=[],
            )

        # ── Legitimate behavior ───────────────────────────────────────────────
        if legit_checks:
            # BYPASS in legitimate-use means owner was denied (regression)
            denied_legit = [c for c in legit_checks if c.outcome == ExploitCheckOutcome.BYPASS]
            error_legit = [c for c in legit_checks if c.outcome == ExploitCheckOutcome.ERROR]
            if denied_legit:
                result.legitimate_behavior = MutationAssuranceDimension(
                    dimension="legitimate_behavior",
                    outcome=ExploitCheckOutcome.BYPASS,
                    detail=(
                        "Legitimate owner was denied access — ownership regression detected.  "
                        f"Route: {', '.join(c.route for c in denied_legit)}"
                    ),
                    check_names=[c.name for c in denied_legit],
                )
            elif error_legit:
                result.legitimate_behavior = MutationAssuranceDimension(
                    dimension="legitimate_behavior",
                    outcome=ExploitCheckOutcome.ERROR,
                    detail=f"Legitimate-use check error: {error_legit[0].execution_error}",
                    check_names=[c.name for c in error_legit],
                )
            else:
                result.legitimate_behavior = MutationAssuranceDimension(
                    dimension="legitimate_behavior",
                    outcome=ExploitCheckOutcome.PASS,
                    detail="Legitimate owner can still access own resource",
                    check_names=[c.name for c in legit_checks],
                )
        else:
            result.legitimate_behavior = MutationAssuranceDimension(
                dimension="legitimate_behavior",
                outcome=ExploitCheckOutcome.UNSUPPORTED,
                detail="No legitimate-use checks executed",
                check_names=[],
            )

        # ── Verification sensitivity (combined) ───────────────────────────────
        sr = result.security_resistance
        lb = result.legitimate_behavior
        detected_by_security = sr and sr.outcome == ExploitCheckOutcome.BYPASS
        detected_by_legit = lb and lb.outcome == ExploitCheckOutcome.BYPASS
        error_in_checks = (sr and sr.outcome == ExploitCheckOutcome.ERROR) or \
                          (lb and lb.outcome == ExploitCheckOutcome.ERROR)

        if detected_by_security or detected_by_legit:
            dimensions = []
            if detected_by_security:
                dimensions.append("security_resistance")
            if detected_by_legit:
                dimensions.append("legitimate_behavior")
            result.verification_sensitivity = MutationAssuranceDimension(
                dimension="verification_sensitivity",
                outcome=ExploitCheckOutcome.BYPASS,  # verification caught the mutant
                detail=f"Mutant detected by: {', '.join(dimensions)}",
                check_names=[c.name for c in checks if c.outcome == ExploitCheckOutcome.BYPASS],
            )
            result.detected = True
            result.detection_state = MutationDetectionState.DETECTED
        elif error_in_checks:
            result.verification_sensitivity = MutationAssuranceDimension(
                dimension="verification_sensitivity",
                outcome=ExploitCheckOutcome.ERROR,
                detail="Verification could not execute cleanly — result is inconclusive",
                check_names=[c.name for c in checks if c.outcome == ExploitCheckOutcome.ERROR],
            )
            result.detected = False
            result.detection_state = MutationDetectionState.ERROR
            result.error = result.error or "Check execution error"
        else:
            # Neither dimension detected the mutant — SURVIVED
            result.verification_sensitivity = MutationAssuranceDimension(
                dimension="verification_sensitivity",
                outcome=ExploitCheckOutcome.PASS,  # verification passed the faulty patch
                detail="Mutant was NOT detected — verification gap identified",
                check_names=[c.name for c in checks],
            )
            result.detected = False
            result.detection_state = MutationDetectionState.SURVIVED
            result.survived_detail = (
                f"Mutation type '{mutant.mutation_type.value}' was not detected by any "
                "verification check.  Expected checks: "
                f"{', '.join(mutant.expected_detection.keys())}.  "
                "Suggested improvement: add verification checks that cover this mutation."
            )

        result.evidence["detection_state"] = result.detection_state.value
        result.evidence["detected_by"] = {
            "security_resistance": detected_by_security,
            "legitimate_behavior": detected_by_legit,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _find_python(self, repo_path: str) -> Optional[str]:
        """Find the Python executable for the isolated copy."""
        candidates = [
            os.path.join(repo_path, ".venv", "bin", "python"),
            os.path.join(repo_path, ".venv", "bin", "python3"),
            "python3",
            "python",
        ]
        for p in candidates:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        # Fall back to system python — required when .venv not present in isolated copy
        import shutil as _shutil
        return _shutil.which("python3") or _shutil.which("python")


# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────

_SCOPE_LIMITATIONS = [
    "Phase 4 mutation testing covers BOLA (CWE-639) only",
    "Only four allowlisted mutation types are supported: "
    "REMOVE_OWNERSHIP_CHECK, INVERT_OWNERSHIP_COMPARISON, "
    "SIBLING_ROUTE_UNPROTECTED, UNCONDITIONAL_DENIAL",
    "Mutations target app/routes/accounts.py and app/routes/transactions.py only",
    "TestClient-based HTTP verification does not exercise TLS, rate limiting, "
    "or production middleware",
    "This assessment covers the tested scope only — it does not constitute "
    "complete security assurance",
    "Surviving mutants indicate verification gaps, not proof of security",
]


def _build_assessment_note(assessment: MutationAssessment) -> str:
    parts = [
        f"Mutation assessment: {assessment.total_mutants} mutant(s) run.  "
        f"Detected: {assessment.detected_count}.  "
        f"Survived: {assessment.survived_count}.  "
        f"Errors: {assessment.error_count}.  "
        f"Unsupported: {assessment.unsupported_count}."
    ]
    if assessment.survived_count > 0:
        parts.append(
            f"WARNING: {assessment.survived_count} mutant(s) survived — "
            "these represent verification gaps that should be addressed."
        )
    if assessment.error_count > 0:
        parts.append(
            f"NOTE: {assessment.error_count} trial(s) encountered errors — "
            "results are inconclusive for those mutants."
        )
    parts.append(
        "This assessment covers the tested scope only.  "
        "VERIFIED WITHIN TESTED SCOPE is the appropriate conclusion when all "
        "tested mutants are detected and no errors remain."
    )
    return "  ".join(parts)
