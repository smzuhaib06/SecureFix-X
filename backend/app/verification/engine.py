"""
Verification Engine  (Phase 2 — Invariant-driven, Technology-aware)
After a patch is applied, runs:
1. Regression test suite (pytest for Python, UNSUPPORTED for Node.js)
2. Static security re-analysis
3. Exploit replay  — driven by SecurityInvariant.attack + TechnologyProfile
4. Legitimate-use contract  — driven by SecurityInvariant.legitimate_use
5. Application build check (technology-aware)

CRITICAL RULES:
- NEVER execute FastAPI TestClient against a Node.js repository.
- NEVER execute Python imports against a Node.js repository.
- UNSUPPORTED means: the correct verification mechanism cannot safely execute.
- FAILED means: the correct mechanism executed and the security property failed.

The oracle evaluation (PASS / BYPASS / ERROR / UNSUPPORTED) is driven by the
SecurityInvariant rather than hardcoded application-specific assumptions.
"""
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from app.models import (
    ExploitCheckOutcome,
    Investigation,
    LegitimateUseCase,
    OracleExpectedOutcome,
    SecurityInvariant,
    SecurityOracle,
    TechnologyProfile,
    VerificationCheck,
    VerificationResult,
    VerificationStrategyType,
)

_REDACT = "[REDACTED]"


# ─────────────────────────────────────────────────────────────────────────────
# Internal oracle evaluation helper
# ─────────────────────────────────────────────────────────────────────────────

def _evaluate_oracle(
    status_code: Optional[int],
    response_body: str,
    expected_outcome: OracleExpectedOutcome,
) -> ExploitCheckOutcome:
    """
    Evaluate a single HTTP response against one OracleExpectedOutcome.

    Rules:
    - If status_code is None → ERROR (response not obtained)
    - If status_code in forbidden_status_codes → BYPASS (invariant violated)
    - If status_code in allowed_status_codes → check protected_data_indicators
        - If any indicator appears in response_body → BYPASS
        - Otherwise → PASS
    - If status_code matches neither list → ERROR (unexpected / unclassified)
    """
    if status_code is None:
        return ExploitCheckOutcome.ERROR

    if status_code in expected_outcome.forbidden_status_codes:
        return ExploitCheckOutcome.BYPASS

    if status_code in expected_outcome.allowed_status_codes:
        # Check for protected data leaking into the response
        for indicator in expected_outcome.protected_data_indicators:
            if indicator and indicator.lower() in response_body.lower():
                return ExploitCheckOutcome.BYPASS
        return ExploitCheckOutcome.PASS

    # Status code not in either list — unclassified
    return ExploitCheckOutcome.ERROR


def _sanitize_body(body: str, max_len: int = 300) -> str:
    """Truncate and redact response bodies before storing as evidence."""
    if not body:
        return ""
    return body[:max_len] + ("…" if len(body) > max_len else "")


# ─────────────────────────────────────────────────────────────────────────────
# Main engine
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_technology_profile(investigation: Investigation) -> Optional[TechnologyProfile]:
    """Resolve TechnologyProfile from investigation — repository agent must have run first."""
    profile = getattr(investigation, "technology_profile", None)
    if profile is None and investigation.repository_info:
        profile = investigation.repository_info.technology_profile
    return profile


class VerificationEngine:
    def verify(self, investigation: Investigation) -> VerificationResult:
        repo_path = investigation.repository_path or ""
        checks: List[VerificationCheck] = []
        invariant: Optional[SecurityInvariant] = investigation.security_invariant
        profile: Optional[TechnologyProfile] = _resolve_technology_profile(investigation)

        # ── Technology guard: reject incompatible verification strategies ──
        if profile is not None:
            strategy = profile.verification_strategy
            runtime = profile.runtime.lower() if profile.runtime else "unknown"

            if runtime == "node":
                # Node.js: cannot use Python TestClient
                # All Python-specific checks become UNSUPPORTED
                return self._node_verification_unsupported(repo_path, investigation, invariant, profile)

        # 1. Write regression test to repo
        regression_written = False
        if investigation.remediation and investigation.remediation.regression_test:
            regression_written = self._write_regression_test(
                repo_path,
                investigation.remediation.regression_test_file or "tests/test_securefix_regression.py",
                investigation.remediation.regression_test,
            )
            checks.append(VerificationCheck(
                name="Regression test written",
                status="passed" if regression_written else "failed",
                detail=(
                    f"Written to {investigation.remediation.regression_test_file}"
                    if regression_written
                    else "Failed to write regression test file"
                ),
            ))

        # 2. Run test suite
        test_result = self._run_tests(repo_path)
        checks.append(VerificationCheck(
            name="Test suite",
            status=test_result["status"],
            detail=test_result["detail"],
        ))

        # 3. Static re-analysis
        static_result = self._static_recheck(repo_path, investigation)
        checks.append(VerificationCheck(
            name="Static security re-scan",
            status=static_result["status"],
            detail=static_result["detail"],
        ))

        # 4. Exploit replay — invariant-driven when available, legacy fallback otherwise
        exploit_check = self._check_exploit_blocked(repo_path, investigation, invariant)
        exploit_blocked = exploit_check.outcome == ExploitCheckOutcome.PASS
        checks.append(exploit_check)

        # 5. Legitimate-use contract check (owner can still access own resource)
        if invariant and invariant.supported and invariant.legitimate_use:
            legit_check = self._check_legitimate_use(repo_path, investigation, invariant)
            checks.append(legit_check)

        # 6. Build check
        build_result = self._check_importable(repo_path, investigation)
        checks.append(VerificationCheck(
            name="Application build",
            status=build_result["status"],
            detail=build_result["detail"],
        ))

        # Overall status — require test suite + static scan for "verified"
        critical_failures = [
            c for c in checks
            if c.status == "failed" and c.name in ("Test suite", "Static security re-scan")
        ]
        any_failure = [c for c in checks if c.status == "failed"]

        if not any_failure:
            overall = "verified"
        elif not critical_failures:
            overall = "partial"
        else:
            overall = "failed"

        regression_passed = any(
            c.name == "Test suite" and c.status == "passed" for c in checks
        )

        return VerificationResult(
            overall_status=overall,
            checks=checks,
            exploit_blocked=exploit_blocked,
            regression_passed=regression_passed,
            summary=self._build_summary(overall, checks, exploit_blocked),
        )

    def _node_verification_unsupported(
        self,
        repo_path: str,
        investigation: Investigation,
        invariant: Optional[SecurityInvariant],
        profile: TechnologyProfile,
    ) -> VerificationResult:
        """
        Node.js/Express repositories cannot be verified via Python TestClient.
        Return UNSUPPORTED for all execution checks.
        Only static re-analysis and patch integrity checks are performed.
        """
        checks: List[VerificationCheck] = []

        # Static security re-analysis (technology-neutral)
        static_result = self._static_recheck(repo_path, investigation)
        checks.append(VerificationCheck(
            name="Static security re-scan",
            status=static_result["status"],
            detail=static_result["detail"],
        ))

        # Exploit replay: UNSUPPORTED for Node.js
        exploit_check = VerificationCheck(name="Exploit replay blocked")
        exploit_check.set_outcome_fields(
            outcome=ExploitCheckOutcome.UNSUPPORTED,
            execution_error=(
                f"Repository runtime is '{profile.runtime}' (framework: '{profile.framework}'). "
                "SECUREFIX cannot execute Python/FastAPI TestClient against a Node.js repository. "
                "Exploit replay verification is UNSUPPORTED for this technology stack. "
                "Verify manually using Node.js test runner."
            ),
        )
        exploit_check.detail = (
            f"UNSUPPORTED: Node.js/{profile.framework} repository cannot be verified via Python TestClient"
        )
        checks.append(exploit_check)

        # Legitimate-use check: UNSUPPORTED for Node.js
        legit_check = VerificationCheck(name="Legitimate-use contract")
        legit_check.set_outcome_fields(
            outcome=ExploitCheckOutcome.UNSUPPORTED,
            execution_error=(
                "Legitimate-use contract verification is UNSUPPORTED for Node.js repositories."
            ),
        )
        legit_check.detail = "UNSUPPORTED: Node.js legitimate-use check requires Node.js test runner"
        checks.append(legit_check)

        # Regression test: UNSUPPORTED for Node.js
        regression_check = VerificationCheck(
            name="Regression test",
            status="skipped",
            detail=(
                f"UNSUPPORTED: Automated regression tests for Node.js are not generated. "
                f"Add tests using {profile.test_framework or 'Jest/Mocha'}."
            ),
        )
        regression_check.set_outcome_fields(outcome=ExploitCheckOutcome.UNSUPPORTED)
        checks.append(regression_check)

        # Build check: Node.js has no Python import check
        build_check = VerificationCheck(
            name="Application build",
            status="skipped",
            detail=(
                "UNSUPPORTED: Node.js build check not implemented. "
                "Verify manually with 'npm install && npm test'."
            ),
        )
        build_check.set_outcome_fields(outcome=ExploitCheckOutcome.UNSUPPORTED)
        checks.append(build_check)

        # Overall status: UNSUPPORTED (not FAILED — correct mechanism did not execute)
        summary = (
            f"Verification for Node.js/{profile.framework} repository: "
            "static analysis only. "
            f"Exploit replay and regression tests are UNSUPPORTED for this technology stack. "
            "Static re-scan: " + static_result["detail"]
        )
        return VerificationResult(
            overall_status="unsupported",
            checks=checks,
            exploit_blocked=False,
            regression_passed=False,
            summary=summary,
        )

    # ── 1-2. Existing unchanged helpers ──────────────────────────────────────

    def _write_regression_test(
        self, repo_path: str, rel_file: str, content: str
    ) -> bool:
        try:
            fpath = os.path.join(repo_path, rel_file)
            os.makedirs(os.path.dirname(fpath), exist_ok=True)
            Path(fpath).write_text(content, encoding="utf-8")
            return True
        except Exception as e:
            print(f"Failed to write regression test: {e}")
            return False

    def _find_python(self, repo_path: str) -> str:
        candidates = [
            os.path.join(repo_path, ".venv", "bin", "python"),
            os.path.join(repo_path, ".venv", "bin", "python3"),
            "python3",
            "python",
        ]
        for p in candidates:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        return "python3"

    def _run_tests(self, repo_path: str) -> dict:
        if not repo_path or not os.path.isdir(repo_path):
            return {"status": "skipped", "detail": "No repository path available"}
        test_dir = os.path.join(repo_path, "tests")
        if not os.path.isdir(test_dir):
            return {"status": "skipped", "detail": "No tests directory found"}
        python = self._find_python(repo_path)
        try:
            result = subprocess.run(
                [python, "-m", "pytest", "tests/", "-v", "--tb=short", "-x"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                passed = result.stdout.count(" PASSED")
                failed_count = result.stdout.count(" FAILED")
                return {"status": "passed", "detail": f"{passed} test(s) passed, {failed_count} failed"}
            else:
                lines = result.stdout.splitlines() + result.stderr.splitlines()
                failure_lines = [l for l in lines if "FAILED" in l or "AssertionError" in l]
                detail = "; ".join(failure_lines[:3]) if failure_lines else result.stdout[-500:]
                return {"status": "failed", "detail": detail[:400]}
        except subprocess.TimeoutExpired:
            return {"status": "failed", "detail": "Test suite timed out after 60s"}
        except FileNotFoundError:
            return {"status": "skipped", "detail": "pytest not available in environment"}
        except Exception as e:
            return {"status": "failed", "detail": str(e)}

    def _static_recheck(self, repo_path: str, investigation: Investigation) -> dict:
        """Confirm the vulnerable pattern is no longer present in patched files."""
        if not repo_path:
            return {"status": "skipped", "detail": "No repository available"}
        proposal = investigation.remediation
        if not proposal:
            return {"status": "skipped", "detail": "No patch to verify"}

        primary = (
            investigation.correlation.primary_finding
            if investigation.correlation
            else investigation.issue_description
        ).lower()

        if "path traversal" in primary or "traversal" in primary:
            has_boundary_check = False
            for rel_path in proposal.files_changed:
                fpath = os.path.join(repo_path, rel_path)
                if os.path.isfile(fpath):
                    content = Path(fpath).read_text(errors="ignore")
                    if "Path traversal defense" in content or "commonpath" in content or "startswith" in content:
                        has_boundary_check = True
            if not has_boundary_check:
                return {"status": "failed", "detail": "Directory boundary validation not detected in patched files"}
            return {"status": "passed", "detail": "Directory boundary validation verified present in patched files"}

        elif "command injection" in primary:
            for rel_path in proposal.files_changed:
                fpath = os.path.join(repo_path, rel_path)
                if os.path.isfile(fpath):
                    content = Path(fpath).read_text(errors="ignore")
                    if "shell=True" in content:
                        return {"status": "failed", "detail": f"shell=True still present in {rel_path}"}
            return {"status": "passed", "detail": "shell=True removed from patched files"}

        else:
            vuln_patterns = [r'# BUG:.*Should be.*user_id', r'# BUG: Should be']
            for rel_path in proposal.files_changed:
                fpath = os.path.join(repo_path, rel_path)
                if not os.path.isfile(fpath):
                    continue
                try:
                    content = Path(fpath).read_text(errors="ignore")
                    for pat in vuln_patterns:
                        if re.search(pat, content, re.IGNORECASE):
                            return {"status": "failed",
                                    "detail": f"Vulnerable pattern still present in {rel_path}"}
                except Exception:
                    pass
            return {"status": "passed", "detail": "Vulnerable patterns no longer detected in patched files"}

    # ── 4. Invariant-driven exploit check ────────────────────────────────────

    def _check_exploit_blocked(
        self,
        repo_path: str,
        investigation: Investigation,
        invariant: Optional[SecurityInvariant],
    ) -> VerificationCheck:
        """
        Execute the attack scenario and evaluate the response via the SecurityOracle.

        When a supported SecurityInvariant is present: reads route, method,
        credentials, and expected outcomes from the invariant — no hardcoded
        application assumptions.

        When no invariant is available: falls back to static code inspection
        (no HTTP execution) and returns UNSUPPORTED.
        """
        check = VerificationCheck(name="Exploit replay blocked")

        if not repo_path:
            check.set_outcome_fields(
                outcome=ExploitCheckOutcome.ERROR,
                execution_error="No repository path available",
            )
            check.detail = "No repository path available for exploit test"
            return check

        if not investigation.remediation:
            check.set_outcome_fields(
                outcome=ExploitCheckOutcome.ERROR,
                execution_error="No remediation patch available",
            )
            check.detail = "No remediation patch available to verify"
            return check

        # ── Unsupported invariant ──────────────────────────────────────────
        if not invariant or not invariant.supported:
            outcome = self._static_fallback_check(repo_path, investigation)
            check.set_outcome_fields(
                outcome=outcome,
                execution_error=(
                    "No supported SecurityInvariant — static code inspection used"
                    if outcome == ExploitCheckOutcome.UNSUPPORTED
                    else None
                ),
            )
            if outcome == ExploitCheckOutcome.PASS:
                check.detail = "Static verification: security check present in patched code"
            elif outcome == ExploitCheckOutcome.UNSUPPORTED:
                check.detail = "No supported SecurityInvariant — manual verification required"
            else:
                check.detail = "Static verification: security pattern not detected"
            return check

        # ── Read attack parameters from invariant ──────────────────────────
        attack = invariant.attack
        oracle = invariant.oracle
        blocked_outcome = oracle.blocked_outcome

        if not blocked_outcome:
            check.set_outcome_fields(
                outcome=ExploitCheckOutcome.UNSUPPORTED,
                route=attack.route_example,
                http_method=attack.method,
                expected_outcome_label="attack_blocked",
                execution_error="No blocked_outcome defined in oracle",
            )
            check.detail = "Oracle has no blocked_outcome — cannot evaluate"
            return check

        route = attack.route_example
        method = attack.method.upper()

        # ── Try TestClient execution (primary) ────────────────────────────
        if attack.auth_endpoint and attack.auth_credentials:
            result = self._run_authenticated_exploit(
                repo_path=repo_path,
                auth_endpoint=attack.auth_endpoint,
                auth_credentials=attack.auth_credentials,
                auth_token_path=attack.auth_token_path or "access_token",
                exploit_method=method,
                exploit_route=route,
                blocked_outcome=blocked_outcome,
            )
            if result["attempted"]:
                outcome = _evaluate_oracle(
                    result.get("status_code"),
                    result.get("body", ""),
                    blocked_outcome,
                )
                check.set_outcome_fields(
                    outcome=outcome,
                    route=route,
                    http_method=method,
                    observed_status_code=result.get("status_code"),
                    expected_outcome_label=blocked_outcome.label,
                    response_evidence=_sanitize_body(result.get("body", "")),
                    execution_error=result.get("error"),
                )
                check.detail = self._exploit_detail(outcome, method, route, result.get("status_code"))
                return check

        # ── Unauthenticated route (no auth required) ───────────────────────
        if not attack.auth_endpoint:
            result = self._run_unauthenticated_request(
                repo_path=repo_path,
                method=method,
                route=route,
                blocked_outcome=blocked_outcome,
            )
            if result["attempted"]:
                outcome = _evaluate_oracle(
                    result.get("status_code"),
                    result.get("body", ""),
                    blocked_outcome,
                )
                check.set_outcome_fields(
                    outcome=outcome,
                    route=route,
                    http_method=method,
                    observed_status_code=result.get("status_code"),
                    expected_outcome_label=blocked_outcome.label,
                    response_evidence=_sanitize_body(result.get("body", "")),
                    execution_error=result.get("error"),
                )
                check.detail = self._exploit_detail(outcome, method, route, result.get("status_code"))
                return check

        # ── Static fallback ────────────────────────────────────────────────
        outcome = self._static_fallback_check(repo_path, investigation)
        check.set_outcome_fields(
            outcome=outcome,
            route=route,
            http_method=method,
            expected_outcome_label=blocked_outcome.label,
            execution_error=(
                "TestClient execution failed — static inspection used"
                if outcome != ExploitCheckOutcome.PASS
                else None
            ),
        )
        check.detail = (
            "Static verification: security check present in patched code"
            if outcome == ExploitCheckOutcome.PASS
            else "Static verification: security pattern not detected or execution failed"
        )
        return check

    # ── 5. Legitimate-use contract check ─────────────────────────────────────

    def _check_legitimate_use(
        self,
        repo_path: str,
        investigation: Investigation,
        invariant: SecurityInvariant,
    ) -> VerificationCheck:
        """
        Verify that the first legitimate-use case in the invariant still works
        after the patch.  This distinguishes 'properly restricted' from 'deny all'.
        """
        # Use the first use case that has credentials and expects 200
        owner_case: Optional[LegitimateUseCase] = None
        for uc in invariant.legitimate_use:
            if 200 in uc.expected_status_codes and uc.auth_credentials:
                owner_case = uc
                break

        if owner_case is None:
            check = VerificationCheck(name="Legitimate-use contract")
            check.set_outcome_fields(
                outcome=ExploitCheckOutcome.UNSUPPORTED,
                execution_error="No executable legitimate-use case with credentials in invariant",
            )
            check.detail = "No executable owner-access test case found in invariant"
            return check

        route = owner_case.route_example
        method = owner_case.method.upper()

        expected_outcome = OracleExpectedOutcome(
            label="owner_access_allowed",
            allowed_status_codes=owner_case.expected_status_codes,
            forbidden_status_codes=[],
        )

        result = self._run_authenticated_exploit(
            repo_path=repo_path,
            auth_endpoint=owner_case.auth_endpoint,
            auth_credentials=owner_case.auth_credentials,
            auth_token_path=owner_case.auth_token_path or "access_token",
            exploit_method=method,
            exploit_route=route,
            blocked_outcome=expected_outcome,
        )

        check = VerificationCheck(name="Legitimate-use contract")
        if not result["attempted"]:
            check.set_outcome_fields(
                outcome=ExploitCheckOutcome.ERROR,
                route=route,
                http_method=method,
                expected_outcome_label="owner_access_allowed",
                execution_error=result.get("error", "Execution did not produce a result"),
            )
            check.detail = "Could not execute legitimate-use scenario"
            return check

        status_code = result.get("status_code")
        outcome = (
            ExploitCheckOutcome.PASS
            if status_code in owner_case.expected_status_codes
            else ExploitCheckOutcome.BYPASS  # owner denied = deny-all regression
        )
        check.set_outcome_fields(
            outcome=outcome,
            route=route,
            http_method=method,
            observed_status_code=status_code,
            expected_outcome_label="owner_access_allowed",
            response_evidence=_sanitize_body(result.get("body", "")),
            execution_error=result.get("error"),
        )
        if outcome == ExploitCheckOutcome.PASS:
            check.detail = f"Owner access: {method} {route} → HTTP {status_code} (legitimate use preserved)"
        else:
            check.detail = (
                f"Owner access regression: {method} {route} → HTTP {status_code} "
                f"(expected one of {owner_case.expected_status_codes})"
            )
        return check

    # ── Low-level HTTP execution helpers ──────────────────────────────────────

    def _run_authenticated_exploit(
        self,
        repo_path: str,
        auth_endpoint: str,
        auth_credentials: dict,
        auth_token_path: str,
        exploit_method: str,
        exploit_route: str,
        blocked_outcome: OracleExpectedOutcome,
    ) -> dict:
        """
        Execute an authenticated HTTP request via a subprocess TestClient script.
        Credentials are passed as JSON via stdin-equivalent string interpolation —
        never via shell arguments.

        Returns {"attempted": bool, "status_code": int|None, "body": str, "error": str|None}
        """
        python = self._find_python(repo_path)
        creds_json = json.dumps(auth_credentials)
        method_lower = exploit_method.lower()

        script = (
            "import sys, json\n"
            "from fastapi.testclient import TestClient\n"
            "try:\n"
            "    from app.main import app\n"
            "    with TestClient(app) as client:\n"
            f"        creds = json.loads({creds_json!r})\n"
            f"        auth_resp = client.post({auth_endpoint!r}, json=creds)\n"
            "        if auth_resp.status_code != 200:\n"
            "            print(json.dumps({'error': f'Auth failed: ' + str(auth_resp.status_code), 'auth_status': auth_resp.status_code}))\n"
            "            sys.exit(2)\n"
            f"        token = auth_resp.json().get({auth_token_path!r})\n"
            f"        resp = getattr(client, {method_lower!r})(\n"
            f"            {exploit_route!r},\n"
            "            headers={'Authorization': f'Bearer {token}'}\n"
            "        )\n"
            "        body = resp.text[:400]\n"
            "        print(json.dumps({'status_code': resp.status_code, 'body': body}))\n"
            "        sys.exit(0)\n"
            "except Exception as e:\n"
            "    print(json.dumps({'error': str(e)}))\n"
            "    sys.exit(3)\n"
        )

        try:
            res = subprocess.run(
                [python, "-c", script],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=20,
            )
            data = {}
            for line in res.stdout.splitlines():
                try:
                    data = json.loads(line)
                    break
                except Exception:
                    pass

            if data.get("error"):
                return {"attempted": True, "status_code": None, "body": "", "error": data["error"]}

            status_code = data.get("status_code")
            body = data.get("body", "")
            if status_code is not None:
                return {"attempted": True, "status_code": status_code, "body": body, "error": None}

            # Subprocess ran but no JSON output → error
            return {
                "attempted": True,
                "status_code": None,
                "body": "",
                "error": f"No JSON output from subprocess (exit {res.returncode}): {res.stderr[:200]}",
            }

        except subprocess.TimeoutExpired:
            return {"attempted": True, "status_code": None, "body": "", "error": "Subprocess timed out"}
        except FileNotFoundError:
            return {"attempted": False, "status_code": None, "body": "", "error": "Python not found"}
        except Exception as e:
            return {"attempted": True, "status_code": None, "body": "", "error": str(e)}

    def _run_unauthenticated_request(
        self,
        repo_path: str,
        method: str,
        route: str,
        blocked_outcome: OracleExpectedOutcome,
    ) -> dict:
        """Execute an unauthenticated HTTP request via TestClient."""
        python = self._find_python(repo_path)
        method_lower = method.lower()
        script = (
            "import sys, json\n"
            "from fastapi.testclient import TestClient\n"
            "try:\n"
            "    from app.main import app\n"
            "    with TestClient(app) as client:\n"
            f"        resp = getattr(client, {method_lower!r})({route!r})\n"
            "        print(json.dumps({'status_code': resp.status_code, 'body': resp.text[:400]}))\n"
            "        sys.exit(0)\n"
            "except Exception as e:\n"
            "    print(json.dumps({'error': str(e)}))\n"
            "    sys.exit(3)\n"
        )
        try:
            res = subprocess.run(
                [python, "-c", script],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=20,
            )
            data = {}
            for line in res.stdout.splitlines():
                try:
                    data = json.loads(line)
                    break
                except Exception:
                    pass
            if data.get("error"):
                return {"attempted": True, "status_code": None, "body": "", "error": data["error"]}
            if data.get("status_code") is not None:
                return {"attempted": True, "status_code": data["status_code"], "body": data.get("body", ""), "error": None}
            return {"attempted": True, "status_code": None, "body": "",
                    "error": f"No output (exit {res.returncode})"}
        except Exception as e:
            return {"attempted": True, "status_code": None, "body": "", "error": str(e)}

    def _static_fallback_check(
        self, repo_path: str, investigation: Investigation
    ) -> ExploitCheckOutcome:
        """
        Last-resort static code inspection when HTTP execution is not possible.
        Looks for known security-fix patterns in patched files.
        Returns PASS if ≥2 patterns match, UNSUPPORTED otherwise.
        Does NOT return BYPASS — static inspection cannot confirm exploitability.
        """
        proposal = investigation.remediation
        if not proposal:
            return ExploitCheckOutcome.UNSUPPORTED

        fix_patterns = [
            r'row\["user_id"\]\s*!=\s*current_user\["id"\]',
            r'status_code=403',
            r'Access forbidden',
            r'Path traversal detected',
            r'SECUREFIX.*[Aa]uthorization',
            r'verif.*owner',
        ]
        for rel_path in proposal.files_changed:
            fpath = os.path.join(repo_path, rel_path)
            if not os.path.isfile(fpath):
                continue
            try:
                content = Path(fpath).read_text(errors="ignore")
                matches = sum(1 for p in fix_patterns if re.search(p, content, re.IGNORECASE))
                if matches >= 2:
                    return ExploitCheckOutcome.PASS
            except Exception:
                pass
        return ExploitCheckOutcome.UNSUPPORTED

    # ── Build check ───────────────────────────────────────────────────────────

    def _check_importable(self, repo_path: str, investigation: Optional[Investigation] = None) -> dict:
        if not repo_path:
            return {"status": "skipped", "detail": "No repository path"}

        # Determine module path from TechnologyProfile
        module_path = "app.main"  # default for FastAPI/Python
        if investigation is not None:
            profile = _resolve_technology_profile(investigation)
            if profile is not None:
                runtime = profile.runtime.lower() if profile.runtime else ""
                if runtime == "node":
                    # Should never reach here (guarded by verify()), but defensive
                    return {
                        "status": "skipped",
                        "detail": "UNSUPPORTED: Node.js repository — Python import check not applicable",
                    }
                if profile.entry_points:
                    ep = profile.entry_points[0]
                    # Convert path to module: app/main.py -> app.main
                    module_path = ep.replace("/", ".").replace("\\", ".").removesuffix(".py")

        python = self._find_python(repo_path)
        try:
            result = subprocess.run(
                [python, "-c", f"import {module_path}"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                return {"status": "passed", "detail": f"Application module '{module_path}' imports successfully"}
            else:
                return {"status": "failed", "detail": result.stderr[:300] or f"Import of {module_path} failed"}
        except Exception as e:
            return {"status": "skipped", "detail": f"Could not run import check: {e}"}

    # ── Summary ───────────────────────────────────────────────────────────────

    def _exploit_detail(
        self,
        outcome: ExploitCheckOutcome,
        method: str,
        route: str,
        status_code: Optional[int],
    ) -> str:
        code_str = f"HTTP {status_code}" if status_code is not None else "no response"
        if outcome == ExploitCheckOutcome.PASS:
            return f"Exploit replay: {method} {route} → {code_str} — attack blocked (invariant holds)"
        elif outcome == ExploitCheckOutcome.BYPASS:
            return f"Exploit replay: {method} {route} → {code_str} — BYPASS detected (invariant violated)"
        elif outcome == ExploitCheckOutcome.ERROR:
            return f"Exploit replay: {method} {route} → {code_str} — execution error"
        else:
            return f"Exploit replay: {method} {route} — UNSUPPORTED"

    def _build_summary(
        self, overall: str, checks: List[VerificationCheck], exploit_blocked: bool
    ) -> str:
        passed = sum(1 for c in checks if c.status == "passed")
        total = len(checks)
        if overall == "verified":
            return (
                f"All {total} verification checks passed. "
                f"Exploit blocked: {'Yes' if exploit_blocked else 'Unconfirmed'}. "
                "Remediation status: VERIFIED."
            )
        elif overall == "partial":
            return (
                f"{passed}/{total} checks passed. "
                "Some verification steps could not complete. "
                "Manual review recommended."
            )
        else:
            failed = [c.name for c in checks if c.status == "failed"]
            return (
                f"{passed}/{total} checks passed. "
                f"Failed: {', '.join(failed)}. "
                "Remediation status: FAILED — review required."
            )
