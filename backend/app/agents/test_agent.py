"""
Test Agent
Technology-aware test coverage analysis.

Detects test infrastructure based on the repository's TechnologyProfile.
NEVER assumes Python for a Node.js repository.
NEVER reports "No test_*.py files" for a non-Python repository.
"""
import os
import re
from pathlib import Path
from typing import List, Optional

from app.agents.base import BaseAgent
from app.models import (
    AgentFinding, AgentResult, AgentStatus,
    FindingStatus, Investigation, Severity, TechnologyProfile,
)

IGNORE_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}


class TestAgent(BaseAgent):
    name = "test_agent"

    async def _execute(self, investigation: Investigation) -> AgentResult:
        repo_path = investigation.repository_path
        if not repo_path:
            return AgentResult(
                agent=self.name,
                status=AgentStatus.FAILED,
                error="No repository path",
                summary="Cannot analyze tests — no repository.",
            )

        # ── Resolve TechnologyProfile ──────────────────────────────────────
        profile: Optional[TechnologyProfile] = getattr(investigation, "technology_profile", None)
        if profile is None and investigation.repository_info:
            profile = investigation.repository_info.technology_profile

        issue = investigation.issue_description.lower()

        # ── Technology-aware test discovery ───────────────────────────────
        if profile is None:
            # Cannot determine technology — report UNSUPPORTED
            return AgentResult(
                agent=self.name,
                status=AgentStatus.COMPLETED,
                findings=[AgentFinding(
                    title="Test analysis skipped — technology profile unavailable",
                    severity=Severity.INFO,
                    finding_status=FindingStatus.UNSUPPORTED,
                    unsupported_reason=(
                        "TechnologyProfile was not populated by RepositoryAgent. "
                        "Cannot determine which test files or frameworks to scan."
                    ),
                )],
                summary="Test analysis UNSUPPORTED: technology profile not available.",
            )

        runtime = profile.runtime.lower() if profile.runtime else "unknown"

        if runtime == "node":
            return await self._analyze_nodejs_tests(repo_path, profile, issue)
        elif runtime == "python":
            return await self._analyze_python_tests(repo_path, profile, issue)
        else:
            return AgentResult(
                agent=self.name,
                status=AgentStatus.COMPLETED,
                findings=[AgentFinding(
                    title=f"Test analysis UNSUPPORTED for runtime: {runtime}",
                    severity=Severity.INFO,
                    finding_status=FindingStatus.UNSUPPORTED,
                    unsupported_reason=(
                        f"SECUREFIX does not yet have test analysis support for runtime '{runtime}'. "
                        f"Test framework detected: {profile.test_framework or 'unknown'}."
                    ),
                )],
                summary=f"Test analysis UNSUPPORTED for runtime '{runtime}'.",
            )

    # ── Node.js test analysis ──────────────────────────────────────────────────

    async def _analyze_nodejs_tests(
        self, repo_path: str, profile: TechnologyProfile, issue: str
    ) -> AgentResult:
        """
        Analyze Node.js/JavaScript test infrastructure.
        Looks for Jest, Mocha, node:test, Vitest, or similar.
        Never looks for test_*.py files.
        """
        test_framework = profile.test_framework or "unknown"
        test_files = self._find_nodejs_test_files(repo_path)
        findings: List[AgentFinding] = []
        coverage_notes: List[str] = []

        if not test_files:
            # No JS test files found
            # Report what we looked for, not a Python-specific message
            patterns_checked = profile.test_file_patterns or [
                "*.test.js", "*.spec.js", "test/**/*.js", "__tests__/**/*.js"
            ]
            findings.append(AgentFinding(
                title="No JavaScript test files found",
                severity=Severity.MEDIUM,
                confidence=0.9,
                files=[],
                evidence=[
                    f"Test framework declared: {test_framework}",
                    f"Patterns checked: {', '.join(patterns_checked)}",
                    f"Repository runtime: Node.js",
                    f"No *.test.js, *.spec.js, or test/ directory test files found",
                ],
                recommendation=(
                    f"Add a test suite using {test_framework if test_framework != 'unknown' else 'Jest, Mocha, or similar'}. "
                    "Test files should cover authentication and security-sensitive routes."
                ),
                finding_status=FindingStatus.CONFIRMED,
                evidence_excerpt="test_files=[]; pattern_search=*.test.js,*.spec.js,test/*.js",
                technology="javascript/nodejs",
                provenance="TestAgent: filesystem scan for JavaScript test files",
            ))
        else:
            # Found test files — analyze their coverage
            has_auth_test = False
            has_security_test = False
            for tf in test_files:
                rel = os.path.relpath(tf, repo_path)
                try:
                    content = Path(tf).read_text(errors="ignore")
                except Exception:
                    continue

                if re.search(r'(?:describe|it|test)\s*\([\'"].*(?:login|auth|token)', content, re.IGNORECASE):
                    has_auth_test = True
                    coverage_notes.append(f"✓ Authentication/login test found in {rel}")

                if re.search(r'(?:describe|it|test)\s*\([\'"].*(?:inject|sanitize|sql|nosql|xss|csrf|security)', content, re.IGNORECASE):
                    has_security_test = True
                    coverage_notes.append(f"✓ Security test found in {rel}")

            # Issue-specific coverage gap detection
            nosql_issue = any(w in issue for w in ["nosql", "injection", "mongo", "auth", "login"])
            if nosql_issue and not has_auth_test:
                findings.append(AgentFinding(
                    title="No authentication/login regression test found",
                    severity=Severity.HIGH,
                    confidence=0.88,
                    files=[os.path.relpath(tf, repo_path) for tf in test_files[:3]],
                    evidence=[
                        "Issue describes authentication/injection concern in Node.js repository",
                        f"Searched {len(test_files)} JavaScript test file(s)",
                        f"No test matching login/auth pattern found",
                    ],
                    recommendation=(
                        "Add a test verifying that operator-injection payloads are rejected "
                        "by the login endpoint. Use your existing test framework "
                        f"({test_framework if test_framework != 'unknown' else 'Jest/Mocha'})."
                    ),
                    finding_status=FindingStatus.CONFIRMED,
                    evidence_excerpt=f"test_files_found={len(test_files)}; auth_test_found=False",
                    technology="javascript/nodejs",
                    provenance="TestAgent: searched for auth test patterns in JS test files",
                ))

        return AgentResult(
            agent=self.name,
            status=AgentStatus.COMPLETED,
            findings=findings,
            summary=(
                f"Node.js test analysis: "
                f"found {len(test_files)} test file(s). "
                f"Test framework: {test_framework}. "
                + ("; ".join(coverage_notes) or "No coverage notes.")
            ),
            raw_output={
                "runtime": "node",
                "test_framework": test_framework,
                "test_files": [os.path.relpath(tf, repo_path) for tf in test_files],
            },
        )

    def _find_nodejs_test_files(self, repo_path: str) -> List[str]:
        """Find JavaScript/TypeScript test files — NOT Python test files."""
        found = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext not in (".js", ".ts", ".jsx", ".tsx", ".mjs"):
                    continue
                # Jest/Mocha/Vitest patterns
                if (
                    fname.endswith(".test.js") or fname.endswith(".test.ts")
                    or fname.endswith(".spec.js") or fname.endswith(".spec.ts")
                    or fname.endswith(".test.mjs")
                ):
                    found.append(os.path.join(root, fname))
                    continue
                # test/ directory
                rel_root = os.path.relpath(root, repo_path)
                if (
                    rel_root == "test" or rel_root.startswith("test/")
                    or rel_root == "tests" or rel_root.startswith("tests/")
                    or "/__tests__/" in os.path.join(root, fname).replace("\\", "/")
                    or "\\__tests__\\" in os.path.join(root, fname)
                ):
                    found.append(os.path.join(root, fname))
        return found

    # ── Python test analysis ───────────────────────────────────────────────────

    async def _analyze_python_tests(
        self, repo_path: str, profile: TechnologyProfile, issue: str
    ) -> AgentResult:
        """
        Analyze Python test infrastructure.
        Looks for pytest, unittest test_*.py / *_test.py files.
        """
        test_framework = profile.test_framework or "pytest"
        test_files = self._find_python_test_files(repo_path)
        findings: List[AgentFinding] = []
        coverage_report: List[str] = []

        has_auth_test = False
        has_cross_user_test = False
        has_ownership_test = False

        for tf in test_files:
            rel = os.path.relpath(tf, repo_path)
            try:
                content = Path(tf).read_text(errors="ignore")
            except Exception:
                continue

            if re.search(r'def\s+test_.*(?:login|auth|token)', content, re.IGNORECASE):
                has_auth_test = True
                coverage_report.append(f"✓ Authentication test found in {rel}")

            if re.search(r'def\s+test_.*(?:cross|other|another|different).*user', content, re.IGNORECASE):
                has_cross_user_test = True
                coverage_report.append(f"✓ Cross-user test found in {rel}")

            if re.search(r'def\s+test_.*(?:access|own|author)', content, re.IGNORECASE):
                has_ownership_test = True
                coverage_report.append(f"✓ Ownership/access test found in {rel}")

        # Assess coverage gaps
        if any(w in issue for w in ["authorization", "access", "bola", "account", "idor"]):
            if not has_cross_user_test:
                findings.append(AgentFinding(
                    title="No cross-user authorization regression test found",
                    severity=Severity.HIGH,
                    confidence=0.92,
                    files=[os.path.relpath(tf, repo_path) for tf in test_files[:2]] if test_files else [],
                    evidence=[
                        "Issue describes authorization bypass between users",
                        "No test found that verifies User A cannot access User B's resources",
                        f"Searched {len(test_files)} Python test file(s)",
                    ],
                    recommendation=(
                        "Add regression test: authenticated as User A, "
                        "attempt to access User B's resource, assert HTTP 403."
                    ),
                    finding_status=FindingStatus.CONFIRMED,
                    evidence_excerpt=f"test_files_found={len(test_files)}; cross_user_test_found=False",
                    technology=f"{profile.language}/{profile.runtime}" if profile.runtime else profile.language,
                    provenance="TestAgent: searched Python test files for cross-user auth patterns",
                ))

            if not has_ownership_test:
                findings.append(AgentFinding(
                    title="Missing ownership enforcement test",
                    severity=Severity.MEDIUM,
                    confidence=0.78,
                    files=[os.path.relpath(tf, repo_path) for tf in test_files[:2]] if test_files else [],
                    evidence=[
                        "No test verifying that resource ownership is enforced",
                        "BOLA vulnerabilities require explicit cross-user access tests",
                    ],
                    recommendation=(
                        "Add a test that: (1) creates/logs in as two users, "
                        "(2) attempts cross-access, (3) asserts 403 response."
                    ),
                    finding_status=FindingStatus.CONFIRMED,
                    evidence_excerpt=f"test_files_found={len(test_files)}; ownership_test_found=False",
                    technology=f"{profile.language}/{profile.runtime}" if profile.runtime else profile.language,
                    provenance="TestAgent: Python test coverage analysis",
                ))

        if not test_files:
            findings.append(AgentFinding(
                title="No Python test files found in repository",
                severity=Severity.MEDIUM,
                confidence=0.95,
                evidence=[
                    f"No test_*.py or *_test.py files detected in {repo_path}",
                    f"Test framework from profile: {test_framework}",
                ],
                recommendation=f"Add a {test_framework} test suite covering authentication and authorization.",
                finding_status=FindingStatus.CONFIRMED,
                evidence_excerpt=f"python_test_files=[]; test_framework={test_framework}",
                technology=f"{profile.language}/{profile.runtime}" if profile.runtime else profile.language,
                provenance="TestAgent: filesystem scan for Python test files",
            ))

        return AgentResult(
            agent=self.name,
            status=AgentStatus.COMPLETED,
            findings=findings,
            summary=(
                f"Python test analysis: analyzed {len(test_files)} test file(s). "
                + ("Coverage gaps identified." if findings else "Test coverage adequate.")
                + f" Notes: {'; '.join(coverage_report) or 'None found'}."
            ),
            raw_output={
                "runtime": "python",
                "test_framework": test_framework,
                "test_files": [os.path.relpath(tf, repo_path) for tf in test_files],
                "has_auth_test": has_auth_test,
                "has_cross_user_test": has_cross_user_test,
                "has_ownership_test": has_ownership_test,
            },
        )

    def _find_python_test_files(self, repo_path: str) -> List[str]:
        """Find Python test files only."""
        found = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for fname in files:
                if (
                    (fname.startswith("test_") or fname.endswith("_test.py"))
                    and fname.endswith(".py")
                ):
                    found.append(os.path.join(root, fname))
        return found


# ── Regression test generator (called after patch) ───────────────────────────

def generate_regression_test(investigation: Investigation) -> str:
    """
    Generate a regression test based on the investigation findings and TechnologyProfile.

    CRITICAL: Never generates FastAPI/Python tests for non-Python repositories.
    Returns UNSUPPORTED notice if safe test generation is not possible.
    """
    # ── Resolve TechnologyProfile ──────────────────────────────────────────
    profile: Optional[TechnologyProfile] = getattr(investigation, "technology_profile", None)
    if profile is None and investigation.repository_info:
        profile = investigation.repository_info.technology_profile

    inv_id = investigation.id

    # ── Guard: no profile means UNSUPPORTED ───────────────────────────────
    if profile is None:
        return _unsupported_test(
            inv_id,
            reason="TechnologyProfile not available — cannot generate safe regression test",
        )

    runtime = profile.runtime.lower() if profile.runtime else "unknown"
    framework = profile.framework.lower() if profile.framework else "unknown"

    # ── Node.js: NEVER generate Python/FastAPI tests ───────────────────────
    if runtime == "node":
        return _unsupported_test(
            inv_id,
            reason=(
                f"Repository runtime is '{runtime}' (framework: '{framework}'). "
                "SECUREFIX does not generate Python/FastAPI regression tests for Node.js repositories. "
                "Please add regression tests using the detected test framework: "
                f"{profile.test_framework or 'unknown (check package.json scripts.test)'}."
            ),
        )

    # ── Python / FastAPI ────────────────────────────────────────────────────
    if runtime == "python" and framework == "fastapi":
        issue = investigation.issue_description.lower()

        if any(w in issue for w in ["authorization", "access", "account", "bola", "idor"]):
            return _bola_regression_test_fastapi(investigation, profile)
        elif "traversal" in issue or "path" in issue:
            return _path_traversal_regression_test_fastapi(investigation, profile)
        elif "command" in issue or "shell" in issue or "rce" in issue:
            return _command_injection_regression_test_fastapi(investigation, profile)
        elif "sql" in issue and "inject" in issue:
            return _sqli_regression_test_fastapi(investigation, profile)
        else:
            return _generic_regression_test_fastapi(investigation, profile)

    # ── Python / other framework (Flask, Django, etc.) ─────────────────────
    if runtime == "python":
        return _unsupported_test(
            inv_id,
            reason=(
                f"Repository framework is '{framework}'. "
                "Regression test generation is currently only supported for FastAPI. "
                f"Please add tests manually using {profile.test_framework or 'pytest'}."
            ),
        )

    # ── Unknown / unsupported runtime ──────────────────────────────────────
    return _unsupported_test(
        inv_id,
        reason=(
            f"Unsupported runtime '{runtime}' for automated regression test generation. "
            f"Technology profile: runtime={runtime}, framework={framework}."
        ),
    )


# ── Technology-aware regression test templates ────────────────────────────────

def _unsupported_test(inv_id: str, reason: str) -> str:
    """
    Return a clearly marked UNSUPPORTED placeholder instead of a fabricated test.
    This will be visible in the report rather than failing with mysterious import errors.
    """
    return f'''"""
SECUREFIX Regression Test — UNSUPPORTED
Investigation: {inv_id}

Automated regression test generation is not supported for this repository.

Reason: {reason}

Action required:
    Add manual regression tests appropriate for this repository's technology stack.
    See the SECUREFIX security invariant for the properties that must be tested.
"""
# SECUREFIX: No automated regression test generated.
# Reason: {reason}
# This file is intentionally empty to prevent false test execution.
'''


def _path_traversal_regression_test_fastapi(
    inv_id: str, profile: TechnologyProfile
) -> str:
    # Find actual route from discovered routes
    routes = []
    if hasattr(inv_id, "repository_info") and inv_id.repository_info:  # type: ignore
        routes = inv_id.repository_info.api_routes  # type: ignore
    target_endpoint = _pick_route_for_keyword(routes, ["file", "download", "report", "path"], "/api/files/download")
    return _path_traversal_regression_test(inv_id, target_endpoint, profile)


def _path_traversal_regression_test(inv_id: str, target_endpoint: str, profile: TechnologyProfile) -> str:
    entry_point = profile.entry_points[0] if profile.entry_points else "app.main"
    module_path = _entry_to_module(entry_point)
    return f'''"""
SECUREFIX Auto-Generated Regression Test
Investigation: {inv_id}
Vulnerability: Path Traversal (CWE-22)
Technology: Python/{profile.framework}

Route under test: {target_endpoint}
(Derived from repository route discovery — not hardcoded)

Before fix: Returns HTTP 200 (VULNERABLE - reads outside boundary)
After fix:  Returns HTTP 403 Forbidden (SECURE)
"""
import pytest
from fastapi.testclient import TestClient
from {module_path} import app

client = TestClient(app)


def test_securefix_{_safe_id(inv_id)}_path_traversal_blocked():
    """Verify that relative path traversal sequences are blocked with HTTP 403."""
    response = client.get("{target_endpoint}?filename=../secret.txt")
    assert response.status_code == 403, (
        f"PATH TRAVERSAL REGRESSION [{inv_id}]: "
        f"Server returned {{response.status_code}} instead of 403 Forbidden! "
        f"Body: {{response.text}}"
    )


def test_securefix_{_safe_id(inv_id)}_legitimate_file_accessible():
    """Verify legitimate file access still works without regression."""
    response = client.get("{target_endpoint}?filename=report1.txt")
    assert response.status_code in (200, 404), (
        f"Legitimate file handler broken: {{response.status_code}}"
    )
'''


def _command_injection_regression_test_fastapi(
    investigation: Investigation, profile: TechnologyProfile
) -> str:
    inv_id = investigation.id
    entry_point = profile.entry_points[0] if profile.entry_points else "app/main.py"
    module_path = _entry_to_module(entry_point)
    # Find actual exec route
    routes = investigation.repository_info.api_routes if investigation.repository_info else []
    exec_endpoint = _pick_route_for_keyword(routes, ["exec", "command", "run", "shell"], "")
    if not exec_endpoint:
        return _unsupported_test(
            inv_id,
            reason=(
                "Cannot identify command execution route from repository analysis. "
                "No route matching 'exec', 'command', 'run', or 'shell' found. "
                "Add test manually targeting the actual vulnerable endpoint."
            ),
        )
    return f'''"""
SECUREFIX Auto-Generated Regression Test
Investigation: {inv_id}
Vulnerability: Command Injection (CWE-78)
Technology: Python/{profile.framework}

Route under test: {exec_endpoint}
(Derived from repository route discovery — not hardcoded)
"""
import pytest
from fastapi.testclient import TestClient
from {module_path} import app

client = TestClient(app)


def test_securefix_{_safe_id(inv_id)}_command_injection_blocked():
    """Verify command injection payloads are rejected."""
    response = client.post("{exec_endpoint}", json={{"command": "test; whoami"}})
    assert response.status_code in (400, 403, 422), (
        f"Command injection payload not rejected: {{response.status_code}}"
    )
'''


def _bola_regression_test_fastapi(
    investigation: Investigation, profile: TechnologyProfile
) -> str:
    """
    Generate a BOLA regression test derived from the repository's actual routes
    and invariant — NOT from hardcoded SecureBank assumptions.
    """
    inv_id = investigation.id
    entry_point = profile.entry_points[0] if profile.entry_points else "app/main.py"
    module_path = _entry_to_module(entry_point)

    # Derive actual route from repository invariant/correlation
    invariant = investigation.security_invariant
    routes = investigation.repository_info.api_routes if investigation.repository_info else []

    # Use invariant data if available (scenario data, not global constants)
    resource_route_template = ""
    auth_endpoint = ""
    if invariant and invariant.supported:
        resource_route_template = invariant.attack.route_template or ""
        auth_endpoint = invariant.attack.auth_endpoint or ""

    # Fall back to route discovery
    if not resource_route_template:
        resource_route_template = _pick_route_template_for_bola(routes)

    if not auth_endpoint:
        auth_endpoint = _pick_auth_endpoint(routes)

    if not resource_route_template or not auth_endpoint:
        return _unsupported_test(
            inv_id,
            reason=(
                "Cannot identify resource route and auth endpoint from repository analysis. "
                f"Routes discovered: {routes[:5] if routes else 'none'}. "
                "Populate the security invariant or add routes to enable test generation."
            ),
        )

    # Replace template placeholder with example IDs derived from repository context
    attack_route = re.sub(r'\{[^}]+\}', '2', resource_route_template)
    owner_route = re.sub(r'\{[^}]+\}', '1', resource_route_template)

    # Derive credential hints from invariant (scenario data, never global assumptions)
    attacker_cred_hint = ""
    owner_cred_hint = ""
    if invariant and invariant.supported:
        attacker_cred_hint = invariant.attack.actor_credential_hint
        if invariant.legitimate_use:
            owner_cred_hint = invariant.legitimate_use[0].actor_credential_hint

    return f'''"""
SECUREFIX Auto-Generated Regression Test
Investigation: {inv_id}
Vulnerability: Broken Object Level Authorization (BOLA/IDOR) (CWE-639)
Technology: Python/{profile.framework}

Routes derived from repository analysis:
    Auth endpoint: {auth_endpoint}
    Resource route template: {resource_route_template}
    Attack example (non-owner): {attack_route}
    Owner example: {owner_route}

Attacker credential hint: {attacker_cred_hint or "see repository seed data"}
Owner credential hint: {owner_cred_hint or "see repository seed data"}

NOTE: This test uses credentials from the repository's own seed/fixture data.
      Replace _get_credentials() with actual test credentials from the repo.

Before fix: cross-user access returns HTTP 200 (VULNERABLE)
After fix:  cross-user access returns HTTP 403 (SECURE)
"""
import pytest
from fastapi.testclient import TestClient
from {module_path} import app

client = TestClient(app)


def _get_attacker_token() -> str:
    """
    Obtain authentication token for the non-owner attacker user.
    IMPORTANT: Fill in credentials from the repository's seed/fixture data.
    These are NOT hardcoded — they must match the actual test environment.
    """
    raise NotImplementedError(
        "Fill in attacker credentials from repository seed data. "
        "POST to {auth_endpoint} with a non-owner user account."
    )


def _get_owner_token() -> str:
    """
    Obtain authentication token for the resource owner.
    IMPORTANT: Fill in credentials from the repository's seed/fixture data.
    """
    raise NotImplementedError(
        "Fill in owner credentials from repository seed data. "
        "POST to {auth_endpoint} with the owner user account."
    )


def test_securefix_{_safe_id(inv_id)}_cross_user_access_blocked():
    """
    SECUREFIX Regression [{inv_id}]
    A non-owner user must NOT be able to access another user's resource.

    Route: {attack_route}
    Before fix: Returns HTTP 200 (VULNERABLE)
    After fix:  Returns HTTP 403 (SECURE)
    """
    attacker_token = _get_attacker_token()
    response = client.get(
        "{attack_route}",
        headers={{"Authorization": f"Bearer {{attacker_token}}"}},
    )
    assert response.status_code == 403, (
        f"BOLA REGRESSION [{inv_id}]: "
        f"Non-owner accessed resource at {attack_route}! "
        f"Status: {{response.status_code}}, Body: {{response.text}}"
    )


def test_securefix_{_safe_id(inv_id)}_owner_access_preserved():
    """Resource owner must still be able to access their own resource after the fix."""
    owner_token = _get_owner_token()
    response = client.get(
        "{owner_route}",
        headers={{"Authorization": f"Bearer {{owner_token}}"}},
    )
    assert response.status_code == 200, (
        f"Owner access broken [{inv_id}]: "
        f"Status: {{response.status_code}}"
    )


def test_securefix_{_safe_id(inv_id)}_unauthenticated_blocked():
    """Unauthenticated requests must be rejected."""
    response = client.get("{attack_route}")
    assert response.status_code in (401, 403), (
        f"Unauthenticated access not blocked [{inv_id}]: {{response.status_code}}"
    )
'''


def _sqli_regression_test_fastapi(
    investigation: Investigation, profile: TechnologyProfile
) -> str:
    inv_id = investigation.id
    entry_point = profile.entry_points[0] if profile.entry_points else "app/main.py"
    module_path = _entry_to_module(entry_point)
    routes = investigation.repository_info.api_routes if investigation.repository_info else []
    auth_endpoint = _pick_auth_endpoint(routes) or ""

    if not auth_endpoint:
        return _unsupported_test(
            inv_id,
            reason=(
                "Cannot identify auth/login endpoint from repository analysis. "
                f"Routes discovered: {routes[:5] if routes else 'none'}."
            ),
        )

    return f'''"""
SECUREFIX Auto-Generated Regression Test
Investigation: {inv_id}
Vulnerability: SQL Injection (CWE-89)
Technology: Python/{profile.framework}

Auth endpoint: {auth_endpoint}
(Derived from repository route discovery — not hardcoded)
"""
import pytest
from fastapi.testclient import TestClient
from {module_path} import app

client = TestClient(app)


def test_securefix_{_safe_id(inv_id)}_sql_injection_blocked():
    """SQL injection payload must not cause error or return unexpected data."""
    resp = client.post(
        "{auth_endpoint}",
        json={{"username": "' OR 1=1 --", "password": "anything"}},
    )
    assert resp.status_code in (401, 422), (
        f"SQL injection not blocked [{inv_id}]: {{resp.status_code}}"
    )
'''


def _generic_regression_test_fastapi(
    investigation: Investigation, profile: TechnologyProfile
) -> str:
    inv_id = investigation.id
    routes = investigation.repository_info.api_routes if investigation.repository_info else []

    if not routes:
        return _unsupported_test(
            inv_id,
            reason=(
                "No API routes discovered in repository — cannot generate targeted regression test. "
                "Run repository analysis first."
            ),
        )

    entry_point = profile.entry_points[0] if profile.entry_points else "app/main.py"
    module_path = _entry_to_module(entry_point)

    # Use the first discovered route as a generic smoke test
    first_route_parts = routes[0].split()
    method = first_route_parts[0].lower() if first_route_parts else "get"
    path = first_route_parts[1] if len(first_route_parts) > 1 else "/"

    return f'''"""
SECUREFIX Auto-Generated Regression Test
Investigation: {inv_id}
Technology: Python/{profile.framework}

Smoke test derived from first discovered route: {routes[0]}
"""
import pytest
from fastapi.testclient import TestClient
from {module_path} import app

client = TestClient(app)


def test_securefix_{_safe_id(inv_id)}_unauthorized_blocked():
    """Unauthorized access to protected resource must be blocked."""
    resp = client.{method}("{path}")
    assert resp.status_code in (401, 403, 405), (
        f"Unexpected response for unauthenticated request to {path}: {{resp.status_code}}"
    )
'''


# ── Route helpers ─────────────────────────────────────────────────────────────

def _pick_route_for_keyword(
    routes: List[str], keywords: List[str], fallback: str
) -> str:
    """Pick the first route matching any of the given keywords."""
    for route in routes:
        route_lower = route.lower()
        if any(kw in route_lower for kw in keywords):
            parts = route.split()
            return parts[1] if len(parts) > 1 else route
    return fallback


def _pick_route_template_for_bola(routes: List[str]) -> str:
    """Find a parameterized route suitable for BOLA testing."""
    for route in routes:
        parts = route.split()
        if len(parts) >= 2:
            path = parts[-1]
            if "{" in path and any(
                kw in path for kw in ("account", "user", "profile", "resource", "transaction", "item", "order")
            ):
                return path
    # Second pass — any parameterised route
    for route in routes:
        parts = route.split()
        if len(parts) >= 2 and "{" in parts[-1]:
            return parts[-1]
    return ""


def _pick_auth_endpoint(routes: List[str]) -> str:
    """Find auth/login endpoint from discovered routes."""
    for route in routes:
        parts = route.split()
        path = parts[-1] if len(parts) >= 2 else route
        if any(kw in path.lower() for kw in ("login", "auth/token", "auth/login", "signin", "sign-in")):
            return path
    for route in routes:
        if "POST" in route.upper() and "auth" in route.lower():
            parts = route.split()
            return parts[-1] if len(parts) >= 2 else route
    return ""


def _entry_to_module(entry_point: str) -> str:
    """Convert a file path to a Python module path."""
    # e.g. "app/main.py" -> "app.main"
    return entry_point.replace("/", ".").replace("\\", ".").removesuffix(".py")


def _safe_id(inv_id: str) -> str:
    return inv_id.replace("-", "_").lower()


import re  # noqa: E402 (used in _bola_regression_test_fastapi)
