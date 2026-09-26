"""
Test Agent
Analyzes test coverage for the reported issue, identifies missing regression tests,
and generates a regression test after the fix is proposed.
"""
import os
import re
from pathlib import Path
from typing import List, Optional

from app.agents.base import BaseAgent
from app.models import AgentFinding, AgentResult, AgentStatus, Investigation, Severity

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

        test_files = self._find_test_files(repo_path)
        findings: List[AgentFinding] = []
        coverage_report = []

        issue = investigation.issue_description.lower()

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
                    files=test_files[:2] if test_files else [],
                    evidence=[
                        "Issue describes authorization bypass between users",
                        "No test found that verifies User A cannot access User B's resources",
                        f"Searched {len(test_files)} test file(s)",
                    ],
                    recommendation=(
                        "Add regression test: authenticated as User A, "
                        "attempt to access User B's resource, assert HTTP 403."
                    ),
                ))

            if not has_ownership_test:
                findings.append(AgentFinding(
                    title="Missing ownership enforcement test",
                    severity=Severity.MEDIUM,
                    confidence=0.78,
                    files=test_files[:2] if test_files else [],
                    evidence=[
                        "No test verifying that resource ownership is enforced",
                        "BOLA vulnerabilities require explicit cross-user access tests",
                    ],
                    recommendation=(
                        "Add a test that: (1) creates/logs in as two users, "
                        "(2) attempts cross-access, (3) asserts 403 response."
                    ),
                ))

        if not test_files:
            findings.append(AgentFinding(
                title="No test files found in repository",
                severity=Severity.MEDIUM,
                confidence=0.95,
                evidence=["No test_*.py or *_test.py files detected"],
                recommendation="Add a test suite covering authentication and authorization.",
            ))

        return AgentResult(
            agent=self.name,
            status=AgentStatus.COMPLETED,
            findings=findings,
            summary=(
                f"Analyzed {len(test_files)} test file(s). "
                + ("Coverage gaps identified for authorization." if findings else "Test coverage adequate.")
                + f" Coverage notes: {'; '.join(coverage_report) or 'None found'}."
            ),
            raw_output={
                "test_files": [os.path.relpath(tf, repo_path) for tf in test_files],
                "has_auth_test": has_auth_test,
                "has_cross_user_test": has_cross_user_test,
                "has_ownership_test": has_ownership_test,
            },
        )

    def _find_test_files(self, repo_path: str) -> List[str]:
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
    Generate a pytest regression test based on the investigation findings.
    Returns test source code as a string.
    """
    issue = investigation.issue_description.lower()
    inv_id = investigation.id

    if any(w in issue for w in ["authorization", "access", "account", "bola", "idor"]):
        return _bola_regression_test(inv_id)
    elif "traversal" in issue or "path" in issue:
        return _path_traversal_regression_test(inv_id, investigation)
    elif "command" in issue or "shell" in issue or "rce" in issue:
        return _command_injection_regression_test(inv_id, investigation)
    elif "sql" in issue and "inject" in issue:
        return _sqli_regression_test(inv_id)
    else:
        return _generic_auth_regression_test(inv_id)


def _path_traversal_regression_test(inv_id: str, investigation: Investigation) -> str:
    routes = investigation.repository_info.api_routes if investigation.repository_info else []
    target_endpoint = "/api/files/download"
    for r in routes:
        if "file" in r or "download" in r or "report" in r or "path" in r:
            path = r.split()[-1] if " " in r else r
            if not path.startswith("/api"):
                path = "/api" + (path if path.startswith("/") else "/" + path)
            target_endpoint = path
            break

    return f'''"""
SECUREFIX Auto-Generated Regression Test
Investigation: {inv_id}
Vulnerability: Path Traversal (CWE-22)
Generated to verify directory boundary enforcement.

Before fix: Returns HTTP 200 (VULNERABLE - reads outside boundary)
After fix:  Returns HTTP 403 Forbidden (SECURE)
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_securefix_{inv_id.replace("-", "_").lower()}_path_traversal_blocked():
    """Verify that relative path traversal sequences ('../') are blocked with HTTP 403."""
    response = client.get("{target_endpoint}?filename=../secret.txt")
    assert response.status_code == 403, (
        f"PATH TRAVERSAL REGRESSION [{inv_id}]: "
        f"Server returned {{response.status_code}} instead of 403 Forbidden! "
        f"Body: {{response.text}}"
    )

def test_securefix_{inv_id.replace("-", "_").lower()}_legitimate_file_accessible():
    """Verify legitimate file access still works without regression."""
    response = client.get("{target_endpoint}?filename=report1.txt")
    assert response.status_code in (200, 404), (
        f"Legitimate file handler broken: {{response.status_code}}"
    )
'''


def _command_injection_regression_test(inv_id: str, investigation: Investigation) -> str:
    return f'''"""
SECUREFIX Auto-Generated Regression Test
Investigation: {inv_id}
Vulnerability: Command Injection (CWE-78)
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_securefix_{inv_id.replace("-", "_").lower()}_command_injection_blocked():
    """Verify command injection payloads are rejected."""
    response = client.post("/api/exec", json={{"command": "test; whoami"}})
    assert response.status_code in (400, 403, 422), (
        f"Command injection payload not rejected: {{response.status_code}}"
    )
'''


def _bola_regression_test(inv_id: str) -> str:
    return f'''"""
SECUREFIX Auto-Generated Regression Test
Investigation: {inv_id}
Vulnerability: Broken Object Level Authorization (BOLA)
Generated to verify the authorization fix.

Before fix: test FAILS (Alice can read Bob's account — 200 returned)
After fix:  test PASSES (Alice gets 403 Forbidden)
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def _login(username: str, password: str) -> str:
    """Helper: log in and return JWT token."""
    resp = client.post(
        "/api/auth/login",
        json={{"username": username, "password": password}},
    )
    assert resp.status_code == 200, f"Login failed for {{username}}: {{resp.text}}"
    return resp.json()["access_token"]


def _auth(token: str) -> dict:
    return {{"Authorization": f"Bearer {{token}}"}}


# ── Core BOLA regression test ─────────────────────────────────────────────────

def test_securefix_{inv_id.replace("-", "_").lower()}_cross_user_account_access():
    """
    SECUREFIX Regression Test [{inv_id}]
    Alice must NOT be able to access Bob's account (account_id=2).

    Before fix: Returns HTTP 200 (VULNERABLE)
    After fix:  Returns HTTP 403 (SECURE)
    """
    alice_token = _login("alice", "alice123")

    response = client.get(
        "/api/accounts/2",   # Bob's account
        headers=_auth(alice_token),
    )

    assert response.status_code == 403, (
        f"BOLA REGRESSION [{inv_id}]: "
        f"Alice accessed Bob's account! "
        f"Status: {{response.status_code}}, "
        f"Body: {{response.text}}"
    )


def test_securefix_{inv_id.replace("-", "_").lower()}_owner_can_access_own_account():
    """Alice can still access her own account after the fix."""
    alice_token = _login("alice", "alice123")

    response = client.get(
        "/api/accounts/1",   # Alice's account
        headers=_auth(alice_token),
    )

    assert response.status_code == 200, (
        f"Owner access broken [{inv_id}]: "
        f"Alice cannot access her own account! "
        f"Status: {{response.status_code}}"
    )


def test_securefix_{inv_id.replace("-", "_").lower()}_unauthenticated_blocked():
    """Unauthenticated requests must be rejected."""
    response = client.get("/api/accounts/1")
    assert response.status_code in (401, 403), (
        f"Unauthenticated access not blocked [{inv_id}]"
    )
'''


def _sqli_regression_test(inv_id: str) -> str:
    return f'''"""
SECUREFIX Auto-Generated Regression Test
Investigation: {inv_id}
Vulnerability: SQL Injection
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_securefix_{inv_id.replace("-", "_").lower()}_sql_injection_blocked():
    """SQL injection payload must not cause error or return unexpected data."""
    resp = client.post(
        "/api/auth/login",
        json={{"username": "' OR 1=1 --", "password": "anything"}},
    )
    assert resp.status_code in (401, 422), (
        f"SQL injection not blocked [{inv_id}]: {{resp.status_code}}"
    )
'''


def _generic_auth_regression_test(inv_id: str) -> str:
    return f'''"""
SECUREFIX Auto-Generated Regression Test
Investigation: {inv_id}
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_securefix_{inv_id.replace("-", "_").lower()}_unauthorized_blocked():
    """Unauthorized access to protected resource must be blocked."""
    resp = client.get("/api/accounts/1")
    assert resp.status_code in (401, 403)
'''
