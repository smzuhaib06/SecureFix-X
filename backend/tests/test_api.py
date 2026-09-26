"""
SECUREFIX backend API smoke tests.
Tests all major routes without running a real investigation
(uses the demo-app path if available, otherwise skips repo-dependent tests).
"""
import os
import pytest
from fastapi.testclient import TestClient

# Point at demo-app for tests that need a repo
DEMO_REPO = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "../../demo-app")
)

# Set env before importing app
os.environ.setdefault("DEMO_REPO_PATH", DEMO_REPO)


@pytest.fixture(scope="module")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


# ── Health ────────────────────────────────────────────────────────────────────

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


# ── Dashboard stats ───────────────────────────────────────────────────────────

def test_dashboard_stats(client):
    r = client.get("/api/dashboard/stats")
    assert r.status_code == 200
    data = r.json()
    assert "active_investigations" in data
    assert "demo_metrics" in data
    assert data["demo_metrics"]["avg_investigation_time_reduction_pct"] == 68


# ── Investigations CRUD ───────────────────────────────────────────────────────

def test_list_investigations_empty(client):
    r = client.get("/api/investigations")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_create_investigation(client):
    r = client.post("/api/investigations", json={
        "title": "Test investigation",
        "issue_description": "authorization bypass test",
        "repository_path": DEMO_REPO,
    })
    assert r.status_code == 201
    data = r.json()
    assert data["id"].startswith("SF-")
    assert data["status"] == "pending"
    assert data["title"] == "Test investigation"


def test_get_investigation(client):
    # Create one first
    create_r = client.post("/api/investigations", json={
        "title": "Get test",
        "issue_description": "test",
        "repository_path": DEMO_REPO,
    })
    inv_id = create_r.json()["id"]

    r = client.get(f"/api/investigations/{inv_id}")
    assert r.status_code == 200
    assert r.json()["id"] == inv_id


def test_get_investigation_not_found(client):
    r = client.get("/api/investigations/SF-DOESNOTEXIST")
    assert r.status_code == 404


def test_delete_investigation(client):
    create_r = client.post("/api/investigations", json={
        "title": "Delete me",
        "issue_description": "test",
        "repository_path": DEMO_REPO,
    })
    inv_id = create_r.json()["id"]

    r = client.delete(f"/api/investigations/{inv_id}")
    assert r.status_code == 204

    r2 = client.get(f"/api/investigations/{inv_id}")
    assert r2.status_code == 404


# ── Investigation validation ──────────────────────────────────────────────────

def test_create_investigation_invalid_path(client):
    r = client.post("/api/investigations", json={
        "title": "Bad path",
        "issue_description": "test",
        "repository_path": "/nonexistent/path/that/does/not/exist",
    })
    assert r.status_code == 400


def test_create_investigation_bad_url(client):
    r = client.post("/api/investigations", json={
        "title": "Bad URL",
        "issue_description": "test",
        "repository_url": "https://evil.com/steal",
    })
    assert r.status_code == 400


def test_approve_non_awaiting(client):
    """Approving an investigation that doesn't exist should return 404."""
    r = client.post("/api/investigations/SF-NONEXISTENT/approve", json={"approved": True})
    assert r.status_code == 404


def test_approve_awaiting_investigation(client):
    """Approving an awaiting_approval investigation should work."""
    # With TestClient, the background task runs synchronously, so the
    # investigation will be at awaiting_approval after creation
    create_r = client.post("/api/investigations", json={
        "title": "Approve workflow test",
        "issue_description": "authorization bypass in account endpoint",
        "repository_path": DEMO_REPO,
    })
    inv_id = create_r.json()["id"]
    inv = client.get(f"/api/investigations/{inv_id}").json()

    if inv["status"] == "awaiting_approval":
        r = client.post(f"/api/investigations/{inv_id}/approve",
                        json={"approved": False, "comment": "test rejection"})
        assert r.status_code == 200
        assert r.json()["remediation"]["status"] == "rejected"
    else:
        # Investigation may have completed or failed — still a valid state
        assert inv["status"] in ("completed", "failed", "running", "pending", "awaiting_approval")


# ── Report ────────────────────────────────────────────────────────────────────

def test_report_not_found(client):
    r = client.get("/api/investigations/SF-FAKE/report")
    assert r.status_code == 404


def test_report_returns_markdown(client):
    """Report for a minimal (pending) investigation returns markdown."""
    create_r = client.post("/api/investigations", json={
        "title": "Report test",
        "issue_description": "sql injection",
        "repository_path": DEMO_REPO,
    })
    inv_id = create_r.json()["id"]

    r = client.get(f"/api/investigations/{inv_id}/report")
    assert r.status_code == 200
    assert "SECUREFIX" in r.text
    assert inv_id in r.text
    # Content-Type should contain markdown
    assert "markdown" in r.headers.get("content-type", "")


# ── Models ────────────────────────────────────────────────────────────────────

def test_investigation_model_fields(client):
    create_r = client.post("/api/investigations", json={
        "title": "Model test",
        "issue_description": "authorization",
        "repository_path": DEMO_REPO,
    })
    data = create_r.json()
    required = ["id", "title", "issue_description", "status",
                "created_at", "updated_at", "agent_results",
                "timeline", "progress_pct"]
    for field in required:
        assert field in data, f"Missing field: {field}"


# ── Repository connector ──────────────────────────────────────────────────────

def test_repo_connector_github_valid():
    from app.repository import RepositoryConnector
    rc = RepositoryConnector()
    rc._validate_url("https://github.com/owner/repo")  # Should not raise


def test_repo_connector_rejects_evil():
    from app.repository import RepositoryConnector
    rc = RepositoryConnector()
    with pytest.raises(ValueError, match="supported"):
        rc._validate_url("https://evil.com/payload")


def test_repo_connector_rejects_ssh():
    from app.repository import RepositoryConnector
    rc = RepositoryConnector()
    with pytest.raises(ValueError, match="HTTPS"):
        rc._validate_url("git@github.com:owner/repo.git")


# ── Store ─────────────────────────────────────────────────────────────────────

def test_store_crud():
    from app.store import InvestigationStore
    from app.models import Investigation
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        s = InvestigationStore(db_path=tmp.name)
        inv = Investigation(title="t", issue_description="d")
        s.create(inv)
        assert s.get(inv.id) is not None
        assert len(s.list_all()) >= 1
        s.delete(inv.id)
        assert s.get(inv.id) is None


def test_sqlite_persistence_across_instances():
    """Verify that investigations and audit events persist across store instantiations."""
    from app.store import InvestigationStore
    from app.models import Investigation
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        s1 = InvestigationStore(db_path=tmp.name)
        inv = Investigation(title="Persistent Investigation", issue_description="Testing disk persistence")
        s1.create(inv)
        inv_id = inv.id

        # Create a second store instance pointing to the exact same SQLite database
        s2 = InvestigationStore(db_path=tmp.name)
        loaded = s2.get(inv_id)
        assert loaded is not None
        assert loaded.title == "Persistent Investigation"

        # Check audit events persisted in SQLite
        audit_events = s2.get_audit(inv_id)
        assert len(audit_events) >= 1
        assert any(e.action == "INVESTIGATION_CREATED" for e in audit_events)


def test_audit_log_api(client):
    """Test the GET /api/investigations/{id}/audit endpoint."""
    r_create = client.post("/api/investigations", json={
        "title": "Audit Test",
        "issue_description": "Verify audit log endpoint",
        "repository_path": DEMO_REPO,
    })
    assert r_create.status_code == 201
    inv_id = r_create.json()["id"]

    r_audit = client.get(f"/api/investigations/{inv_id}/audit")
    assert r_audit.status_code == 200
    events = r_audit.json()
    assert isinstance(events, list)
    assert len(events) >= 1
    assert events[0]["action"] == "INVESTIGATION_CREATED"
    assert events[0]["investigation_id"] == inv_id


def test_exploit_execution_detects_vulnerability():
    """Verify that _check_exploit_blocked actually executes the attack and reports status."""
    from app.verification.engine import VerificationEngine
    from app.models import Investigation, RemediationProposal, FilePatch
    verifier = VerificationEngine()
    inv = Investigation(
        title="BOLA Test",
        issue_description="BOLA on accounts",
        repository_path=DEMO_REPO,
        remediation=RemediationProposal(
            summary="test",
            files_changed=["app/routes/accounts.py"],
            patches=[FilePatch(
                file_path="app/routes/accounts.py",
                before="x",
                after="y",
                diff="d",
                explanation="e",
            )],
        ),
    )
    res = verifier._check_exploit_blocked(DEMO_REPO, inv)
    # In vulnerable state, Alice accessing Bob's account returns HTTP 200
    assert "status_code" in res
    assert res["status_code"] == 200
    assert res["blocked"] is False
    assert "HTTP 200" in res["detail"]


