"""
Test suite for SecureBank accounts.

Note: test_cross_user_account_access demonstrates the BOLA vulnerability.
Before SECUREFIX: this test FAILS (exploit works, returns 200).
After SECUREFIX:  this test PASSES (exploit blocked, returns 403).
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

# Use context manager so lifespan (init_db) runs
@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def get_token(client: TestClient, username: str, password: str) -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_alice_can_access_own_account(client: TestClient):
    """Alice should be able to access her own account (ACC-1001, id=1)."""
    token = get_token(client, "alice", "alice123")
    response = client.get(
        "/api/accounts/1",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["account_number"] == "ACC-1001"


def test_unauthenticated_access_blocked(client: TestClient):
    """Unauthenticated requests must be rejected."""
    response = client.get("/api/accounts/1")
    assert response.status_code in (401, 403)


# ============================================================
# REGRESSION TEST — This is the key BOLA regression test
# Before fix: FAILS (returns 200, exploit works)
# After fix:  PASSES (returns 403, exploit blocked)
# ============================================================
def test_alice_cannot_access_bobs_account(client: TestClient):
    """
    Regression test for BOLA vulnerability.

    Alice (user_id=1) must NOT be able to access Bob's account (id=2, user_id=2).
    Expected: 403 Forbidden
    """
    token = get_token(client, "alice", "alice123")
    response = client.get(
        "/api/accounts/2",  # Bob's account
        headers={"Authorization": f"Bearer {token}"},
    )
    # This assertion FAILS before fix and PASSES after fix
    assert response.status_code == 403, (
        f"BOLA vulnerability: Alice accessed Bob's account! "
        f"Got {response.status_code}, expected 403"
    )
