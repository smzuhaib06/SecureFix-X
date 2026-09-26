"""
Accounts routes for SecureBank demo app.

VULNERABILITY: This module contains an intentional Broken Object Level Authorization (BOLA)
vulnerability. The GET /api/accounts/{account_id} endpoint authenticates the user but
does NOT verify that the authenticated user owns the requested account.

This is the target vulnerability for the SECUREFIX demonstration.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional
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


class AccountList(BaseModel):
    accounts: List[Account]


@router.get("/", response_model=AccountList)
def get_my_accounts(
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    """Get all accounts belonging to the authenticated user."""
    rows = db.execute(
        "SELECT * FROM accounts WHERE user_id = ?", (current_user["id"],)
    ).fetchall()

    accounts = [Account(**dict(row)) for row in rows]
    return AccountList(accounts=accounts)


# ============================================================
# VULNERABLE ENDPOINT — intentional BOLA for demo
# ============================================================
@router.get("/{account_id}", response_model=Account)
def get_account(
    account_id: int,
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Get a specific account by ID.

    VULNERABILITY: Authenticates user (checks JWT token is valid) but does NOT
    verify that current_user.id matches account.user_id.

    Alice (user_id=1) can request /api/accounts/2 and receive Bob's account data.
    """
    # Authentication check: user must be logged in (this part works)
    # Authorization check: MISSING — does not verify ownership
    row = db.execute(
        "SELECT * FROM accounts WHERE id = ?", (account_id,)
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Account not found")

    # BUG: Should be: if row["user_id"] != current_user["id"]: raise 403
    # But that check is absent here.

    return Account(**dict(row))
