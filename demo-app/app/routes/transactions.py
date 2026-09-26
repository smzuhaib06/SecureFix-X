"""
Transactions routes for SecureBank demo app.

VULNERABILITY: Similar BOLA issue — no ownership check on transaction access.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List
import sqlite3

from app.database import get_db
from app.auth import get_current_user

router = APIRouter()


class Transaction(BaseModel):
    id: int
    account_id: int
    transaction_type: str
    amount: float
    description: str | None
    timestamp: str


@router.get("/{transaction_id}", response_model=Transaction)
def get_transaction(
    transaction_id: int,
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Get a specific transaction.

    VULNERABILITY: No ownership verification.
    Any authenticated user can read any transaction by ID.
    """
    row = db.execute(
        "SELECT * FROM transactions WHERE id = ?", (transaction_id,)
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Transaction not found")

    # Missing: ownership check through accounts table

    return Transaction(**dict(row))


@router.get("/account/{account_id}", response_model=List[Transaction])
def get_account_transactions(
    account_id: int,
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Get all transactions for an account.

    VULNERABILITY: No account ownership verification.
    """
    rows = db.execute(
        "SELECT * FROM transactions WHERE account_id = ?", (account_id,)
    ).fetchall()

    return [Transaction(**dict(row)) for row in rows]
