"""
Profile routes for SecureBank demo app.

VULNERABILITY: Profile endpoint exposes sensitive PII with no ownership check.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
import sqlite3

from app.database import get_db
from app.auth import get_current_user

router = APIRouter()


class Profile(BaseModel):
    id: int
    user_id: int
    phone: Optional[str]
    address: Optional[str]
    ssn_last4: Optional[str]
    date_of_birth: Optional[str]


@router.get("/{profile_id}", response_model=Profile)
def get_profile(
    profile_id: int,
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    """
    Get a user profile by ID.

    VULNERABILITY: No ownership check. Any authenticated user can access
    any profile including sensitive PII (SSN last 4, date of birth).
    """
    row = db.execute(
        "SELECT * FROM profiles WHERE id = ?", (profile_id,)
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")

    return Profile(**dict(row))


@router.get("/me/", response_model=Profile)
def get_my_profile(
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    """Get the authenticated user's own profile."""
    row = db.execute(
        "SELECT * FROM profiles WHERE user_id = ?", (current_user["id"],)
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")

    return Profile(**dict(row))
