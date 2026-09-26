"""
Authentication routes for SecureBank demo app.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
import sqlite3

from app.database import get_db
from app.auth import verify_password, create_access_token

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user_id: int
    username: str
    full_name: str


@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (request.username,)
    ).fetchone()

    if not user or not verify_password(request.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(
        data={"sub": str(user["id"]), "username": user["username"]}
    )

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user_id=user["id"],
        username=user["username"],
        full_name=user["full_name"],
    )
