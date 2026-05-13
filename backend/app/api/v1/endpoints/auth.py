from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from datetime import timedelta
from typing import Optional
import asyncpg

from app.auth import (
    UserRole,
    create_access_token,
    verify_password,
    get_password_hash,
    get_current_user,
    require_admin,
    log_audit,
)
from app.db.postgres import get_db

router = APIRouter()
security = HTTPBearer()


class UserCreateRequest(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[UserRole] = UserRole.VIEWER


class UserLoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreateRequest, request: Request, conn: asyncpg.Connection = Depends(get_db)):
    """Register a new user."""
    # Check if user exists
    existing = await conn.fetchrow(
        "SELECT username FROM users WHERE username = $1 OR email = $2",
        user_data.username, user_data.email
    )
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Create user
    hashed_password = get_password_hash(user_data.password)
    await conn.execute(
        "INSERT INTO users (username, email, hashed_password, role) VALUES ($1, $2, $3, $4)",
        user_data.username, user_data.email, hashed_password, user_data.role.value
    )
    
    # Audit log
    await log_audit(
        conn, None, "create", "user", user_data.username,
        f"Created user with role {user_data.role.value}",
        request.client.host if request.client else None
    )
    
    return {"message": "User created successfully", "username": user_data.username}


@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLoginRequest, request: Request, conn: asyncpg.Connection = Depends(get_db)):
    """Login and receive access token."""
    user = await conn.fetchrow(
        "SELECT username, hashed_password, role, is_active FROM users WHERE username = $1",
        credentials.username
    )
    
    if not user or not verify_password(credentials.password, user['hashed_password']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user['is_active']:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    # Update last login
    await conn.execute(
        "UPDATE users SET last_login = NOW() WHERE username = $1",
        credentials.username
    )
    
    # Create access token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user['username'], "role": user['role']},
        expires_delta=access_token_expires
    )
    
    # Audit log
    await log_audit(
        conn, None, "login", "auth", user['username'],
        None,
        request.client.host if request.client else None
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me")
async def read_users_me(current_user: dict = Depends(get_current_user), conn: asyncpg.Connection = Depends(get_db)):
    """Get current user info."""
    return await conn.fetchrow(
        "SELECT username, email, role, is_active, created_at, last_login FROM users WHERE username = $1",
        current_user['username']
    )


@router.get("/users")
async def list_users(
    conn: asyncpg.Connection = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """List all users (admin only)."""
    return await conn.fetch(
        "SELECT id, username, email, role, is_active, created_at, last_login FROM users"
    )


@router.get("/audit-logs")
async def get_audit_logs(
    limit: int = 100,
    conn: asyncpg.Connection = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    """Get audit logs (admin only)."""
    return await conn.fetch(
        "SELECT id, username, action, resource, resource_id, details, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT $1",
        limit
    )

# Remove duplicate import
# (already imported at the top of the file)
