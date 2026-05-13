from __future__ import annotations

import pyotp
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional, List, Callable
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from enum import Enum as PyEnum
import asyncpg

from app.config import get_settings
from app.db.postgres import get_db

security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ============================================================
# TOTP / 2FA helpers
# ============================================================

def generate_totp_secret() -> str:
    """Generate a new base32 TOTP secret for 2FA enrollment."""
    return pyotp.random_base32()


def get_totp_provisioning_url(username: str, secret: str, issuer: str = "ThreatIntel") -> str:
    """Build an otpauth:// provisioning URI for QR-code display."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp_token(secret: str, token: str) -> bool:
    """Verify a TOTP 6-digit token against the given secret."""
    totp = pyotp.totp.TOTP(secret)
    return totp.verify(token, valid_window=1)  # ±1 interval tolerance for clock drift


def generate_recovery_codes(count: int = 10) -> list[str]:
    """Generate one-time recovery codes for 2FA lockout fallback.

    Each code is 8 uppercase alphanumeric characters, stored hashed in the DB.
    """
    alphabet = string.ascii_uppercase + string.digits
    # exclude ambiguous chars 0/O, 1/I/L
    alphabet = "".join(c for c in alphabet if c not in "0O1IL")
    return ["".join(secrets.choice(alphabet) for _ in range(8)) for _ in range(count)]


# ============================================================
# JWT Functions
# ============================================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    settings = get_settings()
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.jwt_expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# ============================================================
# Auth Dependencies
# ============================================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    conn: asyncpg.Connection = Depends(get_db)
) -> dict:
    """Get current authenticated user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        settings = get_settings()
        payload = jwt.decode(credentials.credentials, settings.secret_key, algorithms=[settings.jwt_algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await conn.fetchrow(
        "SELECT username, role, is_active, totp_secret FROM users WHERE username = $1",
        username
    )

    if user is None or not user['is_active']:
        raise credentials_exception

    return dict(user)


def require_role(allowed_roles: List[UserRole]) -> Callable:
    """Dependency factory for role-based access control."""
    async def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user['role'] not in [r.value for r in allowed_roles]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires one of: {[r.value for r in allowed_roles]}"
            )
        return current_user
    return role_checker


async def log_audit(
    conn: asyncpg.Connection,
    username: str,
    action: str,
    resource: str,
    resource_id: Optional[str] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = None
):
    """Log an audit event."""
    await conn.execute(
        """INSERT INTO audit_logs (username, action, resource, resource_id, details, ip_address)
           VALUES ($1, $2, $3, $4, $5, $6)""",
        username, action, resource, resource_id, details, ip_address
    )


# ============================================================
# Role-based dependencies
# ============================================================

require_admin = require_role([UserRole.ADMIN])
require_analyst = require_role([UserRole.ADMIN, UserRole.ANALYST])
require_viewer = require_role([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])