from __future__ import annotations

import pyotp
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional, List, Callable
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel
import asyncpg

from app.auth import (
    UserRole,
    create_access_token,
    verify_password,
    get_password_hash,
    get_current_user,
    require_admin,
    log_audit,
    generate_totp_secret,
    get_totp_provisioning_url,
    verify_totp_token,
    generate_recovery_codes,
)
from app.config import get_settings
from app.db.postgres import get_db

router = APIRouter()
security = HTTPBearer()


# ─── Request / Response Schemas ──────────────────────────────

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


class PreAuthTokenResponse(BaseModel):
    """Returned when login succeeds but 2FA is still required."""
    pre_auth_token: str
    mfa_required: bool = True


class GoogleAuthRequest(BaseModel):
    """Google OAuth2 ID token from frontend."""
    credential: str  # Google JWT ID token


# ─── Google OAuth2 Token Verification ─────────────────────────

def verify_google_token(google_id_token: str) -> dict | None:
    """
    Verify a Google OAuth2 ID token and return user info dict.
    Returns None if token is invalid.

    Requires google-auth or pyjwt[crypto] with Google's public keys.
    Falls back gracefully if google-auth is not installed.
    """
    try:
        from google.oauth2 import id_token
        from google.auth.transport import requests as google_requests

        client_id = get_settings().google_client_id
        if not client_id:
            return None

        audience = client_id if client_id != "web" else None
        id_info = id_token.verify_oauth2_token(
            google_id_token,
            google_requests.Request(),
            audience=audience,
        )

        if id_info.get("issuer") not in ("accounts.google.com", "https://accounts.google.com"):
            return None

        return {
            "sub": id_info.get("sub"),
            "email": id_info.get("email"),
            "name": id_info.get("name", ""),
            "picture": id_info.get("picture", ""),
        }
    except ImportError:
        # google-auth not installed — cannot verify
        return None
    except Exception:
        return None


# ─── Google Sign-In ──────────────────────────────────────────

@router.post("/auth/google", response_model=TokenResponse)
async def google_signin(
    req: GoogleAuthRequest,
    request: Request,
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Sign in or register using a Google OAuth2 ID token.

    Flow:
    1. Frontend gets a Google ID token via google.accounts.id or gsi button
    2. POST it here with {"credential": "<token>"}
    3. Backend verifies the token with Google
    4. Creates or finds the user in the DB
    5. Returns a JWT access token
    """
    google_user = verify_google_token(req.credential)
    if not google_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google token or Google auth not configured",
        )

    email = google_user["email"]
    google_sub = google_user["sub"]

    # Try to find existing user by Google sub or email
    user = await conn.fetchrow(
        "SELECT id, username, email, role, is_active, totp_secret, google_sub "
        "FROM users WHERE email = $1 OR google_sub = $2",
        email, google_sub,
    )

    if user:
        # Existing user — verify it's active
        if not user["is_active"]:
            raise HTTPException(status_code=400, detail="Inactive user")

        # If this Google account isn't linked yet, link it
        if not user.get("google_sub"):
            await conn.execute(
                "UPDATE users SET google_sub = $1 WHERE id = $2",
                google_sub, user["id"],
            )

        username = user["username"]
        role = user["role"]
    else:
        # New user — auto-register from Google profile
        # Derive username from email (user@example.com → user)
        derived_username = email.split("@")[0].lower()

        # Ensure uniqueness
        existing = await conn.fetchrow(
            "SELECT id FROM users WHERE username = $1", derived_username
        )
        if existing:
            username = f"{derived_username}_{google_sub[-6:]}"
        else:
            username = derived_username

        await conn.execute(
            """INSERT INTO users (username, email, hashed_password, role, google_sub)
               VALUES ($1, $2, $3, $4, $5)""",
            username,
            email,
            "",  # No password for Google-only users
            UserRole.VIEWER.value,
            google_sub,
        )

        await log_audit(
            conn, None, "create", "user", username,
            f"User auto-registered via Google OAuth2",
            request.client.host if request.client else None,
        )
        role = UserRole.VIEWER.value

    # Audit log
    await log_audit(
        conn, username, "login_google", "auth", username,
        None,
        request.client.host if request.client else None,
    )

    # Issue access token (note: Google-authenticated users bypass 2FA)
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": username, "role": role, "google_authenticated": True},
        expires_delta=access_token_expires,
    )

    return {"access_token": access_token, "token_type": "bearer"}


# ─── 2FA Setup Schemas ────────────────────────────────────────

class TOTPEnableRequest(BaseModel):
    password: str


class TOTPEnableResponse(BaseModel):
    secret: str
    provisioning_uri: str
    recovery_codes: list[str]


class TOTPVerifyRequest(BaseModel):
    token: str


class RecoveryCodeRequest(BaseModel):
    recovery_code: str


class TOTPDisableRequest(BaseModel):
    password: str


# ─── Login (2FA-aware) ────────────────────────────────────────

@router.post("/login", response_model=TokenResponse | PreAuthTokenResponse)
async def login(
    credentials: UserLoginRequest,
    request: Request,
    conn: asyncpg.Connection = Depends(get_db),
):
    """Login. If 2FA is enabled, returns a 403 with a pre-auth token."""
    user = await conn.fetchrow(
        "SELECT id, username, hashed_password, role, is_active, totp_secret "
        "FROM users WHERE username = $1",
        credentials.username,
    )

    if not user or not verify_password(credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user["is_active"]:
        raise HTTPException(status_code=400, detail="Inactive user")

    await log_audit(
        conn, user["username"], "login_attempt", "auth",
        user["username"],
        request.client.host if request.client else None,
    )

    await conn.execute(
        "UPDATE users SET last_login = NOW() WHERE username = $1",
        credentials.username,
    )

    # If TOTP is enabled, require 2FA verification
    if user["totp_secret"]:
        pre_auth_expires = timedelta(minutes=10)
        pre_auth_token = create_access_token(
            data={
                "sub": user["username"],
                "role": user["role"],
                "mfa_verified": False,
                "pre_auth": True,
            },
            expires_delta=pre_auth_expires,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Multi-factor authentication required",
            headers={"WWW-Authenticate": f'Bearer pre_auth_token="{pre_auth_token}"'},
        )

    # No 2FA — issue full token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"]},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


# ─── 2FA Enrollment ────────────────────────────────────────────

@router.post("/totp/enable", response_model=TOTPEnableResponse)
async def enable_totp(
    req: TOTPEnableRequest,
    current_user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db),
):
    """Enable TOTP 2FA. Requires current password."""
    pw_row = await conn.fetchrow(
        "SELECT hashed_password FROM users WHERE username = $1",
        current_user["username"],
    )
    if not verify_password(req.password, pw_row["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect password")

    if current_user.get("totp_secret"):
        secret = current_user["totp_secret"]
    else:
        secret = generate_totp_secret()
        await conn.execute(
            "UPDATE users SET totp_secret = $1 WHERE username = $2",
            secret,
            current_user["username"],
        )

    recovery_codes = generate_recovery_codes()
    hashed_codes = [get_password_hash(code) for code in recovery_codes]

    await conn.execute(
        """INSERT INTO user_recovery_codes (user_id, code_hash, used, created_at)
           SELECT (SELECT id FROM users WHERE username = $1),
                  unnest($2::text[]), false, NOW()""",
        current_user["username"],
        hashed_codes,
    )

    await log_audit(
        conn, current_user["username"], "totp_enable", "auth",
        current_user["username"],
    )

    return TOTPEnableResponse(
        secret=secret,
        provisioning_uri=get_totp_provisioning_url(
            current_user["username"], secret
        ),
        recovery_codes=recovery_codes,
    )


@router.post("/totp/disable")
async def disable_totp(
    req: TOTPDisableRequest,
    current_user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db),
):
    """Disable TOTP 2FA."""
    if not current_user.get("totp_secret"):
        raise HTTPException(status_code=400, detail="TOTP is not enabled")

    pw_row = await conn.fetchrow(
        "SELECT hashed_password FROM users WHERE username = $1",
        current_user["username"],
    )
    if not verify_password(req.password, pw_row["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect password")

    await conn.execute(
        "UPDATE users SET totp_secret = NULL WHERE username = $1",
        current_user["username"],
    )
    await conn.execute(
        "UPDATE user_recovery_codes SET used = true "
        "WHERE user_id = (SELECT id FROM users WHERE username = $1)",
        current_user["username"],
    )

    await log_audit(
        conn, current_user["username"], "totp_disable", "auth",
        current_user["username"],
    )
    return {"message": "TOTP 2FA disabled successfully"}


# ─── 2FA Verification ─────────────────────────────────────────

@router.post("/totp/verify")
async def verify_totp(
    req: TOTPVerifyRequest,
    request: Request,
    conn: asyncpg.Connection = Depends(get_db),
):
    """Verify TOTP token using a pre-auth token. Returns a full session token."""
    creds_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise creds_exception
    token = auth_header.removeprefix("Bearer ")

    try:
        settings = get_settings()
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        if not payload.get("pre_auth"):
            raise creds_exception
        username: str = payload.get("sub")
        if username is None:
            raise creds_exception
    except JWTError:
        raise creds_exception

    user = await conn.fetchrow(
        "SELECT id, username, totp_secret, role FROM users WHERE username = $1",
        username,
    )
    if not user or not user["totp_secret"]:
        raise HTTPException(status_code=400, detail="TOTP not enabled")

    if not verify_totp_token(user["totp_secret"], req.token):
        await log_audit(conn, user["username"], "totp_failed", "auth", user["username"])
        raise HTTPException(status_code=401, detail="Invalid TOTP token")

    session_expires = timedelta(hours=12)
    session_token = create_access_token(
        data={"sub": user["username"], "role": user["role"], "mfa_verified": True},
        expires_delta=session_expires,
    )

    await log_audit(conn, user["username"], "totp_verify", "auth", user["username"])
    return {"access_token": session_token, "token_type": "bearer", "mfa_verified": True}


# ─── Recovery Code Login ───────────────────────────────────────

@router.post("/totp/recovery")
async def use_recovery_code(
    req: RecoveryCodeRequest,
    request: Request,
    conn: asyncpg.Connection = Depends(get_db),
):
    """Bypass TOTP using a one-time recovery code."""
    creds_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise creds_exception
    token = auth_header.removeprefix("Bearer ")

    try:
        settings = get_settings()
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        if not payload.get("pre_auth"):
            raise creds_exception
        username: str = payload.get("sub")
        if username is None:
            raise creds_exception
    except JWTError:
        raise creds_exception

    user = await conn.fetchrow(
        "SELECT id, username, role FROM users WHERE username = $1", username
    )
    if not user:
        raise creds_exception

    code_hash = get_password_hash(req.recovery_code)
    row = await conn.fetchrow(
        """SELECT id FROM user_recovery_codes
           WHERE user_id = $1 AND code_hash = $2 AND used = false""",
        user["id"],
        code_hash,
    )

    if not row:
        await log_audit(conn, user["username"], "recovery_code_failed", "auth", user["username"])
        raise HTTPException(status_code=401, detail="Invalid or already-used recovery code")

    await conn.execute(
        "UPDATE user_recovery_codes SET used = true, used_at = NOW() WHERE id = $1",
        row["id"],
    )

    session_expires = timedelta(hours=12)
    session_token = create_access_token(
        data={
            "sub": user["username"],
            "role": user["role"],
            "mfa_verified": True,
            "recovery_code_used": True,
        },
        expires_delta=session_expires,
    )

    await log_audit(conn, user["username"], "recovery_code_used", "auth", user["username"])
    return {
        "access_token": session_token,
        "token_type": "bearer",
        "mfa_verified": True,
        "recovery_code_used": True,
    }


# ─── 2FA Status ───────────────────────────────────────────────

@router.get("/totp/status")
async def totp_status(current_user: dict = Depends(get_current_user)):
    """Check whether the current user has TOTP 2FA enabled."""
    return {"enabled": bool(current_user.get("totp_secret"))}


# ─── Existing Endpoints ────────────────────────────────────────

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreateRequest,
    request: Request,
    conn: asyncpg.Connection = Depends(get_db),
):
    """Register a new user."""
    existing = await conn.fetchrow(
        "SELECT username FROM users WHERE username = $1 OR email = $2",
        user_data.username,
        user_data.email,
    )
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already registered")

    hashed_password = get_password_hash(user_data.password)
    await conn.execute(
        "INSERT INTO users (username, email, hashed_password, role) VALUES ($1, $2, $3, $4)",
        user_data.username,
        user_data.email,
        hashed_password,
        user_data.role.value,
    )

    await log_audit(
        conn, None, "create", "user", user_data.username,
        f"Created user with role {user_data.role.value}",
        request.client.host if request.client else None,
    )

    return {"message": "User created successfully", "username": user_data.username}


@router.get("/me")
async def read_users_me(
    current_user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db),
):
    """Get current user info."""
    return await conn.fetchrow(
        "SELECT username, email, role, is_active, "
        "totp_secret IS NOT NULL AS mfa_enabled, "
        "google_sub IS NOT NULL AS google_linked, "
        "created_at, last_login "
        "FROM users WHERE username = $1",
        current_user["username"],
    )


@router.get("/users")
async def list_users(
    conn: asyncpg.Connection = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """List all users (admin only)."""
    return await conn.fetch(
        "SELECT id, username, email, role, is_active, "
        "totp_secret IS NOT NULL AS mfa_enabled, "
        "google_sub IS NOT NULL AS google_linked, "
        "created_at, last_login FROM users"
    )


@router.get("/audit-logs")
async def get_audit_logs(
    limit: int = 100,
    conn: asyncpg.Connection = Depends(get_db),
    current_user: dict = Depends(require_admin),
):
    """Get audit logs (admin only)."""
    return await conn.fetch(
        "SELECT id, username, action, resource, resource_id, details, timestamp "
        "FROM audit_logs ORDER BY timestamp DESC LIMIT $1",
        limit,
    )