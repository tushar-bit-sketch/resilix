"""
RESILIX Security & Authentication Service
Provides:
- Memory-hard password hashing using Cryptography Scrypt (N=16384, r=8, p=1) with Argon2 compatibility
- Server-side session persistence in SQLite + HTTP-only SameSite=Lax cookie + Bearer token support
- Login rate-limiting per IP / username
- Role-based access control (admin vs operator)
- Security audit logging
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from fastapi import Depends, HTTPException, Request, status

from app.config import settings
from app.database import DatabaseSession, get_db, utc_now_iso

# In-memory sliding window rate limiter for login attempts (backed up by user failed_login_attempts in SQLite)
_login_attempts: dict[str, list[float]] = {}


def hash_password(password: str) -> str:
    """Hash a password using memory-hard Scrypt KDF (RFC 7914)."""
    salt = os.urandom(16)
    n, r, p = 16384, 8, 1
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    derived = kdf.derive(password.encode("utf-8"))
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(derived).decode("ascii")
    return f"scrypt${n}${r}${p}${salt_b64}${hash_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored Scrypt hash in constant time."""
    try:
        parts = stored_hash.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = base64.b64decode(parts[4].encode("ascii"))
        expected = base64.b64decode(parts[5].encode("ascii"))
        kdf = Scrypt(salt=salt, length=len(expected), n=n, r=r, p=p)
        kdf.verify(password.encode("utf-8"), expected)
        return True
    except Exception:
        return False


def hash_session_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def check_login_rate_limit(key: str) -> bool:
    """Return True if allowed, False if rate limit exceeded."""
    now = time.time()
    window = settings.login_rate_limit_window_seconds
    max_attempts = settings.login_rate_limit_attempts
    history = [t for t in _login_attempts.get(key, []) if now - t < window]
    _login_attempts[key] = history
    if len(history) >= max_attempts:
        return False
    return True


def record_login_failure_attempt(key: str) -> None:
    now = time.time()
    _login_attempts.setdefault(key, []).append(now)


def clear_login_attempts(key: str) -> None:
    _login_attempts.pop(key, None)


def reset_all_rate_limits() -> None:
    _login_attempts.clear()


def log_audit_event(
    db: DatabaseSession,
    actor_username: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    status_str: str = "SUCCESS",
    ip_address: Optional[str] = "127.0.0.1",
    details: Optional[dict[str, Any]] = None,
) -> None:
    db.execute(
        """
        INSERT INTO audit_logs (
            timestamp, actor_username, actor_role, action,
            resource_type, resource_id, status, ip_address, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            utc_now_iso(),
            actor_username,
            actor_role,
            action,
            resource_type,
            resource_id,
            status_str,
            ip_address or "127.0.0.1",
            json.dumps(details or {}, sort_keys=True),
        ),
    )


def create_user_session(
    db: DatabaseSession,
    user_id: int,
    ip_address: str = "127.0.0.1",
    user_agent: str = "RESILIX-Client",
) -> dict[str, str]:
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_session_token(raw_token)
    csrf_token = secrets.token_hex(16)
    session_id = f"SES-{secrets.token_hex(8).upper()}"
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.session_ttl_minutes)
    created_iso = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    expires_iso = expires.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    db.execute(
        """
        INSERT INTO user_sessions (
            session_id, user_id, token_hash, csrf_token,
            ip_address, user_agent, created_at, expires_at, revoked
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (
            session_id,
            user_id,
            token_hash,
            csrf_token,
            ip_address,
            user_agent[:250],
            created_iso,
            expires_iso,
        ),
    )
    return {
        "session_id": session_id,
        "raw_token": raw_token,
        "csrf_token": csrf_token,
        "expires_at": expires_iso,
    }


def extract_token_from_request(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    cookie_token = request.cookies.get("resilix_session")
    if cookie_token:
        return cookie_token.strip()
    return None


def get_current_user(
    request: Request,
    db: DatabaseSession = Depends(get_db),
) -> dict[str, Any]:
    raw_token = extract_token_from_request(request)
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not raw_token:
        log_audit_event(
            db,
            actor_username="anonymous",
            actor_role="unauthenticated",
            action="UNAUTHORIZED_ACCESS_ATTEMPT",
            resource_type="ENDPOINT",
            resource_id=str(request.url.path),
            status_str="DENIED",
            ip_address=client_ip,
            details={"reason": "Missing authentication token or session cookie"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
        )

    token_hash = hash_session_token(raw_token)
    row = db.fetchone(
        """
        SELECT s.session_id, s.user_id, s.csrf_token, s.expires_at, s.revoked,
               u.username, u.full_name, u.role, u.is_active, u.last_login_at
        FROM user_sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
        """,
        (token_hash,),
    )
    if not row or row["revoked"] == 1 or row["is_active"] == 0:
        log_audit_event(
            db,
            actor_username="anonymous",
            actor_role="unauthenticated",
            action="INVALID_SESSION_TOKEN",
            resource_type="ENDPOINT",
            resource_id=str(request.url.path),
            status_str="DENIED",
            ip_address=client_ip,
            details={"reason": "Session revoked, invalid, or inactive user"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session. Please log in again.",
        )

    now_iso = utc_now_iso()
    if row["expires_at"] < now_iso:
        db.execute(
            "UPDATE user_sessions SET revoked = 1, revoked_at = ? WHERE session_id = ?",
            (now_iso, row["session_id"]),
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired. Please log in again.",
        )

    return {
        "id": row["user_id"],
        "username": row["username"],
        "full_name": row["full_name"],
        "role": row["role"],
        "last_login_at": row["last_login_at"],
        "session_id": row["session_id"],
        "csrf_token": row["csrf_token"],
    }


def require_admin(
    request: Request,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> dict[str, Any]:
    if current_user["role"] != "admin":
        client_ip = request.client.host if request.client else "127.0.0.1"
        log_audit_event(
            db,
            actor_username=current_user["username"],
            actor_role=current_user["role"],
            action="FORBIDDEN_ROLE_ACCESS",
            resource_type="ENDPOINT",
            resource_id=str(request.url.path),
            status_str="DENIED",
            ip_address=client_ip,
            details={"required_role": "admin", "actual_role": current_user["role"]},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator role required for this operation.",
        )
    return current_user
