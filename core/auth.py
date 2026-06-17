"""
Argus V2 — Authentication & user management.

Roles:
  super-admin: full control (config, user mgmt, audit log read-all)
  admin:       launch/stop scans, read all results, change own password
  user:        read-only on results, change own password

Storage:
  - users table in argus.db (cf. core/database.py _init_schema)
  - data/.session_secret : 64 bytes random, generated at first boot
  - data/.first_admin    : credentials of the bootstrap super-admin (single
                           write at first boot, file-mode 0600)

This module is consumed by:
  - dashboard/backend/auth_routes.py    (login / logout / me)
  - dashboard/backend/users_routes.py   (CRUD users — super-admin only)
  - h4wk3y3.py 'user' subcommand          (CLI mgmt)
"""

from __future__ import annotations

import os
import hmac
import json
import secrets
import string
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import bcrypt
import sqlalchemy as sa
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired

from core import orm


VALID_ROLES = ("super-admin", "admin", "user")
SESSION_MAX_AGE_SECONDS = 8 * 3600  # 8h sliding window
BCRYPT_COST = 12


# ───────────────────────────────────────────────────────────────
# Password hashing
# ───────────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """bcrypt hash, returned as utf-8 string for the Postgres TEXT column."""
    if not plain:
        raise ValueError("password cannot be empty")
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(BCRYPT_COST)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time bcrypt verify. Returns False on any error."""
    if not plain or not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ───────────────────────────────────────────────────────────────
# Session secret + cookie signing
# ───────────────────────────────────────────────────────────────

def _session_secret_path(db_path: str) -> Path:
    """Co-locate session secret with the data/ dir (same parent as
    .first_admin). Even with Postgres-backed runtime, .session_secret
    stays a local file so it persists across DB resets."""
    return Path(db_path).parent / ".session_secret"


def get_or_create_session_secret(db_path: str) -> bytes:
    """Read or generate the session signing secret. 64 bytes urandom.
    File mode 0600 so only the running user can read it."""
    p = _session_secret_path(db_path)
    if p.exists():
        return p.read_bytes()
    p.parent.mkdir(parents=True, exist_ok=True)
    secret = os.urandom(64)
    p.write_bytes(secret)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return secret


def sign_session(secret: bytes, payload: Dict[str, Any]) -> str:
    """Sign a session payload (typically {'u': username}). Returns a
    base64-url string suitable for a cookie value."""
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signer = TimestampSigner(secret)
    return signer.sign(raw).decode("utf-8")


def verify_session(secret: bytes, token: str,
                   max_age: int = SESSION_MAX_AGE_SECONDS) -> Optional[Dict[str, Any]]:
    """Verify a session cookie. Returns payload dict if valid + fresh,
    None on bad signature / expired / malformed."""
    if not token:
        return None
    signer = TimestampSigner(secret)
    try:
        raw = signer.unsign(token.encode("utf-8"), max_age=max_age)
        return json.loads(raw)
    except (BadSignature, SignatureExpired, ValueError, TypeError):
        return None


# ───────────────────────────────────────────────────────────────
# CSRF tokens (Étape 1.5)
# ───────────────────────────────────────────────────────────────
# Double-submit-cookie style: the server signs `(salt, username)` with a
# secret derived from `session_secret` and ships it via /api/auth/csrf-token.
# The browser echoes it back on every state-changing request as the
# `X-CSRF-Token` header. The signature binds the token to a specific
# session_secret instance and a specific username, so:
#   * a stolen token from one user can't be replayed for another user
#   * regenerating session_secret invalidates every issued CSRF token
# We deliberately do NOT bake the session token itself into the CSRF
# token — that would require re-issuing CSRF on every session renewal.

CSRF_MAX_AGE_SECONDS = SESSION_MAX_AGE_SECONDS  # same lifetime as session


def _csrf_signer(session_secret: bytes) -> TimestampSigner:
    """Dedicated signer namespace so CSRF and session tokens cannot be
    swapped accidentally — `itsdangerous` includes the salt in the HMAC."""
    return TimestampSigner(session_secret, salt="argus-csrf")


def make_csrf_token(session_secret: bytes, username: str) -> str:
    """Build a fresh CSRF token bound to `username`.

    The token is opaque (signed + timestamped) and safe to expose in HTML
    or in a JSON response. Repeat calls produce different tokens (timestamp
    differs) but all remain valid until `CSRF_MAX_AGE_SECONDS`.
    """
    if not username:
        raise ValueError("username is required to mint a CSRF token")
    return _csrf_signer(session_secret).sign(
        username.encode("utf-8")
    ).decode("utf-8")


def verify_csrf_token(session_secret: bytes, token: str,
                      username: str,
                      max_age: int = CSRF_MAX_AGE_SECONDS) -> bool:
    """True iff `token` is a valid CSRF token for `username` and still fresh."""
    if not token or not username:
        return False
    try:
        raw = _csrf_signer(session_secret).unsign(
            token.encode("utf-8"), max_age=max_age
        )
        # Constant-time compare by rigour (the HMAC is already verified by
        # unsign() above, so impact is minimal — but cheap to do right).
        return hmac.compare_digest(raw, username.encode("utf-8"))
    except (BadSignature, SignatureExpired, ValueError, TypeError):
        return False


# ───────────────────────────────────────────────────────────────
# User CRUD
# ───────────────────────────────────────────────────────────────

_USERS = orm.User.__table__


def get_user(db, username: str) -> Optional[dict]:
    """Return user row as dict, or None if missing."""
    with db.engine.connect() as c:
        row = c.execute(
            sa.select(
                _USERS.c.username, _USERS.c.password_hash, _USERS.c.role,
                _USERS.c.enabled, _USERS.c.created_at, _USERS.c.last_login,
            ).where(_USERS.c.username == username)
        ).first()
    return dict(row._mapping) if row else None


def list_users(db) -> List[dict]:
    with db.engine.connect() as c:
        rows = c.execute(
            sa.select(
                _USERS.c.username, _USERS.c.role, _USERS.c.enabled,
                _USERS.c.created_at, _USERS.c.last_login,
            ).order_by(_USERS.c.created_at)
        )
        return [dict(r._mapping) for r in rows]


def create_user(db, username: str, password: str, role: str) -> None:
    if role not in VALID_ROLES:
        raise ValueError(f"invalid role: {role!r}, expected one of {VALID_ROLES}")
    if not username or not username.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise ValueError("username must be alphanumeric (with - _ . allowed)")
    if get_user(db, username) is not None:
        raise ValueError(f"user {username!r} already exists")
    with db.engine.begin() as c:
        c.execute(sa.insert(_USERS).values(
            username=username,
            password_hash=hash_password(password),
            role=role,
            enabled=1,
            created_at=datetime.now(timezone.utc).isoformat(),
        ))


def set_password(db, username: str, new_password: str) -> None:
    if get_user(db, username) is None:
        raise ValueError(f"user {username!r} does not exist")
    with db.engine.begin() as c:
        c.execute(sa.update(_USERS).where(_USERS.c.username == username)
                    .values(password_hash=hash_password(new_password)))


def set_role(db, username: str, new_role: str) -> None:
    if new_role not in VALID_ROLES:
        raise ValueError(f"invalid role: {new_role!r}")
    if get_user(db, username) is None:
        raise ValueError(f"user {username!r} does not exist")
    with db.engine.begin() as c:
        c.execute(sa.update(_USERS).where(_USERS.c.username == username)
                    .values(role=new_role))


def set_enabled(db, username: str, enabled: bool) -> None:
    if get_user(db, username) is None:
        raise ValueError(f"user {username!r} does not exist")
    with db.engine.begin() as c:
        c.execute(sa.update(_USERS).where(_USERS.c.username == username)
                    .values(enabled=(1 if enabled else 0)))


def touch_last_login(db, username: str) -> None:
    with db.engine.begin() as c:
        c.execute(sa.update(_USERS).where(_USERS.c.username == username)
                    .values(last_login=datetime.now(timezone.utc).isoformat()))


# ───────────────────────────────────────────────────────────────
# Authentication
# ───────────────────────────────────────────────────────────────

def authenticate(db, username: str, password: str) -> Optional[dict]:
    """Return user dict if (username, password) match an ENABLED user,
    None otherwise. Use this from the login endpoint. Caller is
    responsible for audit logging the success / failure."""
    user = get_user(db, username)
    if not user or not user.get("enabled"):
        # constant-time-ish: still hash a dummy to mitigate user enumeration
        verify_password(password, "$2b$12$" + "x" * 53)
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


# ───────────────────────────────────────────────────────────────
# Bootstrap: ensure at least one super-admin exists
# ───────────────────────────────────────────────────────────────

def _gen_random_password(length: int = 16) -> str:
    """URL-safe random password, no ambiguous chars (0/O/l/1)."""
    alphabet = (string.ascii_letters + string.digits).translate(
        str.maketrans("", "", "0Ol1I")
    )
    return "".join(secrets.choice(alphabet) for _ in range(length))


def ensure_super_admin_bootstrap(db, db_path: str) -> Optional[Dict[str, str]]:
    """Run at app startup. If the users table is empty, create a
    super-admin with a random password and write the credentials to
    `data/.first_admin` (mode 0600). Returns the created credentials dict
    or None if a super-admin already exists.

    The .first_admin file is the only readable copy of the password —
    delete it after first login (or rotate the password)."""
    with db.engine.connect() as c:
        count = c.execute(sa.select(sa.func.count()).select_from(_USERS)).scalar() or 0
    if count > 0:
        return None

    username = "admin"
    password = _gen_random_password(16)
    create_user(db, username, password, "super-admin")

    creds_path = Path(db_path).parent / ".first_admin"
    creds_path.parent.mkdir(parents=True, exist_ok=True)
    creds_path.write_text(
        f"# Argus bootstrap super-admin — created {datetime.now(timezone.utc).isoformat()}\n"
        f"# Delete this file after first login.\n"
        f"username: {username}\n"
        f"password: {password}\n"
    )
    try:
        os.chmod(creds_path, 0o600)
    except OSError:
        pass
    return {"username": username, "password": password, "creds_file": str(creds_path)}
