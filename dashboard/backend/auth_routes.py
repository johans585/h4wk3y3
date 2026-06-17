"""
Argus V2 — Auth routes + middleware.

Wires up:
  - session-cookie-based authentication (HttpOnly, signed via itsdangerous)
  - a global HTTP middleware that gates every /api/* route by required role
  - explicit /api/auth/{login,logout,me,change-password} endpoints
  - a simple in-memory rate-limit on /api/auth/login (5 attempts / 60s / IP)

Role hierarchy (descending):
  super-admin  > admin  > user

Path → required role mapping (see _required_role) is the single source of
truth for authorization. Routes added later just need to land under one of
the prefixes covered there.

Everything here is wired by `install_auth(app, db, db_path)`.
"""

from __future__ import annotations

import time
from typing import Optional, Dict
from collections import defaultdict, deque

from fastapi import FastAPI, Request, HTTPException, Form, Body
from fastapi.responses import JSONResponse, RedirectResponse

from core.auth import (
    authenticate, get_or_create_session_secret, sign_session, verify_session,
    get_user, set_password, ensure_super_admin_bootstrap,
    make_csrf_token, verify_csrf_token,
    SESSION_MAX_AGE_SECONDS,
)
from core.audit import log_action, ACTIONS
from dashboard.backend.clientip import client_ip


COOKIE_NAME = "argus_session"
CSRF_HEADER = "X-CSRF-Token"

# Paths exempt from CSRF check. Login itself cannot have a token yet
# (no session); logout is idempotent and behind the session cookie;
# health is unauthenticated and read-only.
_CSRF_EXEMPT_PATHS = frozenset({
    "/api/auth/login",
    "/api/auth/logout",
    "/api/health",
})
_CSRF_PROTECTED_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})


# ────────────────────────────────────────────────────────────────
# Role hierarchy
# ────────────────────────────────────────────────────────────────

_ROLE_RANK = {"user": 1, "admin": 2, "super-admin": 3}


def _role_meets(actual: str, required: str) -> bool:
    """Return True iff `actual` has at least the rank of `required`."""
    return _ROLE_RANK.get(actual, 0) >= _ROLE_RANK.get(required, 99)


# ────────────────────────────────────────────────────────────────
# Path → required role mapping
# ────────────────────────────────────────────────────────────────

def _required_role(method: str, path: str) -> Optional[str]:
    """Return required role string for (method, path), or None if the
    route is public (no auth needed). Returning a role implies auth is
    required AND the user must hold at least that role."""
    # ── Public ─────────────────────────────────────────────────
    if path == "/":
        return None
    # The login page (and only the login page) is reachable without auth —
    # everything else under /ui/ requires at least 'user' role.
    if path == "/ui/login.html":
        return None
    if path == "/api/auth/login":
        return None
    # Liveness/readiness probe — must stay unauthenticated so Docker
    # HEALTHCHECK / k8s liveness probes / uptime monitors can call it.
    # The endpoint exposes only non-sensitive infra status (DB ping,
    # disk space, tool presence, scan counts — no domain/finding data).
    if path == "/api/health":
        return None
    # Favicon: browsers auto-request /favicon.ico on every page including
    # login. Keep it public (it's just a static SVG) to avoid 401/302 noise
    # in browser devtools and audit logs.
    if path == "/favicon.ico":
        return None

    # ── Frontend assets: any authenticated user ────────────────
    if path == "/ui" or path.startswith("/ui/"):
        return "user"

    # ── Authenticated user (any role) ──────────────────────────
    if path in ("/api/auth/me", "/api/auth/logout",
                "/api/auth/change-password", "/api/auth/csrf-token"):
        return "user"

    # ── Super-admin only ───────────────────────────────────────
    if path.startswith("/api/users"):
        return "super-admin"
    if path.startswith("/api/audit"):
        # GET /api/audit returns full log for super-admin, self only for admin.
        # The route handler itself filters by role; here we only enforce
        # that the caller is at least admin (admin to see own, super-admin
        # to see all).
        return "admin"
    if path == "/api/config" or path == "/api/config/reload":
        # Both read and write of the config are super-admin only — config
        # may contain webhook URLs / DNS resolver lists / wildcards that
        # are operational details we don't expose to admin/user roles.
        return "super-admin"

    # ── Admin (or super-admin) ─────────────────────────────────
    if path.startswith("/api/scan/start") or path.startswith("/api/scan/stop"):
        return "admin"
    if method == "DELETE" and path.startswith("/api/domains/"):
        return "admin"
    if method != "GET" and path.startswith("/api/orgs"):
        # Multi-org mutations are admin-level (Étape 2.1).
        return "admin"

    # ── Read-only (any authenticated) ──────────────────────────
    if method == "GET" and path.startswith("/api/"):
        return "user"

    # ── Default deny on unknown writes ─────────────────────────
    if path.startswith("/api/"):
        return "super-admin"

    return None  # static / other


# ────────────────────────────────────────────────────────────────
# Rate limiter (in-memory, login only)
# ────────────────────────────────────────────────────────────────

class _LoginRateLimiter:
    """5 failed attempts / 15 min / IP → 429 for 15 min (Étape 1.5).

    The 15-minute window is mandated by the improvement plan to make
    credential stuffing materially harder while still letting an honest
    user retry after a forgotten password break. Memory cost is bounded
    by the eviction sweep in `_evict`.
    """
    WINDOW = 15 * 60.0   # 15 minutes
    MAX_ATTEMPTS = 5

    def __init__(self):
        self._failures: Dict[str, deque] = defaultdict(deque)

    def _evict(self, ip: str, now: float):
        q = self._failures[ip]
        while q and q[0] < now - self.WINDOW:
            q.popleft()

    def is_blocked(self, ip: str) -> bool:
        now = time.time()
        self._evict(ip, now)
        return len(self._failures[ip]) >= self.MAX_ATTEMPTS

    def record_failure(self, ip: str):
        now = time.time()
        self._evict(ip, now)
        self._failures[ip].append(now)

    def reset(self, ip: str):
        self._failures.pop(ip, None)


# ────────────────────────────────────────────────────────────────
# Public installer
# ────────────────────────────────────────────────────────────────

def install_auth(app: FastAPI, db, db_path: str) -> None:
    """Wire auth into the FastAPI app. Call once from create_app(),
    AFTER the routes are registered so the middleware sees them all."""

    # ── 1. Bootstrap session secret + super-admin if needed ────
    session_secret = get_or_create_session_secret(db_path)
    boot = ensure_super_admin_bootstrap(db, db_path)
    if boot:
        # First-boot banner — visible in container logs. The PASSWORD is
        # deliberately NOT printed: stdout often ends up in a log aggregator
        # (Docker/journald/k8s) where it would leak the super-admin secret.
        # The password lives only in the 0600 creds file below.
        print(
            f"\n{'='*60}\n"
            f"  Argus auth bootstrap — initial super-admin created\n"
            f"  username: {boot['username']}\n"
            f"  credentials written to: {boot['creds_file']}\n"
            f"  → read the file, log in, change the password, delete the file.\n"
            f"{'='*60}\n",
            flush=True,
        )

    rate_limiter = _LoginRateLimiter()

    # ── 2. Global middleware: parse cookie, gate by role, check CSRF ──
    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        method = request.method
        path = request.url.path
        required = _required_role(method, path)

        if required is None:
            # Public route — still attach user info if cookie is valid
            # (so e.g. /ui/ can render username from /api/auth/me without
            # breaking when not logged in).
            request.state.user = _user_from_cookie(request, db, session_secret)
            return await call_next(request)

        user = _user_from_cookie(request, db, session_secret)
        if not user:
            # Browser navigation to a protected /ui/* page → redirect to
            # the login form instead of returning a JSON 401 (which would
            # show the user a raw error page).
            if path.startswith("/ui/") or path == "/ui":
                return RedirectResponse("/ui/login.html", status_code=302)
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        if not _role_meets(user["role"], required):
            # Same idea for forbidden navigation (admin trying /users in
            # browser): land them on the dashboard with a JSON 403 only
            # for API calls.
            if path.startswith("/ui/"):
                return RedirectResponse("/ui/", status_code=302)
            return JSONResponse(
                {"detail": f"role '{required}' required, got '{user['role']}'"},
                status_code=403
            )

        # CSRF gate for state-changing API calls (Étape 1.5). Static UI
        # assets and read-only GETs are exempt. Login/logout/health are
        # exempted in _CSRF_EXEMPT_PATHS for the reasons documented there.
        if (method in _CSRF_PROTECTED_METHODS
                and path.startswith("/api/")
                and path not in _CSRF_EXEMPT_PATHS):
            csrf = request.headers.get(CSRF_HEADER, "")
            if not verify_csrf_token(session_secret, csrf, user["username"]):
                log_action(db, user["username"], _client_ip(request),
                           ACTIONS.LOGIN_FAILURE,
                           target=path,
                           details={"reason": "csrf-missing-or-invalid",
                                    "method": method})
                return JSONResponse(
                    {"detail": "CSRF token missing or invalid"},
                    status_code=403,
                )

        request.state.user = user
        return await call_next(request)

    # ── 3. Routes ──────────────────────────────────────────────

    @app.post("/api/auth/login")
    def login(request: Request,
              username: str = Form(...),
              password: str = Form(...)):
        ip = _client_ip(request)
        if rate_limiter.is_blocked(ip):
            log_action(db, None, ip, ACTIONS.LOGIN_FAILURE,
                       target=username, details={"reason": "rate-limited"})
            raise HTTPException(429, "too many login attempts, try again in 60s")

        user = authenticate(db, username, password)
        if not user:
            rate_limiter.record_failure(ip)
            log_action(db, None, ip, ACTIONS.LOGIN_FAILURE, target=username)
            raise HTTPException(401, "invalid credentials")

        rate_limiter.reset(ip)
        token = sign_session(session_secret, {"u": user["username"]})
        log_action(db, user["username"], ip, ACTIONS.LOGIN_SUCCESS)
        # Touch last_login
        from core.auth import touch_last_login
        touch_last_login(db, user["username"])

        # Issue both the session token (cookie) and a CSRF token (body)
        # in the same response so the SPA doesn't have to round-trip to
        # /api/auth/csrf-token immediately after login.
        csrf = make_csrf_token(session_secret, user["username"])
        resp = JSONResponse({
            "username":   user["username"],
            "role":       user["role"],
            "csrf_token": csrf,
        })
        # Secure-by-default. Opt out only for plain-HTTP local dev with
        # DASHBOARD_HTTP_DEV=1 — leaks of the session cookie over plain
        # HTTP have caused too many incidents to make insecure the default.
        # SameSite=strict (Étape 1.5): the cookie is never sent on
        # cross-site requests, even top-level navigation. Combined with
        # the CSRF header check below, defense-in-depth against forged
        # requests originating from third-party sites.
        import os
        http_dev = os.environ.get("DASHBOARD_HTTP_DEV", "").lower() in ("1", "true", "yes")
        secure = not http_dev
        resp.set_cookie(
            COOKIE_NAME, token,
            httponly=True,
            secure=secure,
            samesite="strict",
            max_age=SESSION_MAX_AGE_SECONDS,
            path="/",
        )
        return resp

    @app.post("/api/auth/logout")
    def logout(request: Request):
        u = getattr(request.state, "user", None)
        if u:
            log_action(db, u["username"], _client_ip(request), ACTIONS.LOGOUT)
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE_NAME, path="/")
        return resp

    @app.get("/api/auth/me")
    def me(request: Request):
        u = request.state.user
        return {
            "username": u["username"],
            "role": u["role"],
            "enabled": bool(u.get("enabled", 1)),
            "last_login": u.get("last_login"),
        }

    @app.get("/api/auth/csrf-token")
    def csrf_token(request: Request):
        """Return a fresh CSRF token bound to the current session.

        The SPA fetches this on boot (and on 403 'CSRF missing or invalid'
        retries) and echoes the value on every state-changing request via
        the `X-CSRF-Token` header. The token is itself signed with the
        session secret + bound to the username, so it can't be forged or
        replayed across accounts.
        """
        u = request.state.user
        return {"csrf_token": make_csrf_token(session_secret, u["username"])}

    @app.post("/api/auth/change-password")
    def change_password(request: Request, payload: dict = Body(...)):
        u = request.state.user
        old = (payload or {}).get("old_password", "")
        new = (payload or {}).get("new_password", "")
        if not new or len(new) < 8:
            raise HTTPException(400, "new_password must be at least 8 chars")
        # Verify old
        if not authenticate(db, u["username"], old):
            log_action(db, u["username"], _client_ip(request),
                       ACTIONS.LOGIN_FAILURE,
                       target=u["username"],
                       details={"context": "change-password old_password mismatch"})
            raise HTTPException(401, "old_password is incorrect")
        set_password(db, u["username"], new)
        log_action(db, u["username"], _client_ip(request),
                   ACTIONS.PASSWORD_CHANGED_SELF)
        return {"ok": True}


# ────────────────────────────────────────────────────────────────
# Helpers used by other route modules (Depends())
# ────────────────────────────────────────────────────────────────

def current_user(request: Request) -> dict:
    """FastAPI dependency: returns the authenticated user dict, or 401."""
    u = getattr(request.state, "user", None)
    if not u:
        raise HTTPException(401, "authentication required")
    return u


def require_role(required: str):
    """FastAPI dependency factory enforcing a minimum role."""
    def _dep(request: Request) -> dict:
        u = current_user(request)
        if not _role_meets(u["role"], required):
            raise HTTPException(403, f"role '{required}' required")
        return u
    return _dep


# ────────────────────────────────────────────────────────────────
# Internals
# ────────────────────────────────────────────────────────────────

def _client_ip(request: Request) -> str:
    # Trusted-proxy-aware client IP (see dashboard.backend.clientip). XFF is
    # honoured only behind a configured trusted proxy, otherwise the direct
    # peer is authoritative — closes the rate-limit bypass + audit spoof.
    return client_ip(request)


def _user_from_cookie(request: Request, db, session_secret: bytes) -> Optional[dict]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    payload = verify_session(session_secret, token)
    if not payload:
        return None
    username = payload.get("u")
    if not username:
        return None
    user = get_user(db, username)
    if not user or not user.get("enabled"):
        return None
    return user
