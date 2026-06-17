"""
Tests for Étape 1.5 — CSRF middleware + cookie hardening + rate-limit.

Each test boots a fresh FastAPI app with `create_app` (auth bootstrap
generates a random super-admin password we capture from stdout). All
mutating requests in this module go through raw `TestClient.request`
WITHOUT the CSRF-injection shim that `tests/test_api.py` patches in —
we want to exercise the protection directly.
"""
import io
import os
import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("DASHBOARD_HTTP_DEV", "1")

from core.config import ArgusConfig
from core.auth import (
    make_csrf_token, verify_csrf_token,
    get_or_create_session_secret,
)
from dashboard.backend.app import create_app
from tests.conftest import _read_bootstrap_pw


@pytest.fixture
def boot(tmp_path, db):
    """Fresh app + bootstrap admin password captured from stdout.

    The ``db`` fixture (from conftest) is Postgres-backed and truncated
    between tests, so the auth bootstrap always finds an empty users
    table and generates a fresh super-admin per test.
    """
    tmp_out = tmp_path / "output"; tmp_out.mkdir()
    cfg = ArgusConfig()
    cfg._data.setdefault("general", {})["output_dir"] = str(tmp_out)

    buf = io.StringIO()
    _orig, sys.stdout = sys.stdout, buf
    try:
        app = create_app(cfg, db)
    finally:
        sys.stdout = _orig
    pw = _read_bootstrap_pw(buf.getvalue())
    assert pw, "bootstrap admin not generated"

    client = TestClient(app)
    # 4th tuple element kept for back-compat: was the SQLite path used by
    # tests that mint CSRF tokens with the session_secret. Replaced by
    # ``str(db.db_path)`` which still points at ``./data/argus.db`` for the
    # session_secret co-location.
    yield client, pw, db, str(db.db_path)
    db.close()


def _login(client, pw):
    r = client.post("/api/auth/login",
                    data={"username": "admin", "password": pw})
    assert r.status_code == 200, r.text
    return r


# ──────────────────────────────────────────────────────────────
# CSRF token primitives (no HTTP) — fast smoke
# ──────────────────────────────────────────────────────────────

class TestCsrfPrimitives:
    def test_token_round_trips(self):
        secret = b"x" * 32
        t = make_csrf_token(secret, "alice")
        assert verify_csrf_token(secret, t, "alice") is True

    def test_token_bound_to_username(self):
        secret = b"x" * 32
        t = make_csrf_token(secret, "alice")
        assert verify_csrf_token(secret, t, "bob") is False

    def test_token_invalid_with_different_secret(self):
        t = make_csrf_token(b"x" * 32, "alice")
        assert verify_csrf_token(b"y" * 32, t, "alice") is False

    def test_empty_token_rejected(self):
        assert verify_csrf_token(b"x" * 32, "", "alice") is False

    def test_malformed_token_rejected(self):
        assert verify_csrf_token(b"x" * 32, "not-a-token", "alice") is False

    def test_empty_username_raises(self):
        with pytest.raises(ValueError):
            make_csrf_token(b"x" * 32, "")


# ──────────────────────────────────────────────────────────────
# End-to-end CSRF middleware behavior
# ──────────────────────────────────────────────────────────────

class TestCsrfMiddleware:
    def test_login_returns_csrf_token(self, boot):
        client, pw, *_ = boot
        r = _login(client, pw)
        body = r.json()
        assert "csrf_token" in body
        assert body["csrf_token"]

    def test_csrf_endpoint_requires_auth(self, boot):
        client, *_ = boot
        r = client.get("/api/auth/csrf-token")
        assert r.status_code == 401

    def test_csrf_endpoint_returns_token_for_authed_user(self, boot):
        client, pw, *_ = boot
        _login(client, pw)
        r = client.get("/api/auth/csrf-token")
        assert r.status_code == 200
        assert r.json().get("csrf_token")

    def test_mutating_request_rejected_without_token(self, boot):
        client, pw, *_ = boot
        _login(client, pw)
        # Logged in but no CSRF header → must 403.
        r = client.delete("/api/domains/never-existed.com")
        assert r.status_code == 403
        assert "csrf" in r.json().get("detail", "").lower()

    def test_mutating_request_accepted_with_token(self, boot):
        client, pw, *_ = boot
        login = _login(client, pw)
        tok = login.json()["csrf_token"]
        r = client.delete("/api/domains/never-existed.com",
                          headers={"X-CSRF-Token": tok})
        # Endpoint itself returns 200 for unknown domain (idempotent delete).
        assert r.status_code == 200

    def test_token_from_endpoint_works_too(self, boot):
        client, pw, *_ = boot
        _login(client, pw)
        # Discard the login-time token, fetch a fresh one from the endpoint.
        tok = client.get("/api/auth/csrf-token").json()["csrf_token"]
        r = client.delete("/api/domains/never-existed.com",
                          headers={"X-CSRF-Token": tok})
        assert r.status_code == 200

    def test_get_requests_not_csrf_gated(self, boot):
        client, pw, *_ = boot
        _login(client, pw)
        # GET on the same path the middleware protects for DELETE must NOT
        # require a CSRF token — read-only is not state-changing.
        r = client.get("/api/domains")
        assert r.status_code == 200

    def test_health_endpoint_exempt(self, boot):
        client, *_ = boot
        # Unauthenticated, no token, GET — must still work.
        r = client.get("/api/health")
        assert r.status_code == 200

    def test_token_from_another_user_rejected(self, boot, tmp_path):
        """A CSRF token minted for user A must not validate for user B
        (binding via signature on the username field)."""
        client, pw, _db, _path = boot
        _login(client, pw)
        # Mint a CSRF token bound to a different user, using the same secret.
        secret = get_or_create_session_secret(_path)
        evil_token = make_csrf_token(secret, "someone-else")
        r = client.delete("/api/domains/never-existed.com",
                          headers={"X-CSRF-Token": evil_token})
        assert r.status_code == 403


# ──────────────────────────────────────────────────────────────
# Cookie hardening
# ──────────────────────────────────────────────────────────────

class TestSessionCookie:
    def test_cookie_set_with_strict_samesite(self, boot):
        client, pw, *_ = boot
        r = _login(client, pw)
        sc = r.headers.get("set-cookie", "")
        assert "argus_session=" in sc
        assert "HttpOnly" in sc
        # SameSite=strict raised in Étape 1.5 (was Lax). Case-insensitive
        # because servers / clients differ on capitalisation.
        assert re.search(r"samesite=strict", sc, re.IGNORECASE), sc


# ──────────────────────────────────────────────────────────────
# Rate-limit (5 fails / 15 min)
# ──────────────────────────────────────────────────────────────

class TestLoginRateLimit:
    def test_window_is_15_minutes(self):
        # Plan says 5/15min. Guard against accidental regression to the
        # previous 60s window.
        from dashboard.backend.auth_routes import _LoginRateLimiter
        rl = _LoginRateLimiter()
        assert rl.WINDOW >= 14 * 60   # at least 14 min — some slack
        assert rl.MAX_ATTEMPTS == 5

    def test_five_failures_then_429(self, boot):
        client, *_ = boot
        # 5 wrong attempts → 401 each
        for _ in range(5):
            r = client.post("/api/auth/login",
                            data={"username": "admin", "password": "wrong"})
            assert r.status_code == 401
        # 6th → 429 (rate-limited, regardless of credentials)
        r = client.post("/api/auth/login",
                        data={"username": "admin", "password": "wrong"})
        assert r.status_code == 429

    def test_successful_login_resets_counter(self, boot):
        client, pw, *_ = boot
        # 4 failures
        for _ in range(4):
            client.post("/api/auth/login",
                        data={"username": "admin", "password": "wrong"})
        # Successful login → should reset
        r = client.post("/api/auth/login",
                        data={"username": "admin", "password": pw})
        assert r.status_code == 200
        # Now 5 more failures must again be needed before 429 — confirm by
        # checking that a 5th wrong attempt is still 401, not 429.
        for _ in range(4):
            client.post("/api/auth/login",
                        data={"username": "admin", "password": "wrong"})
        r = client.post("/api/auth/login",
                        data={"username": "admin", "password": "wrong"})
        # 5th post-reset → counter at 5, still 401 (the limiter checks
        # is_blocked BEFORE recording, so the 5th failure hits the route
        # then is recorded; the 6th is the one that 429s).
        assert r.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
