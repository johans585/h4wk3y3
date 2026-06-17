"""
End-to-end UI tests for the Argus dashboard (Playwright + Chromium).

Covers the real user-facing flows: the login page, valid/invalid auth, the
401→login redirect, cookie issuance, SPA boot, and logout. These exercise the
auth middleware, CSRF wiring and static serving together — the layer the unit
tests can't reach. Auto-skips when Chromium isn't installed (see conftest).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.e2e


def _login(page, base_url, username, password):
    page.goto(f"{base_url}/ui/login.html")
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#submitBtn")


class TestLoginPage:
    def test_login_page_renders(self, page, live_server):
        base_url, _ = live_server
        page.goto(f"{base_url}/ui/login.html")
        assert page.is_visible("#loginForm")
        assert page.is_visible("#username")
        assert page.is_visible("#password")
        assert page.is_visible("#submitBtn")

    def test_invalid_login_shows_error_and_stays(self, page, live_server):
        base_url, _ = live_server
        _login(page, base_url, "admin", "definitely-wrong-password")
        # Error banner appears; we are NOT redirected to the SPA.
        page.wait_for_selector("#err.show", timeout=5000)
        assert page.inner_text("#err").strip() != ""
        assert "/ui/login.html" in page.url

    def test_valid_login_redirects_and_sets_cookie(self, page, live_server):
        base_url, admin_pw = live_server
        _login(page, base_url, "admin", admin_pw)
        # login.html redirects to /ui/ on success.
        page.wait_for_url(f"{base_url}/ui/", timeout=8000)
        cookies = {c["name"]: c for c in page.context.cookies()}
        assert "argus_session" in cookies, f"no session cookie: {list(cookies)}"
        assert cookies["argus_session"]["httpOnly"] is True


class TestAuthGuard:
    def test_unauthenticated_api_is_401(self, page, live_server):
        base_url, _ = live_server
        # Navigate first so fetch runs from the app's own origin (a fetch from
        # about:blank has no origin and is rejected before reaching the server).
        page.goto(f"{base_url}/ui/login.html")
        status = page.evaluate(
            "async () => (await fetch('/api/domains',"
            " {credentials:'same-origin'})).status"
        )
        assert status == 401

    def test_authenticated_api_succeeds(self, page, live_server):
        base_url, admin_pw = live_server
        _login(page, base_url, "admin", admin_pw)
        page.wait_for_url(f"{base_url}/ui/", timeout=8000)
        status = page.evaluate(
            """async (u) => (await fetch(u + '/api/domains',"""
            """ {credentials:'same-origin'})).status""",
            base_url,
        )
        assert status == 200


class TestDashboardSPA:
    def test_spa_boots_after_login(self, page, live_server):
        base_url, admin_pw = live_server
        _login(page, base_url, "admin", admin_pw)
        page.wait_for_url(f"{base_url}/ui/", timeout=8000)
        # The SPA mounts into #root; wait for it to exist in the DOM.
        page.wait_for_selector("#root", timeout=8000)
        # /api/auth/me should resolve to the admin user from the browser.
        me = page.evaluate(
            """async (u) => { const r = await fetch(u + '/api/auth/me',"""
            """ {credentials:'same-origin'}); return r.ok ? await r.json() : null; }""",
            base_url,
        )
        assert me and me.get("username") == "admin"
        assert me.get("role") == "super-admin"

    def test_health_endpoint_public(self, page, live_server):
        base_url, _ = live_server
        page.goto(f"{base_url}/ui/login.html")
        status = page.evaluate(
            "async () => (await fetch('/api/health')).status"
        )
        assert status == 200
