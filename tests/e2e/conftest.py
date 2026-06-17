"""
E2E fixtures: a live dashboard server + a Playwright Chromium page.

Design / safety
---------------
- Reuses the session-scoped ``pg_engine`` fixture from the top-level
  conftest, which already enforces the prod-data guard (won't run against a
  DB holding real scan data). So these tests are safe to run locally only
  against a throwaway DB, and run unconditionally in CI against the ephemeral
  Postgres service.
- The whole module **auto-skips** when Chromium can't launch (browser not
  installed, e.g. a CI job without `playwright install`) so it never turns the
  suite red for an environment reason — it only ever runs when it genuinely
  can.
- The server runs in a background thread (uvicorn) on an ephemeral port. The
  bootstrap admin password is read from the 0600 creds file via the shared
  ``_read_bootstrap_pw`` helper (the app no longer prints the password).
"""

from __future__ import annotations

import io
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest
import sqlalchemy as sa

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.conftest import _read_bootstrap_pw  # noqa: E402

pytestmark = pytest.mark.e2e


# ── Chromium availability gate ──────────────────────────────────────
def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            b.close()
        return True
    except Exception:
        return False


_CHROMIUM_OK = _chromium_available()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_server(pg_engine, tmp_path_factory):
    """Boot the dashboard against the (test) Postgres in a background thread.

    Yields ``(base_url, admin_password)``.
    """
    if not _CHROMIUM_OK:
        pytest.skip("Chromium not launchable (run `playwright install chromium`)")

    import uvicorn
    from core.config import ArgusConfig
    from core.database import ArgusDB
    from dashboard.backend.app import create_app

    # Fresh bootstrap: clear users so create_app() mints a known admin pw.
    with pg_engine.begin() as c:
        c.execute(sa.text("TRUNCATE users RESTART IDENTITY CASCADE"))

    out_dir = tmp_path_factory.mktemp("e2e_output")
    cfg = ArgusConfig()
    cfg._data.setdefault("general", {})["output_dir"] = str(out_dir)
    # Plain-HTTP cookie so the browser sends it back over http://127.0.0.1.
    os.environ["DASHBOARD_HTTP_DEV"] = "1"

    db = ArgusDB(engine=pg_engine)

    buf = io.StringIO()
    _stdout = sys.stdout
    sys.stdout = buf
    try:
        app = create_app(cfg, db)
    finally:
        sys.stdout = _stdout
    admin_pw = _read_bootstrap_pw(buf.getvalue())
    assert admin_pw, "bootstrap admin password not generated"

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port,
                            log_level="warning", loop="asyncio")
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None  # safe in a thread

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    # Wait for readiness.
    import urllib.request
    deadline = time.monotonic() + 20
    ready = False
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/api/health", timeout=2) as r:
                if r.status == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.2)
    if not ready:
        server.should_exit = True
        thread.join(timeout=5)
        pytest.fail("dashboard server did not become ready within 20s")

    yield base_url, admin_pw

    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
def page(live_server):
    """A fresh Playwright page (own context = own cookie jar) per test."""
    from playwright.sync_api import sync_playwright

    base_url, _pw = live_server
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(base_url=base_url)
        pg = context.new_page()
        try:
            yield pg
        finally:
            context.close()
            browser.close()
