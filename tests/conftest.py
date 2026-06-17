"""
Pytest configuration shared across the test suite.

Argus est Postgres-only depuis le switch 2026-05. La fixture ``db`` ouvre
une connexion à la DB Postgres configurée dans ``h4wk3y3.yaml`` (ou via
``ARGUS_TEST_POSTGRES_URL`` pour CI/staging), réinitialise les tables
entre chaque test via TRUNCATE, et retourne une instance ``ArgusDB``
prête à l'emploi.

Tests qui ont besoin d'un DSN brut (au lieu d'une instance ``ArgusDB``)
utilisent la fixture ``db_url`` ci-dessous, qui re-utilise le même
``pg_engine`` et expose le DSN avec password en clair.
"""
import os
import re
import sys
from pathlib import Path
from typing import Iterator, Optional

import pytest
import sqlalchemy as sa


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _read_bootstrap_pw(stdout: str) -> Optional[str]:
    """Extract the bootstrap super-admin password for test logins.

    The app deliberately no longer prints the password to stdout (it would
    leak to log aggregators); it prints only the path to the 0600 creds file.
    We parse that path and read the password from the file. Falls back to the
    legacy `password: X` stdout line for older runs.
    """
    m = re.search(r"credentials written to:\s*(\S+)", stdout)
    if m:
        try:
            txt = Path(m.group(1)).read_text()
            fm = re.search(r"password:\s*(\S+)", txt)
            if fm:
                return fm.group(1)
        except OSError:
            pass
    legacy = re.search(r"password:\s*(\S+)", stdout)
    return legacy.group(1) if legacy else None


# ──────────────────────────────────────────────────────────────
# Postgres-backed `db` fixture (production stack)
# ──────────────────────────────────────────────────────────────

ARGUS_TEST_POSTGRES_URL_ENV = "ARGUS_TEST_POSTGRES_URL"

# Tables to TRUNCATE between tests. Listed in FK-safe order even though
# `TRUNCATE ... CASCADE` would handle it — explicit is easier to debug
# than letting CASCADE silently nuke things.
_ARGUS_TABLES = (
    # FK order: targets references organisations (ON DELETE SET NULL), so
    # truncate targets first to avoid drag on cascade.
    "findings", "subdomains", "live_hosts", "scans",
    "dashboard_runs", "users", "audit_log",
    "targets", "organisations", "scan_artefacts",
)


def _pg_url() -> str:
    """Resolve the Postgres DSN tests should target.

    Priority:
      1. ARGUS_TEST_POSTGRES_URL env var (CI / explicit override).
      2. h4wk3y3.yaml general.db_url — same DSN as production.
      3. None → tests using the `db` fixture are skipped.

    Local dev runs a single Postgres DB (argus_main). The ``db`` fixture
    TRUNCATEs Argus tables, which would silently wipe a real scan if
    pytest is launched right after one. The session-scoped fixture
    ``_prod_data_guard`` (see below) refuses to proceed when the DB
    contains non-test data, unless ``ARGUS_TEST_USE_PROD_DB=1`` is set.
    """
    env = os.environ.get(ARGUS_TEST_POSTGRES_URL_ENV)
    if env:
        return env
    try:
        from core.config import ArgusConfig
        cfg = ArgusConfig()
        url = cfg.get("general", "db_url", default=None)
        if url and url.startswith("postgresql"):
            return url
    except Exception:
        pass
    return ""


@pytest.fixture(scope="session")
def pg_engine():
    """Session-wide Postgres engine. Creates the schema once, then every
    test re-uses it via the `db` fixture below which TRUNCATEs between
    cases. Skips the test if Postgres isn't reachable."""
    url = _pg_url()
    if not url:
        pytest.skip(f"no {ARGUS_TEST_POSTGRES_URL_ENV} configured "
                    "and h4wk3y3.yaml has no postgresql DSN")
    from core.db_engine import build_engine
    from core.orm import Base

    class _Cfg:
        def get(self, *keys, default=None):
            if keys == ("general", "db_url"):
                return url
            return default

    try:
        engine = build_engine(_Cfg())
        # Ensure schema is there — idempotent.
        Base.metadata.create_all(engine)
    except Exception as e:
        pytest.skip(f"Postgres at {url!r} unreachable: {e}")

    # ── Prod-data guard ───────────────────────────────────────
    # The `db` fixture TRUNCATEs every Argus table between tests. If real
    # scan data lives in this DB, that's the data getting wiped. Two layers
    # of protection:
    #   1. ARGUS_TEST_USE_PROD_DB=1  acknowledges that prod data exists.
    #   2. ARGUS_TEST_CONFIRM_WIPE=<exact_count> must echo back the
    #      current scan count — forces the operator to LOOK before wiping.
    # I (the assistant) burned through guard #1 three times in one session
    # because it's just a binary flag. The count-echo gate makes accidental
    # bypass much harder: you have to query the DB to know what to type.
    with engine.connect() as c:
        prod_scans    = c.execute(sa.text(
            "SELECT COUNT(*) FROM scans WHERE scan_id NOT LIKE 'test-%'"
        )).scalar() or 0
        prod_findings = c.execute(sa.text(
            "SELECT COUNT(*) FROM findings WHERE scan_id NOT LIKE 'test-%'"
        )).scalar() or 0
    if prod_scans > 0 or prod_findings > 0:
        bypass    = os.environ.get("ARGUS_TEST_USE_PROD_DB") == "1"
        echoed    = os.environ.get("ARGUS_TEST_CONFIRM_WIPE", "")
        msg = (
            f"⛔ refusing to run tests: {prod_scans} scan(s) + "
            f"{prod_findings} finding(s) in {url!r}. The `db` fixture "
            "TRUNCATEs these tables — that data would be wiped.\n\n"
            "Options:\n"
            "  • Inspect / archive:  jq '.' output/<domain>/findings.json\n"
            "  • Wipe deliberately:  psql -d argus_main -c \"TRUNCATE scans, "
            "findings, subdomains, live_hosts, targets, organisations "
            "RESTART IDENTITY CASCADE\"\n"
            f"  • Force tests:       ARGUS_TEST_USE_PROD_DB=1 "
            f"ARGUS_TEST_CONFIRM_WIPE={prod_scans} pytest tests/\n"
            "                       (echo the scan count above — proves you "
            "looked at the state).\n"
            "  • Restore later:     python scripts/restore_from_json.py <domain>"
        )
        if not bypass:
            engine.dispose()
            pytest.fail(msg)
        if echoed != str(prod_scans):
            engine.dispose()
            pytest.fail(
                f"⛔ ARGUS_TEST_USE_PROD_DB=1 set, but "
                f"ARGUS_TEST_CONFIRM_WIPE={echoed!r} != {prod_scans} "
                f"(current scan count).\n\n{msg}"
            )

    yield engine
    engine.dispose()


@pytest.fixture
def db(pg_engine):
    """ArgusDB bound to the session-wide Postgres engine. The fixture
    TRUNCATEs every Argus table before yielding so each test starts from
    a clean state. No filesystem artefacts."""
    from core.database import ArgusDB

    # Wipe before AND after so a crashing test doesn't leak state into the
    # next one. RESTART IDENTITY resets autoincrement counters; CASCADE
    # mirrors the FK-aware TRUNCATE intent even though we don't have real
    # FK constraints yet.
    def _truncate():
        with pg_engine.begin() as c:
            tables = ", ".join(_ARGUS_TABLES)
            c.execute(sa.text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))

    _truncate()
    inst = ArgusDB(engine=pg_engine)
    try:
        yield inst
    finally:
        try:
            inst.close()
        except Exception:
            pass
        _truncate()


# ──────────────────────────────────────────────────────────────
# `db_url` fixture (used by test_db_backends.py)
# ──────────────────────────────────────────────────────────────
# Argus est Postgres-only depuis le switch 2026-05 ; le slice SQLite a
# été retiré. Le fixture re-utilise le ``pg_engine`` session-wide et
# wipe les tables Argus entre tests.

@pytest.fixture
def db_url(pg_engine) -> Iterator[str]:
    """Per-test PG DSN. TRUNCATE before + after the test."""
    with pg_engine.begin() as c:
        tables = ", ".join(_ARGUS_TABLES)
        c.execute(sa.text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    # render_as_string(hide_password=False) — `str(engine.url)` redacts the
    # password to ``***`` which would silently break ``create_engine(url)``
    # on the receiving side.
    yield pg_engine.url.render_as_string(hide_password=False)
    with pg_engine.begin() as c:
        tables = ", ".join(_ARGUS_TABLES)
        c.execute(sa.text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
