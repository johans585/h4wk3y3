"""
Tests for the Alembic migration baseline.

Postgres-only depuis le switch 2026-05. ``alembic upgrade head`` est
exécuté contre la DB Postgres configurée (mêmes chemins de résolution
que la prod : env var ``ARGUS_DB_URL`` ou ``h4wk3y3.yaml``). Le schéma
est wipé avant chaque test pour repartir d'une DB vide.
"""
import os
import sys
import subprocess
from pathlib import Path

import pytest
import sqlalchemy as sa

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

ALEMBIC_BIN = ROOT / "argus-env" / "bin" / "alembic"

# We avoid the conftest `pg_engine` fixture here because we want to test
# that ``alembic upgrade head`` itself creates the schema — not assume
# ``Base.metadata.create_all`` already did. Instead we DROP SCHEMA before
# each test and let Alembic rebuild it from scratch.


def _has_alembic() -> bool:
    return ALEMBIC_BIN.exists()


pytestmark = pytest.mark.skipif(
    not _has_alembic(),
    reason="alembic CLI not present in argus-env (install requirements.txt)",
)


def _pg_url() -> str:
    """Resolve the PG DSN tests should target — same priority list as
    conftest.py."""
    env = os.environ.get("ARGUS_TEST_POSTGRES_URL") or os.environ.get("ARGUS_DB_URL")
    if env:
        return env
    try:
        from core.config import ArgusConfig
        cfg = ArgusConfig()
        url = cfg.get("general", "db_url", default=None)
        if url and str(url).startswith("postgresql"):
            return str(url)
    except Exception:
        pass
    return ""


def _run_alembic(args, url):
    env = os.environ.copy()
    env["ARGUS_DB_URL"] = url
    return subprocess.run(
        [str(ALEMBIC_BIN), *args],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _reset_pg_schema(url: str) -> None:
    """DROP + CREATE SCHEMA public so Alembic starts on a blank slate."""
    eng = sa.create_engine(url)
    with eng.begin() as c:
        c.execute(sa.text("DROP SCHEMA public CASCADE"))
        c.execute(sa.text("CREATE SCHEMA public"))
    eng.dispose()


@pytest.fixture
def pg_url():
    url = _pg_url()
    if not url:
        pytest.skip("no Postgres DSN configured (ARGUS_DB_URL or h4wk3y3.yaml)")
    try:
        eng = sa.create_engine(url)
        with eng.connect() as c:
            c.execute(sa.text("SELECT 1"))
        eng.dispose()
    except Exception as e:
        pytest.skip(f"Postgres at {url!r} unreachable: {e}")
    _reset_pg_schema(url)
    yield url
    # Restore the standard schema for the rest of the session — the
    # conftest pg_engine fixture relies on tables existing.
    # IMPORTANT: rebuild via `alembic upgrade head` (not Base.metadata.create_all)
    # so that the alembic_version table is restored AND the FK constraints get
    # the same names as production. Otherwise the next test session inherits a
    # schema where alembic_version is missing and FKs use auto-generated names.
    r = _run_alembic(["upgrade", "head"], url)
    if r.returncode != 0:
        # Fallback: if Alembic somehow fails (corrupt migration script, etc.)
        # we still want the test session to be usable — recreate via ORM.
        eng = sa.create_engine(url)
        from core.orm import Base
        Base.metadata.create_all(eng)
        eng.dispose()


class TestAlembicBaseline:
    def test_upgrade_head_creates_full_schema(self, pg_url):
        r = _run_alembic(["upgrade", "head"], pg_url)
        assert r.returncode == 0, (
            f"alembic upgrade head failed:\nstdout:{r.stdout}\nstderr:{r.stderr}"
        )

        eng = sa.create_engine(pg_url)
        insp = sa.inspect(eng)
        tables = set(insp.get_table_names())
        # 7 tables + alembic_version
        assert {"scans", "subdomains", "live_hosts", "findings",
                "dashboard_runs", "users", "audit_log",
                "alembic_version"} <= tables
        eng.dispose()

    def test_migration_matches_orm_metadata(self, pg_url):
        """Alembic-built schema must match ``Base.metadata.create_all``.

        Guards against drift between the migration file
        (``alembic/versions/0001_baseline.py``) and the declarative ORM
        definitions in ``core/orm.py``.
        """
        # Apply Alembic to one schema (we already reset to public above).
        r = _run_alembic(["upgrade", "head"], pg_url)
        assert r.returncode == 0, r.stderr

        # Build a fresh in-memory comparison by reflecting both into
        # SQLAlchemy metadata objects.
        from core.orm import Base
        eng = sa.create_engine(pg_url)
        reflected = sa.MetaData()
        reflected.reflect(bind=eng, only=[
            "scans", "subdomains", "live_hosts", "findings",
            "dashboard_runs", "users", "audit_log",
        ])

        for table_name in reflected.tables:
            ref_cols = {c.name for c in reflected.tables[table_name].columns}
            orm_cols = {c.name for c in Base.metadata.tables[table_name].columns}
            assert ref_cols == orm_cols, (
                f"drift on {table_name}: "
                f"alembic_only={ref_cols - orm_cols} "
                f"orm_only={orm_cols - ref_cols}"
            )
        eng.dispose()

    def test_stamp_marks_version(self, pg_url):
        """``alembic stamp 0001`` on a fresh schema records the revision."""
        r = _run_alembic(["stamp", "0001"], pg_url)
        assert r.returncode == 0, r.stderr

        eng = sa.create_engine(pg_url)
        with eng.connect() as c:
            v = c.execute(sa.text(
                "SELECT version_num FROM alembic_version"
            )).scalar()
        assert v == "0001"
        eng.dispose()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
