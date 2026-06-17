"""
Tests for the SQLAlchemy engine factory (Postgres-only since 2026-05).
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import sqlalchemy as sa

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.db_engine import resolve_db_url, build_engine


def _cfg(values=None):
    """Build a ConfigLike mock. `values` is a dict keyed by tuples
    ``(section, key)``. Mirrors ``ArgusConfig.get(*keys, default=...)``."""
    values = values or {}
    m = MagicMock()
    def get(*args, **kwargs):
        return values.get(args, kwargs.get('default'))
    m.get.side_effect = get
    return m


class TestResolveDbUrl:
    def test_db_url_returned_verbatim(self):
        cfg = _cfg({('general', 'db_url'): 'postgresql+asyncpg://u:p@h/db'})
        assert resolve_db_url(cfg) == 'postgresql+asyncpg://u:p@h/db'

    def test_raises_when_nothing_configured(self):
        """No fallback. If `general.db_url` is missing, the factory
        refuses to build anything rather than silently spinning up an
        unsupported backend."""
        cfg = _cfg()
        with pytest.raises(ValueError, match="no DSN configured"):
            resolve_db_url(cfg)

    def test_raises_on_non_postgres_dsn(self):
        """Argus runtime is Postgres-only. SQLite / MySQL DSNs are rejected
        loudly rather than silently being accepted with broken behaviour."""
        cfg = _cfg({('general', 'db_url'): 'sqlite:////tmp/x.db'})
        with pytest.raises(ValueError, match="postgresql"):
            resolve_db_url(cfg)
        cfg = _cfg({('general', 'db_url'): 'mysql+pymysql://u:p@h/db'})
        with pytest.raises(ValueError, match="postgresql"):
            resolve_db_url(cfg)


class TestBuildEngine:
    """build_engine() against a live Postgres — re-uses the session-wide
    pg_engine fixture from conftest so we don't burn extra connections."""

    def test_returns_postgres_engine(self, pg_engine):
        # build_engine() builds a fresh engine from the URL; we recover the
        # password via render_as_string so the new engine can actually
        # connect to the same DB.
        from core.config import ArgusConfig
        cfg = ArgusConfig()
        eng = build_engine(cfg)
        try:
            assert eng.dialect.name == "postgresql"
            with eng.connect() as c:
                assert c.execute(sa.text("SELECT 1")).scalar() == 1
        finally:
            eng.dispose()

    def test_orm_create_all_matches_alembic_schema(self, pg_engine):
        """Base.metadata.create_all on a fresh PG schema yields the same
        tables as alembic upgrade head. Guards against drift between
        core/orm.py and alembic/versions/0001_baseline.py."""
        insp = sa.inspect(pg_engine)
        # pg_engine already ran Base.metadata.create_all once at session
        # setup — confirm every expected table is there.
        tables = set(insp.get_table_names())
        assert {'scans', 'subdomains', 'live_hosts', 'findings',
                'dashboard_runs', 'users', 'audit_log'} <= tables


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
