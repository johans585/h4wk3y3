"""
Argus V2 — SQLAlchemy engine factory.

Argus est Postgres-only depuis le switch 2026-05. Cette factory produit
exclusivement des engines Postgres ; aucun fallback SQLite, aucune
détection multi-backend. Si le DSN est manquant ou n'est pas Postgres,
elle lève ``ValueError``.

Public API:
    resolve_db_url(config) -> str       # raises ValueError if missing/invalid
    build_engine(config, *, echo=False) -> sqlalchemy.Engine
"""
from __future__ import annotations

import os
from typing import Optional

from sqlalchemy import Engine, create_engine


def resolve_db_url(config) -> str:
    """Return the Postgres DSN to use.

    Precedence (12-factor friendly):
      1. ``ARGUS_DB_URL`` env var (highest — container / CI / staging override).
      2. ``general.db_url`` in ``h4wk3y3.yaml``.

    Raises ``ValueError`` if neither is set, or if the DSN doesn't look like
    a postgresql driver — Argus runtime is Postgres-only (since 2026-05),
    silently spinning up another backend would just mask the misconfiguration.

    Kept in sync with ``alembic/env.py`` which honours the same env var,
    so a single ``ARGUS_DB_URL`` line in the environment drives both the
    app runtime and ``alembic upgrade head``.
    """
    url = os.environ.get("ARGUS_DB_URL") or config.get("general", "db_url", default=None)
    if not url:
        raise ValueError(
            "no DSN configured: set ARGUS_DB_URL env var or `general.db_url` "
            "in h4wk3y3.yaml (e.g. postgresql+psycopg://argus:pw@host/argus_main)"
        )
    url = str(url)
    if not url.startswith("postgresql"):
        raise ValueError(
            f"unsupported DSN {url!r}: Argus runtime requires a postgresql "
            "driver (postgresql+psycopg or postgresql+asyncpg)"
        )
    return url


def build_engine(config, *, echo: bool = False,
                 connect_args: Optional[dict] = None) -> Engine:
    """Create the canonical Argus Postgres engine.

    `echo=True` flips SQLAlchemy SQL echoing — useful for ad-hoc debugging
    but never wired into runtime config.
    """
    url = resolve_db_url(config)
    return create_engine(url, echo=echo,
                         connect_args=dict(connect_args or {}),
                         future=True)
