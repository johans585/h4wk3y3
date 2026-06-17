"""
Argus V2 — Audit log helpers.

Sensitive actions are persisted to the `audit_log` table for traceability:
who did what, from where, when. Reads are exposed via /api/audit
(super-admin sees everything, admin sees only their own entries).

Usage:
    from core.audit import log_action, ACTIONS
    log_action(db, username='alice', ip='10.0.0.5',
               action=ACTIONS.SCAN_STARTED,
               target='example.com',
               details={'mode': 'full', 'modules': ['m02', 'm03']})
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import sqlalchemy as sa

from core import orm

_AUDIT = orm.AuditLog.__table__


# ───────────────────────────────────────────────────────────────
# Action catalogue (use constants instead of strings to avoid typos)
# ───────────────────────────────────────────────────────────────

class ACTIONS:
    # Auth
    LOGIN_SUCCESS          = "LOGIN_SUCCESS"
    LOGIN_FAILURE          = "LOGIN_FAILURE"
    LOGOUT                 = "LOGOUT"
    PASSWORD_CHANGED_SELF  = "PASSWORD_CHANGED_SELF"
    # User management (super-admin only)
    USER_CREATED           = "USER_CREATED"
    USER_DISABLED          = "USER_DISABLED"
    USER_ENABLED           = "USER_ENABLED"
    USER_ROLE_CHANGED      = "USER_ROLE_CHANGED"
    USER_PASSWORD_RESET    = "USER_PASSWORD_RESET"   # super-admin reset for someone else
    # Scans
    SCAN_STARTED           = "SCAN_STARTED"
    SCAN_STOPPED           = "SCAN_STOPPED"
    # Config / wildcards (super-admin only)
    CONFIG_UPDATED         = "CONFIG_UPDATED"
    CONFIG_RELOADED        = "CONFIG_RELOADED"
    WILDCARDS_UPDATED      = "WILDCARDS_UPDATED"
    # Findings
    FINDING_DELETED        = "FINDING_DELETED"


# ───────────────────────────────────────────────────────────────
# Write
# ───────────────────────────────────────────────────────────────

def log_action(db,
               username: Optional[str],
               ip: Optional[str],
               action: str,
               target: Optional[str] = None,
               details: Optional[Dict[str, Any]] = None) -> None:
    """Insert one audit row. `username` may be None for unauthenticated
    failures (e.g. LOGIN_FAILURE before the user is identified — log the
    attempted username in `target` instead). Best-effort: on any DB error,
    swallow + log to stderr (don't break the main request flow)."""
    try:
        with db.engine.begin() as c:
            c.execute(sa.insert(_AUDIT).values(
                ts=datetime.now(timezone.utc).isoformat(),
                username=username, ip=ip, action=action, target=target,
                details=(json.dumps(details, separators=(",", ":"))
                         if details else None),
            ))
    except Exception as e:
        # Never let audit failures break the API call. Print so it shows in logs.
        import sys
        print(f"[audit] failed to log {action}: {e}", file=sys.stderr)


# ───────────────────────────────────────────────────────────────
# Read
# ───────────────────────────────────────────────────────────────

def get_audit(db,
              username: Optional[str] = None,
              action: Optional[str] = None,
              since: Optional[str] = None,
              limit: int = 500) -> List[dict]:
    """Read audit entries. Filters: username (exact), action (exact),
    since (ISO timestamp, returns rows with ts >= since). Most recent first.
    Returns deserialized `details` (dict) instead of the raw JSON string."""
    limit = max(1, min(limit, 5000))  # cap
    stmt = sa.select(
        _AUDIT.c.id, _AUDIT.c.ts, _AUDIT.c.username, _AUDIT.c.ip,
        _AUDIT.c.action, _AUDIT.c.target, _AUDIT.c.details,
    )
    if username:
        stmt = stmt.where(_AUDIT.c.username == username)
    if action:
        stmt = stmt.where(_AUDIT.c.action == action)
    if since:
        stmt = stmt.where(_AUDIT.c.ts >= since)
    stmt = stmt.order_by(_AUDIT.c.ts.desc()).limit(limit)

    with db.engine.connect() as c:
        rows = c.execute(stmt)
        out = []
        for r in rows:
            d = dict(r._mapping)
            details = d.get("details")
            if isinstance(details, str) and details:
                try:
                    d["details"] = json.loads(details)
                except (ValueError, TypeError):
                    pass
            out.append(d)
        return out
