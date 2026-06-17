"""
Argus V2 — Audit log read endpoint.

Authorization rules:
  super-admin → can read all entries (any user, any action)
  admin       → can only read its own entries (forced filter by username)
  user        → 403 (gated by middleware in auth_routes.py)
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, Request, Query, HTTPException

from core.audit import get_audit


def install_audit_routes(app: FastAPI, db) -> None:

    @app.get("/api/audit")
    def audit_list(request: Request,
                   username: Optional[str] = Query(None),
                   action:   Optional[str] = Query(None),
                   since:    Optional[str] = Query(None,
                       description="ISO timestamp; entries with ts >= since"),
                   limit:    int = Query(500, ge=1, le=5000)):
        me = request.state.user
        # Admin can only see their own entries — force the filter regardless
        # of what the client passed.
        if me["role"] == "admin":
            if username and username != me["username"]:
                raise HTTPException(403, "admin can only read its own audit log")
            username = me["username"]
        # super-admin: no constraint, use whatever filter (or none).
        return get_audit(db, username=username, action=action,
                         since=since, limit=limit)
