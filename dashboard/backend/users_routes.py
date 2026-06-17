"""
Argus V2 — User management routes (super-admin only).

All routes here require role 'super-admin' (enforced via Depends).
The middleware in auth_routes.py also gates /api/users/* at super-admin
level, so this is double-defense.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, HTTPException, Depends, Body

from core.auth import (
    list_users, create_user, set_password, set_role, set_enabled, get_user,
    VALID_ROLES,
)
from core.audit import log_action, ACTIONS
from dashboard.backend.auth_routes import require_role
from dashboard.backend.clientip import client_ip as _client_ip


def install_users_routes(app: FastAPI, db) -> None:

    SuperAdmin = Depends(require_role("super-admin"))

    @app.get("/api/users")
    def users_list(_=SuperAdmin):
        return list_users(db)

    @app.post("/api/users")
    def users_create(request: Request, payload: dict = Body(...), me=SuperAdmin):
        username = (payload or {}).get("username", "").strip()
        password = (payload or {}).get("password", "")
        role = (payload or {}).get("role", "user")
        if not username:
            raise HTTPException(400, "username required")
        if not password or len(password) < 8:
            raise HTTPException(400, "password must be at least 8 chars")
        if role not in VALID_ROLES:
            raise HTTPException(400, f"role must be one of {VALID_ROLES}")
        try:
            create_user(db, username, password, role)
        except ValueError as e:
            raise HTTPException(400, str(e))
        log_action(db, me["username"], _client_ip(request),
                   ACTIONS.USER_CREATED, target=username,
                   details={"role": role})
        return {"ok": True, "username": username, "role": role}

    @app.patch("/api/users/{username}/role")
    def users_change_role(username: str, request: Request,
                          payload: dict = Body(...), me=SuperAdmin):
        new_role = (payload or {}).get("role", "")
        if new_role not in VALID_ROLES:
            raise HTTPException(400, f"role must be one of {VALID_ROLES}")
        if get_user(db, username) is None:
            raise HTTPException(404, "user not found")
        # Prevent demoting yourself out of super-admin if you're the last one
        if me["username"] == username and new_role != "super-admin":
            if _count_super_admins(db) <= 1:
                raise HTTPException(409, "cannot demote the last super-admin")
        set_role(db, username, new_role)
        log_action(db, me["username"], _client_ip(request),
                   ACTIONS.USER_ROLE_CHANGED, target=username,
                   details={"new_role": new_role})
        return {"ok": True, "username": username, "role": new_role}

    @app.patch("/api/users/{username}/disable")
    def users_disable(username: str, request: Request, me=SuperAdmin):
        if get_user(db, username) is None:
            raise HTTPException(404, "user not found")
        if me["username"] == username:
            raise HTTPException(409, "cannot disable yourself")
        # Prevent disabling the last super-admin
        target_user = get_user(db, username)
        if target_user["role"] == "super-admin" and _count_super_admins(db, only_enabled=True) <= 1:
            raise HTTPException(409, "cannot disable the last super-admin")
        set_enabled(db, username, False)
        log_action(db, me["username"], _client_ip(request),
                   ACTIONS.USER_DISABLED, target=username)
        return {"ok": True, "username": username, "enabled": False}

    @app.patch("/api/users/{username}/enable")
    def users_enable(username: str, request: Request, me=SuperAdmin):
        if get_user(db, username) is None:
            raise HTTPException(404, "user not found")
        set_enabled(db, username, True)
        log_action(db, me["username"], _client_ip(request),
                   ACTIONS.USER_ENABLED, target=username)
        return {"ok": True, "username": username, "enabled": True}

    @app.post("/api/users/{username}/reset-password")
    def users_reset_password(username: str, request: Request,
                             payload: dict = Body(...), me=SuperAdmin):
        new_password = (payload or {}).get("new_password", "")
        if not new_password or len(new_password) < 8:
            raise HTTPException(400, "new_password must be at least 8 chars")
        if get_user(db, username) is None:
            raise HTTPException(404, "user not found")
        set_password(db, username, new_password)
        log_action(db, me["username"], _client_ip(request),
                   ACTIONS.USER_PASSWORD_RESET, target=username)
        return {"ok": True, "username": username}


def _count_super_admins(db, only_enabled: bool = False) -> int:
    import sqlalchemy as sa
    from core import orm
    t = orm.User.__table__
    stmt = sa.select(sa.func.count()).select_from(t).where(t.c.role == "super-admin")
    if only_enabled:
        stmt = stmt.where(t.c.enabled == 1)
    with db.engine.connect() as c:
        return c.execute(stmt).scalar() or 0


