"""
Argus V2 — Organisation routes (Étape 2.1 multi-org).

GET endpoints are open to any authenticated user (cf. auth_routes._required_role).
POST/PATCH/DELETE are admin-only.

Endpoints:
    GET    /api/orgs                          → [orgs]
    POST   /api/orgs                          → create
    GET    /api/orgs/{name}                   → org + targets + stats
    PATCH  /api/orgs/{name}                   → update (h1_handle, scope_file, notes)
    DELETE /api/orgs/{name}[?force=true]      → delete
    POST   /api/orgs/{name}/targets           → link an apex
    DELETE /api/orgs/{name}/targets/{apex}    → unlink
    GET    /api/orgs/{name}/stats             → aggregate stats only
    GET    /api/targets                       → all targets, optional ?org=<name> or ?unlinked=true
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request, Body, Query
from typing import Optional

from core import organisation as O
from core.audit import log_action
from dashboard.backend.clientip import client_ip as _client_ip


# Audit actions for org mutations — cheap to inline rather than adding to ACTIONS
ORG_CREATED  = "org.created"
ORG_UPDATED  = "org.updated"
ORG_DELETED  = "org.deleted"
ORG_LINKED   = "org.target_linked"
ORG_UNLINKED = "org.target_unlinked"


def _me_username(request: Request) -> str:
    """Best-effort: middleware sets request.state.user if authed."""
    u = getattr(request.state, "user", None)
    if isinstance(u, dict):
        return u.get("username", "?")
    return "?"


def install_orgs_routes(app: FastAPI, db) -> None:

    @app.get("/api/orgs")
    def orgs_list():
        orgs = O.list_orgs(db)
        # Enrich with target count — cheap loop, list_orgs returns ~dozens of rows
        enriched = []
        for org in orgs:
            tgts = O.list_targets_for_org(db, org["name"])
            enriched.append({**org, "target_count": len(tgts)})
        return enriched

    @app.post("/api/orgs")
    def orgs_create(request: Request, payload: dict = Body(...)):
        name       = (payload or {}).get("name", "").strip()
        h1_handle  = (payload or {}).get("h1_handle") or None
        scope_file = (payload or {}).get("scope_file") or None
        notes      = (payload or {}).get("notes") or None
        if not name:
            raise HTTPException(400, "name required")
        try:
            org = O.create_org(db, name,
                               h1_handle=h1_handle,
                               scope_file=scope_file,
                               notes=notes)
        except ValueError as e:
            raise HTTPException(400, str(e))
        log_action(db, _me_username(request), _client_ip(request),
                   ORG_CREATED, target=name,
                   details={"h1_handle": h1_handle, "scope_file": scope_file})
        return org

    @app.get("/api/orgs/{name}")
    def orgs_show(name: str):
        org = O.get_org(db, name)
        if org is None:
            raise HTTPException(404, "organisation not found")
        return {
            "organisation": org,
            "targets":      O.list_targets_for_org(db, name),
            "stats":        O.org_stats(db, name),
        }

    @app.patch("/api/orgs/{name}")
    def orgs_update(name: str, request: Request, payload: dict = Body(...)):
        if O.get_org(db, name) is None:
            raise HTTPException(404, "organisation not found")
        # PATCH semantics : only fields present in the payload are touched.
        # `None` value = clear the field; absent key = leave unchanged.
        kwargs: dict = {}
        if "h1_handle"  in payload: kwargs["h1_handle"]  = payload["h1_handle"]
        if "scope_file" in payload: kwargs["scope_file"] = payload["scope_file"]
        if "notes"      in payload: kwargs["notes"]      = payload["notes"]
        if not kwargs:
            raise HTTPException(400, "nothing to update")
        try:
            org = O.update_org(db, name, **kwargs)
        except ValueError as e:
            raise HTTPException(400, str(e))
        log_action(db, _me_username(request), _client_ip(request),
                   ORG_UPDATED, target=name, details=kwargs)
        return org

    @app.delete("/api/orgs/{name}")
    def orgs_delete(name: str, request: Request,
                    force: bool = Query(False)):
        try:
            O.delete_org(db, name, force=force)
        except ValueError as e:
            # 409 conflict = "has targets, won't delete without --force"
            if "linked" in str(e):
                raise HTTPException(409, str(e))
            raise HTTPException(400, str(e))
        log_action(db, _me_username(request), _client_ip(request),
                   ORG_DELETED, target=name, details={"force": force})
        return {"ok": True, "deleted": name}

    # ── Target ↔ org linkage ──────────────────────────────────

    @app.post("/api/orgs/{name}/targets")
    def orgs_link_target(name: str, request: Request, payload: dict = Body(...)):
        if O.get_org(db, name) is None:
            raise HTTPException(404, "organisation not found")
        apex     = (payload or {}).get("apex", "").strip()
        override = (payload or {}).get("scope_file_override") or None
        notes    = (payload or {}).get("notes") or None
        if not apex:
            raise HTTPException(400, "apex required")
        try:
            t = O.link_target(db, apex, name,
                              scope_file_override=override, notes=notes)
        except ValueError as e:
            raise HTTPException(400, str(e))
        log_action(db, _me_username(request), _client_ip(request),
                   ORG_LINKED, target=apex,
                   details={"org": name, "override": override})
        return t

    @app.delete("/api/orgs/{name}/targets/{apex}")
    def orgs_unlink_target(name: str, apex: str, request: Request):
        # Verify the target is actually linked to THIS org before unlinking
        # (idempotent + safer than blindly calling unlink_target).
        org = O.organisation_for_target(db, apex)
        if org is None or org["name"] != name:
            raise HTTPException(404, "target not linked to this organisation")
        try:
            O.unlink_target(db, apex)
        except ValueError as e:
            raise HTTPException(400, str(e))
        log_action(db, _me_username(request), _client_ip(request),
                   ORG_UNLINKED, target=apex, details={"org": name})
        return {"ok": True, "apex": apex}

    @app.get("/api/orgs/{name}/stats")
    def orgs_stats(name: str):
        if O.get_org(db, name) is None:
            raise HTTPException(404, "organisation not found")
        return O.org_stats(db, name)

    @app.get("/api/orgs/{name}/targets/enriched")
    def orgs_targets_enriched(name: str):
        """Targets + per-target aggregates (last_scan_at, sub/host/findings).

        Cible pour PageOrgDetail : évite N+1 queries côté frontend en
        renvoyant tout en un seul shot.
        """
        if O.get_org(db, name) is None:
            raise HTTPException(404, "organisation not found")
        return O.list_targets_enriched_for_org(db, name)

    # ── Targets (flat listing, optional org filter) ───────────

    @app.get("/api/targets")
    def targets_list(org:      Optional[str] = Query(None),
                     unlinked: bool          = Query(False)):
        if unlinked:
            return O.list_unlinked_targets(db)
        if org:
            if O.get_org(db, org) is None:
                raise HTTPException(404, "organisation not found")
            return O.list_targets_for_org(db, org)
        # All targets
        import sqlalchemy as sa
        from core import orm
        t = orm.Target.__table__
        with db.engine.connect() as c:
            rows = c.execute(sa.select(t).order_by(t.c.apex))
            return [dict(r._mapping) for r in rows]
