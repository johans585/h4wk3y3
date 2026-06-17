"""
Argus V2 — Multi-org persistence helpers (Étape 2.1).

CRUD around the two new tables:
  - organisations(id, name UNIQUE, h1_handle, scope_file, notes, created_at)
  - targets(apex PK, organisation_id FK, scope_file_override, notes, created_at)

Resolution path used everywhere:
    domain → targets(apex=domain) → organisations(id)

No FK was added on scans/findings/etc. We JOIN on demand so the migration
0002 stays additive and reversible. Callers that want per-org filtering
go through `targets_for_org()` or `organisation_for_target()`.

All helpers are SA Core (no ORM session), consistent with core/auth.py.
Functions accept an ArgusDB instance (so they share the engine + raw-conn
shim) and return plain dicts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import sqlalchemy as sa

from core import orm


_ORGS    = orm.Organisation.__table__
_TARGETS = orm.Target.__table__


# ─────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────

def _validate_name(name: str) -> str:
    """Organisation name: kebab/snake friendly, no spaces, no path chars."""
    if not name or not name.strip():
        raise ValueError("organisation name cannot be empty")
    s = name.strip()
    if any(c in s for c in ('/', '\\', '..', '\n', '\t')):
        raise ValueError(f"organisation name {name!r} contains forbidden chars")
    if len(s) > 64:
        raise ValueError("organisation name max length is 64 chars")
    return s


def _validate_apex(apex: str) -> str:
    if not apex or not apex.strip():
        raise ValueError("target apex cannot be empty")
    s = apex.strip().lower().rstrip(".")
    if "://" in s or "/" in s:
        raise ValueError(f"target apex {apex!r} must be a bare domain")
    return s


# ─────────────────────────────────────────────────────────────────────
# Organisation CRUD
# ─────────────────────────────────────────────────────────────────────

def list_orgs(db) -> list[dict]:
    """All organisations, ordered by created_at."""
    with db.engine.connect() as c:
        rows = c.execute(
            sa.select(_ORGS).order_by(_ORGS.c.created_at)
        )
        return [dict(r._mapping) for r in rows]


def get_org(db, name: str) -> Optional[dict]:
    name = _validate_name(name)
    with db.engine.connect() as c:
        row = c.execute(
            sa.select(_ORGS).where(_ORGS.c.name == name)
        ).first()
    return dict(row._mapping) if row else None


def get_org_by_id(db, org_id: int) -> Optional[dict]:
    with db.engine.connect() as c:
        row = c.execute(
            sa.select(_ORGS).where(_ORGS.c.id == int(org_id))
        ).first()
    return dict(row._mapping) if row else None


def create_org(
    db,
    name: str,
    *,
    h1_handle: str | None = None,
    scope_file: str | None = None,
    notes:      str | None = None,
) -> dict:
    name = _validate_name(name)
    if get_org(db, name) is not None:
        raise ValueError(f"organisation {name!r} already exists")
    now = datetime.now(timezone.utc).isoformat()
    with db.engine.begin() as c:
        result = c.execute(sa.insert(_ORGS).values(
            name=name,
            h1_handle=h1_handle,
            scope_file=scope_file,
            notes=notes,
            created_at=now,
        ).returning(_ORGS.c.id))
        org_id = result.scalar()
    # Return the freshly inserted row
    return get_org_by_id(db, org_id)  # type: ignore[return-value]


def update_org(
    db,
    name: str,
    *,
    h1_handle:  str | None = ...,   # type: ignore[assignment]
    scope_file: str | None = ...,   # type: ignore[assignment]
    notes:      str | None = ...,   # type: ignore[assignment]
) -> dict:
    """Update fields in place. Sentinel `...` = leave unchanged; None = explicit clear."""
    name = _validate_name(name)
    if get_org(db, name) is None:
        raise ValueError(f"organisation {name!r} does not exist")
    values: dict = {}
    if h1_handle  is not ...:
        values["h1_handle"]  = h1_handle
    if scope_file is not ...:
        values["scope_file"] = scope_file
    if notes      is not ...:
        values["notes"]      = notes
    if not values:
        return get_org(db, name)  # type: ignore[return-value]
    with db.engine.begin() as c:
        c.execute(sa.update(_ORGS).where(_ORGS.c.name == name).values(**values))
    return get_org(db, name)  # type: ignore[return-value]


def delete_org(db, name: str, *, force: bool = False) -> None:
    """Delete org. Refuses if it has targets unless force=True (then targets
    are unlinked via FK ON DELETE SET NULL)."""
    org = get_org(db, name)
    if org is None:
        raise ValueError(f"organisation {name!r} does not exist")
    targets = list_targets_for_org(db, name)
    if targets and not force:
        raise ValueError(
            f"organisation {name!r} has {len(targets)} target(s) linked — "
            f"unlink them first or pass force=True"
        )
    with db.engine.begin() as c:
        c.execute(sa.delete(_ORGS).where(_ORGS.c.id == org["id"]))


# ─────────────────────────────────────────────────────────────────────
# Target ↔ org link
# ─────────────────────────────────────────────────────────────────────

def get_target(db, apex: str) -> Optional[dict]:
    apex = _validate_apex(apex)
    with db.engine.connect() as c:
        row = c.execute(
            sa.select(_TARGETS).where(_TARGETS.c.apex == apex)
        ).first()
    return dict(row._mapping) if row else None


def link_target(
    db,
    apex: str,
    org_name: str | None,
    *,
    scope_file_override: str | None = None,
    notes:               str | None = None,
) -> dict:
    """Attach an apex to an organisation. If a target row already exists,
    update it in place. `org_name=None` detaches the target from any org
    (keeps the row, useful to preserve scope_file_override).
    """
    apex = _validate_apex(apex)
    org_id: int | None = None
    if org_name is not None:
        org = get_org(db, org_name)
        if org is None:
            raise ValueError(f"organisation {org_name!r} does not exist")
        org_id = org["id"]

    existing = get_target(db, apex)
    now = datetime.now(timezone.utc).isoformat()
    with db.engine.begin() as c:
        if existing is None:
            c.execute(sa.insert(_TARGETS).values(
                apex=apex,
                organisation_id=org_id,
                scope_file_override=scope_file_override,
                notes=notes,
                created_at=now,
            ))
        else:
            values: dict = {"organisation_id": org_id}
            if scope_file_override is not None or existing["scope_file_override"] is None:
                values["scope_file_override"] = scope_file_override
            if notes is not None or existing["notes"] is None:
                values["notes"] = notes
            c.execute(sa.update(_TARGETS).where(_TARGETS.c.apex == apex).values(**values))
    return get_target(db, apex)  # type: ignore[return-value]


def unlink_target(db, apex: str) -> None:
    """Detach a target from its org. Keeps the target row (set
    organisation_id=NULL). To delete the row, use delete_target."""
    apex = _validate_apex(apex)
    if get_target(db, apex) is None:
        raise ValueError(f"target {apex!r} not found")
    with db.engine.begin() as c:
        c.execute(sa.update(_TARGETS)
                    .where(_TARGETS.c.apex == apex)
                    .values(organisation_id=None))


def delete_target(db, apex: str) -> None:
    apex = _validate_apex(apex)
    if get_target(db, apex) is None:
        raise ValueError(f"target {apex!r} not found")
    with db.engine.begin() as c:
        c.execute(sa.delete(_TARGETS).where(_TARGETS.c.apex == apex))


def list_targets_for_org(db, org_name: str) -> list[dict]:
    """All targets attached to the given org (by name)."""
    org = get_org(db, org_name)
    if org is None:
        return []
    with db.engine.connect() as c:
        rows = c.execute(
            sa.select(_TARGETS)
              .where(_TARGETS.c.organisation_id == org["id"])
              .order_by(_TARGETS.c.apex)
        )
        return [dict(r._mapping) for r in rows]


def list_targets_enriched_for_org(db, org_name: str) -> list[dict]:
    """Targets attached to an org, enriched with per-target aggregates :
    last_scan_at, subdomain_count, live_host_count, findings_total,
    findings_by_severity.

    Returns [] if org doesn't exist or has no targets. Used by the
    dashboard PageOrgDetail to render the enriched targets table.
    """
    org = get_org(db, org_name)
    if org is None:
        return []
    targets = list_targets_for_org(db, org_name)
    if not targets:
        return []

    apexes = [t["apex"] for t in targets]
    scans      = orm.Scan.__table__
    subdomains = orm.Subdomain.__table__
    live_hosts = orm.LiveHost.__table__
    findings   = orm.Finding.__table__

    enriched: dict[str, dict] = {}
    for t in targets:
        enriched[t["apex"]] = {
            **t,
            "last_scan_at":         None,
            "subdomain_count":      0,
            "live_host_count":      0,
            "findings_total":       0,
            "findings_by_severity": {},
        }

    with db.engine.connect() as c:
        # last_scan_at per apex (max started_at)
        rows = c.execute(
            sa.select(scans.c.domain, sa.func.max(scans.c.started_at))
              .where(scans.c.domain.in_(apexes))
              .group_by(scans.c.domain)
        )
        for apex, last in rows:
            enriched[apex]["last_scan_at"] = last

        # subdomain counts per apex — use attributed_apex (post-Étape 0003)
        # for correct attribution even after a shared-apex scan (gouv.bj).
        rows = c.execute(
            sa.select(subdomains.c.attributed_apex, sa.func.count())
              .where(subdomains.c.attributed_apex.in_(apexes))
              .group_by(subdomains.c.attributed_apex)
        )
        for apex, n in rows:
            enriched[apex]["subdomain_count"] = int(n)

        # live_hosts via attributed_apex (single query, indexed)
        rows = c.execute(
            sa.select(live_hosts.c.attributed_apex, sa.func.count())
              .where(live_hosts.c.attributed_apex.in_(apexes))
              .group_by(live_hosts.c.attributed_apex)
        )
        for apex, n in rows:
            enriched[apex]["live_host_count"] = int(n)

        # findings count + by severity via attributed_apex
        rows = c.execute(
            sa.select(findings.c.attributed_apex, findings.c.severity, sa.func.count())
              .where(findings.c.attributed_apex.in_(apexes))
              .group_by(findings.c.attributed_apex, findings.c.severity)
        )
        for apex, sev, n in rows:
            enriched[apex]["findings_total"]                += int(n)
            enriched[apex]["findings_by_severity"][sev]      = int(n)

    # Respect l'ordre alpha de list_targets_for_org
    return [enriched[t["apex"]] for t in targets]


def list_unlinked_targets(db) -> list[dict]:
    """Targets that exist in the table but have no organisation_id set."""
    with db.engine.connect() as c:
        rows = c.execute(
            sa.select(_TARGETS)
              .where(_TARGETS.c.organisation_id.is_(None))
              .order_by(_TARGETS.c.apex)
        )
        return [dict(r._mapping) for r in rows]


def organisation_for_target(db, apex: str) -> Optional[dict]:
    """Resolve apex → organisation dict (or None if unlinked)."""
    apex = _validate_apex(apex)
    with db.engine.connect() as c:
        row = c.execute(
            sa.select(_ORGS)
              .join(_TARGETS, _TARGETS.c.organisation_id == _ORGS.c.id)
              .where(_TARGETS.c.apex == apex)
        ).first()
    return dict(row._mapping) if row else None


# ─────────────────────────────────────────────────────────────────────
# Stats helper (cheap aggregation, used by `argus org show` + dashboard)
# ─────────────────────────────────────────────────────────────────────

def org_stats(db, org_name: str) -> dict:
    """Return aggregate counters for an org : targets, scans, findings by severity.

    Uses `attributed_apex` (Étape 0003) for live_hosts/findings counters —
    this means a scan of a shared apex like `gouv.bj` will correctly
    attribute its results to each ministry's apex via longest-suffix
    match. Scan counter still uses `scans.domain` (an apex-level concept
    by design, no per-subdomain scans exist).
    """
    org = get_org(db, org_name)
    if org is None:
        return {"organisation": org_name, "exists": False}
    scans      = orm.Scan.__table__
    findings   = orm.Finding.__table__
    live_hosts = orm.LiveHost.__table__
    with db.engine.connect() as c:
        targets = c.execute(sa.select(sa.func.count())
                              .select_from(_TARGETS)
                              .where(_TARGETS.c.organisation_id == org["id"])
                           ).scalar() or 0
        # Subquery : apexes owned by this org
        apex_subq = (sa.select(_TARGETS.c.apex)
                       .where(_TARGETS.c.organisation_id == org["id"])
                       .scalar_subquery())

        # Scans : per-apex scan launches
        n_scans = c.execute(sa.select(sa.func.count()).select_from(scans)
                              .where(scans.c.domain.in_(apex_subq))).scalar() or 0

        # Live hosts : attribués à cette org via attributed_apex
        n_hosts = c.execute(
            sa.select(sa.func.count()).select_from(live_hosts)
              .where(live_hosts.c.attributed_apex.in_(apex_subq))
        ).scalar() or 0

        # Findings : attribués à cette org via attributed_apex
        sev_rows = c.execute(
            sa.select(findings.c.severity, sa.func.count())
              .where(findings.c.attributed_apex.in_(apex_subq))
              .group_by(findings.c.severity)
        ).all()
        by_sev = {sev: int(n) for sev, n in sev_rows}
        total  = sum(by_sev.values())
    return {
        "organisation": org_name,
        "exists":       True,
        "targets":      int(targets),
        "scans":        int(n_scans),
        "live_hosts":   int(n_hosts),
        "findings":     total,
        "by_severity":  by_sev,
    }
