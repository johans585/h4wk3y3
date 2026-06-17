"""
Argus V2 — CVE query helpers.

Wraps `cves` + `cve_matches` for the dashboard/backend routes.
SA Core only (no ORM session, consistent with other helpers).
"""

from __future__ import annotations

import json
from typing import Optional

import sqlalchemy as sa

from core import orm


_CVES         = orm.CVE.__table__
_CVE_MATCHES  = orm.CVEMatch.__table__


def _row_to_dict(row, columns: list[str]) -> dict:
    """SA Row → dict via column-name mapping (safer than _mapping when joining)."""
    return {col: getattr(row, col, None) for col in columns}


def _decode_json_field(val: str | None) -> object:
    if not val:
        return None
    try:
        return json.loads(val)
    except Exception:
        return None


def _enrich_cve(row: dict) -> dict:
    """Decode JSON-encoded fields into native Python lists/dicts."""
    row["cpes"]         = _decode_json_field(row.get("cpes"))
    row["products"]     = _decode_json_field(row.get("products"))
    row["refs"]         = _decode_json_field(row.get("refs"))
    row["source_feeds"] = _decode_json_field(row.get("source_feeds"))
    # Cast 0/1 → bool for the frontend
    row["kev_flag"]       = bool(row.get("kev_flag"))
    row["kev_ransomware"] = bool(row.get("kev_ransomware"))
    return row


# ─────────────────────────────────────────────────────────────────────
# Listing
# ─────────────────────────────────────────────────────────────────────

def list_cves(
    db,
    *,
    kev_only:       bool = False,
    ransomware:     bool = False,
    min_cvss:       Optional[float] = None,
    min_epss:       Optional[float] = None,
    vendor:         Optional[str] = None,
    search:         Optional[str] = None,
    has_template:   Optional[bool] = None,
    has_matches:    Optional[bool] = None,
    sort:           str = "epss",
    limit:          int = 100,
    offset:         int = 0,
) -> dict:
    """Filterable list with affected-hosts/orgs counts. Returns dict
    {items: [...], total: N, applied_filters: {...}}.
    """
    where = []
    params: dict = {}

    if kev_only:
        where.append("kev_flag = 1")
    if ransomware:
        where.append("kev_ransomware = 1")
    if min_cvss is not None:
        where.append("cvss_v3 >= :min_cvss")
        params["min_cvss"] = float(min_cvss)
    if min_epss is not None:
        where.append("epss >= :min_epss")
        params["min_epss"] = float(min_epss)
    if vendor:
        where.append("vendor = :vendor")
        params["vendor"] = vendor.lower().strip()
    if search:
        # Qualify cve_id explicitly — ambiguous after the LEFT JOIN with cve_matches.
        where.append("(cves.cve_id ILIKE :q OR cves.description ILIKE :q OR cves.vendor ILIKE :q)")
        params["q"] = f"%{search.strip()}%"
    if has_template is True:
        where.append("cves.nuclei_template IS NOT NULL")
    elif has_template is False:
        where.append("cves.nuclei_template IS NULL")

    if has_matches is True:
        where.append("EXISTS (SELECT 1 FROM cve_matches m2 WHERE m2.cve_id = cves.cve_id)")
    elif has_matches is False:
        where.append("NOT EXISTS (SELECT 1 FROM cve_matches m2 WHERE m2.cve_id = cves.cve_id)")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    # Sort key whitelist (security : pas d'injection via sort param).
    # Tie-breaker `cves.cve_id ASC` à la fin de chaque clause = garantit un
    # ordre déterministe entre pages (sinon doublons cross-page quand
    # plusieurs rows partagent la même clé primaire de tri, ex 8x EPSS=0.945).
    SORT_MAP = {
        "epss":      "epss DESC NULLS LAST, kev_flag DESC, cves.cve_id ASC",
        "cvss":      "cvss_v3 DESC NULLS LAST, cves.cve_id ASC",
        "published": "published_at DESC NULLS LAST, cves.cve_id ASC",
        "kev":       "kev_added_at DESC NULLS LAST, cves.cve_id ASC",
        "matches":   "match_count DESC NULLS LAST, epss DESC NULLS LAST, cves.cve_id ASC",
    }
    order_clause = SORT_MAP.get(sort, SORT_MAP["epss"])

    # Compteur total (sans LIMIT)
    with db.engine.connect() as c:
        total = c.execute(
            sa.text(f"SELECT COUNT(*) FROM cves {where_sql}"),
            params,
        ).scalar() or 0

        # Liste + agrégats matches via LEFT JOIN GROUP BY
        rows = c.execute(sa.text(f"""
            SELECT cves.*,
                   COUNT(m.id)                       AS match_count,
                   COUNT(DISTINCT m.attributed_apex) AS apex_count,
                   COUNT(DISTINCT m.organisation_id) AS org_count
              FROM cves
              LEFT JOIN cve_matches m ON m.cve_id = cves.cve_id
             {where_sql}
             GROUP BY cves.cve_id
             ORDER BY {order_clause}
             LIMIT :limit OFFSET :offset
        """), {**params, "limit": int(limit), "offset": int(offset)}).fetchall()

    items = []
    for r in rows:
        d = dict(r._mapping)
        d = _enrich_cve(d)
        d["match_count"] = int(d.get("match_count") or 0)
        d["apex_count"]  = int(d.get("apex_count")  or 0)
        d["org_count"]   = int(d.get("org_count")   or 0)
        items.append(d)

    return {
        "items": items,
        "total": int(total),
        "limit": int(limit),
        "offset": int(offset),
        "sort":  sort,
    }


# ─────────────────────────────────────────────────────────────────────
# Detail
# ─────────────────────────────────────────────────────────────────────

def get_cve(db, cve_id: str) -> Optional[dict]:
    with db.engine.connect() as c:
        row = c.execute(
            sa.select(_CVES).where(_CVES.c.cve_id == cve_id)
        ).first()
    if not row:
        return None
    return _enrich_cve(dict(row._mapping))


def list_matches_for_cve(db, cve_id: str) -> list[dict]:
    """All cve_matches for a CVE, joined with organisations.name for display."""
    with db.engine.connect() as c:
        rows = c.execute(sa.text("""
            SELECT m.id, m.cve_id, m.match_method, m.match_source,
                   m.asset_host, m.asset_ip, m.asset_url, m.asset_port,
                   m.asset_product, m.asset_version, m.version_required,
                   m.attributed_apex, m.organisation_id, m.pivot_method,
                   m.confidence, m.validation_state, m.validated_at,
                   m.validated_by, m.evidence,
                   m.first_seen_at, m.last_seen_at,
                   o.name AS organisation_name
              FROM cve_matches m
              LEFT JOIN organisations o ON o.id = m.organisation_id
             WHERE m.cve_id = :cve_id
             ORDER BY m.confidence DESC, m.attributed_apex NULLS LAST, m.asset_host
        """), {"cve_id": cve_id}).fetchall()
    out = []
    for r in rows:
        d = dict(r._mapping)
        # evidence is JSON-encoded
        d["evidence"] = _decode_json_field(d.get("evidence"))
        out.append(d)
    return out


def cve_global_stats(db) -> dict:
    """Quick counts for the page header."""
    with db.engine.connect() as c:
        total_cves   = c.execute(sa.text("SELECT COUNT(*) FROM cves")).scalar() or 0
        kev_count    = c.execute(sa.text("SELECT COUNT(*) FROM cves WHERE kev_flag=1")).scalar() or 0
        matched_cves = c.execute(sa.text("""
            SELECT COUNT(DISTINCT cve_id) FROM cve_matches
        """)).scalar() or 0
        match_count  = c.execute(sa.text("SELECT COUNT(*) FROM cve_matches")).scalar() or 0
        org_count    = c.execute(sa.text("""
            SELECT COUNT(DISTINCT organisation_id) FROM cve_matches
             WHERE organisation_id IS NOT NULL
        """)).scalar() or 0
        ransom_match = c.execute(sa.text("""
            SELECT COUNT(*) FROM cve_matches cm
              JOIN cves c ON c.cve_id = cm.cve_id
             WHERE c.kev_ransomware = 1
        """)).scalar() or 0
    return {
        "total_cves":      int(total_cves),
        "kev_count":       int(kev_count),
        "matched_cves":    int(matched_cves),
        "match_count":     int(match_count),
        "org_count":       int(org_count),
        "ransomware_match": int(ransom_match),
    }


def list_vendors(db, limit: int = 50) -> list[dict]:
    """Vendors présents en DB (pour le filter dropdown)."""
    with db.engine.connect() as c:
        rows = c.execute(sa.text("""
            SELECT vendor, COUNT(*) AS n
              FROM cves
             WHERE vendor IS NOT NULL
             GROUP BY vendor
             ORDER BY n DESC, vendor
             LIMIT :limit
        """), {"limit": int(limit)}).fetchall()
    return [{"vendor": r[0], "count": int(r[1])} for r in rows]
