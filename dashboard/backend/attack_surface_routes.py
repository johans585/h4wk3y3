"""
Argus V2 — Attack Surface endpoint.

GET /api/attack-surface/hosts?org=<name>     → flat inventory list

Renvoie une liste flat de live_hosts enrichie pour la page Attack Surface
(grid de cards). Chaque host porte ses propres findings (attribués via
finding.url quand disponible), pas un total apex-level qui se répèterait
sur toutes les cards du même apex.

GET only, user-level.
"""

from __future__ import annotations

import json
from typing import Optional
from urllib.parse import urlparse

import sqlalchemy as sa
from fastapi import FastAPI, HTTPException, Query

from core import organisation as O, orm


def _collect_hosts(db, org_filter: Optional[str] = None,
                       include_orphans: bool = True) -> list[dict]:
    """Liste flat des live_hosts enrichie pour la vue inventaire.

    Uses live_hosts.attributed_apex (Étape 0003) — résolu via longest-suffix
    par le hook post-scan + le backfill. Plus de heuristique manuelle host→apex.

    Args:
        org_filter:      restreint au constituent donné. Si None = toutes orgs.
        include_orphans: si True ET pas de filter, inclut aussi les hosts
                         dont attributed_apex IS NULL (shadow IT signal).

    Champs par host :
        host, apex (= attributed_apex), org, url, status, title, tech[],
        waf, cname, findings_by_severity
        is_orphan: bool (attributed_apex IS NULL)
    """
    # 1. Map apex → org (1 seule query)
    with db.engine.connect() as c:
        rows = c.execute(sa.text("""
            SELECT t.apex, o.name AS org
              FROM targets t LEFT JOIN organisations o ON o.id = t.organisation_id
        """))
        apex_to_org = {r[0]: r[1] for r in rows}

    # 2. Construire la WHERE clause selon le filter
    lh_table = orm.LiveHost.__table__
    if org_filter:
        org = O.get_org(db, org_filter)
        if org is None:
            return []
        # Apex de cette org
        org_apexes = [a for a, o in apex_to_org.items() if o == org_filter]
        if not org_apexes:
            return []
        where_clause = lh_table.c.attributed_apex.in_(org_apexes)
    elif include_orphans:
        # Tous les hosts : attribués OU orphelins
        where_clause = sa.true()
    else:
        where_clause = lh_table.c.attributed_apex.isnot(None)

    # 3. Live hosts (1 query, premier rencontré par hostname)
    hosts: dict[str, dict] = {}
    with db.engine.connect() as c:
        rows = c.execute(
            sa.select(lh_table.c.domain,           lh_table.c.url,
                      lh_table.c.status_code,      lh_table.c.title,
                      lh_table.c.technologies,     lh_table.c.waf,
                      lh_table.c.cname,            lh_table.c.attributed_apex)
              .where(where_clause)
        )
        for host, url, status, title, tech, waf, cname, attr_apex in rows:
            if host in hosts:
                continue  # premier rencontré gagne
            tech_list: list[str] = []
            if tech:
                try:
                    parsed = json.loads(tech)
                    if isinstance(parsed, list):
                        tech_list = [str(t) for t in parsed]
                except Exception:
                    pass
            hosts[host] = {
                "host":      host,
                "apex":      attr_apex,
                "org":       apex_to_org.get(attr_apex) if attr_apex else None,
                "url":       url,
                "status":    int(status) if status is not None else None,
                "title":     title,
                "tech":      tech_list,
                "waf":       waf,
                "cname":     cname,
                "is_orphan": attr_apex is None,
                "findings_by_severity": {},
            }

    if not hosts:
        return []

    # 4. Findings attribués PAR HOSTNAME — on lie via finding.url plutôt que
    #    finding.attributed_apex (qui group au niveau apex). On veut afficher
    #    le compte exact PAR HOSTNAME pour distinguer les sous-domaines.
    findings_table = orm.Finding.__table__
    findings_by_host: dict[str, dict[str, int]] = {}
    with db.engine.connect() as c:
        # Pour le filter org : seul les findings dont attributed_apex matche
        # cette org. Sinon : tous.
        if org_filter:
            f_where = findings_table.c.attributed_apex.in_(org_apexes)
        else:
            f_where = sa.true()
        rows = c.execute(
            sa.select(findings_table.c.url, findings_table.c.severity)
              .where(f_where)
              .where(findings_table.c.url.isnot(None))
        )
        for url, sev in rows:
            try:
                host = (urlparse(url).hostname or "").lower()
            except Exception:
                continue
            if not host or host not in hosts:
                continue
            bucket = findings_by_host.setdefault(host, {})
            bucket[sev] = bucket.get(sev, 0) + 1

    for h in hosts.values():
        h["findings_by_severity"] = findings_by_host.get(h["host"], {})

    # Tri : orgs nommées en premier (alpha), puis orphans à la fin
    return sorted(
        hosts.values(),
        key=lambda h: (1 if h["is_orphan"] else 0, h["org"] or "~", h["host"])
    )


def install_attack_surface_routes(app: FastAPI, db) -> None:

    @app.get("/api/attack-surface/hosts")
    def attack_surface_hosts(
        org: Optional[str] = Query(None),
        include_orphans: bool = Query(True,
            description="Include hosts without attributed_apex (shadow IT signal). "
                        "Only relevant when org is not specified."),
    ):
        """Inventaire flat des hosts enrichis pour la grid de cards."""
        if org and O.get_org(db, org) is None:
            raise HTTPException(404, "organisation not found")
        return _collect_hosts(db, org_filter=org, include_orphans=include_orphans)
