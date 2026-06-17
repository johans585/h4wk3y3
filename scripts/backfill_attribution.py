#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Backfill attributed_apex on existing subdomains / live_hosts / findings.

Idempotent : peut être lancé plusieurs fois sans effet de bord — chaque
appel re-calcule l'attribution depuis l'état courant de `targets`.

Usage :
    python3 scripts/backfill_attribution.py [--dry-run]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import sqlalchemy as sa

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import orm
from core.attribution import resolve_apex, load_apexes_sorted, extract_host_from_url
from core.config   import ArgusConfig
from core.database import ArgusDB
from core.db_engine import build_engine


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would change, don't write")
    args = ap.parse_args()

    db = ArgusDB(engine=build_engine(ArgusConfig()))
    apexes = load_apexes_sorted(db)
    if not apexes:
        print("✘ no apex in `targets` — import constituents.csv first.", file=sys.stderr)
        return 1

    print(f"  apex universe         : {len(apexes)} apexes")
    print(f"  mode                  : {'DRY-RUN (no writes)' if args.dry_run else 'APPLY'}")
    print()

    subs_t = orm.Subdomain.__table__
    lh_t   = orm.LiveHost.__table__
    find_t = orm.Finding.__table__

    stats = {"subs": 0, "hosts": 0, "findings": 0, "orphans": 0}
    attributed: set[str] = set()

    with db.engine.begin() as c:
        # ── Subdomains ────────────────────────────────────────────────
        rows = c.execute(sa.select(subs_t.c.id, subs_t.c.subdomain)).fetchall()
        for sid, sub in rows:
            attr = resolve_apex(sub, apexes)
            if not args.dry_run:
                c.execute(sa.update(subs_t).where(subs_t.c.id == sid)
                            .values(attributed_apex=attr))
            stats["subs"] += 1
            if attr is None: stats["orphans"] += 1
            else:            attributed.add(attr)
        print(f"  subdomains processed  : {stats['subs']}")

        # ── Live hosts ────────────────────────────────────────────────
        rows = c.execute(sa.select(lh_t.c.id, lh_t.c.domain)).fetchall()
        for lid, host in rows:
            attr = resolve_apex(host, apexes)
            if not args.dry_run:
                c.execute(sa.update(lh_t).where(lh_t.c.id == lid)
                            .values(attributed_apex=attr))
            stats["hosts"] += 1
            if attr is None: stats["orphans"] += 1
            else:            attributed.add(attr)
        print(f"  live_hosts processed  : {stats['hosts']}")

        # ── Findings ──────────────────────────────────────────────────
        rows = c.execute(sa.select(find_t.c.id, find_t.c.url, find_t.c.domain)).fetchall()
        for fid, furl, fdomain in rows:
            host = extract_host_from_url(furl)
            attr = resolve_apex(host, apexes) if host else None
            if attr is None and fdomain:
                attr = resolve_apex(fdomain, apexes)
            if not args.dry_run:
                c.execute(sa.update(find_t).where(find_t.c.id == fid)
                            .values(attributed_apex=attr))
            stats["findings"] += 1
            if attr is None: stats["orphans"] += 1
            else:            attributed.add(attr)
        print(f"  findings processed    : {stats['findings']}")

    print()
    print("═" * 60)
    print(f"  Total processed   : {stats['subs'] + stats['hosts'] + stats['findings']}")
    print(f"  Distinct apexes   : {len(attributed)}")
    print(f"  Orphans (no match): {stats['orphans']}")
    print("═" * 60)

    if args.dry_run:
        print("\n  (dry-run : nothing committed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
