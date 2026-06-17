#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Import data/constituents.csv → Argus (organisations + targets).

Usage :
  python3 import_data.py                # idempotent : upsert
  python3 import_data.py --dry-run      # preview, ne commit rien
  python3 import_data.py --reset --yes  # truncate orgs/targets PUIS import

Source CSV : entity,apex   (apex = liste virgule-séparée si plusieurs)

Règles :
  - Noms d'org normalisés : '/' → '_' (validation core/organisation.py)
  - Apex partagé entre 2 entités : first-wins (ordre alphabétique du CSV)
"""

import argparse
import csv
import sys
from pathlib import Path

import sqlalchemy as sa

# Argus core
sys.path.insert(0, str(Path(__file__).parent))
from core import organisation as om, orm
from core.config   import ArgusConfig
from core.database import ArgusDB
from core.db_engine import build_engine

ROOT     = Path(__file__).parent
CSV_PATH = ROOT / "data" / "constituents.csv"


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────

def normalize_org_name(name: str) -> str:
    """core/organisation._validate_name interdit '/' '\\' '..' \\n \\t.
    On normalise '/' en '_' pour les noms type 'ASIN/PKI'."""
    return name.replace("/", "_").strip()


def load_csv(path: Path) -> list[tuple[str, list[str]]]:
    """[(entity_normalized, [apex,...]), ...]  — tri alpha pour first-wins."""
    rows: list[tuple[str, list[str]]] = []
    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            ent = normalize_org_name(r["entity"])
            if not ent:
                continue
            apexes = [a.strip().lower() for a in (r["apex"] or "").split(",") if a.strip()]
            rows.append((ent, apexes))
    rows.sort(key=lambda t: t[0].lower())
    return rows


def truncate_tables(db: ArgusDB) -> tuple[int, int]:
    """Truncate organisations + targets (CASCADE pour la FK)."""
    with db.engine.begin() as c:
        n_t = c.execute(sa.select(sa.func.count()).select_from(orm.Target.__table__)).scalar()
        n_o = c.execute(sa.select(sa.func.count()).select_from(orm.Organisation.__table__)).scalar()
        # Postgres TRUNCATE … CASCADE remet la séquence aussi
        c.execute(sa.text("TRUNCATE TABLE targets, organisations RESTART IDENTITY CASCADE"))
    return int(n_o or 0), int(n_t or 0)


# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="Import CSV → Argus (organisations + targets)")
    ap.add_argument("--csv",      default=str(CSV_PATH), help="chemin du CSV (default: data/constituents.csv)")
    ap.add_argument("--dry-run",  action="store_true",  help="preview sans commit")
    ap.add_argument("--reset",    action="store_true",  help="TRUNCATE orgs + targets avant import")
    ap.add_argument("--yes",      action="store_true",  help="skip la confirmation interactive sur --reset")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"✘ CSV introuvable : {csv_path}", file=sys.stderr)
        return 1

    # Setup DB
    config = ArgusConfig()
    db     = ArgusDB(engine=build_engine(config))

    # État courant
    with db.engine.connect() as c:
        cur_o = c.execute(sa.select(sa.func.count()).select_from(orm.Organisation.__table__)).scalar() or 0
        cur_t = c.execute(sa.select(sa.func.count()).select_from(orm.Target.__table__)).scalar() or 0

    csv_rows = load_csv(csv_path)

    print("═" * 70)
    print(f"  Import → Argus    mode: {'DRY-RUN' if args.dry_run else 'APPLY'}")
    print("═" * 70)
    print(f"  CSV source       : {csv_path}  ({len(csv_rows)} entités)")
    print(f"  État DB courant  : {cur_o} org(s) · {cur_t} target(s)")
    print()

    # Reset éventuel
    if args.reset:
        print(f"  ⚠ RESET : truncate organisations + targets ({cur_o} + {cur_t} rows)")
        if not args.dry_run:
            if not args.yes:
                ans = input("  Confirmer ? [yes/N] : ").strip().lower()
                if ans != "yes":
                    print("  ✘ Reset annulé.")
                    return 1
            n_o, n_t = truncate_tables(db)
            print(f"  ✓ Truncated : {n_o} org(s) + {n_t} target(s)")
        else:
            print("  (dry-run : pas de truncate effectif)")
        print()

    # Import
    stats = {
        "orgs_created":   0,
        "orgs_skipped":   0,
        "targets_linked": 0,
        "targets_reused": 0,
        "shared_apex":    0,
        "errors":         0,
    }

    # Garde la trace des apex déjà attribués pour éviter cross-org overwrite
    # en mode upsert (en mode reset, la table est vide donc pas besoin).
    apex_owner: dict[str, str] = {}
    if not args.reset and not args.dry_run:
        # Pré-charge les apex déjà liés depuis la DB
        with db.engine.connect() as c:
            rows = c.execute(sa.text("""
                SELECT t.apex, o.name FROM targets t
                LEFT JOIN organisations o ON o.id = t.organisation_id
                WHERE t.organisation_id IS NOT NULL
            """))
            for apex, oname in rows:
                apex_owner[apex] = oname

    for ent, apexes in csv_rows:
        # 1. Org : create or skip
        existing_org = None if args.dry_run and args.reset else om.get_org(db, ent)
        if existing_org:
            stats["orgs_skipped"] += 1
            print(f"  ≈ org {ent:35s} (existe — id={existing_org['id']})")
        else:
            if not args.dry_run:
                try:
                    om.create_org(db, ent)
                except Exception as e:
                    stats["errors"] += 1
                    print(f"  ✘ create_org({ent!r}) : {e}")
                    continue
            stats["orgs_created"] += 1
            print(f"  + org {ent}")

        # 2. Apex : link_target (upsert)
        for apex in apexes:
            owner = apex_owner.get(apex)
            if owner and owner != ent:
                stats["shared_apex"] += 1
                print(f"      ⚠ {apex} déjà lié à {owner!r} — skip {ent!r}")
                continue
            if not args.dry_run:
                try:
                    om.link_target(db, apex, ent)
                except Exception as e:
                    stats["errors"] += 1
                    print(f"      ✘ link_target({apex!r}, {ent!r}) : {e}")
                    continue
            if owner == ent:
                stats["targets_reused"] += 1
            else:
                stats["targets_linked"] += 1
                apex_owner[apex] = ent
            arrow = "≈" if owner == ent else "+"
            print(f"      {arrow} {apex} → {ent}")

    # Récap
    print()
    print("═" * 70)
    print(f"  Orgs créées        : {stats['orgs_created']}")
    print(f"  Orgs skipped       : {stats['orgs_skipped']}")
    print(f"  Targets liés       : {stats['targets_linked']}")
    print(f"  Targets ré-attachés (idempotent) : {stats['targets_reused']}")
    print(f"  Apex partagés (first-wins skip)  : {stats['shared_apex']}")
    print(f"  Erreurs            : {stats['errors']}")
    print("═" * 70)

    if not args.dry_run:
        with db.engine.connect() as c:
            new_o = c.execute(sa.select(sa.func.count()).select_from(orm.Organisation.__table__)).scalar() or 0
            new_t = c.execute(sa.select(sa.func.count()).select_from(orm.Target.__table__)).scalar() or 0
        print(f"  → DB après import : {new_o} org(s) · {new_t} target(s)")

    return 0 if stats["errors"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
