#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pull CVE intelligence feeds → table `cves`.

Manual command (not in pipeline auto-stages for now).

Usage :
    python3 scripts/cve_pull.py                       # KEV + EPSS + NVD (current + 2 prev years) + nuclei
    python3 scripts/cve_pull.py --years 2024,2025     # only those NVD years
    python3 scripts/cve_pull.py --no-nvd              # skip NVD (KEV+EPSS+nuclei only — ~5 MB download)
    python3 scripts/cve_pull.py --dry-run             # show what would happen, no writes
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config   import ArgusConfig
from core.database import ArgusDB
from core.db_engine import build_engine
from modules.m15_cve_feeds import CVEFeedsModule


def main() -> int:
    ap = argparse.ArgumentParser(description="Pull CVE feeds (KEV/EPSS/NVD/nuclei) → `cves`")
    ap.add_argument("--years",   default=None,
                    help="Comma-separated NVD years to pull, e.g. 2023,2024,2025. "
                         "Default: current + 2 previous.")
    ap.add_argument("--no-nvd",  action="store_true",
                    help="Skip NVD JSON pull (fast mode, ~5 MB download total)")
    ap.add_argument("--recent-only", action="store_true",
                    help="Skip annual NVD feeds, only pull `recent` (8-day delta, ~5MB). "
                         "Combined with KEV/EPSS/nuclei = fast refresh.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Pull and parse but don't write to DB")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="DEBUG-level logs")
    args = ap.parse_args()

    logging.basicConfig(
        level   = logging.DEBUG if args.verbose else logging.INFO,
        format  = "%(message)s",
        stream  = sys.stdout,
    )
    log = logging.getLogger("cve_pull")

    years: list[int] | None = None
    if args.years:
        try:
            years = [int(y.strip()) for y in args.years.split(",") if y.strip()]
        except ValueError:
            log.error("✘ --years must be a comma list of int (e.g. 2024,2025)")
            return 1

    db = ArgusDB(engine=build_engine(ArgusConfig()))

    # Dry-run = on remplace l'engine par un wrapper qui n'écrit pas.
    # Simple approach : on ne commit pas → SQLAlchemy's begin() rollback on context exit.
    # Implementation : monkey-patch the upsert function. Cleaner approach : pass a flag.
    if args.dry_run:
        from modules import m15_cve_feeds
        def _fake_upsert(engine, rows, log):
            log.info(f"▶ DRY-RUN : would upsert {len(rows)} CVE rows (skipped)")
            return {"upserted": 0, "inserted": 0, "updated": 0}
        m15_cve_feeds.upsert_cves = _fake_upsert

    mod = CVEFeedsModule(
        engine      = db.engine,
        years       = years,
        with_nvd    = not args.no_nvd,
        recent_only = args.recent_only,
        log         = log,
    )
    stats = mod.run()

    log.info("")
    log.info(f"Final stats : {stats}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
