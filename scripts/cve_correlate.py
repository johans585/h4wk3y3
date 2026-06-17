#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Correlate `cves` against `live_hosts` → upsert `cve_matches` candidates.

Manual command. Run after `python3 scripts/cve_pull.py` has populated the
`cves` table.

Usage :
    python3 scripts/cve_correlate.py                # full pass
    python3 scripts/cve_correlate.py --limit-cves 500   # quick sample
    python3 scripts/cve_correlate.py --dry-run      # show would-be matches, no writes
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
from modules.m17_cve_correlator import CVECorrelatorModule


def main() -> int:
    ap = argparse.ArgumentParser(description="Correlate CVEs ↔ live_hosts → cve_matches")
    ap.add_argument("--limit-cves", type=int, default=None,
                    help="Cap number of CVE evaluated (debug). Default: all.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Compute matches but don't upsert.")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level   = logging.DEBUG if args.verbose else logging.INFO,
        format  = "%(message)s",
        stream  = sys.stdout,
    )
    log = logging.getLogger("cve_correlate")

    db = ArgusDB(engine=build_engine(ArgusConfig()))

    if args.dry_run:
        from modules import m17_cve_correlator
        def _fake_upsert(self, matches):
            log.info(f"▶ DRY-RUN: would upsert {len(matches)} matches (skipped)")
            return {"matches_total": len(matches), "inserted": 0, "refreshed": 0}
        m17_cve_correlator.CVECorrelatorModule._upsert = _fake_upsert

    mod = CVECorrelatorModule(
        engine     = db.engine,
        limit_cves = args.limit_cves,
        log        = log,
    )
    stats = mod.run()

    log.info("")
    log.info(f"Final stats : {stats}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
