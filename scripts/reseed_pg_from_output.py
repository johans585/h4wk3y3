#!/usr/bin/env python3
"""
Reseed Postgres avec les artefacts JSON déjà présents dans ``output/<domain>/``.

Use case : on a switché Argus en Postgres-only, mais les fichiers JSON de
scans précédents existent toujours sur disque. Ce script recrée
l'historique en DB pour que :

  * le dashboard ait des findings/scans à montrer
  * le diff inter-scans ait une baseline pour les prochains runs

Workflow:
    python scripts/reseed_pg_from_output.py                    # dry-run, all domains
    python scripts/reseed_pg_from_output.py --apply            # commit, all domains
    python scripts/reseed_pg_from_output.py --domain anpe.bj   # only one
    python scripts/reseed_pg_from_output.py --apply --force    # même si scan déjà en DB

Safety:
    * Dry-run par défaut : nothing written.
    * Refuse de re-seed un domaine déjà en DB sauf `--force`.
    * Fingerprint dedup natif (save_finding) ⇒ relancer le script n'ajoute
      pas de doublons.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.config import ArgusConfig
from core.db_engine import build_engine
from core.database import ArgusDB
from core.models import Finding, FindingType, Severity


def _load_json(path: Path, default=None):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception as e:
        print(f"  [warn] cannot parse {path.name}: {e}", file=sys.stderr)
        return default


def _iter_domain_dirs(output_dir: Path) -> List[Path]:
    return sorted([
        d for d in output_dir.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    ])


def _scan_exists_in_db(db: ArgusDB, scan_id: str) -> bool:
    scans = db.get_scans()
    return any(s["scan_id"] == scan_id for s in scans)


def _reseed_one(db: ArgusDB, domain_dir: Path, *,
                apply: bool, force: bool) -> dict:
    """Seed one domain. Returns a counters dict.

    The seed strategy is deliberately *defensive* — every section is
    optional so we don't crash on a partial output directory. Findings
    are upserted by fingerprint, so re-running is safe.
    """
    domain = domain_dir.name
    counters = {
        "domain":     domain,
        "scan_id":    None,
        "subs":       0,
        "live_hosts": 0,
        "findings":   0,
        "skipped":    False,
    }

    summary = _load_json(domain_dir / "scan_summary.json")
    if not summary:
        print(f"[{domain}] no scan_summary.json → skip")
        counters["skipped"] = True
        return counters

    scan_id = summary.get("scan_id") or f"reseed-{domain}-{int(datetime.now().timestamp())}"
    started = summary.get("started_at") or datetime.now(timezone.utc).isoformat()
    finished = summary.get("finished_at")
    counters["scan_id"] = scan_id

    if not force and _scan_exists_in_db(db, scan_id):
        print(f"[{domain}] scan_id {scan_id} already in DB → skip (use --force)")
        counters["skipped"] = True
        return counters

    findings  = _load_json(domain_dir / "findings.json", default=[])  or []
    live      = _load_json(domain_dir / "live_hosts.json", default=[]) or []
    subs_file = domain_dir / "subdomains.txt"
    subs      = []
    if subs_file.exists():
        subs = [l.strip() for l in subs_file.read_text().splitlines() if l.strip()]

    counters["subs"]       = len(subs)
    counters["live_hosts"] = len(live)
    counters["findings"]   = len(findings)

    if not apply:
        return counters

    # ── Real work ──────────────────────────────────────────────
    db.create_scan(scan_id, domain)

    if subs:
        db.upsert_subdomains(scan_id, domain, subs)
    if live:
        # ``upsert_live_hosts`` expects dicts with at least `url`. The
        # JSON shape from m03 already matches.
        db.upsert_live_hosts(scan_id, domain, live)

    for f_dict in findings:
        try:
            # Skip rows that look like asset inventory (subdomain/live_host/url) —
            # those are reconstituted from subs/live tables, not findings.
            if f_dict.get("type") in {"subdomain", "live_host", "url",
                                      "screenshot", "js_endpoint"}:
                continue
            obj = Finding(
                type=FindingType(f_dict["type"]),
                target=f_dict.get("target") or domain,
                title=f_dict.get("title") or f_dict["type"],
                severity=Severity(f_dict.get("severity") or "info"),
                confidence=float(f_dict.get("confidence") or 0.0),
                url=f_dict.get("url"),
                evidence=f_dict.get("evidence"),
                module_source=f_dict.get("module_source"),
                metadata=f_dict.get("metadata") or {},
                tags=f_dict.get("tags") or [],
                timestamp=f_dict.get("timestamp") or started,
                scan_id=scan_id,
            )
            db.save_finding(obj, domain)
        except Exception as e:
            print(f"  [warn] finding skipped ({e}): {f_dict.get('title','?')[:60]}",
                  file=sys.stderr)

    # Mark the scan as finished so it lands in the timeline correctly.
    stats = {
        "subdomains":  counters["subs"],
        "live_hosts":  counters["live_hosts"],
        "findings":    counters["findings"],
        "reseeded_at": datetime.now(timezone.utc).isoformat(),
    }
    db.finish_scan(scan_id, stats)
    # Overwrite finished_at with the original timestamp if we had one, so the
    # diff engine treats it chronologically.
    if finished:
        import sqlalchemy as sa
        from core import orm
        t = orm.Scan.__table__
        with db.engine.begin() as c:
            c.execute(sa.update(t).where(t.c.scan_id == scan_id)
                        .values(started_at=started, finished_at=finished))

    return counters


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--domain", help="Only this domain (default: all under output/)")
    p.add_argument("--apply",  action="store_true",
                   help="Actually write to Postgres (default: dry-run)")
    p.add_argument("--force",  action="store_true",
                   help="Re-seed even if the scan_id already exists in DB")
    p.add_argument("--output-dir", default=None,
                   help="Override output_dir (default: from h4wk3y3.yaml)")
    args = p.parse_args()

    cfg = ArgusConfig()
    out_dir = Path(args.output_dir
                   or cfg.get("general", "output_dir", default="./output")).resolve()
    if not out_dir.exists():
        print(f"output_dir {out_dir} does not exist", file=sys.stderr)
        return 2

    engine = build_engine(cfg)
    db = ArgusDB(engine=engine)
    print(f"DSN: {engine.url}")
    print(f"output_dir: {out_dir}")
    print(f"mode: {'APPLY (writes)' if args.apply else 'DRY-RUN'}")
    print()

    if args.domain:
        targets = [out_dir / args.domain]
        if not targets[0].exists():
            print(f"no such domain dir: {targets[0]}", file=sys.stderr)
            return 2
    else:
        targets = _iter_domain_dirs(out_dir)

    if not targets:
        print("no domain dirs to process")
        return 0

    grand = {"subs": 0, "live_hosts": 0, "findings": 0, "scans": 0}
    for d in targets:
        res = _reseed_one(db, d, apply=args.apply, force=args.force)
        if res["skipped"]:
            continue
        print(f"[{res['domain']:<24}] scan={res['scan_id'][:8]}…  "
              f"subs={res['subs']:>4}  live={res['live_hosts']:>4}  "
              f"findings={res['findings']:>5}")
        grand["scans"]      += 1
        grand["subs"]       += res["subs"]
        grand["live_hosts"] += res["live_hosts"]
        grand["findings"]   += res["findings"]

    print()
    if args.apply:
        print(f"DONE: {grand['scans']} scans, "
              f"{grand['subs']} subs, {grand['live_hosts']} live hosts, "
              f"{grand['findings']} findings reseeded.")
    else:
        print(f"DRY-RUN summary: would reseed {grand['scans']} scans, "
              f"{grand['subs']} subs, {grand['live_hosts']} live hosts, "
              f"{grand['findings']} findings. Pass --apply to commit.")

    db.close()
    engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
