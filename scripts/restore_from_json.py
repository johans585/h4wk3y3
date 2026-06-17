#!/usr/bin/env python3
"""Re-ingest a scan from its output/<domain>/ JSONs back into Postgres.

Why: pytest's `db` fixture TRUNCATEs Argus tables. If the operator wipes
prod data (deliberately or by bypassing the conftest guardrail), the
scan_summary.json + findings.json + live_hosts.json + subdomains.txt on
disk are still there. This script reads them and recreates the rows so
the dashboard sees the scan again — without re-running a 50-min full
scan.

Usage:
    python scripts/restore_from_json.py <domain>

Example:
    python scripts/restore_from_json.py una.bj
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure the project root is on sys.path when invoked as `python scripts/...`
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.config import ArgusConfig
from core.database import ArgusDB
from core.db_engine import build_engine
from core.models import Finding, FindingType, Severity


def _read_json(p: Path, default):
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text())
    except Exception as e:
        print(f"  ⚠ {p.name}: parse failed ({e}) — skipping", file=sys.stderr)
        return default


def restore(domain: str) -> int:
    cfg = ArgusConfig(None)
    out_dir = Path(cfg.get('general', 'output_dir', default='./output')) / domain
    if not out_dir.exists():
        print(f"⛔ no output/{domain}/ — nothing to restore", file=sys.stderr)
        return 1
    summary  = _read_json(out_dir / "scan_summary.json", {})
    findings = _read_json(out_dir / "findings.json", [])
    hosts    = _read_json(out_dir / "live_hosts.json", [])
    subs_f   = out_dir / "subdomains.txt"
    subs     = [s.strip() for s in subs_f.read_text().splitlines() if s.strip()] if subs_f.exists() else []

    scan_id = summary.get('scan_id')
    if not scan_id:
        print("⛔ scan_summary.json has no scan_id — cannot restore", file=sys.stderr)
        return 2

    db = ArgusDB(engine=build_engine(cfg))
    db.create_scan(scan_id, domain)
    print(f"  ✓ scan row recreated: {scan_id}")

    if subs:
        db.upsert_subdomains(scan_id, domain, subs)
        print(f"  ✓ subdomains: {len(subs)}")
    if hosts:
        n = db.upsert_live_hosts(scan_id, domain, hosts)
        print(f"  ✓ live_hosts: {n}")

    sev_map = {s.value: s for s in Severity}
    type_map = {t.value: t for t in FindingType}
    persisted, skipped = 0, 0
    for d in findings:
        try:
            f = Finding(
                type=type_map.get(d.get('type'), FindingType.DOMAIN_INFO),
                target=d.get('target') or domain,
                title=d.get('title') or d.get('type') or 'untitled',
                severity=sev_map.get(d.get('severity'), Severity.INFO),
                confidence=float(d.get('confidence') or 0.0),
                url=d.get('url'),
                evidence=d.get('evidence'),
                module_source=d.get('module_source'),
                metadata=d.get('metadata') or {},
                tags=d.get('tags') or [],
                timestamp=d.get('timestamp') or '',
                scan_id=scan_id,
            )
            f.id = d.get('id') or f.id
            db.save_finding(f, domain)
            persisted += 1
        except Exception as e:
            skipped += 1
            if skipped < 5:
                print(f"  ⚠ skip finding ({type(e).__name__}: {str(e)[:80]})", file=sys.stderr)
    print(f"  ✓ findings: {persisted} persisted, {skipped} skipped")

    # Mark the scan as done so the dashboard doesn't show it as 'running'.
    stats = {
        'scan_id': scan_id, 'domain': domain,
        'subdomains': len(subs), 'live_hosts': len(hosts),
        'urls': summary.get('urls', 0), 'findings': persisted,
        'by_severity': summary.get('by_severity', {}),
        'restored_from_disk': True,
    }
    db.finish_scan(scan_id, stats)
    print(f"✓ {domain} restored from disk")
    return 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: python scripts/restore_from_json.py <domain>")
        sys.exit(64)
    sys.exit(restore(sys.argv[1]))
