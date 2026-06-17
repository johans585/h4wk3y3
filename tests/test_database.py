"""Tests for the SQLAlchemy-backed ArgusDB layer.

Le précédent test ``test_db_lifecycle`` créait un fichier SQLite jetable.
Avec le switch Postgres-only (2026-05) il a été réécrit pour utiliser la
fixture ``db`` du conftest (Postgres truncated par test).
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import Finding, FindingType, Severity


def test_db_lifecycle(db):
    """Smoke end-to-end : create scan → upsert subs → save finding → stats."""
    db.create_scan("scan-001", "example.com")
    scans = db.get_scans("example.com")
    assert len(scans) == 1
    assert scans[0]["domain"] == "example.com"

    subs = ["api.example.com", "admin.example.com", "mail.example.com"]
    new_subs = db.upsert_subdomains("scan-001", "example.com", subs)
    assert len(new_subs) == 3

    # Second insert — no new ones
    new_subs2 = db.upsert_subdomains("scan-002", "example.com", subs)
    assert len(new_subs2) == 0

    # New subdomain on a second pass
    new_subs3 = db.upsert_subdomains("scan-002", "example.com", ["new.example.com"])
    assert new_subs3 == ["new.example.com"]

    all_subs = db.get_subdomains("example.com")
    assert sorted(all_subs) == sorted(subs + ["new.example.com"])

    # Save finding
    f = Finding(
        type=FindingType.JS_SECRET,
        target="example.com",
        title="API key exposed",
        severity=Severity.CRITICAL,
        confidence=0.9,
        url="https://example.com/app.js",
        scan_id="scan-001",
    )
    db.save_finding(f, "example.com")

    findings = db.get_findings(domain="example.com")
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"

    stats = db.stats_for_domain("example.com")
    assert stats.get("critical") == 1

    db.finish_scan("scan-001", {"total": 1})
    scans = db.get_scans("example.com")
    # Most recent first — scan-001 may now have finished_at + status=done.
    statuses = {s["scan_id"]: s["status"] for s in scans}
    assert statuses["scan-001"] == "done"
