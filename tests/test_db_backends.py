"""
ArgusDB invariants validated against Postgres.

Argus est Postgres-only depuis 2026-05 ; ce fichier garde son nom
historique (« backends ») mais le slice SQLite a été retiré — seules
les vérifications PG subsistent.

Covered:
  * schema creation (Base.metadata.create_all via build_engine)
  * scans lifecycle (create_scan / finish_scan / get_scans)
  * subdomain upsert + first_seen preservation
  * live_hosts upsert + diff (first_seen_scan_id / last_seen_scan_id)
  * findings upsert by fingerprint
  * diff_findings (new / gone)
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.database import ArgusDB
from core.db_engine import build_engine
from core.orm import Base
from core.models import Finding, FindingType, Severity


@pytest.fixture
def db(db_url: str):
    """Build an ArgusDB backed by `db_url`, ensure schema exists, yield it."""
    # ArgusDB(db_path=...) builds the engine internally from a path. To target
    # an arbitrary DSN (incl. Postgres), construct the engine first and pass
    # it explicitly. The schema is created via ORM metadata so this fixture
    # works on a fresh Postgres DB too — no Alembic dependency.
    cfg = _DsnConfig(db_url)
    engine = build_engine(cfg)
    Base.metadata.create_all(engine)

    inst = ArgusDB(engine=engine)
    try:
        yield inst
    finally:
        inst.close()
        engine.dispose()


class _DsnConfig:
    """ArgusConfig stub forwarding a single `db_url` to build_engine."""
    def __init__(self, url: str):
        self._url = url
    def get(self, *keys, default=None):
        if keys == ('general', 'db_url'):
            return self._url
        return default


def _mk(domain="example.com", url=None, sev=Severity.HIGH,
        ftype=FindingType.PATTERN_MATCH, scan_id="s1", evidence=None):
    return Finding(type=ftype, target=domain, title="Test",
                   severity=sev, confidence=0.8,
                   url=url, evidence=evidence, scan_id=scan_id)


# ──────────────────────────────────────────────────────────────
# Scans
# ──────────────────────────────────────────────────────────────

class TestScansBackend:
    def test_create_and_get(self, db):
        db.create_scan("s1", "example.com")
        scans = db.get_scans("example.com")
        assert len(scans) == 1
        assert scans[0]["scan_id"] == "s1"
        assert scans[0]["status"] == "running"

    def test_finish_scan_marks_done(self, db):
        db.create_scan("s1", "example.com")
        db.finish_scan("s1", {"total": 1})
        scans = db.get_scans("example.com")
        assert scans[0]["status"] == "done"

    def test_get_scans_no_domain_returns_all(self, db):
        db.create_scan("s1", "a.com")
        db.create_scan("s2", "b.com")
        all_scans = db.get_scans()
        assert {s["scan_id"] for s in all_scans} == {"s1", "s2"}


# ──────────────────────────────────────────────────────────────
# Subdomains + Live hosts
# ──────────────────────────────────────────────────────────────

class TestSubdomainsBackend:
    def test_upsert_returns_only_new(self, db):
        db.create_scan("s1", "example.com")
        new1 = db.upsert_subdomains("s1", "example.com",
                                    ["api.example.com", "x.example.com"])
        assert sorted(new1) == ["api.example.com", "x.example.com"]
        new2 = db.upsert_subdomains("s1", "example.com",
                                    ["api.example.com", "y.example.com"])
        assert new2 == ["y.example.com"]


class TestLiveHostsBackend:
    def test_first_observation_sets_scan_id(self, db):
        db.create_scan("s1", "example.com")
        n = db.upsert_live_hosts("s1", "example.com", [
            {"url": "https://a.example.com", "status_code": 200,
             "technologies": ["Nginx"]},
        ])
        assert n == 1

    def test_diff_live_hosts_new_then_gone(self, db):
        db.create_scan("s1", "example.com")
        db.upsert_live_hosts("s1", "example.com", [
            {"url": "https://a", "status_code": 200},
            {"url": "https://gone", "status_code": 200},
        ])
        new, gone = db.diff_live_hosts("example.com", "s1")
        assert len(new) == 2 and gone == []

        time.sleep(0.02)
        db.create_scan("s2", "example.com")
        db.upsert_live_hosts("s2", "example.com",
                             [{"url": "https://a", "status_code": 200}])
        new, gone = db.diff_live_hosts("example.com", "s2")
        assert new == []
        assert len(gone) == 1
        assert gone[0]["url"] == "https://gone"


# ──────────────────────────────────────────────────────────────
# Findings + diff
# ──────────────────────────────────────────────────────────────

class TestFindingsBackend:
    def test_upsert_by_fingerprint_collapses(self, db):
        db.create_scan("s1", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s1"), "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s1"), "example.com")
        rows = db.get_findings(domain="example.com", limit=100)
        assert len(rows) == 1

    def test_diff_findings_new_and_gone(self, db):
        db.create_scan("s1", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s1"), "example.com")
        db.save_finding(_mk(url="https://gone", scan_id="s1"), "example.com")

        time.sleep(0.02)
        db.create_scan("s2", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s2"), "example.com")
        db.save_finding(_mk(url="https://NEW", scan_id="s2"), "example.com")

        new, gone = db.diff_findings("example.com", "s2")
        assert {n["url"] for n in new} == {"https://NEW"}
        assert {g["url"] for g in gone} == {"https://gone"}

    def test_get_findings_filters_compose(self, db):
        db.create_scan("s1", "example.com")
        for i, sev in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.LOW]):
            db.save_finding(
                _mk(url=f"https://x/{i}", sev=sev, scan_id="s1"),
                "example.com",
            )
        crits = db.get_findings(domain="example.com",
                                severity="critical", limit=100)
        assert len(crits) == 1
        assert crits[0]["severity"] == "critical"


# ──────────────────────────────────────────────────────────────
# Module artefacts (scan_artefacts) — Étape 0006
# ──────────────────────────────────────────────────────────────

def _sec(value, filename="https://x/a.js", sev="high"):
    return {"type": "api_key", "value": value, "filename": filename,
            "severity": sev, "confidence": 0.9, "source": "native"}


class TestArtefactsBackend:
    KEYS = ["type", "value", "filename"]

    def test_upsert_returns_count_and_get_roundtrips(self, db):
        db.create_scan("s1", "example.com")
        n = db.upsert_artefacts("s1", "example.com", "m11", "js_secret",
                                [_sec("AKIA1"), _sec("AKIA2")], self.KEYS)
        assert n == 2
        rows = db.get_artefacts("example.com", "js_secret")
        assert len(rows) == 2
        assert {r["value"] for r in rows} == {"AKIA1", "AKIA2"}

    def test_same_item_upserts_in_place(self, db):
        db.create_scan("s1", "example.com")
        db.upsert_artefacts("s1", "example.com", "m11", "js_secret",
                            [_sec("AKIA1")], self.KEYS)
        # Re-run same identity (type+value+filename) → one row, not two.
        db.upsert_artefacts("s1", "example.com", "m11", "js_secret",
                            [_sec("AKIA1", sev="critical")], self.KEYS)
        rows = db.get_artefacts("example.com", "js_secret")
        assert len(rows) == 1
        assert rows[0]["severity"] == "critical"   # data refreshed in place

    def test_diff_artefacts_new_and_gone(self, db):
        db.create_scan("s1", "example.com")
        db.upsert_artefacts("s1", "example.com", "m11", "js_secret",
                            [_sec("KEEP"), _sec("GONE")], self.KEYS)
        new, gone = db.diff_artefacts("example.com", "js_secret", "s1")
        assert {n["value"] for n in new} == {"KEEP", "GONE"} and gone == []

        time.sleep(0.02)
        db.create_scan("s2", "example.com")
        db.upsert_artefacts("s2", "example.com", "m11", "js_secret",
                            [_sec("KEEP"), _sec("NEW")], self.KEYS)
        new, gone = db.diff_artefacts("example.com", "js_secret", "s2")
        assert {n["value"] for n in new} == {"NEW"}
        assert {g["value"] for g in gone} == {"GONE"}

    def test_scan_id_filter_scopes_to_latest(self, db):
        db.create_scan("s1", "example.com")
        db.upsert_artefacts("s1", "example.com", "m11", "js_secret",
                            [_sec("KEEP"), _sec("GONE")], self.KEYS)
        time.sleep(0.02)
        db.create_scan("s2", "example.com")
        db.upsert_artefacts("s2", "example.com", "m11", "js_secret",
                            [_sec("KEEP")], self.KEYS)
        # Whole history kept (GONE survives as a stale row)…
        assert len(db.get_artefacts("example.com", "js_secret")) == 2
        # …but scoping to s2 returns only what that scan last saw.
        assert len(db.get_artefacts("example.com", "js_secret",
                                    scan_id="s2")) == 1

    def test_kind_and_domain_isolation(self, db):
        db.create_scan("s1", "example.com")
        db.create_scan("s2", "other.com")
        db.upsert_artefacts("s1", "example.com", "m11", "js_secret",
                            [_sec("A")], self.KEYS)
        db.upsert_artefacts("s1", "example.com", "m06", "takeover",
                            [{"host": "x", "service": "s3"}], ["host"])
        db.upsert_artefacts("s2", "other.com", "m11", "js_secret",
                            [_sec("B")], self.KEYS)
        assert len(db.get_artefacts("example.com", "js_secret")) == 1
        assert len(db.get_artefacts("example.com", "takeover")) == 1
        assert len(db.get_artefacts("other.com", "js_secret")) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
