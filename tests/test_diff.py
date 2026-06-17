"""
Tests for Étape 1.2 — real inter-scan diff.

Verifies that ArgusDB:
  * upserts findings by fingerprint (domain, type, url, evidence-hash)
  * keeps findings across `create_scan()` calls (no more DELETE)
  * tracks first_seen_scan_id / last_seen_scan_id correctly
  * exposes diff_findings() returning (new, gone) lists
  * computes is_new from first_seen_scan_id (not a static field)

Also covers the pipeline integration: _save_output writes diff_new.json /
diff_gone.json files and feeds the Notifier with the new-only list.
"""
import sys
import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.database import finding_fingerprint
from core.models import Finding, FindingType, Severity, ScanTarget

# `db` fixture supplied by tests/conftest.py — Postgres-backed, schema
# truncated between each test.


def _mk(domain="example.com", url=None, sev=Severity.HIGH,
        ftype=FindingType.PATTERN_MATCH, scan_id="s1",
        evidence=None, title="Test"):
    return Finding(type=ftype, target=domain, title=title,
                   severity=sev, confidence=0.8, url=url,
                   evidence=evidence, scan_id=scan_id)


# ──────────────────────────────────────────────────────────────
# Fingerprint determinism
# ──────────────────────────────────────────────────────────────

class TestFingerprint:
    def test_same_inputs_same_fingerprint(self):
        a = finding_fingerprint("example.com", "pattern_match", "https://x", "evi")
        b = finding_fingerprint("example.com", "pattern_match", "https://x", "evi")
        assert a == b

    def test_different_url_different_fingerprint(self):
        a = finding_fingerprint("example.com", "pattern_match", "https://x", "evi")
        b = finding_fingerprint("example.com", "pattern_match", "https://y", "evi")
        assert a != b

    def test_different_domain_different_fingerprint(self):
        a = finding_fingerprint("a.com", "pattern_match", "https://x", "evi")
        b = finding_fingerprint("b.com", "pattern_match", "https://x", "evi")
        assert a != b

    def test_none_evidence_stable(self):
        a = finding_fingerprint("example.com", "pattern_match", "https://x", None)
        b = finding_fingerprint("example.com", "pattern_match", "https://x", "")
        # None and "" must collapse — both mean "no evidence".
        assert a == b


# ──────────────────────────────────────────────────────────────
# Upsert behavior
# ──────────────────────────────────────────────────────────────

class TestUpsertByFingerprint:
    def test_same_fingerprint_collapses_to_one_row(self, db):
        db.create_scan("s1", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s1"), "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s1"), "example.com")
        rows = db.get_findings(domain="example.com", limit=100)
        assert len(rows) == 1

    def test_different_url_yields_different_rows(self, db):
        db.create_scan("s1", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s1"), "example.com")
        db.save_finding(_mk(url="https://y", scan_id="s1"), "example.com")
        rows = db.get_findings(domain="example.com", limit=100)
        assert len(rows) == 2

    def test_re_observation_updates_last_seen(self, db):
        db.create_scan("s1", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s1"), "example.com")

        time.sleep(0.01)
        db.create_scan("s2", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s2"), "example.com")

        rows = db.get_findings(domain="example.com", limit=100)
        assert len(rows) == 1
        r = rows[0]
        assert r["first_seen_scan_id"] == "s1"
        assert r["last_seen_scan_id"] == "s2"
        # Re-observation must NOT mark the finding as new for s2
        assert r["is_new"] == 0

    def test_first_observation_is_new(self, db):
        db.create_scan("s1", "example.com")
        f = _mk(url="https://x", scan_id="s1")
        db.save_finding(f, "example.com")
        rows = db.get_findings(domain="example.com", limit=100)
        assert rows[0]["is_new"] == 1
        assert f.is_new is True

    def test_finding_id_canonicalized_on_upsert(self, db):
        """Subsequent save_finding() with the same fingerprint must reuse the
        DB id, so callers that hold a Finding reference see the canonical id."""
        db.create_scan("s1", "example.com")
        f1 = _mk(url="https://x", scan_id="s1")
        db.save_finding(f1, "example.com")
        original_id = f1.id

        time.sleep(0.01)
        db.create_scan("s2", "example.com")
        f2 = _mk(url="https://x", scan_id="s2")
        db.save_finding(f2, "example.com")
        # f2 must now carry the same id as f1 (dedup canonicalization)
        assert f2.id == original_id
        assert f2.is_new is False


# ──────────────────────────────────────────────────────────────
# diff_findings()
# ──────────────────────────────────────────────────────────────

class TestDiffFindings:
    def test_first_scan_all_new_none_gone(self, db):
        db.create_scan("s1", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s1"), "example.com")
        db.save_finding(_mk(url="https://y", scan_id="s1"), "example.com")
        new, gone = db.diff_findings("example.com", "s1")
        assert len(new) == 2
        assert gone == []

    def test_unchanged_second_scan_empty_diff(self, db):
        db.create_scan("s1", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s1"), "example.com")
        db.save_finding(_mk(url="https://y", scan_id="s1"), "example.com")

        time.sleep(0.01)
        db.create_scan("s2", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s2"), "example.com")
        db.save_finding(_mk(url="https://y", scan_id="s2"), "example.com")

        new, gone = db.diff_findings("example.com", "s2")
        assert new == []
        assert gone == []

    def test_new_finding_appears_in_diff_new(self, db):
        db.create_scan("s1", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s1"), "example.com")

        time.sleep(0.01)
        db.create_scan("s2", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s2"), "example.com")
        db.save_finding(_mk(url="https://NEW", scan_id="s2"), "example.com")

        new, gone = db.diff_findings("example.com", "s2")
        assert len(new) == 1
        assert new[0]["url"] == "https://NEW"
        assert gone == []

    def test_disappeared_finding_appears_in_diff_gone(self, db):
        db.create_scan("s1", "example.com")
        db.save_finding(_mk(url="https://x", scan_id="s1"), "example.com")
        db.save_finding(_mk(url="https://GONE", scan_id="s1"), "example.com")

        time.sleep(0.01)
        db.create_scan("s2", "example.com")
        # Only re-observe https://x — https://GONE disappears.
        db.save_finding(_mk(url="https://x", scan_id="s2"), "example.com")

        new, gone = db.diff_findings("example.com", "s2")
        assert new == []
        assert len(gone) == 1
        assert gone[0]["url"] == "https://GONE"

    def test_diff_isolated_per_domain(self, db):
        db.create_scan("s1a", "a.com")
        db.save_finding(_mk(domain="a.com", url="https://a", scan_id="s1a"), "a.com")
        db.create_scan("s1b", "b.com")
        db.save_finding(_mk(domain="b.com", url="https://b", scan_id="s1b"), "b.com")

        new_a, gone_a = db.diff_findings("a.com", "s1a")
        new_b, gone_b = db.diff_findings("b.com", "s1b")
        assert len(new_a) == 1 and new_a[0]["url"] == "https://a"
        assert len(new_b) == 1 and new_b[0]["url"] == "https://b"


# ──────────────────────────────────────────────────────────────
# get_previous_scan_id()
# ──────────────────────────────────────────────────────────────

class TestPreviousScanId:
    def test_none_when_first_scan(self, db):
        db.create_scan("s1", "example.com")
        assert db.get_previous_scan_id("example.com", "s1") is None

    def test_returns_immediately_previous(self, db):
        db.create_scan("s1", "example.com")
        time.sleep(0.01)
        db.create_scan("s2", "example.com")
        time.sleep(0.01)
        db.create_scan("s3", "example.com")
        assert db.get_previous_scan_id("example.com", "s3") == "s2"
        assert db.get_previous_scan_id("example.com", "s2") == "s1"
        assert db.get_previous_scan_id("example.com", "s1") is None

    def test_ignores_other_domains(self, db):
        db.create_scan("a-old", "a.com")
        time.sleep(0.01)
        db.create_scan("b-old", "b.com")
        time.sleep(0.01)
        db.create_scan("a-new", "a.com")
        assert db.get_previous_scan_id("a.com", "a-new") == "a-old"


# ──────────────────────────────────────────────────────────────
# Live hosts diff
# ──────────────────────────────────────────────────────────────

class TestLiveHostsDiff:
    def test_first_scan_all_new(self, db):
        db.create_scan("s1", "example.com")
        db.upsert_live_hosts("s1", "example.com", [
            {"url": "https://a.example.com", "status_code": 200},
            {"url": "https://b.example.com", "status_code": 200},
        ])
        new, gone = db.diff_live_hosts("example.com", "s1")
        assert len(new) == 2
        assert gone == []

    def test_first_seen_preserved_on_reobserve(self, db):
        import sqlalchemy as sa
        from core import orm
        lh_t = orm.LiveHost.__table__

        db.create_scan("s1", "example.com")
        db.upsert_live_hosts("s1", "example.com",
                             [{"url": "https://a.example.com", "status_code": 200}])
        with db.engine.connect() as c:
            first_seen = c.execute(
                sa.select(lh_t.c.first_seen)
                  .where(lh_t.c.url == "https://a.example.com")
            ).scalar()

        time.sleep(0.01)
        db.create_scan("s2", "example.com")
        db.upsert_live_hosts("s2", "example.com",
                             [{"url": "https://a.example.com", "status_code": 200}])
        with db.engine.connect() as c:
            row = c.execute(
                sa.select(lh_t.c.first_seen, lh_t.c.first_seen_scan_id,
                          lh_t.c.last_seen_scan_id)
                  .where(lh_t.c.url == "https://a.example.com")
            ).first()
        assert row.first_seen == first_seen
        assert row.first_seen_scan_id == "s1"
        assert row.last_seen_scan_id == "s2"

    def test_host_disappears_in_diff_gone(self, db):
        db.create_scan("s1", "example.com")
        db.upsert_live_hosts("s1", "example.com", [
            {"url": "https://a", "status_code": 200},
            {"url": "https://gone", "status_code": 200},
        ])
        time.sleep(0.01)
        db.create_scan("s2", "example.com")
        db.upsert_live_hosts("s2", "example.com",
                             [{"url": "https://a", "status_code": 200}])

        new, gone = db.diff_live_hosts("example.com", "s2")
        assert new == []
        assert len(gone) == 1
        assert gone[0]["url"] == "https://gone"


# ──────────────────────────────────────────────────────────────
# Pipeline integration — diff_new.json / diff_gone.json + Notifier
# ──────────────────────────────────────────────────────────────

class TestPipelineDiffOutput:
    """End-to-end: run a tiny pipeline that drops findings via the DB and
    check the JSON outputs written by `Pipeline._save_output()`."""

    @pytest.fixture
    def pipeline_setup(self, tmp_path, db, monkeypatch):
        """Stand up a Pipeline with an in-memory config pointing at tmp_path
        for output. No real modules are exercised — we just call _save_output
        with a hand-built ScanTarget."""
        from core.config import ArgusConfig
        from core.pipeline import Pipeline

        cfg = ArgusConfig.__new__(ArgusConfig)  # bypass YAML load
        cfg._data = {
            "general": {
                "output_dir": str(tmp_path),
                "log_level": "INFO",
                "log_file":  None,
            },
            "notifications": {
                "discord_webhook": "",
                "slack_webhook":   "",
                "notify_on":       ["critical", "high"],
            },
        }
        cfg.get = lambda *keys, default=None: (
            _nested_get(cfg._data, keys, default)
        )

        def _output_dir(domain):
            p = tmp_path / domain
            p.mkdir(parents=True, exist_ok=True)
            return p
        cfg.output_dir = _output_dir

        pipeline = Pipeline(cfg, db)
        return pipeline, cfg, tmp_path

    def test_diff_files_written_on_first_scan(self, db, pipeline_setup):
        pipeline, cfg, tmp_path = pipeline_setup
        target = ScanTarget(domain="example.com", scan_id="s1")
        db.create_scan("s1", "example.com")
        f = _mk(url="https://x", scan_id="s1")
        target.add_finding(f)
        db.save_finding(f, "example.com")

        pipeline._save_output(target)

        out = tmp_path / "example.com"
        assert (out / "diff_new.json").exists()
        assert (out / "diff_gone.json").exists()
        new = json.loads((out / "diff_new.json").read_text())
        gone = json.loads((out / "diff_gone.json").read_text())
        assert len(new) == 1
        assert new[0]["url"] == "https://x"
        assert gone == []

    def test_diff_files_capture_new_finding_on_second_scan(self, db, pipeline_setup):
        pipeline, cfg, tmp_path = pipeline_setup

        # Scan 1: one finding
        t1 = ScanTarget(domain="example.com", scan_id="s1")
        db.create_scan("s1", "example.com")
        f1 = _mk(url="https://x", scan_id="s1")
        t1.add_finding(f1)
        db.save_finding(f1, "example.com")
        pipeline._save_output(t1)

        time.sleep(0.01)

        # Scan 2: same x + new y
        t2 = ScanTarget(domain="example.com", scan_id="s2")
        db.create_scan("s2", "example.com")
        f2a = _mk(url="https://x", scan_id="s2")
        t2.add_finding(f2a)
        db.save_finding(f2a, "example.com")
        f2b = _mk(url="https://y", scan_id="s2")
        t2.add_finding(f2b)
        db.save_finding(f2b, "example.com")
        pipeline._save_output(t2)

        out = tmp_path / "example.com"
        new = json.loads((out / "diff_new.json").read_text())
        gone = json.loads((out / "diff_gone.json").read_text())
        # Only y is new in scan 2; x was already observed in scan 1.
        urls_new = {r["url"] for r in new}
        assert urls_new == {"https://y"}
        assert gone == []

    def test_notifier_fires_only_on_new_findings(self, db, pipeline_setup):
        pipeline, cfg, tmp_path = pipeline_setup
        # Wire a fake webhook so the notifier path runs.
        cfg._data["notifications"]["discord_webhook"] = "https://discord.example/hook"

        # Scan 1: one HIGH finding — should notify (first observation).
        t1 = ScanTarget(domain="example.com", scan_id="s1")
        db.create_scan("s1", "example.com")
        f1 = _mk(url="https://x", scan_id="s1", sev=Severity.HIGH)
        t1.add_finding(f1)
        db.save_finding(f1, "example.com")

        with patch("core.pipeline.Notifier") as MockNotifier:
            instance = MockNotifier.return_value
            instance.should_notify.return_value = True
            pipeline._save_output(t1)
            assert instance.notify.call_count == 1

        # Scan 2: same finding re-observed — must NOT notify.
        time.sleep(0.01)
        t2 = ScanTarget(domain="example.com", scan_id="s2")
        db.create_scan("s2", "example.com")
        f2 = _mk(url="https://x", scan_id="s2", sev=Severity.HIGH)
        t2.add_finding(f2)
        db.save_finding(f2, "example.com")

        with patch("core.pipeline.Notifier") as MockNotifier:
            instance = MockNotifier.return_value
            instance.should_notify.return_value = True
            pipeline._save_output(t2)
            # No new findings → Notifier should never be invoked.
            instance.notify.assert_not_called()


def _nested_get(data: dict, keys, default):
    """ArgusConfig.get(*keys, default=...) shim for the in-memory fixture."""
    if not keys:
        return data
    cur = data
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
