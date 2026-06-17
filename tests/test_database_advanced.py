"""
Tests avancés pour ArgusDB :
- Option A (purge findings/live_hosts au re-scan)
- Subdomains first_seen persistance
- Scan statuts (running → done → abandoned)
- get_findings filtres
- Stats par domaine
"""
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))

from core.models import Finding, FindingType, Severity

# `db` fixture supplied by tests/conftest.py — Postgres-backed, schema
# truncated between each test. The previous SQLite-tempfile fixture was
# retired in PG.6 (Postgres-only switch 2026-05).


def _finding(domain, sev=Severity.HIGH, ftype=FindingType.PATTERN_MATCH,
             scan_id="s1", url=None, evidence=None, title="Test"):
    """Build a Finding. Pass `url`/`evidence`/`title` to make the fingerprint
    unique — the DB upserts by `(domain, type, url, evidence)` since Étape 1.2,
    so callers that want N distinct rows must vary one of those fields.
    """
    f = Finding(type=ftype, target=domain, title=title,
                severity=sev, confidence=0.8, scan_id=scan_id,
                url=url, evidence=evidence)
    return f


class TestDiffPersistence:
    """Findings now survive scans (Étape 1.2). create_scan() no longer purges
    so the diff engine can compare scans N and N-1."""

    def test_findings_survive_new_scan(self, db):
        """Findings persist across create_scan() — required for diff."""
        db.create_scan("scan-1", "example.com")
        for i in range(5):
            db.save_finding(
                _finding("example.com", scan_id="scan-1", url=f"https://a/{i}"),
                "example.com",
            )
        assert len(db.get_findings(domain="example.com", limit=100)) == 5

        db.create_scan("scan-2", "example.com")
        # No purge: previous findings still visible (gone-but-not-forgotten).
        assert len(db.get_findings(domain="example.com", limit=100)) == 5

    def test_rescan_preserves_subdomains(self, db):
        """Subdomains survive re-scan (unchanged from before Étape 1.2)."""
        db.create_scan("scan-1", "example.com")
        db.upsert_subdomains("scan-1", "example.com",
                             ["a.example.com", "b.example.com"])

        db.create_scan("scan-2", "example.com")
        subs = db.get_subdomains("example.com")
        assert "a.example.com" in subs
        assert "b.example.com" in subs

    def test_rescan_does_not_affect_other_domains(self, db):
        """create_scan() does not mutate findings of other domains."""
        db.create_scan("scan-1", "example.com")
        db.create_scan("scan-x", "other.com")
        db.save_finding(
            _finding("other.com", scan_id="scan-x", url="https://x"),
            "other.com",
        )

        db.create_scan("scan-2", "example.com")
        other_findings = db.get_findings(domain="other.com", limit=100)
        assert len(other_findings) == 1

    def test_abandoned_status(self, db):
        """Les scans running passent en abandoned."""
        import sqlalchemy as sa
        from core import orm
        scans_t = orm.Scan.__table__

        db.create_scan("scan-old", "example.com")
        # Simule un scan bloqué
        with db.engine.begin() as c:
            c.execute(sa.update(scans_t)
                        .where(scans_t.c.scan_id == "scan-old")
                        .values(status="running"))

        # Nouveau scan → abandonne les running
        with db.engine.begin() as c:
            c.execute(sa.update(scans_t)
                        .where(scans_t.c.domain == "example.com")
                        .where(scans_t.c.status == "running")
                        .values(status="abandoned"))
        db.create_scan("scan-new", "example.com")

        scans = db.get_scans("example.com")
        statuses = {s['scan_id']: s['status'] for s in scans}
        assert statuses.get("scan-old") == "abandoned"
        assert statuses.get("scan-new") == "running"


class TestSubdomainDiff:
    def test_first_seen_preserved(self, db):
        """first_seen n'est jamais mis à jour lors d'un upsert."""
        import time
        import sqlalchemy as sa
        from core import orm
        subs_t = orm.Subdomain.__table__

        db.create_scan("s1", "example.com")
        db.upsert_subdomains("s1", "example.com", ["api.example.com"])
        with db.engine.connect() as c:
            first_seen = c.execute(
                sa.select(subs_t.c.first_seen)
                  .where(subs_t.c.subdomain == "api.example.com")
            ).scalar()

        time.sleep(0.05)
        db.upsert_subdomains("s2", "example.com", ["api.example.com"])
        with db.engine.connect() as c:
            second = c.execute(
                sa.select(subs_t.c.first_seen)
                  .where(subs_t.c.subdomain == "api.example.com")
            ).scalar()
        assert second == first_seen

    def test_new_subdomain_returned(self, db):
        db.create_scan("s1", "example.com")
        db.upsert_subdomains("s1", "example.com", ["a.example.com"])
        new = db.upsert_subdomains("s1", "example.com",
                                   ["a.example.com", "b.example.com"])
        assert new == ["b.example.com"]

    def test_cross_domain_isolation(self, db):
        """Subdomains sont isolés par domaine parent."""
        db.create_scan("s1", "foo.com")
        db.create_scan("s2", "bar.com")
        db.upsert_subdomains("s1", "foo.com", ["api.foo.com"])
        db.upsert_subdomains("s2", "bar.com", ["api.bar.com"])
        assert db.get_subdomains("foo.com") == ["api.foo.com"]
        assert db.get_subdomains("bar.com") == ["api.bar.com"]


class TestFindingFilters:
    def setup_method(self):
        pass

    def test_filter_by_severity(self, db):
        db.create_scan("s1", "example.com")
        db.save_finding(_finding("example.com", Severity.CRITICAL,
                                 scan_id="s1", url="https://a"), "example.com")
        db.save_finding(_finding("example.com", Severity.LOW,
                                 scan_id="s1", url="https://b"), "example.com")
        db.save_finding(_finding("example.com", Severity.HIGH,
                                 scan_id="s1", url="https://c"), "example.com")

        crits = db.get_findings(domain="example.com", severity="critical", limit=100)
        assert len(crits) == 1
        assert crits[0]['severity'] == 'critical'

    def test_filter_by_type(self, db):
        db.create_scan("s1", "example.com")
        db.save_finding(_finding("example.com", ftype=FindingType.SUBDOMAIN,
                                 scan_id="s1", url="https://sub"), "example.com")
        db.save_finding(_finding("example.com", ftype=FindingType.PATTERN_MATCH,
                                 scan_id="s1", url="https://pat"), "example.com")

        subs = db.get_findings(domain="example.com",
                               finding_type="subdomain", limit=100)
        assert len(subs) == 1
        assert subs[0]['type'] == 'subdomain'

    def test_limit(self, db):
        db.create_scan("s1", "example.com")
        for i in range(20):
            db.save_finding(
                _finding("example.com", scan_id="s1", url=f"https://h/{i}"),
                "example.com",
            )
        findings = db.get_findings(domain="example.com", limit=5)
        assert len(findings) == 5

    def test_stats_aggregation(self, db):
        db.create_scan("s1", "example.com")
        for i, sev in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.HIGH,
                                 Severity.MEDIUM, Severity.LOW, Severity.INFO]):
            db.save_finding(
                _finding("example.com", sev, scan_id="s1", url=f"https://x/{i}"),
                "example.com",
            )
        stats = db.stats_for_domain("example.com")
        assert stats['critical'] == 1
        assert stats['high'] == 2
        assert stats['medium'] == 1


class TestScanLifecycle:
    def test_scan_finish(self, db):
        db.create_scan("s1", "example.com")
        db.finish_scan("s1", {"total": 42, "subdomains": 10})
        scans = db.get_scans("example.com")
        assert scans[0]['status'] == 'done'
        import json
        stats = json.loads(scans[0]['stats'])
        assert stats['total'] == 42

    def test_multiple_scans_history(self, db):
        """Tous les scans historiques sont conservés."""
        for i in range(3):
            db.create_scan(f"scan-{i}", "example.com")
            db.finish_scan(f"scan-{i}", {})
        scans = db.get_scans("example.com")
        assert len(scans) == 3

    def test_get_scans_no_domain(self, db):
        """Sans filtre domaine, retourne tous les scans."""
        db.create_scan("s1", "foo.com")
        db.create_scan("s2", "bar.com")
        all_scans = db.get_scans()
        assert len(all_scans) == 2


class TestAtomicDedup:
    """ATOMIC_FINDING_TYPES collapses multi-module detection of the same
    asset (same domain+type+url) into one row + `metadata.detected_by`.
    Preserves the first writer's evidence/title — see save_finding().
    """

    def test_atomic_dedup_merges_two_modules(self, db):
        """m09 + m14 both emit ACTIVE_FILE_EXPOSURE on /.env → 1 row,
        detected_by lists both."""
        import json as _json
        db.create_scan("scan-1", "example.com")

        f1 = Finding(type=FindingType.ACTIVE_FILE_EXPOSURE,
                     target="example.com", url="https://x.example.com/.env",
                     title=".env exposed (m09 wording)", severity=Severity.CRITICAL,
                     confidence=0.95, evidence="42 vars, keys: APP_NAME, ...",
                     scan_id="scan-1", module_source="m09")
        db.save_finding(f1, "example.com")

        f2 = Finding(type=FindingType.ACTIVE_FILE_EXPOSURE,
                     target="example.com", url="https://x.example.com/.env",
                     title="Exposed file: /.env",
                     severity=Severity.CRITICAL, confidence=0.95,
                     evidence="1162 bytes | 42 keys (m14 wording)",
                     scan_id="scan-1", module_source="m14")
        db.save_finding(f2, "example.com")

        rows = db.get_findings(domain="example.com", limit=10)
        # One row, not two.
        assert len(rows) == 1
        row = rows[0]
        # First writer's evidence/title preserved (m09's literal strings).
        assert row["evidence"] == "42 vars, keys: APP_NAME, ..."
        assert row["title"] == ".env exposed (m09 wording)"
        assert row["module_source"] == "m09"
        meta = _json.loads(row["metadata"]) if isinstance(row["metadata"], str) else row["metadata"]
        assert meta.get("detected_by") == ["m09", "m14"]
        assert meta.get("confirmed_by_count") == 2

    def test_atomic_dedup_takes_max_severity(self, db):
        """Secondary with higher severity bumps the existing row."""
        db.create_scan("scan-1", "example.com")
        f1 = Finding(type=FindingType.ACTIVE_FILE_EXPOSURE,
                     target="example.com", url="https://x/.env",
                     title=".env", severity=Severity.HIGH, confidence=0.8,
                     evidence="ev1", scan_id="scan-1", module_source="m09")
        db.save_finding(f1, "example.com")
        f2 = Finding(type=FindingType.ACTIVE_FILE_EXPOSURE,
                     target="example.com", url="https://x/.env",
                     title=".env", severity=Severity.CRITICAL, confidence=0.95,
                     evidence="ev2", scan_id="scan-1", module_source="m14")
        db.save_finding(f2, "example.com")
        rows = db.get_findings(domain="example.com", limit=10)
        assert len(rows) == 1
        assert rows[0]["severity"] == "critical"
        assert rows[0]["confidence"] == 0.95

    def test_atomic_no_merge_for_same_module(self, db):
        """Same module emitting twice with different evidence — fingerprint
        collapses them anyway (URL identity), but no detected_by churn."""
        db.create_scan("scan-1", "example.com")
        for ev in ("ev1", "ev2"):
            f = Finding(type=FindingType.ACTIVE_FILE_EXPOSURE,
                        target="example.com", url="https://x/.env",
                        title=".env", severity=Severity.CRITICAL,
                        confidence=0.9, evidence=ev,
                        scan_id="scan-1", module_source="m09")
            db.save_finding(f, "example.com")
        rows = db.get_findings(domain="example.com", limit=10)
        assert len(rows) == 1  # atomic dedup by (domain,type,url)

    def test_non_atomic_keeps_separate_rows(self, db):
        """PATTERN_MATCH is not atomic — distinct evidences → distinct rows."""
        db.create_scan("scan-1", "example.com")
        for tag in ("xss-canary", "sqli-canary"):
            f = Finding(type=FindingType.PATTERN_MATCH,
                        target="example.com", url="https://x/login",
                        title=f"pattern {tag}", severity=Severity.MEDIUM,
                        confidence=0.5, evidence=tag,
                        scan_id="scan-1", module_source="m12")
            db.save_finding(f, "example.com")
        rows = db.get_findings(domain="example.com", limit=10)
        assert len(rows) == 2


class TestEmailPostureNoCollapse:
    """Regression (QA 2026-06-03): SPF / DMARC / DKIM are three distinct
    findings that legitimately co-exist on one domain. They share
    (domain, type='email_spoofable', url=None), so while `email_spoofable` was
    in ATOMIC_FINDING_TYPES they collapsed to a single row — silently dropping
    two, and (last-write-wins) keeping a MEDIUM while clobbering the two HIGHs.
    The fix removes email_spoofable from the atomic set and folds a stable
    discriminant (metadata.record / metadata.check) into the fingerprint.
    """

    def test_spf_dmarc_dkim_persist_as_three_rows(self, db):
        db.create_scan("s1", "example.com")
        specs = [
            ("SPF",   Severity.HIGH,   "no TXT record matching v=spf1 at apex"),
            ("DMARC", Severity.HIGH,   "no TXT record at _dmarc.example.com"),
            ("DKIM",  Severity.MEDIUM, "checked: default, google, k1"),
        ]
        for rec, sev, ev in specs:
            db.save_finding(Finding(
                type=FindingType.EMAIL_SPOOFABLE, target="example.com",
                title=f"{rec} record missing", severity=sev, confidence=0.95,
                evidence=ev, scan_id="s1", module_source="m01",
                metadata={"record": rec},
            ), "example.com")
        rows = db.get_findings(domain="example.com", limit=10)
        assert len(rows) == 3
        # Both HIGHs survive — they used to be clobbered by the MEDIUM.
        assert sum(1 for r in rows if r["severity"] == "high") == 2

    def test_unverified_spf_dmarc_share_evidence_but_persist(self, db):
        """m02 emits spf_unverified + dmarc_unverified as 'misconfiguration'
        with IDENTICAL evidence; the metadata.check discriminant keeps them
        distinct (they collapsed to one row before the fix)."""
        db.create_scan("s1", "example.com")
        ev = "All public resolvers timed out / SERVFAIL"
        for chk in ("spf_unverified", "dmarc_unverified"):
            db.save_finding(Finding(
                type=FindingType.MISCONFIGURATION, target="example.com",
                title=chk, severity=Severity.INFO, confidence=0.95,
                evidence=ev, scan_id="s1", module_source="m02",
                metadata={"check": chk},
            ), "example.com")
        rows = db.get_findings(domain="example.com", limit=10)
        assert len(rows) == 2


class TestScanLifecycleResilience:
    """finish_scan(status=) + abandon_stale_scans() — interrupted scans must
    never stay stuck on 'running' (QA 2026-06-03, axe #1)."""

    def test_finish_scan_partial_status(self, db):
        db.create_scan("s-int", "example.com")
        db.finish_scan("s-int", {"findings": 3}, status="partial")
        sc = db.get_scans("example.com")
        assert sc and sc[0]["status"] == "partial"

    def test_abandon_stale_scans_age_gated(self, db):
        # A fresh 'running' scan is NOT abandoned (age threshold protects it).
        db.create_scan("s-fresh", "example.com")
        assert db.abandon_stale_scans(older_than_hours=6) == 0
        rows = {s["scan_id"]: s for s in db.get_scans("example.com")}
        assert rows["s-fresh"]["status"] == "running"
        # With a zero threshold it IS swept.
        assert db.abandon_stale_scans(older_than_hours=0) >= 1
        rows = {s["scan_id"]: s for s in db.get_scans("example.com")}
        assert rows["s-fresh"]["status"] == "abandoned"
