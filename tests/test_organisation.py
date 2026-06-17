"""Tests for core/organisation.py — multi-org CRUD + cascade behaviour (Étape 2.1)."""

from __future__ import annotations

import pytest

from core import organisation as O


# ─────────────────────────────────────────────────────────────────────
# Organisation CRUD
# ─────────────────────────────────────────────────────────────────────

class TestOrgCRUD:
    def test_list_empty(self, db):
        assert O.list_orgs(db) == []

    def test_create_basic(self, db):
        org = O.create_org(db, "acme")
        assert org["name"] == "acme"
        assert org["id"] is not None
        assert org["h1_handle"] is None

    def test_create_with_fields(self, db):
        org = O.create_org(db, "shopify",
                           h1_handle="shopify",
                           scope_file="scopes/shopify.yaml",
                           notes="big program")
        assert org["h1_handle"] == "shopify"
        assert org["scope_file"] == "scopes/shopify.yaml"
        assert org["notes"] == "big program"

    def test_create_duplicate(self, db):
        O.create_org(db, "acme")
        with pytest.raises(ValueError, match="already exists"):
            O.create_org(db, "acme")

    @pytest.mark.parametrize("bad", ["", "  ", "with/slash", "../traversal",
                                     "x" * 65])
    def test_create_validation(self, db, bad):
        with pytest.raises(ValueError):
            O.create_org(db, bad)

    def test_get_by_name(self, db):
        O.create_org(db, "acme")
        org = O.get_org(db, "acme")
        assert org is not None and org["name"] == "acme"

    def test_get_missing_returns_none(self, db):
        assert O.get_org(db, "nothing") is None

    def test_list_returns_all(self, db):
        O.create_org(db, "acme")
        O.create_org(db, "shopify")
        names = [o["name"] for o in O.list_orgs(db)]
        assert set(names) == {"acme", "shopify"}

    def test_update_partial(self, db):
        O.create_org(db, "acme", notes="initial")
        org = O.update_org(db, "acme", h1_handle="acme")
        assert org["h1_handle"] == "acme"
        assert org["notes"] == "initial"  # unchanged

    def test_update_explicit_clear(self, db):
        O.create_org(db, "acme", h1_handle="acme", notes="x")
        org = O.update_org(db, "acme", h1_handle=None)
        assert org["h1_handle"] is None
        assert org["notes"] == "x"

    def test_update_missing(self, db):
        with pytest.raises(ValueError, match="does not exist"):
            O.update_org(db, "ghost", notes="x")

    def test_delete_clean(self, db):
        O.create_org(db, "acme")
        O.delete_org(db, "acme")
        assert O.get_org(db, "acme") is None

    def test_delete_with_targets_refused(self, db):
        O.create_org(db, "acme")
        O.link_target(db, "acme.com", "acme")
        with pytest.raises(ValueError, match="linked"):
            O.delete_org(db, "acme")

    def test_delete_force_unlinks_targets(self, db):
        O.create_org(db, "acme")
        O.link_target(db, "acme.com", "acme")
        O.delete_org(db, "acme", force=True)
        assert O.get_org(db, "acme") is None
        # Target row preserved, but unlinked (FK ON DELETE SET NULL)
        t = O.get_target(db, "acme.com")
        assert t is not None
        assert t["organisation_id"] is None


# ─────────────────────────────────────────────────────────────────────
# Target ↔ org link
# ─────────────────────────────────────────────────────────────────────

class TestTargetLink:
    def test_link_creates_row(self, db):
        O.create_org(db, "acme")
        t = O.link_target(db, "acme.com", "acme")
        assert t["apex"] == "acme.com"
        org = O.get_org(db, "acme")
        assert t["organisation_id"] == org["id"]

    def test_link_normalises_apex(self, db):
        O.create_org(db, "acme")
        t = O.link_target(db, "ACME.COM.", "acme")
        assert t["apex"] == "acme.com"

    @pytest.mark.parametrize("bad", ["", "  ", "https://acme.com", "acme.com/path"])
    def test_link_apex_validation(self, db, bad):
        O.create_org(db, "acme")
        with pytest.raises(ValueError):
            O.link_target(db, bad, "acme")

    def test_link_unknown_org(self, db):
        with pytest.raises(ValueError, match="does not exist"):
            O.link_target(db, "acme.com", "ghost")

    def test_link_idempotent(self, db):
        O.create_org(db, "acme")
        O.create_org(db, "wonka")
        O.link_target(db, "acme.com", "acme")
        # Re-link to a different org → updates the existing row
        t = O.link_target(db, "acme.com", "wonka")
        wonka = O.get_org(db, "wonka")
        assert t["organisation_id"] == wonka["id"]

    def test_link_with_override(self, db):
        O.create_org(db, "acme")
        t = O.link_target(db, "acme.com", "acme",
                          scope_file_override="scopes/acme-prod.yaml")
        assert t["scope_file_override"] == "scopes/acme-prod.yaml"

    def test_unlink_preserves_row(self, db):
        O.create_org(db, "acme")
        O.link_target(db, "acme.com", "acme")
        O.unlink_target(db, "acme.com")
        t = O.get_target(db, "acme.com")
        assert t is not None
        assert t["organisation_id"] is None

    def test_link_none_detaches(self, db):
        O.create_org(db, "acme")
        O.link_target(db, "acme.com", "acme")
        t = O.link_target(db, "acme.com", None)
        assert t["organisation_id"] is None

    def test_delete_target(self, db):
        O.create_org(db, "acme")
        O.link_target(db, "acme.com", "acme")
        O.delete_target(db, "acme.com")
        assert O.get_target(db, "acme.com") is None

    def test_list_targets_for_org(self, db):
        O.create_org(db, "acme")
        O.link_target(db, "acme.com", "acme")
        O.link_target(db, "api.acme.io", "acme")
        targets = O.list_targets_for_org(db, "acme")
        apexes = {t["apex"] for t in targets}
        assert apexes == {"acme.com", "api.acme.io"}

    def test_list_unlinked(self, db):
        O.create_org(db, "acme")
        O.link_target(db, "acme.com", "acme")
        # Orphan target row
        O.link_target(db, "orphan.com", None)
        unlinked = [t["apex"] for t in O.list_unlinked_targets(db)]
        assert "orphan.com" in unlinked
        assert "acme.com" not in unlinked

    def test_organisation_for_target(self, db):
        O.create_org(db, "acme")
        O.link_target(db, "acme.com", "acme")
        org = O.organisation_for_target(db, "acme.com")
        assert org is not None and org["name"] == "acme"

    def test_organisation_for_unlinked_target(self, db):
        O.link_target(db, "orphan.com", None)
        assert O.organisation_for_target(db, "orphan.com") is None

    def test_organisation_for_unknown_target(self, db):
        assert O.organisation_for_target(db, "never-seen.com") is None


# ─────────────────────────────────────────────────────────────────────
# Stats
# ─────────────────────────────────────────────────────────────────────

class TestOrgStats:
    def test_stats_empty(self, db):
        O.create_org(db, "acme")
        s = O.org_stats(db, "acme")
        assert s["exists"] is True
        assert s["targets"] == 0
        assert s["findings"] == 0
        assert s["by_severity"] == {}

    def test_stats_with_findings(self, db):
        from core.models import Finding, FindingType, Severity
        O.create_org(db, "acme")
        O.link_target(db, "acme.com", "acme")
        db.create_scan("scan-x", "acme.com")
        for i, sev in enumerate([Severity.HIGH, Severity.HIGH, Severity.MEDIUM]):
            f = Finding(type=FindingType.PATTERN_MATCH, target="acme.com",
                        title=f"f{i}", severity=sev, confidence=0.8,
                        url=f"https://acme.com/{i}", scan_id="scan-x")
            db.save_finding(f, "acme.com")
        db.finish_scan("scan-x", {})

        s = O.org_stats(db, "acme")
        assert s["targets"] == 1
        assert s["scans"] == 1
        assert s["findings"] == 3
        assert s["by_severity"]["high"] == 2
        assert s["by_severity"]["medium"] == 1

    def test_stats_missing_org(self, db):
        s = O.org_stats(db, "ghost")
        assert s["exists"] is False
