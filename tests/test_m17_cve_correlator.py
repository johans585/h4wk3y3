"""Unit tests for m17 — CVE correlator (PURE tokenisation + matching).

All target functions are module-level pure helpers + the `_compute_matches`
method which operates purely on in-memory lists (no DB, no network). We
instantiate the module with a MagicMock engine only to reach `_compute_matches`
(it never touches the engine).
"""
import json
from unittest.mock import MagicMock


from modules import m17_cve_correlator as m17
from modules.m17_cve_correlator import (
    CVECorrelatorModule,
    GENERIC_TOKENS,
)


# ─── _normalize ────────────────────────────────────────────────────────────
class TestNormalize:
    def test_lowercase_and_strip_punct(self):
        assert m17._normalize("Apache HTTP_Server!") == "apache http server"

    def test_none_and_empty(self):
        assert m17._normalize(None) == ""
        assert m17._normalize("") == ""

    def test_collapse_runs(self):
        assert m17._normalize("foo---bar...baz") == "foo bar baz"


# ─── _useful_tokens ─────────────────────────────────────────────────────────
class TestUsefulTokens:
    def test_drops_generic_and_short_and_digits(self):
        toks = m17._useful_tokens("Apache HTTP server 2 v1 solr")
        # 'http', 'server' are generic; '2' digit; 'v1' len 2 → dropped
        assert "apache" in toks
        assert "solr" in toks
        assert "http" not in toks
        assert "server" not in toks
        assert "2" not in toks
        assert "v1" not in toks

    def test_empty(self):
        assert m17._useful_tokens(None) == set()
        assert m17._useful_tokens("") == set()

    def test_all_generic_yields_empty(self):
        assert m17._useful_tokens("web api core http") == set()


# ─── host_tokens / cve_tokens ───────────────────────────────────────────────
class TestTokenAggregators:
    def test_host_tokens_union(self):
        toks = m17.host_tokens(["Apache HTTP Server", "WordPress 6.5", "nginx"])
        assert {"apache", "wordpress", "nginx"} <= toks
        assert "http" not in toks

    def test_host_tokens_empty(self):
        assert m17.host_tokens(None) == set()
        assert m17.host_tokens([]) == set()

    def test_cve_tokens_vendor_plus_products(self):
        toks = m17.cve_tokens("Apache", [
            {"vendor": "apache", "product": "solr"},
            {"vendor": "apache", "product": "tomcat"},
        ])
        assert {"apache", "solr", "tomcat"} <= toks


# ─── cve_vendor_and_product_tokens (the discriminating split) ────────────────
class TestVendorProductSplit:
    def test_specific_excludes_vendor(self):
        # Apache Solr → vendor {apache}, specific {solr}
        vt, st = m17.cve_vendor_and_product_tokens(
            "Apache", [{"vendor": "apache", "product": "solr"}])
        assert vt == {"apache"}
        assert st == {"solr"}

    def test_product_equals_vendor_yields_no_specific(self):
        # Drupal/Drupal → specific empty → vendor fallback path
        vt, st = m17.cve_vendor_and_product_tokens(
            "Drupal", [{"vendor": "drupal", "product": "drupal"}])
        assert "drupal" in vt
        assert st == set()

    def test_no_products(self):
        vt, st = m17.cve_vendor_and_product_tokens("WordPress", None)
        assert "wordpress" in vt
        assert st == set()


# ─── _compute_matches (pure, 2-tier strategy) ────────────────────────────────
def _module():
    return CVECorrelatorModule(engine=MagicMock(), log=MagicMock())


def _host(hid, host, tech):
    return {
        "id": hid, "host": host, "url": f"https://{host}",
        "status": 200, "technologies": tech,
        "attributed_apex": host, "organisation_id": 1,
        "tokens": m17.host_tokens(tech),
    }


def _cve(cve_id, vendor, products):
    vt, st = m17.cve_vendor_and_product_tokens(vendor, products)
    return {
        "cve_id": cve_id, "vendor": vendor, "products": products,
        "cvss_v3": 9.8, "epss": 0.5, "kev_flag": 1,
        "nuclei_template": None, "kev_added_at": None,
        "vendor_tokens": vt, "specific_tokens": st,
    }


class TestComputeMatches:
    def test_strict_product_match(self):
        mod = _module()
        host = _host(1, "solr.example.com", ["Apache Solr"])
        cve = _cve("CVE-2019-17558", "Apache",
                   [{"vendor": "apache", "product": "solr"}])
        matches = mod._compute_matches([cve], [host])
        assert len(matches) == 1
        m = matches[0]
        assert m["match_method"] == "product_name"
        assert m["confidence"] == 0.6
        assert m["asset_product"] == "solr"
        ev = json.loads(m["evidence"])
        assert ev["tier"] == "strict_product"
        assert ev["matched_token"] == "solr"

    def test_specific_cve_does_not_vendor_fallback(self):
        # Apache Solr CVE must NOT match a plain Apache host (no 'solr' token).
        mod = _module()
        apache_host = _host(2, "web.example.com", ["Apache HTTP Server"])
        cve = _cve("CVE-2019-17558", "Apache",
                   [{"vendor": "apache", "product": "solr"}])
        matches = mod._compute_matches([cve], [apache_host])
        assert matches == []

    def test_vendor_fallback_match(self):
        # Drupal CVE (product==vendor) → vendor-only match, confidence 0.4.
        mod = _module()
        host = _host(3, "cms.example.com", ["Drupal 9"])
        cve = _cve("CVE-2018-7600", "Drupal",
                   [{"vendor": "drupal", "product": "drupal"}])
        matches = mod._compute_matches([cve], [host])
        assert len(matches) == 1
        m = matches[0]
        assert m["match_method"] == "product_name_only"
        assert m["confidence"] == 0.4
        ev = json.loads(m["evidence"])
        assert ev["tier"] == "vendor_fallback"

    def test_no_match_when_tech_absent(self):
        mod = _module()
        host = _host(4, "nginx.example.com", ["nginx"])
        cve = _cve("CVE-2018-7600", "Drupal",
                   [{"vendor": "drupal", "product": "drupal"}])
        assert mod._compute_matches([cve], [host]) == []

    def test_dedup_same_host_per_cve(self):
        # CVE with two specific tokens both present on host → single match row.
        mod = _module()
        host = _host(5, "stack.example.com", ["Apache Solr", "Apache Tomcat"])
        cve = _cve("CVE-XXXX", "Apache", [
            {"vendor": "apache", "product": "solr"},
            {"vendor": "apache", "product": "tomcat"},
        ])
        matches = mod._compute_matches([cve], [host])
        host_ids = {m["asset_host"] for m in matches}
        # one row per host_id (dedup via seen_host_ids)
        assert len(matches) == 1
        assert host_ids == {"stack.example.com"}

    def test_multiple_hosts_one_cve(self):
        mod = _module()
        h1 = _host(6, "a.example.com", ["WordPress"])
        h2 = _host(7, "b.example.com", ["WordPress 6.5"])
        h3 = _host(8, "c.example.com", ["nginx"])
        cve = _cve("CVE-WP", "WordPress",
                   [{"vendor": "wordpress", "product": "wordpress"}])
        matches = mod._compute_matches([cve], [h1, h2, h3])
        hosts_hit = {m["asset_host"] for m in matches}
        assert hosts_hit == {"a.example.com", "b.example.com"}


def test_generic_tokens_contains_expected():
    # Guard: noise filter must include obvious protocol/generic terms.
    assert {"http", "https", "server", "web", "api"} <= GENERIC_TOKENS
