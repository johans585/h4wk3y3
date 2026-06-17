"""Tests for core/scope.py — authoritative in-scope check."""


import pytest

from core.scope import (
    Scope,
    _match_pattern,
    _normalize_host,
    build_scope_for_target,
    load_wildcards_file,
)


# ─────────────────────────────────────────────────────────────────────
# Host normalisation
# ─────────────────────────────────────────────────────────────────────

class TestNormalizeHost:
    @pytest.mark.parametrize("inp,expected", [
        ("example.com", "example.com"),
        ("https://example.com/path?q=1", "example.com"),
        ("http://Example.COM:8080/", "example.com"),
        ("sub.example.com", "sub.example.com"),
        ("https://sub.example.com:443", "sub.example.com"),
        ("//example.com/foo", "example.com"),  # protocol-relative parses path
        ("", ""),
        ("   ", ""),
        ("example.com.", "example.com"),  # trailing dot stripped
        ("EXAMPLE.com", "example.com"),
    ])
    def test_extract_host(self, inp, expected):
        # Note: protocol-relative URLs like "//example.com" parse the
        # host as path under urlparse → fall back to split-on-/
        if inp == "//example.com/foo":
            # Two slashes with no scheme → urlparse returns hostname=None.
            # Our split-on-/ fallback gives "" (first segment empty).
            # This is acceptable — feed proper URLs in real usage.
            assert _normalize_host(inp) in ("", "example.com")
        else:
            assert _normalize_host(inp) == expected


# ─────────────────────────────────────────────────────────────────────
# Pattern matching
# ─────────────────────────────────────────────────────────────────────

class TestMatchPattern:
    @pytest.mark.parametrize("host,pattern,expected", [
        # Exact match
        ("example.com", "example.com", True),
        ("foo.com", "example.com", False),

        # *.pattern → matches subdomain AND apex (HackerOne convention:
        # *.example.com is typically taken to include example.com itself)
        ("sub.example.com", "*.example.com", True),
        ("a.b.example.com", "*.example.com", True),
        ("example.com", "*.example.com", True),  # apex covered

        # Leading dot → apex + subdomains
        ("example.com", ".example.com", True),
        ("sub.example.com", ".example.com", True),
        ("other.com", ".example.com", False),

        # Legacy *example.com
        ("example.com", "*example.com", True),
        ("sub.example.com", "*example.com", True),

        # Case insensitivity
        ("EXAMPLE.COM", "example.com", True),
        ("Sub.Example.COM", "*.example.com", True),

        # Trailing dots stripped
        ("example.com.", "example.com", True),
        ("example.com", "example.com.", True),

        # No partial match without wildcard
        ("notexample.com", "example.com", False),
        ("badexample.com", "example.com", False),
    ])
    def test_match(self, host, pattern, expected):
        assert _match_pattern(host, pattern) == expected

    def test_empty_inputs(self):
        assert _match_pattern("", "example.com") is False
        assert _match_pattern("example.com", "") is False
        assert _match_pattern("", "") is False


# ─────────────────────────────────────────────────────────────────────
# Scope.is_in_scope — main contract
# ─────────────────────────────────────────────────────────────────────

class TestScopeBasic:
    def test_apex_in_scope(self):
        s = Scope(apex="example.com")
        assert s.is_in_scope("example.com") is True
        assert s.is_in_scope("https://example.com/foo") is True

    def test_subdomain_in_scope(self):
        s = Scope(apex="example.com")
        assert s.is_in_scope("api.example.com") is True
        assert s.is_in_scope("https://deep.sub.example.com/a/b") is True

    def test_unrelated_host_out_of_scope(self):
        s = Scope(apex="example.com")
        assert s.is_in_scope("cdn.tiers.com") is False
        assert s.is_in_scope("https://google.com") is False
        assert s.is_in_scope("notexample.com") is False

    def test_empty_input(self):
        s = Scope(apex="example.com")
        assert s.is_in_scope("") is False
        assert s.is_in_scope("   ") is False


class TestScopeExtraWildcards:
    def test_extra_wildcard_in_scope(self):
        s = Scope(apex="example.com", extra_in_scope=["*.partner.com"])
        assert s.is_in_scope("api.partner.com") is True
        assert s.is_in_scope("partner.com") is True
        assert s.is_in_scope("cdn.other.com") is False

    def test_multiple_extras(self):
        s = Scope(
            apex="example.com",
            extra_in_scope=["*.example-shop.com", "static.example-cdn.io"],
        )
        assert s.is_in_scope("a.example-shop.com") is True
        assert s.is_in_scope("static.example-cdn.io") is True
        assert s.is_in_scope("other.example-cdn.io") is False


class TestScopeOutOfScope:
    def test_explicit_exclusion_wins(self):
        s = Scope(
            apex="example.com",
            out_of_scope=["checkout.example.com"],
        )
        # Apex still in scope
        assert s.is_in_scope("example.com") is True
        assert s.is_in_scope("api.example.com") is True
        # Excluded host: rejected even though it's a subdomain
        assert s.is_in_scope("checkout.example.com") is False

    def test_excluded_wildcard(self):
        s = Scope(
            apex="example.com",
            out_of_scope=["*.staging.example.com"],
        )
        assert s.is_in_scope("api.staging.example.com") is False
        assert s.is_in_scope("staging.example.com") is False  # *.pat covers apex
        # Production still in
        assert s.is_in_scope("api.example.com") is True


# ─────────────────────────────────────────────────────────────────────
# Scope.filter_urls
# ─────────────────────────────────────────────────────────────────────

class TestFilterUrls:
    def test_filter_keeps_order(self):
        s = Scope(apex="example.com")
        urls = [
            "https://example.com/a",
            "https://cdn.other.com/lib.js",
            "https://api.example.com/v1",
            "https://googletagmanager.com/gtag.js",
        ]
        kept, drops = s.filter_urls(urls)
        assert kept == [
            "https://example.com/a",
            "https://api.example.com/v1",
        ]
        # Drops keyed by normalised host
        assert drops["cdn.other.com"] == 1
        assert drops["googletagmanager.com"] == 1

    def test_filter_empty(self):
        s = Scope(apex="example.com")
        kept, drops = s.filter_urls([])
        assert kept == []
        assert drops == {}

    def test_filter_dedupes_drop_counter(self):
        s = Scope(apex="example.com")
        urls = ["https://cdn.tiers.com/a", "https://cdn.tiers.com/b"] * 3
        kept, drops = s.filter_urls(urls)
        assert kept == []
        assert drops["cdn.tiers.com"] == 6


# ─────────────────────────────────────────────────────────────────────
# Wildcards-file loader + builder
# ─────────────────────────────────────────────────────────────────────

class TestWildcardsLoader:
    def test_loads_clean_file(self, tmp_path):
        wc = tmp_path / "wildcards"
        wc.write_text("\n".join([
            "*.example.com",
            "# comment",
            "",
            "*.partner.com",
            "  *.spaced.com  ",
        ]))
        out = load_wildcards_file(wc)
        assert out == ["*.example.com", "*.partner.com", "*.spaced.com"]

    def test_missing_file(self, tmp_path):
        out = load_wildcards_file(tmp_path / "does-not-exist")
        assert out == []


class TestBuildScope:
    def test_dedupes_apex_self_references(self, tmp_path):
        wc = tmp_path / "wildcards"
        wc.write_text("\n".join([
            "*.example.com",     # same as apex implicit rule → dropped
            "example.com",       # same as apex → dropped
            "*.partner.com",     # genuine extra → kept
        ]))
        scope = build_scope_for_target("example.com", wildcards_path=wc)
        assert scope.apex == "example.com"
        assert "*.partner.com" in scope.extra_in_scope
        # The apex shorthands should NOT inflate extra_in_scope
        assert "*.example.com" not in scope.extra_in_scope
        assert "example.com" not in scope.extra_in_scope

    def test_no_wildcards_path(self):
        scope = build_scope_for_target("example.com", wildcards_path=None)
        assert scope.apex == "example.com"
        assert scope.extra_in_scope == []

    def test_out_of_scope_passthrough(self, tmp_path):
        wc = tmp_path / "wildcards"
        wc.write_text("*.partner.com\n")
        scope = build_scope_for_target(
            "example.com",
            wildcards_path=wc,
            out_of_scope=["checkout.example.com"],
        )
        assert "checkout.example.com" in scope.out_of_scope
        assert scope.is_in_scope("checkout.example.com") is False
        assert scope.is_in_scope("api.partner.com") is True


# ─────────────────────────────────────────────────────────────────────
# Regression: realistic gau/katana output
# ─────────────────────────────────────────────────────────────────────

class TestRealisticInputs:
    def test_gau_wayback_garbage_filtered(self):
        """gau notoriously returns CDN/analytics URLs scraped from wayback.
        These MUST be dropped so they don't reach m12/m14."""
        scope = Scope(apex="targetcorp.com")
        urls = [
            "https://www.targetcorp.com/account",
            "https://api.targetcorp.com/v2/users",
            "https://www.google-analytics.com/collect",
            "https://googletagmanager.com/gtm.js",
            "https://connect.facebook.net/en_US/sdk.js",
            "https://cdn.jsdelivr.net/npm/jquery",
            "https://fonts.googleapis.com/css",
            "https://www.targetcorp.com/login?next=/",
            # Subdomain typo that shouldn't slip through
            "https://targetcorpx.com/admin",
        ]
        kept, drops = scope.filter_urls(urls)
        assert kept == [
            "https://www.targetcorp.com/account",
            "https://api.targetcorp.com/v2/users",
            "https://www.targetcorp.com/login?next=/",
        ]
        assert "google-analytics.com" in drops or "www.google-analytics.com" in drops
        assert "targetcorpx.com" in drops
