"""Tests for Étape 2.2 — scope-as-code YAML loader, reasoning, restrictions.

Covers:
  - YAML parsing (valid + malformed)
  - is_in_scope_with_reason (stable reason strings)
  - ScopeRestriction.matches + Scope.get_restrictions
  - Restriction `disabled` rejects (filter_urls drops with reason)
  - find_scope_file resolution under scopes/
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from core.scope import (
    Scope,
    ScopeRestriction,
    ScopeYamlError,
    find_scope_file,
    load_scope_yaml,
)


# ─────────────────────────────────────────────────────────────────────
# YAML loader — happy path
# ─────────────────────────────────────────────────────────────────────

def _write(p: Path, body: str) -> Path:
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return p


class TestLoadScopeYaml:
    def test_minimal_valid(self, tmp_path):
        f = _write(tmp_path / "ex.yaml", """
            organisation: example-program
            apex: example.com
            scope:
              in:  ["*.example.com"]
              out: ["*.example-internal.com"]
        """)
        sc = load_scope_yaml(f)
        assert sc.organisation == "example-program"
        assert sc.apex == "example.com"
        assert sc.extra_in_scope == ["*.example.com"]
        assert sc.out_of_scope == ["*.example-internal.com"]
        assert sc.restrictions == []
        assert sc.source.startswith("yaml:")

    def test_apex_override(self, tmp_path):
        # File with no apex — caller must supply one
        f = _write(tmp_path / "x.yaml", """
            organisation: foo
            scope: {in: ["*.bar.com"]}
        """)
        sc = load_scope_yaml(f, apex_override="bar.com")
        assert sc.apex == "bar.com"
        assert sc.organisation == "foo"

    def test_string_value_coerced_to_list(self, tmp_path):
        f = _write(tmp_path / "ex.yaml", """
            organisation: ex
            apex: ex.com
            scope:
              in:  "*.ex.com"
              out: "*.bad.com"
        """)
        sc = load_scope_yaml(f)
        assert sc.extra_in_scope == ["*.ex.com"]
        assert sc.out_of_scope == ["*.bad.com"]

    def test_restrictions_parsed(self, tmp_path):
        f = _write(tmp_path / "ex.yaml", """
            organisation: ex
            apex: ex.com
            scope:
              restrictions:
                - host: "checkout.ex.com"
                  max_rps: 5
                  note: "low rate"
                - path: "/api/payments/*"
                  disabled: true
        """)
        sc = load_scope_yaml(f)
        assert len(sc.restrictions) == 2
        r1, r2 = sc.restrictions
        assert r1.host == "checkout.ex.com" and r1.max_rps == 5 and r1.note == "low rate"
        assert r2.path == "/api/payments/*" and r2.disabled is True

    def test_org_alias(self, tmp_path):
        # Accept `org:` as an alias for `organisation:`
        f = _write(tmp_path / "ex.yaml", """
            org: short-form
            apex: ex.com
        """)
        sc = load_scope_yaml(f)
        assert sc.organisation == "short-form"


# ─────────────────────────────────────────────────────────────────────
# YAML loader — malformed input
# ─────────────────────────────────────────────────────────────────────

class TestLoadScopeYamlErrors:
    def test_missing_file(self, tmp_path):
        with pytest.raises(ScopeYamlError, match="not found"):
            load_scope_yaml(tmp_path / "missing.yaml")

    def test_invalid_yaml(self, tmp_path):
        f = (tmp_path / "bad.yaml")
        f.write_text("organisation: [unterminated", encoding="utf-8")
        with pytest.raises(ScopeYamlError, match="invalid YAML"):
            load_scope_yaml(f)

    def test_top_level_not_mapping(self, tmp_path):
        f = _write(tmp_path / "bad.yaml", "- just a list\n- nope\n")
        with pytest.raises(ScopeYamlError, match="top-level"):
            load_scope_yaml(f)

    def test_missing_organisation(self, tmp_path):
        f = _write(tmp_path / "bad.yaml", "apex: ex.com\n")
        with pytest.raises(ScopeYamlError, match="organisation"):
            load_scope_yaml(f)

    def test_missing_apex(self, tmp_path):
        f = _write(tmp_path / "bad.yaml", "organisation: ex\n")
        with pytest.raises(ScopeYamlError, match="apex"):
            load_scope_yaml(f)

    def test_scope_not_mapping(self, tmp_path):
        f = _write(tmp_path / "bad.yaml", """
            organisation: ex
            apex: ex.com
            scope: "in: foo"
        """)
        with pytest.raises(ScopeYamlError, match="scope"):
            load_scope_yaml(f)

    def test_restriction_needs_host_or_path(self, tmp_path):
        f = _write(tmp_path / "bad.yaml", """
            organisation: ex
            apex: ex.com
            scope:
              restrictions:
                - max_rps: 5
        """)
        with pytest.raises(ScopeYamlError, match="host.*path"):
            load_scope_yaml(f)

    def test_restriction_max_rps_must_be_int(self, tmp_path):
        f = _write(tmp_path / "bad.yaml", """
            organisation: ex
            apex: ex.com
            scope:
              restrictions:
                - host: "*.ex.com"
                  max_rps: "five"
        """)
        with pytest.raises(ScopeYamlError, match="max_rps"):
            load_scope_yaml(f)

    def test_in_list_non_string(self, tmp_path):
        f = _write(tmp_path / "bad.yaml", """
            organisation: ex
            apex: ex.com
            scope:
              in: [123, "*.ex.com"]
        """)
        with pytest.raises(ScopeYamlError, match="scope.in"):
            load_scope_yaml(f)


# ─────────────────────────────────────────────────────────────────────
# is_in_scope_with_reason — stable reason strings
# ─────────────────────────────────────────────────────────────────────

class TestIsInScopeWithReason:
    def test_apex_reason(self):
        sc = Scope(apex="example.com")
        assert sc.is_in_scope_with_reason("example.com")          == (True, "apex")
        assert sc.is_in_scope_with_reason("api.example.com")      == (True, "apex")

    def test_extra_pattern_reason(self):
        sc = Scope(apex="x.com", extra_in_scope=["*.cdn.com"])
        ok, reason = sc.is_in_scope_with_reason("foo.cdn.com")
        assert ok is True
        assert reason == "extra:*.cdn.com"

    def test_out_wins(self):
        sc = Scope(apex="ex.com", out_of_scope=["staging.ex.com"])
        ok, reason = sc.is_in_scope_with_reason("staging.ex.com")
        assert ok is False
        assert reason == "out:staging.ex.com"

    def test_empty(self):
        sc = Scope(apex="ex.com")
        ok, reason = sc.is_in_scope_with_reason("")
        assert (ok, reason) == (False, "empty")

    def test_no_match(self):
        sc = Scope(apex="ex.com", extra_in_scope=["*.foo.com"])
        ok, reason = sc.is_in_scope_with_reason("https://google.com")
        assert ok is False
        assert reason == "no match"

    def test_back_compat_is_in_scope_still_bool(self):
        # Étape 1.1 callers still pass a bare bool around.
        sc = Scope(apex="ex.com")
        assert sc.is_in_scope("api.ex.com") is True
        assert sc.is_in_scope("foo.bar.com") is False


# ─────────────────────────────────────────────────────────────────────
# ScopeRestriction.matches + Scope.get_restrictions
# ─────────────────────────────────────────────────────────────────────

class TestScopeRestrictionMatches:
    def test_host_only(self):
        r = ScopeRestriction(host="checkout.ex.com", max_rps=5)
        assert r.matches("https://checkout.ex.com/")          is True
        assert r.matches("checkout.ex.com")                   is True
        assert r.matches("https://www.ex.com/checkout")       is False

    def test_path_only_glob(self):
        r = ScopeRestriction(path="/api/payments/*", disabled=True)
        assert r.matches("https://x.com/api/payments/charge") is True
        assert r.matches("https://x.com/api/payments/")       is True
        assert r.matches("https://x.com/api/users")           is False

    def test_path_root_for_bare_host(self):
        # A bare host is treated as path "/", so /api/* does NOT match
        # but a generic "/*" does.
        r1 = ScopeRestriction(path="/api/*")
        r2 = ScopeRestriction(path="/*")
        assert r1.matches("ex.com") is False
        assert r2.matches("ex.com") is True

    def test_host_glob(self):
        r = ScopeRestriction(host="*.payments.ex.com", disabled=True)
        assert r.matches("https://eu.payments.ex.com/x") is True
        assert r.matches("https://payments.ex.com/")     is False  # fnmatch *.x

    def test_empty_restriction_no_op(self):
        r = ScopeRestriction(max_rps=5)
        assert r.matches("anything") is False  # neither host nor path → no-op

    def test_get_restrictions_returns_all_matching(self):
        sc = Scope(apex="ex.com", restrictions=[
            ScopeRestriction(host="*.ex.com", max_rps=10),
            ScopeRestriction(path="/api/payments/*", disabled=True),
        ])
        matched = sc.get_restrictions("https://checkout.ex.com/api/payments/charge")
        assert len(matched) == 2


# ─────────────────────────────────────────────────────────────────────
# Restriction.disabled rejects via is_in_scope_with_reason + filter_urls
# ─────────────────────────────────────────────────────────────────────

class TestRestrictionDisabledFilters:
    def _scope(self):
        return Scope(
            apex="ex.com",
            restrictions=[
                ScopeRestriction(path="/api/payments/*", disabled=True),
                ScopeRestriction(host="checkout.ex.com", max_rps=5),
            ],
        )

    def test_disabled_path_rejects(self):
        sc = self._scope()
        ok, reason = sc.is_in_scope_with_reason("https://x.ex.com/api/payments/charge")
        assert ok is False
        assert reason.startswith("restriction:disabled")

    def test_max_rps_alone_does_not_reject(self):
        sc = self._scope()
        # /cart is fine, max_rps is informational
        ok, reason = sc.is_in_scope_with_reason("https://checkout.ex.com/cart")
        assert ok is True
        assert reason == "apex"

    def test_filter_urls_drops_disabled(self):
        sc = self._scope()
        urls = [
            "https://www.ex.com/login",
            "https://www.ex.com/api/payments/charge",
            "https://www.ex.com/api/users",
        ]
        kept, drops = sc.filter_urls(urls)
        assert "https://www.ex.com/login"             in kept
        assert "https://www.ex.com/api/users"         in kept
        assert "https://www.ex.com/api/payments/charge" not in kept
        # drop counted under host
        assert drops.get("www.ex.com", 0) == 1


# ─────────────────────────────────────────────────────────────────────
# find_scope_file
# ─────────────────────────────────────────────────────────────────────

class TestFindScopeFile:
    def test_returns_yaml_when_present(self, tmp_path):
        d = tmp_path / "scopes"
        d.mkdir()
        f = d / "example.com.yaml"
        f.write_text("organisation: x\napex: example.com\n")
        assert find_scope_file("example.com", scopes_dir=d) == f

    def test_returns_yml_when_present(self, tmp_path):
        d = tmp_path / "scopes"
        d.mkdir()
        f = d / "example.com.yml"
        f.write_text("organisation: x\napex: example.com\n")
        assert find_scope_file("example.com", scopes_dir=d) == f

    def test_returns_none_when_absent(self, tmp_path):
        d = tmp_path / "scopes"
        d.mkdir()
        assert find_scope_file("nothing.com", scopes_dir=d) is None

    def test_returns_none_when_dir_absent(self, tmp_path):
        assert find_scope_file("ex.com", scopes_dir=tmp_path / "nope") is None

    def test_case_insensitive_apex(self, tmp_path):
        d = tmp_path / "scopes"
        d.mkdir()
        f = d / "example.com.yaml"
        f.write_text("organisation: x\napex: example.com\n")
        assert find_scope_file("Example.COM", scopes_dir=d) == f
