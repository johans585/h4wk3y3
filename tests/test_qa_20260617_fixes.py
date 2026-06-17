"""
Regression tests for the 2026-06-17 QA pass (end-to-end stress test on anpe.bj).

Covers the deterministic logic fixes:
  - ScanTarget.summary() reports DISCOVERED subdomains (matches DB/dashboard),
    not the smaller DNS-resolved subset that flows downstream.
  - m12 _cap_severity demotes URL-source param/path sniffs to LOW while keeping
    genuine sensitive references (backup/config/.git/.env) at their severity.
  - ArgusDB._canonical_url collapses ':443' / trailing-slash / case URL variants
    so the same live host never persists twice across scans.

The m11 source-map-aggregation fix (one finding per host instead of one per
.map file) is validated empirically by the anpe.bj re-scan; see the QA notes.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.models import ScanTarget, Severity
from core.database import ArgusDB
from modules.m12_pattern import _cap_severity


# ── ScanTarget.summary subdomain semantics ────────────────────────────────────
class TestSummarySubdomainCount:
    def test_reports_discovered_not_resolved(self):
        t = ScanTarget(domain="example.com")
        t.subdomains = ["a.example.com", "b.example.com"]                 # resolved subset
        t.subdomains_discovered = ["a.example.com", "b.example.com",
                                   "c.example.com", "d.example.com"]      # all discovered
        assert t.summary()["subdomains"] == 4

    def test_falls_back_when_discovered_empty(self):
        t = ScanTarget(domain="example.com")
        t.subdomains = ["a.example.com", "b.example.com"]
        assert t.summary()["subdomains"] == 2


# ── m12 URL-source severity cap ───────────────────────────────────────────────
class TestCapSeverity:
    def test_url_param_sniff_capped_to_low(self):
        # admin_panel / url_param / redirect_param are path/param guesses.
        assert _cap_severity("admin_panel", "url", Severity.MEDIUM) == Severity.LOW
        assert _cap_severity("url_param", "url", Severity.MEDIUM) == Severity.LOW

    def test_url_real_reference_keeps_severity(self):
        # A real file/secret reference literally in the URL stays high/critical.
        assert _cap_severity("backup_file", "url", Severity.HIGH) == Severity.HIGH
        assert _cap_severity("git_exposed", "url", Severity.CRITICAL) == Severity.CRITICAL

    def test_body_source_unchanged(self):
        assert _cap_severity("jwt", "body", Severity.MEDIUM) == Severity.MEDIUM
        assert _cap_severity("aws-keys", "body", Severity.CRITICAL) == Severity.CRITICAL


# ── live_hosts URL canonicalisation (de-dup) ──────────────────────────────────
class TestCanonicalUrl:
    def test_strips_default_https_port(self):
        assert ArgusDB._canonical_url("https://h:443") == "https://h"

    def test_strips_default_http_port(self):
        assert ArgusDB._canonical_url("http://h:80") == "http://h"

    def test_strips_root_trailing_slash(self):
        assert ArgusDB._canonical_url("https://h/") == "https://h"

    def test_port_and_slash_variants_collapse(self):
        a = ArgusDB._canonical_url("https://prics.anpe.bj:443")
        b = ArgusDB._canonical_url("https://prics.anpe.bj/")
        c = ArgusDB._canonical_url("https://prics.anpe.bj")
        assert a == b == c == "https://prics.anpe.bj"

    def test_keeps_non_default_port(self):
        assert ArgusDB._canonical_url("https://h:8443/x") == "https://h:8443/x"

    def test_keeps_real_path(self):
        assert ArgusDB._canonical_url("https://h/api/v1") == "https://h/api/v1"

    def test_lowercases_scheme_and_host(self):
        assert ArgusDB._canonical_url("HTTPS://H.Example.COM/") == "https://h.example.com"

    def test_passthrough_on_garbage(self):
        # No scheme/host → returned unchanged (never raises).
        assert ArgusDB._canonical_url("not a url") == "not a url"


# ── Active-findings filter (drop 'gone' history from default views) ───────────
class TestActiveFindingsFilter:
    """A noisy old scan leaves 'gone' findings in the table. The dashboard
    default must count only findings present in the LATEST scan, so a fixed +
    re-scanned target stops showing the old noise. Full history stays available
    via active=False."""

    def _add(self, db, domain, scan_id, url, sev):
        from core.models import Finding, FindingType, Severity
        db.save_finding(Finding(
            type=FindingType.PATTERN_MATCH, target=domain, url=url,
            title=f"f {url}", severity=Severity(sev), evidence=url,
            module_source="m12", scan_id=scan_id,
        ), domain)

    def test_stats_active_excludes_gone(self, db):
        import time
        dom = "active-test.example.com"
        db.create_scan("old", dom)
        for i in range(5):
            self._add(db, dom, "old", f"https://{dom}/old{i}", "medium")
        db.finish_scan("old", {})
        time.sleep(0.02)
        db.create_scan("new", dom)
        self._add(db, dom, "new", f"https://{dom}/new0", "high")
        db.finish_scan("new", {})

        assert db.latest_scan_id(dom) == "new"
        active = db.stats_for_domain(dom, active=True)
        history = db.stats_for_domain(dom, active=False)
        assert active == {"high": 1}                       # only the latest scan
        assert history.get("medium") == 5 and history.get("high") == 1
        assert sum(history.values()) == 6


# ── Source-map recovery (deep analysis of recovered source) ───────────────────
def _make_m11():
    from unittest.mock import MagicMock
    from modules.m11_js_analyzer import JSAnalyzerModule
    cfg = MagicMock()
    cfg.get.side_effect = lambda *a, **k: ('INFO' if 'log_level' in a
                                           else None if 'log_file' in a else k.get('default'))
    cfg.output_dir.return_value = Path('/tmp')
    return JSAnalyzerModule(cfg, MagicMock())


class TestSourcemapVendorFilter:
    def test_first_party_kept(self):
        from modules.m11_js_analyzer import _is_vendor_source
        assert not _is_vendor_source('webpack:///./src/api/api.js')
        assert not _is_vendor_source('webpack:///./src/components/Admin.vue?a1')
        assert not _is_vendor_source('./src/store/auth.js')

    def test_vendor_skipped(self):
        from modules.m11_js_analyzer import _is_vendor_source
        assert _is_vendor_source('webpack:///./node_modules/axios/index.js')
        assert _is_vendor_source('webpack:///webpack/bootstrap')
        assert _is_vendor_source('webpack:///webpack/runtime/jsonp')

    def test_scheme_does_not_flag_everything(self):
        # Regression: the webpack:/// scheme alone must not mark code as vendor.
        from modules.m11_js_analyzer import _is_vendor_source
        assert not _is_vendor_source('webpack:///src/main.ts')


class TestSafeSourcePath:
    def test_strips_scheme_query_and_traversal(self):
        from modules.m11_js_analyzer import _safe_source_path
        assert _safe_source_path('webpack:///./src/api/api.js?abfd') == 'src/api/api.js'
        p = _safe_source_path('webpack:///../../../../etc/passwd')
        assert '..' not in p and not p.startswith('/')


class TestRefinedSourceSecrets:
    def test_detects_service_tokens(self):
        m = _make_m11()
        code = ('const gh="\x67hp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";\n'
                'const cfg={clientSecret:"s3cr3t_9xKQ12abcdefHJ45"};')
        kinds = {s['kind'] for s in m._analyze_source_extra(code, 'f.js.map#src/c.js')}
        assert 'github_token' in kinds
        assert 'config_credential' in kinds

    def test_skips_placeholders(self):
        m = _make_m11()
        code = 'apiSecret: "your_secret_here", token: process.env.FOO'
        assert m._analyze_source_extra(code, 'f') == []


class TestSourceIntelHarvest:
    def test_harvests_recon_intel(self):
        m = _make_m11()
        code = ('const base="https://api-internal.staging.anpe.bj/v2";\n'
                'const e=process.env.API_GATEWAY_URL;\n'
                'const routes=[{path:"/admin/users"},{path:"/internal/billing"}];\n'
                'function can(){return isAdmin()||hasRole("superadmin");}\n'
                '// TODO remove hardcoded secret before prod\n')
        intel = {'internal_hosts': set(), 'api_bases': set(), 'env_vars': set(),
                 'routes': set(), 'graphql_ops': set(), 'access_control': set(),
                 'flagged_comments': [], 'files': 0}
        endpoints = []
        m._collect_source_intel(code, 'src/x.js', intel, endpoints)
        assert any('staging.anpe.bj' in h for h in intel['internal_hosts'])
        assert 'API_GATEWAY_URL' in intel['env_vars']
        assert '/admin/users' in intel['routes'] and '/internal/billing' in intel['routes']
        assert 'isAdmin' in intel['access_control']
        assert intel['flagged_comments']                     # TODO comment captured
        assert any(e['url'] == '/admin/users' for e in endpoints)  # routes → endpoints

    def test_request_shapes_and_deps(self):
        m = _make_m11()
        code = ('axios.post("/api/users/create", {name});\n'
                'this.http.get("/api/admin/list");\n'
                '/*! vue v2.6.14 */\n')
        intel = {k: set() for k in ('internal_hosts', 'api_bases', 'env_vars',
                                    'routes', 'graphql_ops', 'access_control',
                                    'requests', 'deps')}
        intel['flagged_comments'] = []
        endpoints = []
        m._collect_source_intel(code, 'f.js', intel, endpoints)
        assert 'POST /api/users/create' in intel['requests']
        assert 'GET /api/admin/list' in intel['requests']
        assert 'vue@2.6.14' in intel['deps']
        assert any(e.get('method') == 'POST' for e in endpoints)


# ── ROI: closing the loop (recovered targets → active testing) ────────────────
class TestRecoveredTargetsLoad:
    """m11 writes recovered_targets.json; m13/m14 ingest it scope-filtered so
    in-scope recovered backends get probed and out-of-scope leaks are counted
    but never scanned."""

    def test_scope_filter_keeps_inscope_drops_ip(self, tmp_path):
        import json
        from core.models import ScanTarget
        from core.scope import Scope
        (tmp_path / "recovered_targets.json").write_text(json.dumps({
            "hosts": ["sica-api.anpe.bj", "185.170.214.22:8055"],
            "api_urls": ["https://sica-api.anpe.bj/api",
                         "http://185.170.214.22:8055/api",
                         "https://bds-api.anpe.bj/v1"],
        }))
        t = ScanTarget(domain="anpe.bj")
        t.scope = Scope(apex="anpe.bj")
        m = _make_m11()
        in_scope, dropped = m._load_recovered_targets(tmp_path, t)
        # in-scope: the two *.anpe.bj api urls + https://sica-api.anpe.bj host form
        assert any("sica-api.anpe.bj/api" in u for u in in_scope)
        assert any("bds-api.anpe.bj" in u for u in in_scope)
        # the raw-IP backend is out of scope → dropped, never returned
        assert not any("185.170.214.22" in u for u in in_scope)
        assert dropped >= 1

    def test_absent_file_returns_empty(self, tmp_path):
        from core.models import ScanTarget
        m = _make_m11()
        assert m._load_recovered_targets(tmp_path, ScanTarget(domain="x.com")) == ([], 0)


class TestBackendSignatures:
    def test_signatures_well_formed(self):
        import re as _re
        from modules.m14_active import BACKEND_SIGNATURES
        assert {'directus', 'strapi', 'hasura', 'supabase', 'pocketbase'} <= set(BACKEND_SIGNATURES)
        for product, sigs in BACKEND_SIGNATURES.items():
            for path, rx, sev, label in sigs:
                assert path.startswith('/')
                _re.compile(rx)                    # regex must compile
                assert sev in ('critical', 'high', 'medium', 'low', 'info')
                assert label
