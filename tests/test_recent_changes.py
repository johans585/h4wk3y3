"""Targeted tests for the recent changes across modules."""
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from modules.m02_subdomain import SubdomainModule
from modules.m03_http_validator import (
    HTTPValidatorModule, TECH_PATTERNS, FAVICON_HASHES
)
from modules.m04_url_collector import (
    _scale, _chunks, MEDIUM_HOSTS, LARGE_HOSTS, URL_HARD_CAP,
    WAYBACK_PARALLEL, HOSTS_PER_BATCH,
)
from modules.m06_takeover import TAKEOVER_SIGNATURES
from modules.m13_nuclei import NucleiModule


# ──────────────────────────────────────────────────────────────────────
# M01 — dnsx resolvers fallback + drop-ratio guard
# ──────────────────────────────────────────────────────────────────────
class TestM01Resolvers:
    @pytest.fixture
    def module(self, tmp_path):
        cfg = MagicMock()
        cfg.get = lambda *a, **k: k.get('default', {})
        cfg.output_dir = lambda d: tmp_path
        return SubdomainModule(cfg, MagicMock(), stealth=False)

    def test_resolvers_fallback_when_missing(self, module, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = module._resolvers_path()
        assert path is not None
        content = Path(path).read_text().splitlines()
        assert "1.1.1.1" in content
        assert "8.8.8.8" in content
        assert len([r for r in content if r.strip()]) >= 8

    def test_resolvers_fallback_when_empty(self, module, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # Pre-create an EMPTY file
        empty = tmp_path / "data" / "resolvers" / "resolvers.txt"
        empty.parent.mkdir(parents=True, exist_ok=True)
        empty.write_text("")
        # Wipe cache from any previous fixture
        module._resolvers_cached = None
        path = module._resolvers_path()
        assert path is not None
        content = Path(path).read_text().strip()
        assert content, "resolvers should be re-populated when empty"

    def test_resolvers_uses_existing_file(self, module, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        existing = tmp_path / "data" / "resolvers" / "resolvers.txt"
        existing.parent.mkdir(parents=True, exist_ok=True)
        existing.write_text("9.9.9.9\n")
        module._resolvers_cached = None
        path = module._resolvers_path()
        assert Path(path).read_text() == "9.9.9.9\n"


# ──────────────────────────────────────────────────────────────────────
# M02 — Tech detection upgrades
# ──────────────────────────────────────────────────────────────────────
class TestM02TechFingerprinting:
    @pytest.fixture
    def module(self, tmp_path):
        cfg = MagicMock()
        cfg.get = lambda *a, **k: k.get('default', {})
        cfg.output_dir = lambda d: tmp_path
        return HTTPValidatorModule(cfg, MagicMock(), stealth=False)

    def test_tech_pattern_count(self):
        # Étape 1.3 — table is now cookie-only supplement; httpx -td handles
        # the rest. Asserting a small range (NOT 0) catches both regressions
        # (someone re-added redundant regex) and accidental deletes.
        assert 5 <= len(TECH_PATTERNS) <= 25

    def test_favicon_hashes_have_known_entries(self):
        assert "GitLab" in FAVICON_HASHES.values()
        assert "Jenkins" in FAVICON_HASHES.values()

    def test_meta_generator_extracted(self, module):
        body = '<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>'
        techs = module._detect_tech({}, body)
        assert any('generator:WordPress 6.4.2' in t for t in techs)

    def test_x_powered_by_captured_verbatim(self, module):
        techs = module._detect_tech({'X-Powered-By': 'Express/4.18.2'}, '')
        assert any('x-powered-by:express/4.18.2' in t.lower() for t in techs)

    def test_modern_framework_via_generator_meta(self, module):
        # Étape 1.3 — SvelteKit / Astro / Remix / etc. now detected by httpx
        # -td. The fallback we keep is the <meta generator> tag which httpx
        # currently does NOT parse — that's our last-resort version capture.
        body = '<head><meta name="generator" content="SvelteKit v2.5"></head>'
        techs = module._detect_tech({}, body)
        assert any('generator:SvelteKit' in t for t in techs)

    def test_session_cookie_php(self, module):
        techs = module._detect_tech({'Set-Cookie': 'PHPSESSID=abcdef; Path=/'}, '')
        assert "PHP" in techs

    def test_session_cookie_aspnet(self, module):
        techs = module._detect_tech(
            {'Set-Cookie': 'ASP.NET_SessionId=xyz; HttpOnly'}, '')
        assert "ASP.NET" in techs


# ──────────────────────────────────────────────────────────────────────
# M03 — Resource safety helpers
# ──────────────────────────────────────────────────────────────────────
class TestM03ResourceSafety:
    def test_scale_no_change_small(self):
        assert _scale(20, 50) == 20

    def test_scale_halves_on_medium(self):
        assert _scale(20, MEDIUM_HOSTS) == 10
        assert _scale(20, MEDIUM_HOSTS + 50) == 10

    def test_scale_quarters_on_large(self):
        assert _scale(20, LARGE_HOSTS) == 5
        assert _scale(20, LARGE_HOSTS + 100) == 5

    def test_scale_floor_of_one(self):
        assert _scale(2, LARGE_HOSTS) >= 1

    def test_chunks_yields_exact_sizes(self):
        out = list(_chunks(list(range(125)), 50))
        assert len(out) == 3
        assert len(out[0]) == 50
        assert len(out[2]) == 25

    def test_constants_sane(self):
        assert WAYBACK_PARALLEL <= 20
        assert HOSTS_PER_BATCH >= 10
        assert URL_HARD_CAP >= 100_000


# ──────────────────────────────────────────────────────────────────────
# M06 — Modern takeover signatures
# ──────────────────────────────────────────────────────────────────────
class TestM06ModernSignatures:
    def test_modern_paas_present(self):
        services = {svc.lower() for _, svc, _ in TAKEOVER_SIGNATURES}
        for s in ("vercel", "render", "fly.io", "supabase",
                  "cloudflare workers", "cloudflare pages"):
            assert s in services, f"missing modern service: {s}"

    def test_count_grew(self):
        # Original was 28 — we expanded to ~70+
        assert len(TAKEOVER_SIGNATURES) >= 60

    def test_no_duplicate_cnames(self):
        cnames = [c for c, _, _ in TAKEOVER_SIGNATURES]
        assert len(cnames) == len(set(cnames)), "Duplicate CNAME pattern"


# ──────────────────────────────────────────────────────────────────────
# M08 — High-impact info templates
# ──────────────────────────────────────────────────────────────────────
class TestM08HighImpactInfo:
    @pytest.fixture
    def module(self, tmp_path):
        cfg = MagicMock()
        cfg.get = lambda *a, **k: k.get('default', {})
        cfg.output_dir = lambda d: tmp_path
        return NucleiModule(cfg, MagicMock(), stealth=False)

    def test_module_id(self, module):
        assert module.MODULE_ID == "m13"


# ──────────────────────────────────────────────────────────────────────
# Pipeline includes M09
# ──────────────────────────────────────────────────────────────────────
def test_pipeline_includes_m09():
    from core.pipeline import Pipeline
    ids = [m[0] for m in Pipeline.MODULE_ORDER]
    assert "m14" in ids
    # And it runs after m13
    assert ids.index("m14") > ids.index("m13")
