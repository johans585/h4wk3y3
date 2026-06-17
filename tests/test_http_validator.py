"""Tests for M02 HTTP Validator — tech detection, WAF detection, confidence."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from unittest.mock import MagicMock
from modules.m03_http_validator import HTTPValidatorModule


def make_module():
    config = MagicMock()
    def mock_get(*args, **kwargs):
        default = kwargs.get('default', None)
        if 'log_level' in args:
            return 'INFO'
        if 'log_file' in args:
            return None
        return default
    config.get.side_effect = mock_get
    db = MagicMock()
    return HTTPValidatorModule(config, db)


class TestTechDetection:
    """After Étape 1.3, _detect_tech is supplemental only.

    Wappalyzer-grade detection (Nginx, Apache, WordPress, Cloudflare, …) now
    comes from `httpx -tech-detect` and is parsed in `_livehost_from_httpx`
    into `LiveHost.technologies`. `_detect_tech` only adds what httpx misses:
    session-cookie fingerprints, <meta generator>, and verbatim X-Powered-By.
    """

    def setup_method(self):
        self.m = make_module()

    def test_laravel_detected_from_cookie(self):
        headers = {'Set-Cookie': 'laravel_session=abc123; Path=/'}
        result = self.m._detect_tech(headers, '')
        assert 'Laravel' in result

    def test_php_detected_from_phpsessid_cookie(self):
        headers = {'Set-Cookie': 'PHPSESSID=abc123; Path=/'}
        result = self.m._detect_tech(headers, '')
        assert 'PHP' in result

    def test_java_detected_from_jsessionid_cookie(self):
        headers = {'Set-Cookie': 'JSESSIONID=ABCD1234; Path=/'}
        result = self.m._detect_tech(headers, '')
        assert 'Java' in result

    def test_express_detected_from_connect_sid_cookie(self):
        headers = {'Set-Cookie': 'connect.sid=s%3Aabc123; Path=/; HttpOnly'}
        result = self.m._detect_tech(headers, '')
        assert 'Express' in result

    def test_generator_meta_tag_emitted(self):
        body = '<head><meta name="generator" content="WordPress 6.4.2"></head>'
        result = self.m._detect_tech({}, body)
        assert any(t.startswith('generator:WordPress') for t in result)

    def test_x_powered_by_verbatim(self):
        headers = {'X-Powered-By': 'PHP/8.2.10'}
        result = self.m._detect_tech(headers, '')
        assert any('x-powered-by:php/8.2.10' in t for t in result)

    def test_no_signal_on_empty(self):
        result = self.m._detect_tech({}, '')
        assert result == []

    def test_deduplication(self):
        # Same cookie signal must not be emitted twice.
        headers = {'Set-Cookie': 'PHPSESSID=a; phpsessid=b'}
        result = self.m._detect_tech(headers, '')
        assert result.count('PHP') == 1

    def test_no_more_server_header_detection(self):
        """Regression guard: _detect_tech must NOT re-detect signals already
        produced by httpx -td (Nginx/Apache/WordPress/Cloudflare/...)."""
        headers = {'Server': 'nginx/1.21.0', 'Set-Cookie': 'PHPSESSID=x'}
        body    = '<html><body>wp-content/themes/main.css</body></html>'
        result = self.m._detect_tech(headers, body)
        # PHP from cookie still emitted, Nginx / WordPress no longer.
        assert 'PHP' in result
        assert 'Nginx' not in result
        assert 'WordPress' not in result


class TestWAFDetection:
    def setup_method(self):
        self.m = make_module()

    def test_cloudflare_waf(self):
        headers = {'CF-Ray': '7e3f4a5b6c7d8e9f-CDG', 'Server': 'cloudflare'}
        assert self.m._detect_waf(headers) == 'Cloudflare'

    def test_imperva_waf(self):
        headers = {'X-Iinfo': '1-2-3-4', 'Set-Cookie': 'incap_ses_xyz=abc'}
        assert self.m._detect_waf(headers) == 'Imperva/Incapsula'

    def test_sucuri_waf(self):
        headers = {'X-Sucuri-ID': '12345'}
        assert self.m._detect_waf(headers) == 'Sucuri'

    def test_no_waf_returns_none(self):
        headers = {'Server': 'nginx', 'Content-Type': 'text/html'}
        assert self.m._detect_waf(headers) is None


# NOTE: TestConfidenceScoring and TestFaviconUrlHash used to cover the legacy
# `_confidence(status)` and `_favicon_url_hash(body, base_url)` helpers. Both
# have been replaced by the httpx-driven pipeline:
#   - confidence scoring is no longer surfaced as a standalone method (status
#     comes straight from httpx and is consumed downstream)
#   - favicon hashing is now async (`_favicon_href` extracts the href and
#     `_fetch_favicon_hash` fetches+hashes content via the live session),
#     which can't be exercised with the pure-synchronous fixtures these tests
#     were built on.
# The covering tests live in test_recent_changes.py / integration runs.


class TestFaviconHrefExtraction:
    """Cover the synchronous href-extraction step that survived the refactor."""

    def setup_method(self):
        self.m = make_module()

    def test_extracts_favicon_path(self):
        body = '<link rel="icon" href="/favicon.ico">'
        result = self.m._favicon_href(body, 'https://example.com')
        assert result == 'https://example.com/favicon.ico'

    def test_shortcut_icon_variant(self):
        body = '<link rel="shortcut icon" href="/static/icon.png">'
        result = self.m._favicon_href(body, 'https://example.com')
        assert result == 'https://example.com/static/icon.png'

    def test_no_link_tag_falls_back_to_root_favicon(self):
        # When the page has no <link rel="icon"> the helper falls back to the
        # conventional /favicon.ico location.
        body = '<html><head><title>Test</title></head></html>'
        result = self.m._favicon_href(body, 'https://example.com')
        assert result == 'https://example.com/favicon.ico'


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
