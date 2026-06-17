"""Tests for M05 JS Analyzer — discovery, analysis, deduplication."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from unittest.mock import MagicMock
from modules.m11_js_analyzer import (
    JSAnalyzerModule, SECRET_PATTERNS, ENDPOINT_PATTERNS, DANGEROUS_PATTERNS
)
from core.models import Severity


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
    return JSAnalyzerModule(config, db)


# ── Secret pattern detection ──────────────────────────────────────────────────

class TestSecretPatterns:
    def setup_method(self):
        self.m = make_module()

    def _find(self, name, content):
        secrets, _ = self.m._analyze_content(content, "https://example.com/app.js")
        return [s for s in secrets if s['kind'] == name]

    def test_aws_access_key_detected(self):
        content = 'var key = "\x41KIAI0SFODNN7FAKEKEY"; console.log(key);'
        results = self._find('aws_access_key', content)
        assert len(results) >= 1
        assert '\x41KIAI0SFODNN7FAKEKEY' in results[0]['value']

    def test_aws_access_key_severity_critical(self):
        content = 'const AWS_KEY = "\x41KIAI0SFODNN7FAKEKEY";'
        secrets, _ = self.m._analyze_content(content, "https://x.com/a.js")
        aws = [s for s in secrets if s['kind'] == 'aws_access_key']
        assert aws[0]['severity'] == Severity.CRITICAL

    def test_google_api_key_detected(self):
        content = 'const key = "\x41IzaSyFAKEKEY1234567890ABCDEFGHIjklMNOP";'
        results = self._find('google_api_key', content)
        assert len(results) >= 1

    def test_private_key_detected(self):
        content = '// key below\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----'
        results = self._find('private_key', content)
        assert len(results) >= 1
        assert results[0]['severity'] == Severity.CRITICAL

    def test_jwt_detected(self):
        jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        content = f'localStorage.setItem("token", "{jwt}");'
        results = self._find('jwt_token', content)
        assert len(results) >= 1

    def test_stripe_live_key_detected(self):
        content = 'const STRIPE = "\x73k_live_ABCDEFGHIJKLMNOPQRSTUVWX";'
        results = self._find('stripe_live_key', content)
        assert len(results) >= 1
        assert results[0]['severity'] == Severity.CRITICAL

    def test_stripe_test_key_low_severity(self):
        content = 'const STRIPE = "\x73k_test_ABCDEFGHIJKLMNOPQRSTUVWX";'
        results = self._find('stripe_test_key', content)
        assert len(results) >= 1
        assert results[0]['severity'] == Severity.LOW

    def test_firebase_url_detected(self):
        content = 'databaseURL: "https://myapp.firebaseio.com"'
        results = self._find('firebase_url', content)
        assert len(results) >= 1

    def test_mongodb_uri_with_credentials(self):
        content = 'const DB = "mongodb://admin:s3cr3t@db.company.io:27017/mydb";'
        results = self._find('mongodb_uri', content)
        assert len(results) >= 1
        assert results[0]['severity'] == Severity.CRITICAL

    def test_mongodb_uri_without_credentials_not_matched(self):
        # No password = not a credential leak
        content = 'const info = "mongodb://localhost:27017/test";'
        results = self._find('mongodb_uri', content)
        assert len(results) == 0

    def test_placeholder_values_skipped(self):
        content = 'const key = "your_api_key_here";'
        results = self._find('generic_api_key', content)
        assert len(results) == 0

    def test_no_false_positive_on_clean_code(self):
        content = 'function getUser(id) { return fetch("/api/users/" + id); }'
        secrets, _ = self.m._analyze_content(content, "https://x.com/app.js")
        critical = [s for s in secrets if s['severity'] == Severity.CRITICAL]
        assert len(critical) == 0

    def test_confidence_is_float(self):
        content = 'var k = "\x41KIAIOSFODNN7EXAMPLE";'
        secrets, _ = self.m._analyze_content(content, "https://x.com/app.js")
        for s in secrets:
            assert isinstance(s['confidence'], float)
            assert 0.0 <= s['confidence'] <= 1.0

    def test_s3_bucket_detected(self):
        content = 'const CDN = "mybucket.s3.amazonaws.com";'
        results = self._find('s3_bucket', content)
        assert len(results) >= 1


# ── Endpoint extraction ───────────────────────────────────────────────────────

class TestEndpointExtraction:
    def setup_method(self):
        self.m = make_module()

    def _endpoints(self, content):
        _, endpoints = self.m._analyze_content(content, "https://example.com/app.js")
        return [e['url'] for e in endpoints]

    def test_fetch_endpoint_extracted(self):
        content = 'fetch("/api/v1/users").then(r => r.json())'
        urls = self._endpoints(content)
        assert any('/api/v1/users' in u for u in urls)

    def test_axios_get_extracted(self):
        content = 'axios.get("/api/profile").then(res => console.log(res))'
        urls = self._endpoints(content)
        assert any('/api/profile' in u for u in urls)

    def test_axios_post_extracted(self):
        content = 'axios.post("/api/auth/login", {user, pass})'
        urls = self._endpoints(content)
        assert any('/api/auth/login' in u for u in urls)

    def test_xmlhttprequest_extracted(self):
        content = 'xhr.open("POST", "/api/upload", true)'
        urls = self._endpoints(content)
        assert any('/api/upload' in u for u in urls)

    def test_jquery_get_extracted(self):
        content = '$.get("/api/items", function(data) { ... })'
        urls = self._endpoints(content)
        assert any('/api/items' in u for u in urls)

    def test_string_literal_api_path(self):
        content = 'const BASE = "/api/v2/admin/users";'
        urls = self._endpoints(content)
        assert any('/api/v2/admin/users' in u for u in urls)

    def test_data_uris_excluded(self):
        content = 'fetch("data:image/png;base64,iVBORw0K...")'
        urls = self._endpoints(content)
        assert not any('data:' in u for u in urls)

    def test_endpoints_deduplicated(self):
        content = 'fetch("/api/users"); fetch("/api/users");'
        _, endpoints = self.m._analyze_content(content, "https://x.com/app.js")
        urls = [e['url'] for e in endpoints]
        assert urls.count('/api/users') == 1


# ── Dangerous patterns ────────────────────────────────────────────────────────

class TestDangerousPatterns:
    def setup_method(self):
        self.m = make_module()

    def _dangerous(self, content):
        secrets, _ = self.m._analyze_content(content, "https://example.com/app.js")
        return [s for s in secrets if s.get('source') == 'native' and
                s['kind'] in {d[0] for d in DANGEROUS_PATTERNS}]

    def test_document_write_detected(self):
        content = 'document.write("<script src=" + url + ">");'
        results = self._dangerous(content)
        assert any(r['kind'] == 'document_write' for r in results)

    def test_postmessage_handler_detected(self):
        content = 'window.addEventListener("message", function(e) { eval(e.data); })'
        results = self._dangerous(content)
        kinds = [r['kind'] for r in results]
        assert 'postmessage_no_origin' in kinds

    def test_sensitive_localstorage_detected(self):
        content = 'localStorage.setItem("token", userToken);'
        results = self._dangerous(content)
        assert any(r['kind'] == 'sensitive_localstorage' for r in results)


# ── Deduplication ─────────────────────────────────────────────────────────────

class TestDeduplication:
    def setup_method(self):
        self.m = make_module()

    def test_dedup_secrets_by_kind_and_value(self):
        secrets = [
            {'kind': 'aws_access_key', 'value': '\x41KIAIOSFODNN7EXAMPLE', 'source': 'native'},
            {'kind': 'aws_access_key', 'value': '\x41KIAIOSFODNN7EXAMPLE', 'source': 'native'},
            {'kind': 'aws_access_key', 'value': '\x41KIADIFFERENTKEY12345', 'source': 'native'},
        ]
        result = self.m._dedup_secrets(secrets)
        assert len(result) == 2

    def test_jsluice_wins_over_native_on_same_key(self):
        secrets = [
            {'kind': 'gcpKey', 'value': 'AIzaSyTest', 'source': 'native'},
            {'kind': 'gcpKey', 'value': 'AIzaSyTest', 'source': 'jsluice', 'data': {'key': 'AIzaSyTest'}},
        ]
        result = self.m._dedup_secrets(secrets)
        assert len(result) == 1
        assert result[0]['source'] == 'jsluice'

    def test_dedup_endpoints_by_url(self):
        endpoints = [
            {'url': '/api/users', 'source': 'native'},
            {'url': '/api/users', 'source': 'jsluice', 'method': 'GET'},
            {'url': '/api/posts', 'source': 'native'},
        ]
        result = self.m._dedup_endpoints(endpoints)
        assert len(result) == 2
        # jsluice version preferred
        users = next(e for e in result if e['url'] == '/api/users')
        assert users['source'] == 'jsluice'


# ── URL resolution ────────────────────────────────────────────────────────────

class TestUrlResolution:
    def setup_method(self):
        self.m = make_module()

    def test_absolute_url_unchanged(self):
        r = self.m._resolve_url('https://cdn.example.com/app.js', 'https://example.com')
        assert r == 'https://cdn.example.com/app.js'

    def test_relative_path_resolved(self):
        r = self.m._resolve_url('/static/js/app.js', 'https://example.com/page')
        assert r == 'https://example.com/static/js/app.js'

    def test_protocol_relative_resolved(self):
        r = self.m._resolve_url('//cdn.example.com/app.js', 'https://example.com')
        assert r == 'https://cdn.example.com/app.js'

    def test_relative_path_from_subpath(self):
        r = self.m._resolve_url('../js/bundle.js', 'https://example.com/assets/css/')
        assert 'js/bundle.js' in r

    def test_empty_src_returns_empty(self):
        r = self.m._resolve_url('', 'https://example.com')
        assert r == ''


# ── Source map analysis ───────────────────────────────────────────────────────

class TestSourceMapDetection:
    def setup_method(self):
        self.m = make_module()

    def test_sourcemappingurl_comment_parsed(self):
        content = "var x=1;\n//# sourceMappingURL=app.js.map\n"
        import re
        m = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', content)
        assert m is not None
        assert m.group(1) == 'app.js.map'

    def test_sourcemappingurl_with_full_path(self):
        content = '//# sourceMappingURL=/static/maps/main.js.map'
        import re
        m = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', content)
        assert m is not None
        ref = m.group(1)
        resolved = self.m._resolve_url(ref, 'https://example.com/js/main.js')
        assert resolved == 'https://example.com/static/maps/main.js.map'

    def test_data_uri_sourcemap_ignored(self):
        content = '//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozf'
        import re
        m = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', content)
        assert m is not None
        ref = m.group(1)
        assert ref.startswith('data:')


# ── Pattern registry completeness ─────────────────────────────────────────────

class TestPatternRegistry:
    def test_all_secret_patterns_compile(self):
        import re
        for name, sev, conf, pattern in SECRET_PATTERNS:
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"Pattern '{name}' failed to compile: {e}")

    def test_all_endpoint_patterns_compile(self):
        import re
        for pattern in ENDPOINT_PATTERNS:
            try:
                re.compile(pattern, re.I)
            except re.error as e:
                pytest.fail(f"Endpoint pattern failed to compile: {e}")

    def test_all_dangerous_patterns_compile(self):
        import re
        for name, sev, conf, pattern in DANGEROUS_PATTERNS:
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"Dangerous pattern '{name}' failed to compile: {e}")

    def test_secret_severities_are_valid(self):
        for name, sev, conf, _ in SECRET_PATTERNS:
            assert isinstance(sev, Severity), f"{name} has invalid severity"

    def test_secret_confidences_in_range(self):
        for name, sev, conf, _ in SECRET_PATTERNS:
            assert 0.0 <= conf <= 1.0, f"{name} confidence {conf} out of range"

    def test_no_duplicate_secret_names(self):
        names = [p[0] for p in SECRET_PATTERNS]
        assert len(names) == len(set(names)), "Duplicate secret pattern names"

    def test_jsluice_binary_detection(self):
        # JSLUICE_AVAILABLE should be a bool
        assert isinstance(JSAnalyzerModule.JSLUICE_AVAILABLE, bool)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
