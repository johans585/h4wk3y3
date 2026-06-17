"""Unit tests for M09 — Quick Checks.

Pure tests only: no network, no real DB. Covers the deterministic logic:
  - _classify_jwt (staticmethod) — alg=none / no-exp / kid-traversal / jku-x5u
  - _jwt_claim_names (staticmethod) — claim KEYS only, never values
  - _check_jwt — in-memory scan of live_hosts headers/cookies → findings
  - regexes: JWT_RE, CLOUD_RE, _ENV_LINE_RE
  - URL helpers: _root, _join
"""
import sys
import base64
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from unittest.mock import MagicMock

from modules.m09_quick_checks import QuickChecksModule, _root, _join
from core.models import ScanTarget, FindingType, Severity


def make_module():
    cfg = MagicMock()
    cfg.get = lambda *a, **k: k['default'] if 'default' in k else None
    db = MagicMock()
    return QuickChecksModule(cfg, db, stealth=False)


def make_target(domain='example.com'):
    return ScanTarget(domain=domain, scan_id='test-scan')


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()


def make_jwt(header: dict, payload: dict, sig: str = 'AAAAAAAA') -> str:
    return f"{_b64(header)}.{_b64(payload)}.{sig}"


# Pre-built tokens reused across tests.
JWT_NONE = make_jwt({'alg': 'none'}, {'sub': '1', 'exp': 9999999999})
JWT_NOEXP = make_jwt({'alg': 'HS256'}, {'sub': '1', 'role': 'user'})
JWT_KID = make_jwt({'alg': 'HS256', 'kid': '../../etc/passwd'}, {'exp': 9999999999})
JWT_JKU = make_jwt({'alg': 'RS256', 'jku': 'http://evil/k.json'}, {'exp': 9999999999})
JWT_OK = make_jwt({'alg': 'HS256', 'kid': 'key-1'}, {'sub': '1', 'exp': 9999999999})


class TestModuleMetadata:
    def test_module_id(self):
        assert QuickChecksModule.MODULE_ID == "m09"

    def test_graphql_paths_present(self):
        assert '/graphql' in QuickChecksModule.GRAPHQL_PATHS

    def test_env_paths_present(self):
        assert '/.env' in QuickChecksModule.ENV_PATHS


class TestURLHelpers:
    def test_root_strips_path(self):
        assert _root('https://a.example.com/foo/bar?x=1') == 'https://a.example.com/'

    def test_root_preserves_scheme(self):
        assert _root('http://a.example.com/x') == 'http://a.example.com/'

    def test_join_basic(self):
        assert _join('https://a.example.com/', '/.env') == 'https://a.example.com/.env'

    def test_join_adds_trailing_slash_to_base(self):
        assert _join('https://a.example.com', 'graphql') == 'https://a.example.com/graphql'

    def test_join_no_double_slash(self):
        assert _join('https://a.example.com/', '/graphql') == 'https://a.example.com/graphql'


class TestClassifyJWT:
    def test_alg_none_critical(self):
        w = QuickChecksModule._classify_jwt(JWT_NONE)
        assert w is not None
        assert w['severity'] == Severity.CRITICAL
        assert w['alg'] == 'NONE'
        assert 'none' in w['reason'].lower()

    def test_missing_exp_medium(self):
        w = QuickChecksModule._classify_jwt(JWT_NOEXP)
        assert w['severity'] == Severity.MEDIUM
        assert 'exp' in w['reason']

    def test_kid_path_traversal_high(self):
        w = QuickChecksModule._classify_jwt(JWT_KID)
        assert w['severity'] == Severity.HIGH
        assert 'kid' in w['reason']

    def test_kid_absolute_path_high(self):
        tok = make_jwt({'alg': 'HS256', 'kid': '/etc/shadow'}, {'exp': 9999999999})
        w = QuickChecksModule._classify_jwt(tok)
        assert w['severity'] == Severity.HIGH

    def test_jku_header_high(self):
        w = QuickChecksModule._classify_jwt(JWT_JKU)
        assert w['severity'] == Severity.HIGH
        assert 'jku' in w['reason'] or 'x5u' in w['reason']

    def test_x5u_header_high(self):
        tok = make_jwt({'alg': 'RS256', 'x5u': 'http://evil/c.pem'}, {'exp': 9999999999})
        w = QuickChecksModule._classify_jwt(tok)
        assert w['severity'] == Severity.HIGH

    def test_well_formed_token_no_weakness(self):
        assert QuickChecksModule._classify_jwt(JWT_OK) is None

    def test_garbage_returns_none(self):
        assert QuickChecksModule._classify_jwt('not.a.jwt') is None

    def test_priority_none_over_exp(self):
        # alg=none AND missing exp → must report the critical one
        tok = make_jwt({'alg': 'none'}, {'sub': '1'})
        w = QuickChecksModule._classify_jwt(tok)
        assert w['severity'] == Severity.CRITICAL


class TestJWTClaimNames:
    def test_returns_keys_only(self):
        names = QuickChecksModule._jwt_claim_names(JWT_NOEXP)
        assert set(names) == {'sub', 'role'}

    def test_does_not_leak_values(self):
        tok = make_jwt({'alg': 'HS256'}, {'email': 'victim@example.com', 'exp': 1})
        names = QuickChecksModule._jwt_claim_names(tok)
        assert 'email' in names
        # the VALUE must never appear in the returned names
        assert 'victim@example.com' not in names

    def test_garbage_returns_empty(self):
        assert QuickChecksModule._jwt_claim_names('bad.token') == []


class TestCheckJWT:
    def test_finds_weak_token_in_header(self):
        m = make_module()
        t = make_target()
        t.live_hosts = [{
            'url': 'https://a.example.com', 'domain': 'a.example.com',
            'headers': {'Authorization': f'Bearer {JWT_NONE}'},
        }]
        out = m._check_jwt(t)
        assert len(out) == 1
        assert out[0]['host'] == 'https://a.example.com'
        # token redacted: only sha256 + length, never the raw token
        assert 'token_sha256' in out[0]
        assert JWT_NONE not in json.dumps(out)
        # finding emitted
        assert len(t.findings) == 1
        f = t.findings[0]
        assert f.type == FindingType.JWT_WEAKNESS
        assert f.severity == Severity.CRITICAL

    def test_ok_token_no_finding(self):
        m = make_module()
        t = make_target()
        t.live_hosts = [{
            'url': 'https://a.example.com', 'domain': 'a.example.com',
            'headers': {'Authorization': f'Bearer {JWT_OK}'},
        }]
        out = m._check_jwt(t)
        assert out == []
        assert t.findings == []

    def test_evidence_does_not_contain_raw_token(self):
        m = make_module()
        t = make_target()
        t.live_hosts = [{
            'url': 'https://a.example.com', 'domain': 'a.example.com',
            'headers': {'Set-Cookie': f'session={JWT_KID}; HttpOnly'},
        }]
        m._check_jwt(t)
        assert len(t.findings) == 1
        assert JWT_KID not in (t.findings[0].evidence or '')

    def test_token_in_cookie_issues_list(self):
        m = make_module()
        t = make_target()
        t.live_hosts = [{
            'url': 'https://a.example.com', 'domain': 'a.example.com',
            'cookie_issues': [f'auth={JWT_JKU}'],
        }]
        out = m._check_jwt(t)
        assert len(out) == 1
        assert t.findings[0].severity == Severity.HIGH

    def test_non_dict_host_skipped(self):
        m = make_module()
        t = make_target()
        t.live_hosts = ['garbage', None]
        assert m._check_jwt(t) == []

    def test_no_token_no_finding(self):
        m = make_module()
        t = make_target()
        t.live_hosts = [{'url': 'https://a.example.com',
                         'headers': {'Server': 'nginx'}}]
        assert m._check_jwt(t) == []


class TestRegexes:
    def test_jwt_re_matches_real_token(self):
        assert QuickChecksModule.JWT_RE.search(JWT_NONE) is not None

    def test_jwt_re_no_match_on_plain_text(self):
        assert QuickChecksModule.JWT_RE.search('just some random text') is None

    def test_cloud_re_s3_virtualhosted(self):
        m = QuickChecksModule.CLOUD_RE.search(
            'https://my-bucket.s3.us-east-1.amazonaws.com/key')
        assert m is not None
        assert 'my-bucket' in m.group(0)

    def test_cloud_re_s3_path_style(self):
        assert QuickChecksModule.CLOUD_RE.search(
            'https://s3.amazonaws.com/some-bucket/x') is not None

    def test_cloud_re_gcs(self):
        assert QuickChecksModule.CLOUD_RE.search(
            'https://storage.googleapis.com/mybucket/f') is not None

    def test_cloud_re_azure_blob(self):
        assert QuickChecksModule.CLOUD_RE.search(
            'https://acct.blob.core.windows.net/c') is not None

    def test_cloud_re_no_match_normal_url(self):
        assert QuickChecksModule.CLOUD_RE.search('https://example.com/page') is None

    def test_env_line_re_captures_keys_only(self):
        body = b"APP_NAME=Argus\nDB_PASSWORD=secret123\n# comment\nAPI_KEY=abc"
        keys = [k.decode() for k in QuickChecksModule._ENV_LINE_RE.findall(body)]
        assert set(keys) == {'APP_NAME', 'DB_PASSWORD', 'API_KEY'}
        # value must not be captured
        assert 'secret123' not in keys

    def test_env_line_re_no_leading_whitespace(self):
        body = b"\n   APP_LOCALE=en\nDEBUG=true"
        keys = [k.decode() for k in QuickChecksModule._ENV_LINE_RE.findall(body)]
        # regression guard: keys must be clean, no '\nAPP_LOCALE'
        assert 'APP_LOCALE' in keys
        assert all(not k.startswith('\n') and not k.startswith(' ') for k in keys)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
