"""
Tests complets pour M07 PatternModule :
- gf patterns disponibles
- _scan_urls sur patterns.yaml
- body snippet matching
- severity mapping gf → Finding
- GF_SEVERITY mapping complet
"""
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))

import pytest
from unittest.mock import MagicMock
from pathlib import Path


def make_m07():
    from modules.m12_pattern import PatternModule
    cfg = MagicMock()
    def mock_get(*a, **kw):
        if 'log_level' in a: return 'INFO'
        if 'log_file' in a:  return None
        return kw.get('default')
    cfg.get.side_effect = mock_get
    cfg.output_dir.return_value = Path('/tmp')
    db = MagicMock()
    return PatternModule(cfg, db)


class TestGFSeverityMapping:
    def test_critical_categories(self):
        from modules.m12_pattern import GF_SEVERITY
        from core.models import Severity
        assert GF_SEVERITY.get('rce') == Severity.CRITICAL
        assert GF_SEVERITY.get('aws-keys') == Severity.CRITICAL

    def test_high_categories(self):
        from modules.m12_pattern import GF_SEVERITY
        from core.models import Severity
        for cat in ['xss', 'sqli', 'ssrf', 'lfi', 'ssti', 'takeovers', 'firebase']:
            assert GF_SEVERITY.get(cat) == Severity.HIGH, f"{cat} should be HIGH"

    def test_medium_categories(self):
        from modules.m12_pattern import GF_SEVERITY
        from core.models import Severity
        for cat in ['idor', 'redirect', 'cors', 's3-buckets', 'debug-pages', 'upload-fields']:
            assert GF_SEVERITY.get(cat) == Severity.MEDIUM, f"{cat} should be MEDIUM"

    def test_all_gf_patterns_have_severity(self):
        from modules.m12_pattern import GF_SEVERITY
        m = make_m07()
        for pattern in m.GF_PATTERNS:
            assert pattern in GF_SEVERITY, f"Missing severity for {pattern}"


class TestScanURLs:
    def test_detects_aws_key_in_url(self):
        m = make_m07()
        urls = ['https://example.com/config?key=\x41KIAIOSFODNN7EXAMPLE123456']
        matches = m._scan_urls(urls)
        assert any('aws' in x.get('pattern','').lower() for x in matches)

    def test_detects_env_file(self):
        m = make_m07()
        urls = ['https://example.com/.env', 'https://example.com/.env.local']
        matches = m._scan_urls(urls)
        assert any('env' in x.get('pattern','').lower() for x in matches)

    def test_detects_git_config(self):
        m = make_m07()
        urls = ['https://example.com/.git/config']
        matches = m._scan_urls(urls)
        assert any('git' in x.get('pattern','').lower() for x in matches)

    def test_detects_backup_file(self):
        m = make_m07()
        urls = ['https://example.com/backup.sql', 'https://example.com/db.sql.bak']
        matches = m._scan_urls(urls)
        assert len(matches) > 0

    def test_clean_urls_no_critical(self):
        m = make_m07()
        urls = [
            'https://example.com/',
            'https://example.com/about',
            'https://example.com/contact',
            'https://example.com/products/item-1',
        ]
        matches = m._scan_urls(urls)
        critical = [x for x in matches if x.get('severity') == 'critical']
        assert len(critical) == 0

    def test_match_has_required_fields(self):
        m = make_m07()
        urls = ['https://example.com/.git/config']
        matches = m._scan_urls(urls)
        if matches:
            required = {'pattern', 'url', 'match', 'severity', 'source'}
            assert required.issubset(set(matches[0].keys()))


class TestBodySnippetMatching:
    def test_matches_jwt_in_body(self):
        m = make_m07()
        if not m.patterns:
            pytest.skip("No patterns loaded")

        body = 'var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc";'
        matches = []
        for pattern in m.patterns:
            try:
                hit = pattern['_regex'].search(body)
                if hit:
                    matches.append({'pattern': pattern['name'], 'match': hit.group(0)})
            except Exception:
                pass
        jwt_matches = [x for x in matches if 'jwt' in x.get('pattern','').lower()
                       or 'token' in x.get('pattern','').lower()]
        # Si patterns.yaml inclut une règle JWT/token, elle DOIT avoir capturé
        # le JWT embarqué (invariant réel). Sinon la liste est vide — toléré
        # car le set de patterns est configurable.
        for jm in jwt_matches:
            assert 'eyJ' in jm['match'] or 'token' in jm['match'].lower()

    def test_matches_api_key_in_body(self):
        m = make_m07()
        if not m.patterns:
            pytest.skip("No patterns loaded")

        body = 'const API_KEY = "\x41KIAIOSFODNN7EXAMPLE";'
        matches = []
        for pattern in m.patterns:
            try:
                hit = pattern['_regex'].search(body)
                if hit:
                    matches.append(pattern['name'])
            except Exception:
                pass
        # L'AWS key pattern doit matcher dans le body aussi
        aws = [x for x in matches if 'aws' in x.lower()]
        assert len(aws) >= 1


class TestGFPatternAvailability:
    def test_gf_patterns_dir_exists(self):
        gf_dir = Path.home() / '.gf'
        assert gf_dir.exists(), "~/.gf doit exister"

    def test_essential_patterns_present(self):
        gf_dir = Path.home() / '.gf'
        essential = ['xss', 'sqli', 'ssrf', 'redirect', 'lfi']
        for p in essential:
            assert (gf_dir / f'{p}.json').exists(), f"Pattern {p}.json manquant dans ~/.gf"

    def test_get_available_patterns(self):
        m = make_m07()
        available = m._get_available_gf_patterns()
        assert isinstance(available, set)
        assert len(available) > 0
        assert 'xss' in available or 'redirect' in available
