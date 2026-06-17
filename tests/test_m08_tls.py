"""Unit tests for M08 — TLS Audit.

Pure tests only: no network, no testssl.sh binary, no real DB.
Covers the deterministic helpers:
  - _classify_testssl (staticmethod) — testssl rows → classified findings
  - _pick_https_hosts — HTTPS host selection / dedup / apex-first ordering / cap
  - _TESTSSL_SEV — severity mapping table
  - _emit_findings — kind → FindingType mapping
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from unittest.mock import MagicMock

from modules.m08_tls import TLSModule, _TESTSSL_SEV
from core.models import ScanTarget, FindingType, Severity


def make_module(stealth=False):
    cfg = MagicMock()
    cfg.get = lambda *a, **k: k['default'] if 'default' in k else None
    db = MagicMock()
    return TLSModule(cfg, db, stealth=stealth)


def make_target(domain='example.com'):
    return ScanTarget(domain=domain, scan_id='test-scan')


class TestModuleMetadata:
    def test_module_id(self):
        assert TLSModule.MODULE_ID == "m08"

    def test_severity_table_maps_critical(self):
        assert _TESTSSL_SEV['CRITICAL'] == Severity.CRITICAL

    def test_severity_table_warn_to_low(self):
        assert _TESTSSL_SEV['WARN'] == Severity.LOW

    def test_severity_table_ok_to_info(self):
        assert _TESTSSL_SEV['OK'] == Severity.INFO


class TestClassifyTestssl:
    def test_info_rows_dropped(self):
        items = [
            {'id': 'whatever', 'severity': 'INFO', 'finding': 'nothing'},
            {'id': 'whatever2', 'severity': 'OK', 'finding': 'fine'},
        ]
        assert TLSModule._classify_testssl(items) == []

    def test_high_cipher_classified_as_weak(self):
        items = [{'id': 'RC4', 'severity': 'HIGH', 'finding': 'RC4 ciphers offered'}]
        out = TLSModule._classify_testssl(items)
        assert len(out) == 1
        assert out[0]['kind'] == 'TLS_WEAK'
        assert out[0]['severity'] == Severity.HIGH.value
        assert out[0]['id'] == 'RC4'
        assert 'RC4' in out[0]['message']

    def test_cert_keyword_classified_as_cert_issue(self):
        items = [{'id': 'cert_expiration', 'severity': 'MEDIUM',
                  'finding': 'expires soon'}]
        out = TLSModule._classify_testssl(items)
        assert out[0]['kind'] == 'TLS_CERT_ISSUE'

    def test_chain_keyword_is_cert_issue(self):
        items = [{'id': 'cert_chain_of_trust', 'severity': 'HIGH',
                  'finding': 'broken chain'}]
        out = TLSModule._classify_testssl(items)
        assert out[0]['kind'] == 'TLS_CERT_ISSUE'

    def test_hsts_keyword_classified_as_hsts(self):
        items = [{'id': 'HSTS', 'severity': 'LOW', 'finding': 'not offered'}]
        out = TLSModule._classify_testssl(items)
        assert out[0]['kind'] == 'HSTS'

    def test_unknown_severity_treated_as_info_dropped(self):
        items = [{'id': 'x', 'severity': 'BOGUS', 'finding': 'y'}]
        assert TLSModule._classify_testssl(items) == []

    def test_message_truncated_to_300(self):
        items = [{'id': 'x', 'severity': 'HIGH', 'finding': 'A' * 500}]
        out = TLSModule._classify_testssl(items)
        assert len(out[0]['message']) == 300

    def test_cve_preserved(self):
        items = [{'id': 'heartbleed', 'severity': 'CRITICAL',
                  'finding': 'vulnerable', 'cve': 'CVE-2014-0160'}]
        out = TLSModule._classify_testssl(items)
        assert out[0]['cve'] == 'CVE-2014-0160'

    def test_finding_falls_back_to_cve_when_no_finding_text(self):
        items = [{'id': 'x', 'severity': 'HIGH', 'cve': 'CVE-2020-1234'}]
        out = TLSModule._classify_testssl(items)
        assert out[0]['message'] == 'CVE-2020-1234'

    def test_non_dict_items_skipped(self):
        items = ['garbage', None, {'id': 'a', 'severity': 'HIGH', 'finding': 'f'}]
        out = TLSModule._classify_testssl(items)
        assert len(out) == 1

    def test_none_input(self):
        assert TLSModule._classify_testssl(None) == []

    def test_id_falls_back_to_test_key(self):
        items = [{'test': 'fallback_id', 'severity': 'HIGH', 'finding': 'f'}]
        out = TLSModule._classify_testssl(items)
        assert out[0]['id'] == 'fallback_id'


class TestPickHTTPSHosts:
    def test_only_https_kept(self):
        m = make_module()
        t = make_target()
        t.live_hosts = [
            {'url': 'https://a.example.com'},
            {'url': 'http://b.example.com'},  # plain http dropped
        ]
        hosts = m._pick_https_hosts(t, cfg={})
        assert hosts == ['a.example.com']

    def test_dedup_by_netloc(self):
        m = make_module()
        t = make_target()
        t.live_hosts = [
            {'url': 'https://a.example.com'},
            {'url': 'https://a.example.com'},
        ]
        hosts = m._pick_https_hosts(t, cfg={})
        assert hosts == ['a.example.com']

    def test_apex_first(self):
        m = make_module()
        t = make_target(domain='example.com')
        t.live_hosts = [
            {'url': 'https://zzz.example.com'},
            {'url': 'https://example.com'},
            {'url': 'https://aaa.example.com'},
        ]
        hosts = m._pick_https_hosts(t, cfg={})
        assert hosts[0] == 'example.com'

    def test_shortest_after_apex(self):
        m = make_module()
        t = make_target(domain='example.com')
        t.live_hosts = [
            {'url': 'https://longsubdomain.example.com'},
            {'url': 'https://x.example.com'},
        ]
        hosts = m._pick_https_hosts(t, cfg={})
        # both non-apex → shorter netloc first
        assert hosts[0] == 'x.example.com'

    def test_cap_applied(self):
        m = make_module()
        t = make_target()
        t.live_hosts = [{'url': f'https://h{i}.example.com'} for i in range(20)]
        hosts = m._pick_https_hosts(t, cfg={'max_hosts': 3})
        assert len(hosts) == 3

    def test_non_dict_entries_ignored(self):
        m = make_module()
        t = make_target()
        t.live_hosts = ['garbage', None, {'url': 'https://a.example.com'}]
        hosts = m._pick_https_hosts(t, cfg={})
        assert hosts == ['a.example.com']

    def test_no_https_returns_empty(self):
        m = make_module()
        t = make_target()
        t.live_hosts = [{'url': 'http://a.example.com'}]
        assert m._pick_https_hosts(t, cfg={}) == []


class TestEmitFindings:
    def test_cert_issue_maps_to_cert_finding_type(self):
        m = make_module()
        t = make_target()
        m._emit_findings(t, 'a.example.com', [
            {'id': 'cert_expiration', 'kind': 'TLS_CERT_ISSUE',
             'severity': 'high', 'message': 'expired'},
        ])
        assert len(t.findings) == 1
        f = t.findings[0]
        assert f.type == FindingType.TLS_CERT_ISSUE
        assert f.severity == Severity.HIGH
        assert 'certificate' in f.tags
        assert f.url == 'https://a.example.com'

    def test_hsts_maps_to_misconfiguration(self):
        m = make_module()
        t = make_target()
        m._emit_findings(t, 'a.example.com', [
            {'id': 'HSTS', 'kind': 'HSTS', 'severity': 'low', 'message': 'missing'},
        ])
        assert t.findings[0].type == FindingType.MISCONFIGURATION
        assert 'hsts' in t.findings[0].tags

    def test_weak_maps_to_tls_weak(self):
        m = make_module()
        t = make_target()
        m._emit_findings(t, 'a.example.com', [
            {'id': 'RC4', 'kind': 'TLS_WEAK', 'severity': 'medium', 'message': 'rc4'},
        ])
        assert t.findings[0].type == FindingType.TLS_WEAK

    def test_cve_tag_added(self):
        m = make_module()
        t = make_target()
        m._emit_findings(t, 'a.example.com', [
            {'id': 'heartbleed', 'kind': 'TLS_WEAK', 'severity': 'critical',
             'message': 'vuln', 'cve': 'CVE-2014-0160'},
        ])
        assert 'cve' in t.findings[0].tags
        assert t.findings[0].metadata['cve'] == 'CVE-2014-0160'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
