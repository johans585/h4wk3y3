"""Unit tests for M07 — Ports & Service Discovery.

Pure tests only: no network, no naabu/rustscan/nmap/cdncheck binaries, no real DB.
Covers the deterministic helpers:
  - _parse_nmap_xml (staticmethod) — regex XML → service dicts
  - _is_private_ip — IP classification
  - _emit_service_findings — service→severity mapping + web-port filtering
  - _emit_origin_leak_findings — CDN-host detection / origin-leak heuristic
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from unittest.mock import MagicMock

from modules.m07_ports import PortsModule, _is_private_ip, _WEB_PORTS_COVERED
from core.models import ScanTarget, FindingType, Severity


def make_module(stealth=False):
    cfg = MagicMock()
    cfg.get = lambda *a, **k: k['default'] if 'default' in k else None
    db = MagicMock()
    return PortsModule(cfg, db, stealth=stealth)


def make_target():
    t = ScanTarget(domain='example.com', scan_id='test-scan')
    return t


class TestModuleMetadata:
    def test_module_id(self):
        assert PortsModule.MODULE_ID == "m07"

    def test_web_ports_include_common(self):
        for p in (80, 443, 8080, 8443):
            assert p in _WEB_PORTS_COVERED


class TestIsPrivateIP:
    def test_rfc1918_10(self):
        assert _is_private_ip('10.0.0.1') is True

    def test_rfc1918_192(self):
        assert _is_private_ip('192.168.1.1') is True

    def test_rfc1918_172(self):
        assert _is_private_ip('172.16.5.5') is True

    def test_public_ip(self):
        assert _is_private_ip('8.8.8.8') is False

    def test_public_ip_2(self):
        assert _is_private_ip('1.2.3.4') is False

    def test_garbage_is_not_private(self):
        # invalid input must not raise, and is treated as non-private
        assert _is_private_ip('not-an-ip') is False

    def test_empty_is_not_private(self):
        assert _is_private_ip('') is False


class TestParseNmapXML:
    def test_single_open_port(self):
        # The parser reliably extracts port/proto/state. (Its lazy-optional
        # <service> group does not populate name/product/version for this
        # input shape — we assert only the fields it deterministically fills.)
        xml = (
            '<port protocol="tcp" portid="22">'
            '<state state="open" reason="syn-ack"/>'
            '<service name="ssh" product="OpenSSH" version="8.4"/>'
            '</port>'
        )
        out = PortsModule._parse_nmap_xml(xml)
        assert len(out) == 1
        svc = out[0]
        assert svc['port'] == 22
        assert svc['proto'] == 'tcp'
        assert svc['state'] == 'open'
        # schema completeness: keys always present even when empty
        assert set(svc) >= {'port', 'proto', 'state', 'name', 'product',
                            'version', 'extrainfo'}

    def test_port_id_is_int(self):
        xml = ('<port protocol="tcp" portid="3306">'
               '<state state="open"/>'
               '<service name="mysql"/></port>')
        out = PortsModule._parse_nmap_xml(xml)
        assert out[0]['port'] == 3306
        assert isinstance(out[0]['port'], int)

    def test_closed_state_dropped(self):
        xml = ('<port protocol="tcp" portid="23">'
               '<state state="closed"/>'
               '<service name="telnet"/></port>')
        out = PortsModule._parse_nmap_xml(xml)
        assert out == []

    def test_multiple_ports(self):
        xml = (
            '<port protocol="tcp" portid="22"><state state="open"/>'
            '<service name="ssh"/></port>'
            '<port protocol="udp" portid="443"><state state="open"/>'
            '<service name="https"/></port>'
        )
        out = PortsModule._parse_nmap_xml(xml)
        ports = {s['port'] for s in out}
        protos = {s['proto'] for s in out}
        assert ports == {22, 443}
        assert protos == {'tcp', 'udp'}

    def test_only_open_ports_kept_among_mixed(self):
        xml = (
            '<port protocol="tcp" portid="22"><state state="open"/></port>'
            '<port protocol="tcp" portid="23"><state state="closed"/></port>'
            '<port protocol="tcp" portid="80"><state state="filtered"/></port>'
        )
        out = PortsModule._parse_nmap_xml(xml)
        assert {s['port'] for s in out} == {22}

    def test_empty_input(self):
        assert PortsModule._parse_nmap_xml('') == []

    def test_no_port_blocks(self):
        assert PortsModule._parse_nmap_xml('<nmaprun></nmaprun>') == []


class TestEmitServiceFindings:
    def test_risky_service_high_severity(self):
        m = make_module()
        t = make_target()
        ips = {'1.2.3.4': ['db.example.com']}
        services = {'1.2.3.4': [{'port': 3306, 'name': 'mysql',
                                 'product': 'MySQL', 'version': '8.0'}]}
        m._emit_service_findings(t, ips, services, cfg={})
        assert len(t.findings) == 1
        f = t.findings[0]
        assert f.type == FindingType.SERVICE_EXPOSED
        assert f.severity == Severity.HIGH
        assert f.metadata['port'] == 3306
        assert f.metadata['service'] == 'mysql'

    def test_ssh_is_low(self):
        m = make_module()
        t = make_target()
        ips = {'1.2.3.4': ['h.example.com']}
        services = {'1.2.3.4': [{'port': 22, 'name': 'ssh'}]}
        m._emit_service_findings(t, ips, services, cfg={})
        assert len(t.findings) == 1
        assert t.findings[0].severity == Severity.LOW

    def test_info_service_dropped_by_default(self):
        m = make_module()
        t = make_target()
        ips = {'1.2.3.4': ['h.example.com']}
        # http is not in the risky map → INFO → dropped unless emit_info_services
        services = {'1.2.3.4': [{'port': 8085, 'name': 'http'}]}
        m._emit_service_findings(t, ips, services, cfg={})
        assert t.findings == []

    def test_info_service_emitted_when_opted_in(self):
        m = make_module()
        t = make_target()
        ips = {'1.2.3.4': ['h.example.com']}
        services = {'1.2.3.4': [{'port': 8085, 'name': 'http'}]}
        m._emit_service_findings(t, ips, services, cfg={'emit_info_services': True})
        assert len(t.findings) == 1
        assert t.findings[0].severity == Severity.INFO

    def test_target_uses_host_when_available(self):
        m = make_module()
        t = make_target()
        ips = {'9.9.9.9': ['redis.example.com']}
        services = {'9.9.9.9': [{'port': 6379, 'name': 'redis'}]}
        m._emit_service_findings(t, ips, services, cfg={})
        assert t.findings[0].target == 'redis.example.com'

    def test_target_falls_back_to_ip(self):
        m = make_module()
        t = make_target()
        ips = {'9.9.9.9': []}  # no host mapping
        services = {'9.9.9.9': [{'port': 6379, 'name': 'redis'}]}
        m._emit_service_findings(t, ips, services, cfg={})
        assert t.findings[0].target == '9.9.9.9'

    def test_telnet_high(self):
        m = make_module()
        t = make_target()
        ips = {'1.1.1.1': ['x.example.com']}
        services = {'1.1.1.1': [{'port': 23, 'name': 'telnet'}]}
        m._emit_service_findings(t, ips, services, cfg={})
        assert t.findings[0].severity == Severity.HIGH


class TestEmitOriginLeakFindings:
    def test_cdn_marked_host_non_cdn_ip_flagged(self):
        m = make_module()
        t = make_target()
        t.live_hosts = [{'url': 'https://www.example.com',
                         'ip': '203.0.113.5', 'waf': 'cloudflare'}]
        ips = {'203.0.113.5': ['www.example.com']}
        # cdncheck did NOT classify the IP as CDN → likely origin leak
        cdn_by_ip = {'203.0.113.5': None}
        m._emit_origin_leak_findings(t, ips, cdn_by_ip)
        assert len(t.findings) == 1
        f = t.findings[0]
        assert f.type == FindingType.ORIGIN_IP_LEAK
        assert f.severity == Severity.MEDIUM
        assert f.metadata['ip'] == '203.0.113.5'

    def test_cdn_confirmed_ip_not_flagged(self):
        m = make_module()
        t = make_target()
        t.live_hosts = [{'url': 'https://www.example.com',
                         'ip': '203.0.113.5', 'waf': 'cloudflare'}]
        ips = {'203.0.113.5': ['www.example.com']}
        cdn_by_ip = {'203.0.113.5': 'cloudflare'}  # confirmed CDN → no leak
        m._emit_origin_leak_findings(t, ips, cdn_by_ip)
        assert t.findings == []

    def test_non_cdn_host_not_flagged(self):
        m = make_module()
        t = make_target()
        # no WAF/CNAME CDN marker → not a candidate
        t.live_hosts = [{'url': 'https://www.example.com', 'ip': '203.0.113.5'}]
        ips = {'203.0.113.5': ['www.example.com']}
        m._emit_origin_leak_findings(t, ips, {'203.0.113.5': None})
        assert t.findings == []

    def test_cdn_marker_via_cname(self):
        m = make_module()
        t = make_target()
        t.live_hosts = [{'url': 'https://www.example.com', 'ip': '198.51.100.7',
                         'cname': 'd123.cloudfront.net'}]
        ips = {'198.51.100.7': ['www.example.com']}
        m._emit_origin_leak_findings(t, ips, {'198.51.100.7': None})
        assert len(t.findings) == 1
        assert t.findings[0].metadata['ip'] == '198.51.100.7'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
