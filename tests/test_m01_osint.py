"""Unit tests for M01 OSINT — pure SPF/DMARC classification, WHOIS parsing.

Pure functions only: no network, no whois binary, no DNS.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from modules.m01_osint import (
    OSINTModule,
    _classify_spf,
    _classify_dmarc,
    _SPF_RE,
    _DMARC_RE,
)
from core.models import Severity


class TestClassifySPF:
    def test_strict_all_is_info(self):
        sev, reason = _classify_spf("v=spf1 include:_spf.google.com -all")
        assert sev == Severity.INFO
        assert '-all' in reason

    def test_softfail_is_low(self):
        sev, reason = _classify_spf("v=spf1 a mx ~all")
        assert sev == Severity.LOW
        assert 'soft' in reason.lower()

    def test_neutral_is_medium(self):
        sev, reason = _classify_spf("v=spf1 ?all")
        assert sev == Severity.MEDIUM
        assert 'neutral' in reason.lower()

    def test_plus_all_is_high(self):
        sev, reason = _classify_spf("v=spf1 +all")
        assert sev == Severity.HIGH
        assert 'spoofable' in reason.lower()

    def test_no_all_mechanism_is_medium(self):
        sev, reason = _classify_spf("v=spf1 include:example.com")
        assert sev == Severity.MEDIUM
        assert 'no all' in reason.lower()

    def test_strict_takes_precedence_over_softfail_token(self):
        # '-all' must be matched before '~all' even if both substrings could
        # conceivably appear; strict wins (it is checked first).
        sev, _ = _classify_spf("v=spf1 mx -all")
        assert sev == Severity.INFO

    def test_case_insensitive(self):
        sev, _ = _classify_spf("V=SPF1 -ALL")
        assert sev == Severity.INFO


class TestClassifyDMARC:
    def test_reject_is_info(self):
        sev, reason = _classify_dmarc("v=DMARC1; p=reject; rua=mailto:a@b.com")
        assert sev == Severity.INFO
        assert 'reject' in reason

    def test_quarantine_is_low(self):
        sev, reason = _classify_dmarc("v=DMARC1; p=quarantine")
        assert sev == Severity.LOW
        assert 'quarantine' in reason.lower()

    def test_none_is_high(self):
        sev, reason = _classify_dmarc("v=DMARC1; p=none")
        assert sev == Severity.HIGH
        assert 'enforcement' in reason.lower() or 'spoofable' in reason.lower()

    def test_missing_policy_is_high(self):
        sev, reason = _classify_dmarc("v=DMARC1; rua=mailto:a@b.com")
        assert sev == Severity.HIGH
        assert 'missing' in reason.lower()

    def test_case_insensitive_policy(self):
        sev, _ = _classify_dmarc("v=DMARC1; P=REJECT")
        assert sev == Severity.INFO


class TestSPFRegex:
    def test_matches_plain_spf(self):
        assert _SPF_RE.match("v=spf1 -all")

    def test_matches_quoted_spf(self):
        assert _SPF_RE.match('"v=spf1 -all')

    def test_rejects_non_spf_txt(self):
        assert _SPF_RE.match("google-site-verification=abc") is None

    def test_rejects_dmarc(self):
        assert _SPF_RE.match("v=DMARC1; p=none") is None


class TestDMARCRegex:
    def test_extracts_policy_value(self):
        m = _DMARC_RE.search("v=DMARC1; p=quarantine; pct=100")
        assert m and m.group(1).lower() == 'quarantine'

    def test_no_match_without_policy(self):
        assert _DMARC_RE.search("v=DMARC1; rua=mailto:x@y.com") is None


class TestParseWhois:
    SAMPLE = """\
Domain Name: EXAMPLE.COM
Registrar: MarkMonitor Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2031-08-13T04:00:00Z
Updated Date: 2024-08-14T07:01:34Z
Domain Status: clientDeleteProhibited
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
"""

    def test_extracts_registrar(self):
        out = OSINTModule._parse_whois(self.SAMPLE)
        assert out['registrar'] == 'MarkMonitor Inc.'

    def test_extracts_creation_date(self):
        out = OSINTModule._parse_whois(self.SAMPLE)
        assert out['created'] == '1995-08-14T04:00:00Z'

    def test_extracts_expiry_via_registry_pattern(self):
        out = OSINTModule._parse_whois(self.SAMPLE)
        assert out['expires'] == '2031-08-13T04:00:00Z'

    def test_nameservers_lowercased_sorted_unique(self):
        out = OSINTModule._parse_whois(self.SAMPLE)
        assert out['nameservers'] == ['a.iana-servers.net', 'b.iana-servers.net']

    def test_alternate_lowercase_created_field(self):
        # ccTLD-style "created:" key handled by the second pattern.
        out = OSINTModule._parse_whois("created: 2010-01-01\nExpiration Date: 2030-01-01")
        assert out['created'] == '2010-01-01'
        assert out['expires'] == '2030-01-01'

    def test_empty_input_returns_empty_dict(self):
        assert OSINTModule._parse_whois("") == {}

    def test_no_nameserver_key_when_absent(self):
        out = OSINTModule._parse_whois("Registrar: Foo")
        assert 'nameservers' not in out

    def test_dedup_nameservers(self):
        raw = "Name Server: NS1.X.COM\nName Server: ns1.x.com\n"
        out = OSINTModule._parse_whois(raw)
        assert out['nameservers'] == ['ns1.x.com']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
