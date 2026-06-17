"""Tests for core data models."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import Finding, FindingType, Severity, ScanTarget, LiveHost


def test_finding_creation():
    f = Finding(
        type=FindingType.SUBDOMAIN,
        target="sub.example.com",
        title="Test subdomain",
        severity=Severity.INFO,
        confidence=0.9
    )
    assert f.type == FindingType.SUBDOMAIN
    assert f.severity == Severity.INFO
    assert f.confidence == 0.9
    assert f.id  # UUID generated


def test_finding_serialization():
    f = Finding(
        type=FindingType.JS_SECRET,
        target="example.com",
        title="AWS Key found",
        severity=Severity.CRITICAL,
        confidence=0.95,
        evidence="\x41KIAIOSFODNN7EXAMPLE"
    )
    d = f.to_dict()
    assert d['type'] == 'js_secret'
    assert d['severity'] == 'critical'
    assert d['evidence'] == '\x41KIAIOSFODNN7EXAMPLE'

    # Round-trip
    f2 = Finding.from_dict(d)
    assert f2.type == FindingType.JS_SECRET
    assert f2.severity == Severity.CRITICAL


def test_scan_target():
    t = ScanTarget(domain="example.com")
    assert t.domain == "example.com"
    assert t.scan_id  # UUID generated

    f = Finding(
        type=FindingType.LIVE_HOST,
        target="example.com",
        title="Live host",
        severity=Severity.INFO
    )
    t.add_finding(f)
    assert len(t.findings) == 1
    assert f.scan_id == t.scan_id

    summary = t.summary()
    assert summary['findings'] == 1
    assert summary['domain'] == 'example.com'


def test_severity_counts():
    t = ScanTarget(domain="test.com")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.MEDIUM]:
        t.add_finding(Finding(
            type=FindingType.NUCLEI_FINDING,
            target="test.com",
            title=f"Test {sev.value}",
            severity=sev
        ))
    assert t.critical_count() == 1
    summary = t.summary()
    assert summary['by_severity']['high'] == 2


def test_live_host():
    h = LiveHost(
        url="https://admin.example.com",
        domain="admin.example.com",
        status_code=200,
        technologies=["WordPress", "PHP", "Nginx"],
        waf="Cloudflare"
    )
    assert h.waf == "Cloudflare"
    assert "WordPress" in h.technologies


if __name__ == '__main__':
    test_finding_creation()
    test_finding_serialization()
    test_scan_target()
    test_severity_counts()
    test_live_host()
    print("✅ All model tests passed")
