"""
Argus V2 - Unified Data Models
All findings follow a common schema for consistency across modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, TYPE_CHECKING
from datetime import datetime, timezone
from enum import Enum
import uuid
import json

if TYPE_CHECKING:
    from core.scope import Scope


class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class FindingType(str, Enum):
    SUBDOMAIN          = "subdomain"
    LIVE_HOST          = "live_host"
    URL                = "url"
    JS_SECRET          = "js_secret"
    JS_VULNERABILITY   = "js_vulnerability"   # eval, innerHTML, postmessage, etc.
    JS_ENDPOINT        = "js_endpoint"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    PATTERN_MATCH      = "pattern_match"
    NUCLEI_FINDING     = "nuclei_finding"
    PARAMETER          = "parameter"
    SCREENSHOT         = "screenshot"
    TECHNOLOGY         = "technology"
    MISCONFIGURATION   = "misconfiguration"
    ACTIVE_XSS         = "active_xss"
    ACTIVE_SQLI        = "active_sqli"
    ACTIVE_OPEN_REDIRECT = "active_open_redirect"
    ACTIVE_FILE_EXPOSURE = "active_file_exposure"
    # WSTG extensions (2026-05-08)
    JWT_WEAKNESS         = "jwt_weakness"             # alg=none, kid path-inj, JKU/X5U exposure
    GRAPHQL_INTROSPECTION = "graphql_introspection"   # /graphql introspection enabled
    HOST_HEADER_INJECTION = "host_header_injection"   # canary reflected from Host or X-Forwarded-Host
    CLOUD_BUCKET         = "cloud_bucket"              # S3/Azure/GCS/Firebase exposed
    HTTP_METHODS         = "http_methods"              # OPTIONS Allow exposes PUT/DELETE/TRACE
    # Phase 1 extensions (2026-05-12) — m01 OSINT, m07 ports, m08 TLS
    EMAIL_SPOOFABLE      = "email_spoofable"          # missing/weak SPF, DMARC, DKIM
    BREACHED_CREDENTIAL  = "breached_credential"       # HIBP / dehashed / public dumps
    GIT_SECRET           = "git_secret"                # trufflehog / gitleaks on GitHub orgs
    DOMAIN_INFO          = "domain_info"               # WHOIS / RDAP metadata (info-level inventory)
    SERVICE_EXPOSED      = "service_exposed"           # m07 — naabu + nmap -sV on non-web ports
    ORIGIN_IP_LEAK       = "origin_ip_leak"            # m07 — cdncheck shows origin outside CDN
    TLS_WEAK             = "tls_weak"                  # m08 — weak cipher/protocol/cert chain
    TLS_CERT_ISSUE       = "tls_cert_issue"            # m08 — expired/self-signed/short-lived


@dataclass
class Finding:
    """Unified finding schema — every module outputs this."""
    type:          FindingType
    target:        str
    title:         str
    severity:      Severity         = Severity.INFO
    confidence:    float            = 1.0
    url:           Optional[str]    = None
    module_source: Optional[str]    = None
    evidence:      Optional[str]    = None
    metadata:      Dict[str, Any]   = field(default_factory=dict)
    tags:          List[str]        = field(default_factory=list)
    id:            str              = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:     str              = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_id:       Optional[str]    = None
    is_new:        bool             = True   # False if already seen in a previous scan

    def to_dict(self) -> dict:
        d = asdict(self)
        d['type']     = self.type.value
        d['severity'] = self.severity.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> 'Finding':
        d['type']     = FindingType(d['type'])
        d['severity'] = Severity(d['severity'])
        return cls(**d)


@dataclass
class ScanTarget:
    """A single scan target with its results."""
    domain:      str
    scan_id:     str              = field(default_factory=lambda: str(uuid.uuid4()))
    started_at:  str              = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str]   = None
    subdomains:  List[str]        = field(default_factory=list)
    # Full set of subdomains DISCOVERED (passive + active), persisted to the
    # `subdomains` table. `subdomains` above is narrowed by m02 to the DNS-
    # resolved subset that flows downstream to m03+. Keeping both apart so the
    # scan summary reports "discovered" (matches the DB / dashboard count)
    # rather than the smaller "resolved" count.
    subdomains_discovered: List[str] = field(default_factory=list)
    live_hosts:  List[dict]       = field(default_factory=list)
    urls:        List[str]        = field(default_factory=list)
    findings:    List[Finding]    = field(default_factory=list)
    stats:       Dict[str, Any]   = field(default_factory=dict)
    # Scope is attached by Pipeline at scan start. Modules MUST consult
    # it before pushing any URL/host into downstream stages (m04→m12,
    # m11→m12, m12→m14, m13 host list, etc.). None = no scope check
    # (test fixtures or one-shot module reruns); modules treat that as
    # "allow everything" for backward compatibility.
    scope:       Optional["Scope"] = None

    def add_finding(self, finding: Finding) -> None:
        finding.scan_id = self.scan_id
        self.findings.append(finding)

    def findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def critical_count(self) -> int:
        return len(self.findings_by_severity(Severity.CRITICAL))

    def summary(self) -> dict:
        sev_counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            sev_counts[f.severity.value] += 1
        return {
            "scan_id":     self.scan_id,
            "domain":      self.domain,
            "started_at":  self.started_at,
            "finished_at": self.finished_at,
            "subdomains":  len(self.subdomains_discovered or self.subdomains),
            "live_hosts":  len(self.live_hosts),
            "urls":        len(self.urls),
            "findings":    len(self.findings),
            "by_severity": sev_counts,
        }


@dataclass
class LiveHost:
    """Represents a live HTTP host from Module 2."""
    url:             str
    domain:          str
    ip:              Optional[str]         = None
    status_code:     Optional[int]         = None
    title:           Optional[str]         = None
    server:          Optional[str]         = None
    technologies:    List[str]             = field(default_factory=list)
    waf:             Optional[str]         = None
    cname:           Optional[str]         = None
    favicon_hash:    Optional[str]         = None
    cors:            Optional[str]         = None
    headers:         Dict[str, str]        = field(default_factory=dict)
    confidence:      float                 = 1.0
    redirect_chain:  List[str]             = field(default_factory=list)
    # Extended detection (M02 enrichment)
    tech_versions:        Dict[str, str]   = field(default_factory=dict)
    missing_sec_headers:  List[str]        = field(default_factory=list)
    cookie_issues:        List[str]        = field(default_factory=list)
    # CSP detail issues (CONF-12) — list of {directive, value, severity, reason}
    csp_issues:           List[Dict[str, Any]] = field(default_factory=list)
    well_known:           Dict[str, int]   = field(default_factory=dict)  # path -> status
    co_located_count:     int              = 0
    previous_status:      Optional[int]    = None  # status at previous scan, None if first time
