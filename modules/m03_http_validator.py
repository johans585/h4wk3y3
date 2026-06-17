"""
Argus V2 - Module 02: HTTP Validator & Technology Detection
aiohttp async scanning + 70+ stack patterns + WAF + CNAME + real favicon hash.

Tech detection sources (in order of confidence):
  1. <meta name="generator" content="...">   — explicit, often versioned
  2. Real favicon hash (mmh3, Shodan/FOFA) — strong fingerprint
  3. Header patterns (Server, X-Powered-By, X-Generator, Set-Cookie names)
  4. Body markers (HTML comments, asset paths, CSS class prefixes)
  5. Cookie name patterns (laravel_session, ci_session, ASP.NET_SessionId, etc.)
"""

import asyncio
import aiohttp
import base64
import json
import re
import ssl
from collections import Counter
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin
from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, LiveHost, Severity

try:
    import mmh3  # Shodan/FOFA-compatible favicon hashing
    _MMH3_OK = True
except ImportError:
    _MMH3_OK = False


# ─────────────────────────────────────────────────────────────────────────────
# 120+ Technology Detection Patterns
# Format: (name, match_type, value)
# match_type: 'header_server' | 'header_x' | 'header_any' | 'body' | 'cookie'
# ─────────────────────────────────────────────────────────────────────────────
# Tech detection — supplemental only.
#
# httpx-toolkit already runs Wappalyzer-grade detection via `-tech-detect`
# and populates LiveHost.technologies from its `tech` JSON field (see
# _livehost_from_httpx). The patterns below cover the small set of signals
# Wappalyzer/httpx miss in practice:
#
#   1. Session-cookie fingerprinting — when the server scrubs Server /
#      X-Powered-By headers, the only clue left is often a framework
#      session cookie name (PHPSESSID, JSESSIONID, laravel_session, …).
#   2. Generator meta tag — explicit & versioned (CMS hint).
#
# Other patterns (web servers, CDN, frameworks via body markup, specific
# apps, build tools, hosting providers) were removed in Étape 1.3 — httpx
# detects them and our regexes were inferior duplicates.
#
# Tuple format: (name, source, regex). source ∈ {cookie}.
TECH_PATTERNS = [
    ("PHP",             "cookie",        r"phpsessid"),
    ("Java",            "cookie",        r"jsessionid"),
    ("ASP.NET",         "cookie",        r"asp\.net_sessionid|aspsessionid"),
    ("CodeIgniter",     "cookie",        r"ci_session"),
    ("Express",         "cookie",        r"connect\.sid"),
    ("Flask",           "cookie",        r"^session=eyj"),
    ("Laravel",         "cookie",        r"laravel_session|xsrf-token"),
    ("Magento",         "cookie",        r"mage-cache|mage-messages"),
    ("Ruby on Rails",   "cookie",        r"_session_id"),
    ("ColdFusion",      "cookie",        r"cfid|cftoken"),
]

# Famous Shodan/FOFA-style favicon hashes (mmh3 of base64-encoded favicon).
# Add your own as you confirm them.
FAVICON_HASHES = {
    -2128230612: "GitLab",
    -1922474189: "Jenkins",
    -1395400727: "JFrog Artifactory",
    -1342941324: "Spring Boot",
     -394348746: "Apache Tomcat",
     -157497072: "Confluence",
       81586312: "Joomla",
      -32115002: "Grafana",
     -987765937: "Kibana",
       16613547: "Adminer",
      -50166246: "phpMyAdmin",
       99352816: "Atlassian Jira",
     1671639633: "GitHub Enterprise",
     -297069493: "Sonatype Nexus",
      999357577: "Portainer",
     1230066722: "Roundcube Webmail",
}

# WAF Signatures
WAF_SIGNATURES = {
    "Cloudflare":       [r"cf-ray", r"__cfduid", r"cloudflare"],
    "AWS WAF":          [r"x-amzn-requestid", r"awswaf"],
    "Akamai":           [r"akamai|x-akamai"],
    "Imperva/Incapsula":[r"incap_ses|x-iinfo"],
    "Sucuri":           [r"x-sucuri-id"],
    "Sucuri Firewall":  [r"x-sucuri-cache", r"sucuri/cloudproxy"],
    "F5 BIG-IP":        [r"bigipserver|x-waf-event"],
    "ModSecurity":      [r"mod_security|modsecurity"],
    "Barracuda":        [r"barra_counter_session"],
    "Fortinet":         [r"fortigate|fortiweb"],
    "Reblaze":          [r"x-rbzid|reblaze"],
    "Wallarm":          [r"nginx-wallarm|x-wallarm"],
    "Radware":          [r"x-sl-comp|radware"],
    "NSFOCUS":          [r"nsfocus"],
    "Citrix Netscaler": [r"ns_af|citrix_ns_id|netscaler"],
    "Edgecast":         [r"server.*edgecast|x-edgecast"],
    "StackPath":        [r"server.*stackpath|x-sp-"],
    "Wordfence":        [r"x-wf-"],
    "Azure WAF":        [r"x-azure-ref.*waf|azure-waf"],
}

# ─────────────────────────────────────────────────────────────────────────────
# Security headers checked for findings (missing → finding INFO/LOW)
# ─────────────────────────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    'Strict-Transport-Security':  ('low',  'HSTS missing — MITM downgrade possible'),
    'Content-Security-Policy':    ('low',  'CSP missing — XSS mitigation absent'),
    'X-Frame-Options':            ('info', 'X-Frame-Options missing — clickjacking possible (unless CSP frame-ancestors)'),
    'X-Content-Type-Options':     ('info', 'X-Content-Type-Options missing — MIME sniffing possible'),
    'Referrer-Policy':            ('info', 'Referrer-Policy missing — referer leakage possible'),
    'Permissions-Policy':         ('info', 'Permissions-Policy missing — features not restricted'),
}

# /.well-known endpoints to probe (HEAD only, fast). Presence = info finding.
WELL_KNOWN_PATHS = [
    '/.well-known/security.txt',           # RFC 9116
    '/.well-known/openid-configuration',   # OAuth/OIDC
    '/.well-known/oauth-authorization-server',
    '/robots.txt',                         # not /.well-known but useful to know
]


class HTTPValidatorModule(BaseModule):

    MODULE_ID   = "m03"
    MODULE_NAME = "HTTP Validator & Tech Detection"

    async def run(self, target: ScanTarget) -> None:
        """
        Three-phase HTTP validation:

          1. **DNS pre-filter** via dnspython multi-NS (core/dns_resolver.py)
             — drops subs that don't resolve so phase 2 doesn't waste
             httpx slots on dead names.
          2. **HTTP probe** via httpx-toolkit (ProjectDiscovery) — Wappalyzer
             tech detection, redirect chain, CNAME, IP, status, title, server.
             Subprocess + JSONL streamed line-by-line.
          3. **Custom enrichment** via aiohttp on confirmed-alive hosts only:
             favicon mmh3 hash + WAF heuristic + CORS check + extra tech
             patterns from the legacy detector.

        The legacy aiohttp.ClientSession probe (still in this file as
        `_probe_host`/`_probe`) is kept for reference and may be reused as
        a fallback if `httpx-toolkit` is unavailable on the host.
        """
        cfg     = self.config.get('http_validator', default={})
        out_dir = self._output_dir(target)

        if not target.subdomains:
            self.log.warning("No subdomains from M01 — nothing to validate")
            return

        # Pre-httpx scope filter. m02 is now scope-filtered (C2 fix), but
        # belt-and-braces here: out-of-scope hosts wasted httpx probes
        # before we could drop them, and CNAME chains can surface 3rd-party
        # FQDNs that mustn't be touched even passively.
        if target.scope is not None:
            before = len(target.subdomains)
            target.subdomains = [
                s for s in target.subdomains if target.scope.is_in_scope(s)
            ]
            if before - len(target.subdomains):
                self.log.info(
                    f"   🛡 scope filter: −{before - len(target.subdomains)} subs "
                    f"dropped before httpx probe"
                )
            if not target.subdomains:
                self.log.warning("All subs out of scope — nothing to probe")
                return

        self.log.info(f"🌐 HTTP validation — {len(target.subdomains)} subdomains")

        # ── Snapshot previous live_hosts for status_code change tracking ──
        prev_status: Dict[str, int] = {}
        prev_file = out_dir / "live_hosts.json"
        if prev_file.exists():
            try:
                prev_data = json.loads(prev_file.read_text())
                prev_status = {h.get('url'): h.get('status_code')
                               for h in (prev_data or []) if h.get('url')}
                # Preserve as .prev for diff visibility in dashboard.
                (out_dir / "live_hosts.prev.json").write_text(prev_file.read_text())
            except Exception as e:
                self.log.debug(f"prev live_hosts snapshot failed: {e}")

        # ── Resolvers list (passed to httpx-toolkit which handles DNS itself) ──
        from core.dns_resolver import DEFAULT_NAMESERVERS
        nameservers = cfg.get('dns_nameservers') or DEFAULT_NAMESERVERS

        # Optional DNS pre-filter — diagnostic only. httpx-toolkit's resolver
        # is more robust under load (retries, parallel queries to all
        # configured NS, NS-rotation on failure), so by default we let it
        # process the full sub list rather than dropping subs that our
        # dnspython prefilter timed out on. Enable `dns_prefilter: true` in
        # config to short-circuit hosts that NXDOMAIN before HTTP probing.
        resolved: Dict[str, List[str]] = {}
        if cfg.get('dns_prefilter', False):
            from core.dns_resolver import resolve_subs_parallel
            self.log.info(
                f"   ⛓  DNS pre-filter via {len(nameservers)} public NS "
                f"(concurrency={cfg.get('dns_concurrency', 30)})"
            )
            resolved = await resolve_subs_parallel(
                target.subdomains, nameservers,
                concurrency=cfg.get('dns_concurrency', 30),
                timeout=cfg.get('dns_timeout', 5.0),
            )
            self.log.info(f"   DNS: {len(resolved)}/{len(target.subdomains)} resolve")
            (out_dir / "resolved_ips.json").write_text(json.dumps(resolved, indent=2))
            probe_subs = list(resolved.keys()) or list(target.subdomains)
        else:
            probe_subs = list(target.subdomains)

        # ── HTTP probe via httpx-toolkit ─────────────────────────────────
        live_data = await self._httpx_probe(probe_subs, nameservers, cfg, out_dir)

        if not live_data:
            self.log.warning(
                f"⚠ httpx probed {len(resolved)} resolved subs but found 0 live — "
                f"check firewall/egress (test: curl -v https://{target.domain})"
            )
            target.live_hosts = []
            (out_dir / "live_hosts.json").write_text("[]")
            (out_dir / "live_hosts.txt").write_text("")
            return

        live_hosts: List[LiveHost] = [
            self._livehost_from_httpx(d, resolved) for d in live_data
        ]

        # Dedupe by domain (keep https over http if both present)
        by_domain: Dict[str, LiveHost] = {}
        for h in live_hosts:
            cur = by_domain.get(h.domain)
            if cur is None or h.url.startswith('https') and not cur.url.startswith('https'):
                by_domain[h.domain] = h
        live_hosts = list(by_domain.values())

        # ── Co-location count: how many other subs share this IP ─────────
        ip_clusters: Dict[str, List[str]] = {}
        for h in live_hosts:
            if h.ip:
                ip_clusters.setdefault(h.ip, []).append(h.domain)
        for h in live_hosts:
            if h.ip:
                h.co_located_count = len(ip_clusters.get(h.ip, []))

        # ── Status code change tracking (vs previous scan) ───────────────
        for h in live_hosts:
            h.previous_status = prev_status.get(h.url)

        # ── Phase 3: enrichment (favicon, WAF, custom tech, CORS,
        #             security headers, cookies, well-known) ──────────────
        if cfg.get('enrich_extras', True):
            await self._enrich_extras(live_hosts, cfg)

        # ── Scope filter — central choke-point ──────────────────────────
        # Every downstream module (m05/m06/m13/m14/m07/m08/m09) reads
        # target.live_hosts. Filtering here ensures none of them ever sees
        # an out-of-scope host. m02 should already have filtered the
        # subdomain list, but a CNAME that resolves to a third-party host
        # (or a redirect that m03 followed) can still drag external hosts in.
        scope = getattr(target, 'scope', None)
        if scope is not None:
            before = len(live_hosts)
            live_hosts = [h for h in live_hosts if scope.is_in_scope(h.url)]
            dropped = before - len(live_hosts)
            if dropped:
                self.log.info(
                    f"   scope: kept {len(live_hosts)}/{before} live hosts "
                    f"({dropped} third-party dropped — downstream protected)"
                )

        # ── Persist ──────────────────────────────────────────────────────
        target.live_hosts = [h.__dict__ for h in live_hosts]
        # Normalize URLs in the .txt list: strip default ports, ensure trailing
        # slash on root URLs so the operator sees a consistent format.
        (out_dir / "live_hosts.txt").write_text('\n'.join(sorted(set(
            self._normalize_url(h.url) for h in live_hosts))))
        (out_dir / "live_hosts.json").write_text(json.dumps(target.live_hosts, indent=2))

        # Persist to DB so /api/live-hosts and inter-domain queries see them.
        # The schema's UNIQUE(url) auto-dedupes across re-scans.
        try:
            n = self.db.upsert_live_hosts(target.scan_id, target.domain, target.live_hosts)
            self.log.debug(f"   db: upserted {n} live_hosts rows")
        except Exception as e:
            self.log.warning(f"db.upsert_live_hosts failed: {e}")

        tech_report = {h.url: h.technologies for h in live_hosts if h.technologies}
        (out_dir / "tech_report.json").write_text(json.dumps(tech_report, indent=2))
        # NB: /api/tech derives tech from the live_hosts DB rows directly, so
        # tech is already DB-backed — no scan_artefacts copy needed here.

        # External redirect map (M06 takeover hint + preview/staging finding)
        # Hosts redirecting to a different apex domain — flag preview/staging
        # platforms specifically (often unintended public exposure).
        PREVIEW_PLATFORMS = (
            'preview.infomaniak.website', 'vercel.app', 'netlify.app',
            'render.com', 'herokuapp.com', 'pages.dev', 'workers.dev',
            'githubusercontent.com', 'github.io', 'firebaseapp.com',
            'web.app', 'ngrok.io', 'ngrok-free.app', 'glitch.me',
        )
        ext_redirects: Dict[str, Dict] = {}
        for h in live_hosts:
            if not h.redirect_chain:
                continue
            orig_apex  = '.'.join(h.domain.split('.')[-2:])
            final_host = h.url.split('://', 1)[-1].split('/')[0]
            final_apex = '.'.join(final_host.split('.')[-2:])
            if final_apex and final_apex != orig_apex:
                ext_redirects[h.domain] = {
                    'redirect_chain': h.redirect_chain,
                    'final_url':      h.url,
                    'external_host':  final_host,
                }
                # Flag preview/staging exposure
                low = final_host.lower()
                if any(p in low for p in PREVIEW_PLATFORMS):
                    self._add_finding(target, Finding(
                        type=FindingType.MISCONFIGURATION,
                        target=h.domain, url=h.url,
                        title=f"Preview/staging platform exposed: {h.domain} → {final_host}",
                        severity=Severity.MEDIUM, confidence=0.85,
                        evidence=f"Redirect chain: {' → '.join(h.redirect_chain)}",
                        tags=['preview', 'staging', 'exposure'],
                        metadata={
                            'final_url':     h.url,
                            'external_host': final_host,
                            'platform':      next(p for p in PREVIEW_PLATFORMS if p in low),
                        },
                    ))
        if ext_redirects:
            (out_dir / "redirects.json").write_text(json.dumps(ext_redirects, indent=2))

        # ── Findings ─────────────────────────────────────────────────────
        # Live hosts themselves are NOT findings — they're asset inventory,
        # persisted in the `live_hosts` table and served via /api/live-hosts/.
        # Only signals derived from them (CORS misconfig, missing headers,
        # cookie issues, status changes, well-known exposures) get emitted.
        for h in live_hosts:
            if h.cors:
                is_critical = 'wildcard+credentials' in h.cors or 'credentials:' in h.cors
                self._add_finding(target, Finding(
                    type=FindingType.MISCONFIGURATION,
                    target=h.domain, url=h.url,
                    title=f"CORS misconfiguration: {h.cors}",
                    severity=Severity.HIGH if is_critical else Severity.MEDIUM,
                    confidence=0.8, metadata={"cors_policy": h.cors},
                ))

            # ── Missing security headers (1 grouped finding per host) ────
            if h.missing_sec_headers:
                # Pick the worst severity among the missing headers
                worst = 'info'
                for m in h.missing_sec_headers:
                    sev, _ = SECURITY_HEADERS.get(m, ('info', ''))
                    if sev == 'low':  worst = 'low'
                self._add_finding(target, Finding(
                    type=FindingType.MISCONFIGURATION,
                    target=h.domain, url=h.url,
                    title=f"Missing security headers: {', '.join(h.missing_sec_headers)}",
                    severity=Severity(worst), confidence=0.95,
                    tags=['security-headers'],
                    metadata={"missing": h.missing_sec_headers,
                              "details": {m: SECURITY_HEADERS[m][1]
                                          for m in h.missing_sec_headers if m in SECURITY_HEADERS}},
                ))

            # ── Cookie flag issues (Secure / HttpOnly / SameSite) ────────
            if h.cookie_issues:
                self._add_finding(target, Finding(
                    type=FindingType.MISCONFIGURATION,
                    target=h.domain, url=h.url,
                    title=f"Insecure cookie flags: {len(h.cookie_issues)} cookie(s)",
                    severity=Severity.LOW, confidence=0.9,
                    tags=['cookies', 'session'],
                    evidence='\n'.join(h.cookie_issues),
                    metadata={"issues": h.cookie_issues},
                ))

            # ── CSP weak directives (CONF-12) ────────────────────────────
            if h.csp_issues:
                # Pick the worst severity among the issues
                rank = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                worst = max((iss['severity'] for iss in h.csp_issues),
                            key=lambda s: rank.get(s, 0))
                titles = ", ".join(sorted({iss['directive'] for iss in h.csp_issues}))
                self._add_finding(target, Finding(
                    type=FindingType.MISCONFIGURATION,
                    target=h.domain, url=h.url,
                    title=f"Weak CSP: {len(h.csp_issues)} issue(s) on {titles}",
                    severity=Severity(worst), confidence=0.95,
                    tags=['csp', 'security-headers'],
                    evidence='\n'.join(f"[{iss['severity']}] {iss['directive']}: {iss['reason']}"
                                       for iss in h.csp_issues),
                    metadata={"issues": h.csp_issues},
                ))

            # ── Status code change vs previous scan ──────────────────────
            if h.previous_status is not None and h.previous_status != h.status_code:
                self._add_finding(target, Finding(
                    type=FindingType.MISCONFIGURATION,
                    target=h.domain, url=h.url,
                    title=f"Status code change: {h.previous_status} → {h.status_code}",
                    severity=Severity.INFO, confidence=1.0,
                    tags=['changed'],
                    metadata={"previous_status": h.previous_status,
                              "current_status":  h.status_code},
                ))

            # ── Notable well-known endpoints (security.txt etc.) ─────────
            if h.well_known:
                hits = {p: s for p, s in h.well_known.items()
                        if s and s < 400 and p != '/robots.txt'}
                if hits:
                    self._add_finding(target, Finding(
                        type=FindingType.MISCONFIGURATION,
                        target=h.domain, url=h.url,
                        title=f"Well-known endpoints exposed: {len(hits)}",
                        severity=Severity.INFO, confidence=1.0,
                        tags=['well-known'],
                        metadata={"endpoints": hits},
                    ))

        # Unreachable = subs that we sent to httpx but got no live response.
        # We enrich with IPs from M01's ips.json (the dns_prefilter `resolved`
        # dict is empty when the prefilter is off — its default).
        live_set  = {h.domain for h in live_hosts}
        unreached = sorted(set(probe_subs) - live_set)
        if unreached:
            ips_map: Dict[str, List[str]] = {}
            ips_file = out_dir / "ips.json"
            if ips_file.exists():
                try:
                    ips_map = json.loads(ips_file.read_text()) or {}
                except Exception:
                    pass
            (out_dir / "unreachable.json").write_text(json.dumps(
                [{"sub":  s,
                  "ips":  resolved.get(s) or ips_map.get(s, []),
                  "kind": "no_http"}
                 for s in unreached],
                indent=2,
            ))
            self.log.info(
                f"   {len(unreached)} subs had no HTTP response "
                f"(see unreachable.json)"
            )

        self.log.info(f"✅ M02 done — {len(live_hosts)} live hosts")

    # ── httpx-toolkit (ProjectDiscovery) HTTP probe ─────────────────────────
    async def _httpx_probe(
        self,
        subs:         List[str],
        nameservers:  List[str],
        cfg:          dict,
        out_dir:      Path,
    ) -> List[dict]:
        """
        Run httpx-toolkit on the resolved subs. Streams JSONL lines to stdout
        and we parse them as they arrive. The Go binary handles concurrency,
        retries, redirects, TLS quirks, and Wappalyzer tech detection — all
        of which we previously had to maintain in pure aiohttp.

        On Kali the binary is /usr/bin/httpx-toolkit (Python httpx CLI lives at
        /usr/bin/httpx and rejects PD flags, so we explicitly look up the
        toolkit binary).
        """
        import shutil
        import subprocess
        import time
        # Locate the PD binary (not the Python CLI).
        bin_path = shutil.which('httpx-toolkit') or shutil.which('httpx-pd')
        if not bin_path:
            # On non-Kali distros the binary may be plain `httpx`.
            for cand in ('httpx',):
                p = shutil.which(cand)
                if p and 'projectdiscovery' in (subprocess.run(
                        [p, '-version'], capture_output=True, text=True
                    ).stdout + ' ').lower():
                    bin_path = p
                    break
        if not bin_path:
            self.log.error(
                "httpx-toolkit not found — install ProjectDiscovery httpx "
                "(apt install httpx-toolkit on Kali, or `go install "
                "github.com/projectdiscovery/httpx/cmd/httpx@latest`)"
            )
            return []

        subs_file      = out_dir / "_httpx_subs.tmp"
        resolvers_file = out_dir / "_httpx_resolvers.tmp"
        subs_file.write_text('\n'.join(subs))
        resolvers_file.write_text('\n'.join(nameservers))

        threads      = cfg.get('concurrent', 50)
        timeout_s    = cfg.get('timeout', 10)
        retries      = cfg.get('retries', 2)
        rate_limit   = cfg.get('rate_limit', 150)

        cmd = [
            bin_path,
            '-l',           str(subs_file),
            '-resolvers',   str(resolvers_file),
            '-threads',     str(threads),
            '-timeout',     str(timeout_s),
            '-retries',     str(retries),
            '-rate-limit',  str(rate_limit),
            '-follow-redirects',
            '-status-code', '-title', '-tech-detect',
            '-web-server',  '-ip', '-cname',
            '-no-color', '-silent',
            '-json',        # JSONL output on stdout
            # Don't probe a port outside 80/443 — speeds up considerably and
            # we already have IP from DNS phase if we want raw TCP later.
            '-ports', cfg.get('probe_ports', '80,443,8080,8443'),
        ]
        self.log.info(
            f"   ⚡ httpx probe — {len(subs)} subs (threads={threads}, "
            f"timeout={timeout_s}s, retries={retries})"
        )
        t0 = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=cfg.get('httpx_max_runtime', 1800),
            )
        except asyncio.TimeoutError:
            self.log.warning("httpx probe timed out — partial results")
            try: proc.terminate()
            except Exception: pass
            return []
        except Exception as e:
            self.log.error(f"httpx subprocess error: {e}")
            return []
        finally:
            for f in (subs_file, resolvers_file):
                try: f.unlink(missing_ok=True)
                except Exception: pass

        results: List[dict] = []
        for line in (stdout or b'').decode(errors='ignore').splitlines():
            line = line.strip()
            if not line or not line.startswith('{'):
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        elapsed = time.time() - t0
        if proc.returncode != 0:
            stderr_txt = (stderr or b'').decode(errors='ignore')[:500]
            self.log.warning(
                f"httpx exit={proc.returncode} after {elapsed:.1f}s — "
                f"got {len(results)} results. stderr: {stderr_txt}"
            )
        else:
            # `results` = raw httpx responses (one per scheme/port that answered);
            # the caller dedupes by host (https>http) before persisting, so this
            # is an upper bound, not the final live-host count. Say "responses".
            self.log.info(f"   httpx: {len(results)} responses (pre-dedup) in {elapsed:.1f}s")
        return results

    @staticmethod
    def _livehost_from_httpx(d: dict, resolved: Dict[str, List[str]]) -> LiveHost:
        """Build a LiveHost from one httpx-toolkit JSONL record.

        httpx-toolkit JSON keys (verified on projectdiscovery/httpx latest):
          - status_code (int)         ← was status-code in older versions
          - host        (str)         = hostname, NOT the IP
          - host_ip     (str)         = resolved IP
          - a           (list)        = all A records
          - tech        (list)        ← was technologies in older versions
          - cnames      (list)
          - webserver, title, url, input, final-url, content-length, ...
        """
        url       = d.get('url') or ''
        domain    = (d.get('input') or url.split('://', 1)[-1].split('/')[0]
                     .split(':')[0])
        # Real IP: try host_ip → first A record → DNS phase fallback
        ip        = d.get('host_ip') or (d.get('a') or [None])[0]
        if not ip and resolved.get(domain):
            ip = resolved[domain][0]
        cname     = (d.get('cnames') or [None])[0]
        # tech is the new key; accept legacy 'technologies' for safety
        techs     = list(d.get('tech') or d.get('technologies') or [])
        server    = d.get('webserver') or ''
        title     = d.get('title') or None
        status    = d.get('status_code') or d.get('status-code') or 0
        # Redirect chain from `chain-status-codes` (status only); reconstruct
        # with final-url + the input URL for visibility.
        redirect_chain: List[str] = []
        if d.get('final-url') and d['final-url'] != url:
            redirect_chain = [url, d['final-url']]
            url = d['final-url']

        return LiveHost(
            url=url,
            domain=domain,
            ip=ip,
            status_code=status,
            title=title,
            server=server,
            technologies=techs,
            cname=cname,
            confidence=1.0 if status in (200, 301, 302, 401, 403) else 0.7,
            redirect_chain=redirect_chain,
            headers={},   # populated by _enrich_extras if enabled
        )

    # ── Phase 3: enrichment on confirmed-alive hosts ────────────────────────
    async def _enrich_extras(self, hosts: List[LiveHost], cfg: dict) -> None:
        """
        Best-effort: fetch each host once with aiohttp to get full headers,
        favicon hash, WAF heuristic, CORS check, custom tech patterns,
        security headers, cookie flags, and well-known endpoints.

        Uses a CACHED RESOLVER seeded from httpx's IPs to avoid double DNS
        lookups (which were causing 5-10s timeouts on slow networks and
        silently dropping CORS/WAF detection).
        """
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE

        # Seed resolver with the IPs httpx already resolved.
        from core.dns_resolver import make_cached_aiohttp_resolver
        ip_map = {h.domain: h.ip for h in hosts if h.ip}
        resolver = make_cached_aiohttp_resolver(ip_map)

        timeout   = aiohttp.ClientTimeout(total=cfg.get('timeout', 10), connect=8)
        connector = aiohttp.TCPConnector(
            ssl=ssl_ctx,
            limit=cfg.get('enrich_concurrency', 30),
            limit_per_host=2,
            resolver=resolver,
        )

        # Counter health summary
        stats = Counter()
        sem = asyncio.Semaphore(cfg.get('enrich_concurrency', 30))

        async with aiohttp.ClientSession(
            timeout=timeout, connector=connector,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
        ) as sess:
            await asyncio.gather(*(
                self._enrich_one(sess, sem, h, stats) for h in hosts
            ), return_exceptions=True)

        ok      = stats.get('ok', 0)
        retried = stats.get('retried_ok', 0)
        failed  = sum(v for k, v in stats.items() if k.startswith('fail_'))
        if failed or retried:
            fail_breakdown = ', '.join(f"{k[5:]}={v}" for k, v in sorted(stats.items())
                                       if k.startswith('fail_'))
            self.log.info(
                f"   enrichment: {ok+retried}/{len(hosts)} OK "
                f"({retried} after retry), {failed} failed [{fail_breakdown}]"
            )
        else:
            self.log.info(f"   enrichment: {ok}/{len(hosts)} OK")

    async def _enrich_one(self, sess, sem, h: LiveHost, stats: Counter) -> None:
        async with sem:
            ok, last_exc = await self._enrich_fetch(sess, h)
            if ok:
                stats['ok'] += 1
            else:
                # Retry once on transient (DNS/timeout/conn-reset) errors
                exc_name = type(last_exc).__name__.lower() if last_exc else ''
                exc_msg  = str(last_exc).lower() if last_exc else ''
                is_transient = (
                    'timeout' in exc_name or 'timeout' in exc_msg
                    or 'dns' in exc_name or 'reset' in exc_msg
                    or 'cannot connect' in exc_msg
                )
                if is_transient:
                    await asyncio.sleep(0.5)
                    ok2, last_exc = await self._enrich_fetch(sess, h)
                    if ok2:
                        stats['retried_ok'] += 1
                        return
                # Bucket the failure
                if 'timeout' in exc_name or 'timeout' in exc_msg:
                    stats['fail_timeout'] += 1
                elif 'dns' in exc_name:
                    stats['fail_dns'] += 1
                elif 'ssl' in exc_name or 'certificate' in exc_msg:
                    stats['fail_ssl'] += 1
                else:
                    stats['fail_other'] += 1
                self.log.debug(f"enrich failed for {h.url}: {type(last_exc).__name__}: {last_exc}")

        # Well-known probes — outside the main fetch sem so they don't
        # serialize behind it. Use HEAD-only (no body), 5s timeout.
        # Non-blocking: we don't await this if main fetch failed.
        if ok or stats.get('retried_ok'):
            try:
                await self._check_well_known(sess, h)
            except Exception as e:
                self.log.debug(f"well-known check failed for {h.url}: {e}")

    async def _enrich_fetch(self, sess, h: LiveHost):
        """Single GET attempt. Returns (success_bool, last_exception_or_none)."""
        try:
            async with sess.get(h.url, allow_redirects=True, max_redirects=5) as resp:
                headers = dict(resp.headers)
                body_bytes = await resp.content.read(8192)
                body = body_bytes.decode('utf-8', errors='ignore')
                h.headers = headers
                h.waf  = self._detect_waf(headers)
                h.cors = self._detect_cors(headers)
                # Merge custom tech patterns
                extra_tech = self._detect_tech(headers, body)
                h.technologies = list(dict.fromkeys(h.technologies + extra_tech))
                # Versioned tech extraction (Server, generator, X-Powered-By)
                h.tech_versions.update(self._extract_tech_versions(headers, body))
                # Security headers + cookie issues
                h.missing_sec_headers = self._detect_missing_security_headers(headers)
                h.cookie_issues = self._detect_cookie_issues(headers)
                h.csp_issues = self._analyse_csp(headers)
                # Favicon hash
                try:
                    favicon_url = self._favicon_href(body, h.url)
                    if favicon_url:
                        fh, fav_tech = await self._fetch_favicon_hash(sess, favicon_url)
                        if fh is not None:
                            h.favicon_hash = str(fh)
                            if fav_tech:
                                h.technologies = list(dict.fromkeys(fav_tech + h.technologies))
                except Exception:
                    pass
            return True, None
        except Exception as e:
            return False, e

    async def _check_well_known(self, sess, h: LiveHost) -> None:
        """HEAD probe of /.well-known + /robots.txt. Stores {path: status_code}."""
        from urllib.parse import urlsplit
        u = urlsplit(h.url)
        base = f"{u.scheme}://{u.netloc}"
        results: Dict[str, int] = {}
        async def _probe(path: str):
            try:
                async with sess.head(base + path, allow_redirects=False,
                                     timeout=aiohttp.ClientTimeout(total=5)) as r:
                    results[path] = r.status
            except Exception:
                pass
        await asyncio.gather(*(_probe(p) for p in WELL_KNOWN_PATHS),
                             return_exceptions=True)
        h.well_known = results

    @staticmethod
    def _detect_missing_security_headers(headers: dict) -> List[str]:
        """Return list of standard security headers missing from response."""
        present = {k.lower() for k in headers.keys()}
        return [h for h in SECURITY_HEADERS if h.lower() not in present]

    @staticmethod
    def _detect_cookie_issues(headers) -> List[str]:
        """
        Parse Set-Cookie headers; return list of human-readable issues
        like 'session: missing Secure', 'auth: missing HttpOnly+SameSite'.
        Only flags cookies that LOOK session/auth (heuristic on name).

        Accepts a dict or aiohttp CIMultiDict. Multi-cookie responses are
        parsed via http.cookies.SimpleCookie which handles attribute order
        and `Expires=Wed, 09 Jun 2021…` commas the old regex split tripped on.
        """
        from http.cookies import SimpleCookie

        issues: List[str] = []
        # Collect every Set-Cookie line. aiohttp's CIMultiDict supports
        # getall(); plain dicts only return the first one.
        raws: List[str] = []
        getall = getattr(headers, 'getall', None)
        if callable(getall):
            for v in (getall('Set-Cookie', []) or getall('set-cookie', []) or []):
                raws.append(v)
        else:
            v = headers.get('Set-Cookie') or headers.get('set-cookie') or ''
            if isinstance(v, str) and v:
                # aiohttp's plain-dict view joins multi-Set-Cookie with '\n'.
                raws.extend(v.split('\n'))
        if not raws:
            return issues

        SESSION_HINTS = ('session', 'sess', 'auth', 'token', 'sid', 'login')
        for raw in raws:
            if not raw:
                continue
            jar = SimpleCookie()
            try:
                jar.load(raw)
            except Exception:
                continue
            for name, morsel in jar.items():
                lname = name.lower()
                if not any(h in lname for h in SESSION_HINTS):
                    continue
                missing = []
                # Morsel keys are lowercased attribute names. Bool attrs
                # show as '' when present, so we test truthiness loosely.
                if not morsel.get('secure'):   missing.append('Secure')
                if not morsel.get('httponly'): missing.append('HttpOnly')
                if not morsel.get('samesite'): missing.append('SameSite')
                if missing:
                    issues.append(f"{lname}: missing {'+'.join(missing)}")
        return issues

    @staticmethod
    def _analyse_csp(headers: dict) -> List[Dict[str, str]]:
        """Parse Content-Security-Policy and return a list of weakness
        descriptors. Covers WSTG CONF-12. Each entry:
          { directive, value, severity, reason }
        """
        out: List[Dict[str, str]] = []
        csp = headers.get('Content-Security-Policy') or headers.get('content-security-policy') or ''
        if not csp:
            return out
        # Parse directives. CSP grammar: "directive value; directive value; ..."
        directives: Dict[str, str] = {}
        for raw in csp.split(';'):
            raw = raw.strip()
            if not raw:
                continue
            parts = raw.split(None, 1)
            name = parts[0].lower()
            val = parts[1] if len(parts) > 1 else ''
            directives[name] = val.strip()

        # Helper: directive with fallback to default-src
        def eff(name: str) -> str:
            return directives.get(name, directives.get('default-src', ''))

        SCRIPT_LIKE = ('script-src', 'script-src-elem', 'script-src-attr', 'default-src')
        STYLE_LIKE  = ('style-src',  'style-src-elem',  'style-src-attr')

        for d in SCRIPT_LIKE:
            v = directives.get(d, '')
            if not v:
                continue
            if "'unsafe-inline'" in v:
                out.append({"directive": d, "value": v, "severity": "medium",
                            "reason": "unsafe-inline allows inline <script>/event-handlers"})
            if "'unsafe-eval'" in v:
                out.append({"directive": d, "value": v, "severity": "medium",
                            "reason": "unsafe-eval allows eval() / new Function() / setTimeout(string)"})
            if " * " in f" {v} " or v.strip() == "*" or v.endswith(" *"):
                out.append({"directive": d, "value": v, "severity": "medium",
                            "reason": "wildcard '*' source — defeats the point of CSP"})
            if "data:" in v and d in ('script-src', 'default-src'):
                out.append({"directive": d, "value": v, "severity": "low",
                            "reason": "data: scheme allows inline data URI scripts"})

        for d in STYLE_LIKE:
            v = directives.get(d, '')
            if v and "'unsafe-inline'" in v:
                out.append({"directive": d, "value": v, "severity": "low",
                            "reason": "unsafe-inline in style allows CSS injection-based exfiltration"})

        # default-src missing — every directive falls back to script-src=*
        if 'default-src' not in directives and 'script-src' not in directives:
            out.append({"directive": "default-src", "value": "(absent)", "severity": "low",
                        "reason": "no default-src AND no script-src — every fetch type is unrestricted"})

        # report-uri or report-to missing → no telemetry on violations
        if 'report-uri' not in directives and 'report-to' not in directives:
            out.append({"directive": "report-uri", "value": "(absent)", "severity": "info",
                        "reason": "no report-uri/report-to — CSP violations are silent"})

        # frame-ancestors missing → relies on X-Frame-Options for clickjacking
        if 'frame-ancestors' not in directives:
            out.append({"directive": "frame-ancestors", "value": "(absent)", "severity": "info",
                        "reason": "frame-ancestors missing — relies on X-Frame-Options for clickjacking"})

        return out

    @staticmethod
    def _extract_tech_versions(headers: dict, body: str) -> Dict[str, str]:
        """Extract version strings from Server/X-Powered-By/generator meta."""
        out: Dict[str, str] = {}
        # Server: e.g. "Apache/2.4.41 (Ubuntu)"
        srv = headers.get('Server') or headers.get('server') or ''
        m = re.match(r'([\w\-]+)/([\d.]+)', srv)
        if m:
            out[m.group(1)] = m.group(2)
        # X-Powered-By: e.g. "PHP/8.1.0", "Express", "ASP.NET"
        xpb = headers.get('X-Powered-By') or headers.get('x-powered-by') or ''
        m = re.match(r'([\w.\-]+)/([\d.]+)', xpb)
        if m:
            out[m.group(1)] = m.group(2)
        # <meta name="generator" content="WordPress 6.4.2">
        m = re.search(
            r'<meta\s+name=["\']?generator["\']?\s+content=["\']([^"\']+)["\']',
            body, re.I)
        if m:
            content = m.group(1).strip()
            mv = re.match(r'([\w\s.\-]+?)\s+v?([\d.]+)', content)
            if mv:
                out[mv.group(1).strip()] = mv.group(2)
            else:
                out[content[:40]] = ''  # name only, no version
        return out

    def _detect_tech(self, headers: dict, body: str) -> List[str]:
        """Supplemental tech detection — runs on top of what httpx -td already
        populated. Only emits what httpx tends to miss:

          * Session-cookie fingerprints (server hides itself, only the cookie
            name betrays the framework).
          * <meta name="generator"> tag content (CMS version).
          * Verbatim X-Generator / X-Powered-By header echo (already-known
            tech, kept here for downstream version extraction).
        """
        found: List[str] = []
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        set_cookie = headers_lower.get('set-cookie', '')

        for name, source, pattern in TECH_PATTERNS:
            # All remaining patterns are cookie-source after Étape 1.3 — the
            # `source` field is kept so the table stays grep-able for future
            # additions without forcing a schema change.
            if source != 'cookie':
                continue
            if set_cookie and re.search(pattern, set_cookie, re.I):
                found.append(name)

        # ── Generator meta tag (explicit + version) ─────────────────────
        gen_match = re.search(
            r'<meta\s+name=["\']?generator["\']?\s+content=["\']([^"\']+)["\']',
            body, re.I)
        if gen_match:
            found.append(f"generator:{gen_match.group(1)[:80]}")

        # ── X-Generator / X-Powered-By verbatim ─────────────────────────
        for hk in ('x-generator', 'x-powered-by'):
            v = headers_lower.get(hk, '')
            if v and len(v) < 120:
                found.append(f"{hk}:{v}")

        return list(dict.fromkeys(found))  # preserve order, deduplicate

    def _detect_waf(self, headers: dict) -> Optional[str]:
        headers_str = ' '.join(f"{k}: {v}" for k, v in headers.items()).lower()
        for waf_name, patterns in WAF_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, headers_str, re.I):
                    return waf_name
        return None

    def _detect_cors(self, headers: dict) -> Optional[str]:
        """
        Detect CORS misconfigurations.
        Returns a description string if misconfigured, None if fine.
        """
        acao = headers.get('Access-Control-Allow-Origin', '').strip()
        acac = headers.get('Access-Control-Allow-Credentials', '').strip().lower()
        if not acao:
            return None
        if acao == '*' and acac == 'true':
            return 'wildcard+credentials'  # critical: credentials with wildcard
        if acao == '*':
            return 'wildcard'              # medium: any origin allowed
        # Reflect arbitrary Origin (checked dynamically at runtime — flag the header presence)
        if acao not in ('null',) and acac == 'true':
            return f'credentials:{acao}'  # reflected origin with credentials
        return None

    @staticmethod
    def _normalize_url(url: str) -> str:
        """
        Strip default ports (:80 on http, :443 on https) and ensure root URLs
        end with /. Keeps live_hosts.txt readable: avoids the
        `https://x:443` / `https://x/` mix.
        """
        from urllib.parse import urlsplit, urlunsplit
        try:
            u = urlsplit(url)
            host = u.hostname or ''
            port = u.port
            if port == 80 and u.scheme == 'http':  port = None
            if port == 443 and u.scheme == 'https': port = None
            netloc = f"{host}:{port}" if port else host
            path = u.path or '/'
            return urlunsplit((u.scheme, netloc, path, u.query, u.fragment))
        except Exception:
            return url

    # Attributes in <link> can appear in any order. The previous regex
    # required `rel` to come before `href`, missing the common
    # `<link href="…" rel="icon">` pattern → silent tech-detection misses.
    _LINK_ICON_RE = re.compile(
        r'<link\b[^>]*\brel=["\'](?:[^"\']*\s)?(?:shortcut[\s-]?)?icon[^"\']*["\'][^>]*>',
        re.I,
    )
    _HREF_RE = re.compile(r'\bhref=["\']([^"\']+)["\']', re.I)

    def _favicon_href(self, body: str, base_url: str) -> Optional[str]:
        """Resolve the favicon URL (handles relative + absolute hrefs)."""
        m = self._LINK_ICON_RE.search(body)
        if m:
            href = self._HREF_RE.search(m.group(0))
            if href:
                return urljoin(base_url, href.group(1))
        # Fallback: /favicon.ico
        return urljoin(base_url, '/favicon.ico')

    async def _fetch_favicon_hash(self, session, url: str) -> Tuple[Optional[int], Optional[List[str]]]:
        """
        Shodan/FOFA-style favicon fingerprint:
          mmh3.hash(base64(favicon_bytes, mime-aware) chunked at 76 chars + \\n)

        Returns (hash, [tech_names])  — tech_names is empty if hash isn't in our table.
        """
        if not _MMH3_OK:
            return None, None
        try:
            async with session.get(url, allow_redirects=True,
                                   timeout=aiohttp.ClientTimeout(total=5)) as r:
                if r.status != 200:
                    return None, None
                content = await r.content.read(200_000)
                if not content:
                    return None, None
                # python-style base64 wrapping (76-char lines + trailing newline)
                b64 = base64.encodebytes(content).decode()
                h = mmh3.hash(b64)
                tech = [FAVICON_HASHES[h]] if h in FAVICON_HASHES else []
                return h, tech
        except Exception:
            return None, None
