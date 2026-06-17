"""
Argus V2 - Module 09: Active Validation
Targeted active testing on signal gathered by previous modules.

Inputs (consumed):
  - gf_xss.txt          → dalfox per URL (XSS payload set)
  - gf_sqli.txt         → sqlmap --batch --random-agent --level=1 --risk=1 (light)
  - gf_open-redirect-body.txt + gf:open-redirect URL pattern → redirect probe
  - reflected_params.json → priority queue for the above (already-confirmed echo)
  - api_specs.json      → endpoint enum
  - (future) arjun-discovered params on responsive endpoints

Outputs:
  - active_findings.json
  - findings (FindingType.ACTIVE_*) with severity HIGH/CRITICAL when confirmed

Design principles:
  - **Time-boxed**: total wall-clock cap (default 30 min) splits between checks.
  - **URL caps**: per-tool URL limits prevent runaway scans.
  - **Stealth-aware**: when stealth=True, we add jitter and lower concurrency.
  - **No SQLi --level/risk above 1** by default — we want fast confirmation,
    not exhaustive testing (that's a manual job).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
import shutil
import ssl
import string
import time
from pathlib import Path
from typing import List, Set, Optional, Tuple
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

import aiohttp

from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, Severity


# File-exposure paths with REQUIRED fingerprints. Tuple format:
#   (path, good_fp, severity)
#   - good_fp: substring that MUST be present in body to confirm
#     (None = needs content-type check only, used for binary-content paths)
#   - severity: assigned to the finding when confirmed
#
# Paths that previously had no fingerprint defined caused massive false
# positives on soft-404 hosts (any 200 OK = "confirmed"). All paths here
# now have a strict fingerprint. Paths that aren't real exposures (/admin/,
# /test.php, etc.) were dropped — those are page paths, not data leaks.
SENSITIVE_PATHS: List[Tuple[str, Optional[bytes], str]] = [
    # VCS metadata — repo source leak
    ('/.git/HEAD',                b'ref: refs/',           'high'),
    ('/.git/config',              b'[core]',               'critical'),
    ('/.svn/entries',             b'svn:',                 'high'),

    # Env / cloud / SSH credentials — game over.
    # `.env*` are ALSO probed by m09 (quick_checks). The duplicate that
    # used to surface in findings.json is now collapsed at save-time:
    # ACTIVE_FILE_EXPOSURE is in ATOMIC_TYPES (see core/database.py), so
    # save_finding() merges (domain, type, url) hits into a single row
    # with `metadata.detected_by` listing every module that confirmed.
    # Keeping the dual coverage protects against m09 silently failing
    # (timeout, scope-drop, exception swallowed) — better redundant
    # detection than a single point of failure.
    ('/.env',                     b'=',                    'critical'),
    ('/.env.production',          b'=',                    'critical'),
    ('/.env.local',               b'=',                    'critical'),
    ('/.env.dev',                 b'=',                    'critical'),
    ('/.aws/credentials',         b'aws_access_key',       'critical'),
    ('/.ssh/id_rsa',              b'PRIVATE KEY',          'critical'),

    # PHP config backups (DB creds typically inside)
    ('/wp-config.php.bak',        b'DB_PASSWORD',          'critical'),
    ('/wp-config.php.save',       b'DB_PASSWORD',          'critical'),
    ('/wp-config.php~',           b'DB_PASSWORD',          'critical'),
    ('/config.php.bak',           b'<?php',                'high'),
    ('/config.php~',              b'<?php',                'high'),
    ('/config.php.swp',           b'b0VIM',                'high'),       # vim swap magic

    # Web server config
    ('/.htaccess',                b'RewriteEngine',        'medium'),
    ('/.htpasswd',                b':$apr1$',              'high'),
    ('/web.config.bak',           b'<configuration',       'medium'),
    ('/web.config~',              b'<configuration',       'medium'),

    # SQL dumps
    ('/dump.sql',                 b'INSERT INTO',          'critical'),
    ('/database.sql',             b'INSERT INTO',          'critical'),
    ('/backup.sql',               b'INSERT INTO',          'critical'),

    # Compressed archives — verify magic bytes
    ('/backup.zip',               b'PK\x03\x04',           'high'),
    ('/site.zip',                 b'PK\x03\x04',           'high'),
    ('/www.zip',                  b'PK\x03\x04',           'high'),
    ('/backup.tar.gz',            b'\x1f\x8b',             'high'),

    # Server info pages (HTML by design — content-type filter bypassed)
    ('/server-status',            b'Apache Server Status', 'medium'),
    ('/server-info',              b'Server Information',   'medium'),
    ('/phpinfo.php',              b'PHP Version',          'medium'),
    ('/info.php',                 b'PHP Version',          'medium'),

    # macOS junk
    ('/.DS_Store',                b'Bud1',                 'low'),
]

# Paths that legitimately return text/html — bypass the content-type filter.
HTML_OK_PATHS: Set[str] = {'/server-status', '/server-info', '/phpinfo.php', '/info.php'}

# Paths whose response body contains secrets and must NEVER be persisted
# verbatim in evidence. Anything outside this set keeps a 160-byte preview
# (which is useful for triage on .git/HEAD, ZIP magic, etc.).
_SECRET_PATHS: Set[str] = {
    # .env* removed from SENSITIVE_PATHS above; entries kept here are
    # harmless (nothing matches them in the new path list) — left for
    # documentation in case the redaction needs to be re-enabled.
    '/.env', '/.env.production', '/.env.local', '/.env.dev',
    '/.aws/credentials', '/.ssh/id_rsa',
    '/wp-config.php.bak', '/wp-config.php.save', '/wp-config.php~',
    '/.htpasswd',
    '/dump.sql', '/database.sql', '/backup.sql',
}

# Regex for KEY=VALUE lines used by both .env-style and shell-export bodies.
_ENV_KEY_RE = re.compile(rb'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=', re.MULTILINE)


def _redact_exposure_evidence(path: str, body: bytes) -> str:
    """Build a non-leaking evidence string for sensitive_paths matches.

    For .env-style configs → list keys, count, size, sha256 (NEVER values).
    For SSH/AWS creds → fingerprint only.
    For SQL dumps → table-count hint via simple INSERT INTO grep.
    Everything else → 160 bytes preview (default, unchanged).
    """
    digest = hashlib.sha256(body).hexdigest()
    if path not in _SECRET_PATHS:
        return body[:160].decode(errors='replace')

    nbytes = len(body)
    if path.startswith('/.env') or path.startswith('/wp-config') or path.endswith('.sql'):
        keys = [m.group(1).decode(errors='replace') for m in _ENV_KEY_RE.finditer(body)]
        keys = sorted(set(keys))
        shown = keys[:20]
        more = max(0, len(keys) - len(shown))
        return (
            f"{nbytes} bytes | {len(keys)} keys | "
            f"sample={', '.join(shown)}"
            + (f" (+{more} more)" if more else "")
            + f" | sha256={digest[:16]}…"
        )
    if path == '/.ssh/id_rsa' or path == '/.aws/credentials' or path == '/.htpasswd':
        return f"{nbytes} bytes credential blob | sha256={digest[:16]}… (content redacted)"
    return f"{nbytes} bytes | sha256={digest[:16]}…"

SEV_MAP = {
    'critical': Severity.CRITICAL,
    'high':     Severity.HIGH,
    'medium':   Severity.MEDIUM,
    'low':      Severity.LOW,
    'info':     Severity.INFO,
}


# Headless-CMS / backend-API unauth signatures, probed against recovered API
# base origins (m11 source-map recovery). (path, body_regex, severity, label).
# A hit = status 200 AND the body regex matches → unauth reachable endpoint.
BACKEND_SIGNATURES: dict = {
    'directus': [
        ('/server/info',  r'"(?:directus|project_name|project)"', 'high',
         'Directus /server/info reachable unauthenticated'),
        ('/server/ping',  r'^pong$', 'info', 'Directus ping'),
        ('/items',        r'"data"\s*:\s*\[', 'high',
         'Directus /items collection listing reachable unauthenticated'),
        ('/users',        r'"data"\s*:\s*\[', 'critical',
         'Directus /users readable unauthenticated (PII)'),
    ],
    'strapi': [
        ('/admin/init',   r'"hasAdmin"', 'medium', 'Strapi admin init state exposed'),
        ('/api',          r'"data"|"error"', 'low', 'Strapi /api reachable'),
    ],
    'hasura': [
        ('/v1/version',   r'"version"', 'medium', 'Hasura version exposed'),
        ('/v1/graphql',   r'"__schema"|"data"', 'high',
         'Hasura GraphQL endpoint reachable (check introspection)'),
    ],
    'supabase': [
        ('/auth/v1/health', r'"date"|"description"|"version"', 'medium',
         'Supabase auth health exposed'),
        ('/rest/v1/',     r'"swagger"|"openapi"|"paths"', 'high',
         'Supabase REST OpenAPI reachable unauthenticated'),
    ],
    'pocketbase': [
        ('/api/health',      r'"code"\s*:\s*200', 'info', 'PocketBase health'),
        ('/api/collections', r'"items"\s*:\s*\[|"totalItems"', 'high',
         'PocketBase /api/collections reachable unauthenticated'),
    ],
    'graphql': [
        ('/graphql',      r'"__schema"|"errors"', 'medium',
         'GraphQL endpoint reachable (check introspection)'),
    ],
}


def _is_in_scope(url: str, apex: str, scope=None) -> bool:
    """True if URL host is in scope. Defers to the Scope object when
    provided (preferred), falls back to apex match for legacy callers."""
    if scope is not None:
        return scope.is_in_scope(url)
    if not apex:
        return True
    try:
        host = (urlparse(url).hostname or '').lower()
    except Exception:
        return True
    apex_l = apex.lower()
    return host == apex_l or host.endswith('.' + apex_l)


def _read_candidates(out_dir: Path, category: str) -> List[str]:
    """Return URL candidates for `category` (xss/sqli/redirect/...) emitted
    by m12. Reads the consolidated ``m14_candidates.json`` first (new in
    Étape 1.3) and falls back to the per-category ``gf_<name>.txt`` file
    for back-compat with older scan outputs.
    """
    out: List[str] = []
    seen: Set[str] = set()
    cand_file = out_dir / "m14_candidates.json"
    if cand_file.exists():
        try:
            data = json.loads(cand_file.read_text())
            for c in data:
                if (c.get('category') or '').lower() != category:
                    continue
                u = (c.get('url') or '').strip()
                if u and u not in seen:
                    out.append(u); seen.add(u)
        except Exception:
            pass
    legacy = out_dir / f"gf_{category}.txt"
    if legacy.exists():
        for line in legacy.read_text().splitlines():
            u = line.strip()
            if u and u not in seen:
                out.append(u); seen.add(u)
    return out


class ActiveValidationModule(BaseModule):

    MODULE_ID   = "m14"
    MODULE_NAME = "ActiveValidation"

    async def run(self, target: ScanTarget) -> None:
        cfg     = self.config.get('active_validation', default={})
        out_dir = self._output_dir(target)
        if not target.live_hosts:
            self.log.warning("No live hosts — skipping active validation")
            return

        if not cfg.get('enabled', True):
            self.log.info("Active validation disabled in config — skipping")
            return

        # Wall-clock budget split across stages.
        total_budget = cfg.get('total_budget_sec', 1800)  # 30 min
        start = time.time()

        def remaining() -> float:
            return max(0.0, total_budget - (time.time() - start))

        active_findings: List[dict] = []

        # Scope filter: drop live_hosts whose hostname isn't in scope.
        # Defers to target.scope when present (Pipeline attaches it at
        # scan start) — that uses the full wildcards file + out_of_scope
        # rules. Falls back to apex match if scope is missing.
        scope = getattr(target, 'scope', None)
        all_live_urls = [h.get('url', '') for h in target.live_hosts if h.get('url')]
        live_urls = [u for u in all_live_urls if _is_in_scope(u, target.domain, scope=scope)]
        out_of_scope = len(all_live_urls) - len(live_urls)
        if out_of_scope:
            self.log.info(f"   scope filter: dropped {out_of_scope}/{len(all_live_urls)} out-of-scope live hosts")
        if not live_urls:
            self.log.warning("No in-scope hosts after scope filter — skipping active validation")
            return
        self.log.info(f"⚔️  Active validation — {len(live_urls)} hosts | budget {total_budget}s")

        # ── Recovered targets (m11 source-map recovery) ─────────────────────
        # Backends / API base URLs the public crawl never reached. Probed for
        # file exposure below + the headless-CMS/API signature check (stage 0).
        recovered_urls, rec_dropped = self._load_recovered_targets(out_dir, target)
        if rec_dropped:
            self.log.info(f"   recovered targets: {rec_dropped} out-of-scope (logged, not probed)")
        if recovered_urls:
            self.log.info(f"   +{len(recovered_urls)} recovered in-scope target(s) for active probing")
            for u in recovered_urls:
                if u not in live_urls:
                    live_urls.append(u)

        # ── 0. Recovered-backend signature probes (Directus/Strapi/Hasura…) ──
        if cfg.get('backend_probe', True) and recovered_urls and remaining() > 60:
            t = time.time()
            hits = await self._probe_recovered_backends(recovered_urls, cfg)
            self.log.info(f"   backend probe: {len(hits)} unauth backend exposure(s) "
                          f"in {int(time.time()-t)}s")
            for h in hits:
                active_findings.append(h)
                self._add_finding(target, Finding(
                    type=FindingType.MISCONFIGURATION,
                    target=target.domain,
                    url=h['url'],
                    title=h['title'],
                    severity=SEV_MAP.get(h.get('severity', 'high'), Severity.HIGH),
                    confidence=h.get('confidence', 0.8),
                    evidence=h.get('evidence', ''),
                    tags=['active', 'backend', h.get('product', 'api')],
                    metadata=h,
                ))

        # ── 1. File exposure brute-check (fast, broad) ──────────────────────
        if cfg.get('file_exposure', True) and live_urls and remaining() > 60:
            t = time.time()
            exposures = await self._brute_files(
                live_urls,
                concurrency  = cfg.get('file_exposure_concurrency', 40),
                timeout      = cfg.get('file_exposure_timeout', 5),
                budget       = min(remaining() * 0.4, 600),
            )
            self.log.info(f"   file exposure: {len(exposures)} confirmed in {int(time.time()-t)}s")
            for e in exposures:
                active_findings.append(e)
                self._add_finding(target, Finding(
                    type=FindingType.ACTIVE_FILE_EXPOSURE,
                    target=target.domain,
                    url=e['url'],
                    title=f"Exposed file: {e['path']}",
                    severity=SEV_MAP.get(e.get('severity','medium'), Severity.MEDIUM),
                    confidence=0.95,
                    evidence=e.get('evidence',''),
                    tags=['active','file-exposure'],
                    metadata=e,
                ))

        # ── 2. Open redirect validation ─────────────────────────────────────
        if cfg.get('open_redirect', True) and remaining() > 60:
            t = time.time()
            candidates = self._collect_open_redirect_urls(out_dir, target.domain, scope=scope)
            if not candidates:
                self.log.info("   open-redirect: 0 candidates (gf_redirect.txt empty or out of scope)")
            else:
                redirects = await self._test_open_redirects(
                    candidates[:cfg.get('open_redirect_cap', 50)],
                    timeout=8,
                    budget=min(remaining() * 0.2, 300),
                )
                self.log.info(
                    f"   open-redirect: {len(redirects)} confirmed in "
                    f"{int(time.time()-t)}s ({len(candidates)} candidates)"
                )
                for r in redirects:
                    active_findings.append(r)
                    self._add_finding(target, Finding(
                        type=FindingType.ACTIVE_OPEN_REDIRECT,
                        target=target.domain,
                        url=r['url'],
                        title=f"Open redirect via ?{r['param']}=",
                        severity=Severity.MEDIUM,
                        confidence=0.95,
                        evidence=r['final_location'],
                        tags=['active','open-redirect'],
                        metadata=r,
                    ))

        # ── 3. Dalfox XSS confirmation ──────────────────────────────────────
        if cfg.get('xss_dalfox', False) and remaining() > 60:  # OPSEC: opt-in (noisy)
            t = time.time()
            xss_targets = self._collect_xss_candidates(out_dir)
            xss_targets = self._filter_in_scope(target, xss_targets, "XSS candidates")
            if xss_targets:
                xss = await self._run_dalfox(
                    xss_targets[:cfg.get('xss_cap', 40)],
                    out_dir,
                    timeout=min(remaining() * 0.2, 600),
                )
                self.log.info(f"   dalfox: {len(xss)} XSS confirmed in {int(time.time()-t)}s")
                for x in xss:
                    active_findings.append(x)
                    self._add_finding(target, Finding(
                        type=FindingType.ACTIVE_XSS,
                        target=target.domain,
                        url=x.get('url',''),
                        title=f"Confirmed XSS: {x.get('type','')}",
                        severity=Severity.HIGH,
                        confidence=0.92,
                        evidence=x.get('payload','')[:300],
                        tags=['active','xss'],
                        metadata=x,
                    ))

        # ── 4. SQLMap (very light, only on reflected/gf:sqli) ───────────────
        if cfg.get('sqli_sqlmap', False) and remaining() > 60:  # OPSEC: opt-in (intrusive)
            t = time.time()
            sqli_targets = self._collect_sqli_candidates(out_dir)
            sqli_targets = self._filter_in_scope(target, sqli_targets, "SQLi candidates")
            if sqli_targets:
                hits = await self._run_sqlmap(
                    sqli_targets[:cfg.get('sqli_cap', 15)],
                    out_dir,
                    budget=min(remaining(), 600),
                )
                self.log.info(f"   sqlmap: {len(hits)} SQLi confirmed in {int(time.time()-t)}s")
                for h in hits:
                    active_findings.append(h)
                    self._add_finding(target, Finding(
                        type=FindingType.ACTIVE_SQLI,
                        target=target.domain,
                        url=h.get('url',''),
                        title=f"Confirmed SQLi: {h.get('dbms','')}",
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        evidence=h.get('evidence',''),
                        tags=['active','sqli'],
                        metadata=h,
                    ))

        # ── 6. WSTG add-ons: HTTP methods / GraphQL introspection / Host header injection ──
        # Each is fast (~5-15s on a typical scan), opt-out via config.
        if cfg.get('http_methods_probe', True) and live_urls and remaining() > 30:
            t = time.time()
            methods_findings = await self._probe_http_methods(live_urls,
                concurrency=cfg.get('http_methods_concurrency', 20),
                timeout=cfg.get('http_methods_timeout', 6))
            for h in methods_findings:
                self._add_finding(target, Finding(
                    type=FindingType.HTTP_METHODS, target=target.domain, url=h['url'],
                    title=f"Dangerous HTTP methods enabled: {', '.join(h['dangerous'])}",
                    severity=Severity.MEDIUM if any(m in h['dangerous'] for m in ('PUT','DELETE','PATCH')) else Severity.LOW,
                    confidence=0.95, tags=['wstg-conf-06', 'http-methods'],
                    evidence=f"Allow: {h['allow']}", metadata=h,
                ))
            self.log.info(f"   HTTP methods: {len(methods_findings)} hosts with dangerous verbs in {int(time.time()-t)}s")

        if cfg.get('graphql_introspection_probe', True) and remaining() > 30:
            t = time.time()
            gql_endpoints = self._collect_graphql_candidates(live_urls, out_dir)
            if gql_endpoints:
                gql_findings = await self._probe_graphql(gql_endpoints,
                    concurrency=cfg.get('graphql_concurrency', 8),
                    timeout=cfg.get('graphql_timeout', 12))
                for h in gql_findings:
                    self._add_finding(target, Finding(
                        type=FindingType.GRAPHQL_INTROSPECTION, target=target.domain, url=h['url'],
                        title=f"GraphQL introspection enabled: {h['url']}",
                        severity=Severity.HIGH if h.get('mutations') else Severity.MEDIUM,
                        confidence=0.95, tags=['wstg-apit-99', 'graphql'],
                        evidence=f"queryType: {h.get('queryType')} | mutations: {h.get('mutations', 0)} | types: {h.get('types', 0)}",
                        metadata=h,
                    ))
                self.log.info(f"   GraphQL: {len(gql_findings)}/{len(gql_endpoints)} introspection-enabled in {int(time.time()-t)}s")
            else:
                self.log.debug("GraphQL: no /graphql endpoint candidates found")

        if cfg.get('host_header_injection_probe', True) and live_urls and remaining() > 30:
            t = time.time()
            hh_findings = await self._probe_host_header_injection(live_urls,
                concurrency=cfg.get('host_header_concurrency', 15),
                timeout=cfg.get('host_header_timeout', 8))
            for h in hh_findings:
                self._add_finding(target, Finding(
                    type=FindingType.HOST_HEADER_INJECTION, target=target.domain, url=h['url'],
                    title=f"Host header injection: canary reflected via {h['header']} ({h['where']})",
                    severity=Severity.HIGH if h['where'] == 'Location' else Severity.MEDIUM,
                    confidence=0.85, tags=['wstg-inpv-17', 'host-header'],
                    evidence=f"Header={h['header']} → reflected in {h['where']}",
                    metadata=h,
                ))
            self.log.info(f"   Host header injection: {len(hh_findings)} reflections in {int(time.time()-t)}s")

        (out_dir / "active_findings.json").write_text(json.dumps(active_findings, indent=2))

        elapsed = int(time.time() - start)
        self.log.info(
            f"✅ M09 done — {len(active_findings)} confirmed findings | {elapsed}s used"
        )

    # ── Stage 1: file exposure brute ────────────────────────────────────────

    async def _brute_files(
        self, hosts: List[str], concurrency: int,
        timeout: int, budget: float,
    ) -> List[dict]:
        """
        Probe SENSITIVE_PATHS on each in-scope host. Confirmation requires:
          - HTTP status 200/206
          - For paths NOT in HTML_OK_PATHS: content-type must NOT be text/html
            (filters soft-404 SPAs that return index.html for any path)
          - Body must contain the path's required `good_fp` fingerprint
        Hosts that 200 on a random canary path are treated as soft-404 and
        skipped entirely (probes against them are unreliable).
        """
        sem = asyncio.Semaphore(concurrency)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=concurrency * 2)
        confirmed: List[dict] = []
        deadline = time.time() + budget

        async def detect_soft_404(session, host: str) -> bool:
            # Use a more generous timeout than the per-path probe — we need
            # this signal to be reliable. One retry on transient failure.
            canary = '/argus-' + ''.join(random.choices(
                string.ascii_lowercase + string.digits, k=14)) + '.txt'
            url = host.rstrip('/') + canary
            for attempt in (1, 2):
                try:
                    async with session.get(
                        url, allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as r:
                        return r.status in (200, 206)
                except Exception:
                    if attempt == 2:
                        return False
                    await asyncio.sleep(0.5)
            return False

        async def check(session, host: str, path: str, good_fp: Optional[bytes], severity: str):
            if time.time() > deadline:
                return
            url = host.rstrip('/') + path
            origin = ''
            try:
                p = urlparse(host)
                origin = f"{p.scheme}://{p.netloc}"
            except Exception:
                origin = host
            async with sem:
                try:
                    async with session.get(
                        url, allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                    ) as r:
                        if r.status not in (200, 206):
                            return
                        ct = (r.headers.get('Content-Type', '') or '').lower()
                        if path not in HTML_OK_PATHS and 'text/html' in ct:
                            return  # soft-404 / SPA index.html / WAF page
                        body = await r.content.read(20_000)
                        if good_fp is not None and good_fp not in body:
                            return
                        # Redact evidence for paths that contain secrets.
                        # `.env`, `wp-config.php*`, `id_rsa`, etc. would
                        # otherwise persist DB passwords / API keys / private
                        # keys verbatim in findings.json + DB. For benign
                        # paths (`.git/HEAD`, ZIP magic) the first 160 bytes
                        # are safe and useful for triage.
                        confirmed.append({
                            'host':         origin,
                            'path':         path,
                            'url':          url,
                            'status':       r.status,
                            'length':       int(r.headers.get('Content-Length', 0)) or len(body),
                            'content_type': ct[:80],
                            'severity':     severity,
                            'evidence':     _redact_exposure_evidence(path, body),
                            'body_sha256':  hashlib.sha256(body).hexdigest(),
                        })
                except Exception:
                    pass

        async with aiohttp.ClientSession(
            connector=connector,
            headers={'User-Agent': 'Argus/2.0 ActiveValidation'},
        ) as session:
            # Pre-flight: detect soft-404 hosts and skip them.
            sample_results = await asyncio.gather(
                *(detect_soft_404(session, h) for h in hosts),
                return_exceptions=True,
            )
            # Three buckets: clean (canary returned !=200 → real 404s), soft
            # (canary returned 200/206 → SPA/WAF page), and unknown
            # (detect_soft_404 raised — usually network down). Including
            # "unknown" in scannable used to cascade into timeouts here for
            # the same hosts; safer to skip them with a log line.
            scannable: List[str] = []
            soft_hosts: List[str] = []
            errored: List[str] = []
            for h, r in zip(hosts, sample_results):
                if isinstance(r, Exception):
                    errored.append(h)
                elif r is True:
                    soft_hosts.append(h)
                else:
                    scannable.append(h)
            if soft_hosts:
                self.log.info(
                    f"   soft-404 detected on {len(soft_hosts)}/{len(hosts)} "
                    f"hosts — skipping file_exposure on those"
                )
            if errored:
                self.log.info(
                    f"   pre-flight canary failed on {len(errored)}/{len(hosts)} "
                    f"hosts — skipping file_exposure on those (likely unreachable)"
                )

            tasks = []
            for host in scannable:
                for path, good_fp, severity in SENSITIVE_PATHS:
                    tasks.append(check(session, host, path, good_fp, severity))
            for chunk_start in range(0, len(tasks), 200):
                chunk = tasks[chunk_start:chunk_start + 200]
                await asyncio.gather(*chunk, return_exceptions=True)
                if time.time() > deadline:
                    break
        return confirmed

    # ── Stage 2: open redirect ──────────────────────────────────────────────

    def _collect_open_redirect_urls(self, out_dir: Path, apex: str, scope=None) -> List[Tuple[str, str]]:
        """
        Return [(url, suspect_param)] for in-scope URLs hosting redirect-like
        params. Source: m12's m14_candidates.json (category=redirect) when
        present, fallback to gf_redirect.txt for back-compat.
        """
        targets: List[Tuple[str, str]] = []
        suspect = {'next','redirect','redir','url','goto','dest','destination',
                   'return','return_url','returnurl','returnto','rurl','to',
                   'out','view','dir','show','navigation','open','file',
                   'val','validate','domain','callback','jump','target'}
        urls = _read_candidates(out_dir, 'redirect')
        for url in urls:
            if '?' not in url or not _is_in_scope(url, apex, scope=scope):
                continue
            try:
                p = urlparse(url)
                qs = parse_qs(p.query, keep_blank_values=True)
                for name in qs:
                    if name.lower() in suspect:
                        targets.append((url, name))
                        break
            except Exception:
                continue
        return targets

    async def _test_open_redirects(
        self, candidates: List[Tuple[str, str]], timeout: int, budget: float,
    ) -> List[dict]:
        """Inject https://argus-canary.invalid into the suspect param, watch Location."""
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=20)
        confirmed: List[dict] = []
        deadline = time.time() + budget
        canary_host = 'argus-redirect-canary.invalid'
        canary_url  = f'https://{canary_host}/'

        async def probe(session, url: str, param: str):
            if time.time() > deadline:
                return
            try:
                p = urlparse(url)
                qs = parse_qs(p.query, keep_blank_values=True)
                qs[param] = [canary_url]
                new_q = urlencode([(k, v[0] if v else '') for k, v in qs.items()])
                test_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, ''))
                async with session.get(test_url, allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                    if r.status not in (301, 302, 303, 307, 308):
                        return
                    loc = r.headers.get('Location', '')
                    if canary_host in loc or loc.startswith(canary_url):
                        confirmed.append({
                            'url':            test_url,
                            'param':          param,
                            'status':         r.status,
                            'final_location': loc,
                        })
            except Exception:
                pass

        async with aiohttp.ClientSession(connector=connector,
                                         headers={'User-Agent': 'Argus/2.0 ActiveValidation'}) as session:
            await asyncio.gather(*(probe(session, u, p) for u, p in candidates),
                                 return_exceptions=True)
        return confirmed

    # ── Stage 3: dalfox XSS ─────────────────────────────────────────────────

    async def _probe_recovered_backends(self, recovered_urls: List[str],
                                        cfg: dict) -> List[dict]:
        """Probe recovered API base origins for known headless-CMS / backend
        unauth signatures (Directus/Strapi/Hasura/Supabase/PocketBase/GraphQL).
        A hit needs status 200 AND a body-signature match — keeps FP low. Only
        non-`info` matches become findings; `info` is fingerprint noise."""
        # Distinct origins (scheme://host[:port]) from the recovered URLs.
        origins: Set[str] = set()
        for u in recovered_urls:
            try:
                p = urlparse(u if "://" in u else f"https://{u}")
                if p.scheme and p.netloc:
                    origins.add(f"{p.scheme}://{p.netloc}")
            except Exception:
                continue
        if not origins:
            return []
        origins = set(list(origins)[:int(cfg.get('backend_probe_max_origins', 20))])

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        hits: List[dict] = []
        seen: Set[str] = set()
        sem = asyncio.Semaphore(int(cfg.get('backend_probe_concurrency', 10)))

        async def probe(sess, origin, product, path, rx, sev, label):
            url = origin.rstrip('/') + path
            async with sem:
                try:
                    async with sess.get(url, timeout=aiohttp.ClientTimeout(total=8),
                                        allow_redirects=False) as r:
                        if r.status != 200:
                            return
                        body = (await r.text())[:20000]
                except Exception:
                    return
            if not re.search(rx, body, re.I | re.M):
                return
            if sev == 'info':
                self.log.debug(f"   backend fingerprint: {product} at {origin}")
                return
            key = f"{product}:{url}"
            if key in seen:
                return
            seen.add(key)
            hits.append({
                'url': url, 'product': product, 'severity': sev,
                'title': f"{label} ({origin})",
                'confidence': 0.85,
                'evidence': f"GET {url} → 200, body matches /{rx}/",
                'check': 'backend_probe',
            })

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl_ctx),
            headers={'User-Agent': 'Argus/2.0 ActiveValidation'},
        ) as sess:
            tasks = []
            for origin in origins:
                for product, sigs in BACKEND_SIGNATURES.items():
                    for path, rx, sev, label in sigs:
                        tasks.append(probe(sess, origin, product, path, rx, sev, label))
            await asyncio.gather(*tasks)
        return hits

    def _collect_xss_candidates(self, out_dir: Path) -> List[str]:
        """Combine reflected params (priority) + m12 XSS candidates."""
        urls: List[str] = []
        seen: Set[str] = set()

        # Priority 1: reflected params from M07
        refl_file = out_dir / "reflected_params.json"
        if refl_file.exists():
            try:
                refl = json.loads(refl_file.read_text())
                for r in refl:
                    u = r.get('url', '')
                    if u and u not in seen:
                        urls.append(u); seen.add(u)
            except Exception:
                pass

        # Priority 2: m12 candidates (xss category), back-compat gf_xss.txt
        for url in _read_candidates(out_dir, 'xss'):
            if url and url not in seen and '?' in url:
                urls.append(url); seen.add(url)
        return urls

    async def _run_dalfox(self, urls: List[str], out_dir: Path, timeout: float) -> List[dict]:
        if not shutil.which('dalfox'):
            self.log.debug("dalfox not installed — skipping XSS validation")
            return []
        out_file = out_dir / "dalfox_results.json"
        in_file  = out_dir / "dalfox_targets.txt"
        in_file.write_text('\n'.join(urls))

        try:
            proc = await asyncio.create_subprocess_exec(
                'dalfox', 'file', str(in_file),
                '--silence',
                '--no-color',
                '--skip-bav',                # skip basic auth bypass — we want speed
                '-o', str(out_file),
                '--format', 'json',
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
        except Exception as e:
            self.log.debug(f"dalfox error: {e}")
        finally:
            in_file.unlink(missing_ok=True)

        if not out_file.exists():
            return []
        results: List[dict] = []
        for line in out_file.read_text().splitlines():
            try:
                d = json.loads(line)
                results.append({
                    'url':     d.get('data') or d.get('url') or '',
                    'type':    d.get('type','XSS'),
                    'param':   d.get('param',''),
                    'payload': d.get('payload','')[:300],
                    'method':  d.get('method','GET'),
                })
            except Exception:
                pass
        return results

    # ── Stage 4: sqlmap (light) ─────────────────────────────────────────────

    def _collect_sqli_candidates(self, out_dir: Path) -> List[str]:
        urls: List[str] = []
        seen: Set[str] = set()

        # Reflected first (more likely to be exploitable)
        refl_file = out_dir / "reflected_params.json"
        if refl_file.exists():
            try:
                refl = json.loads(refl_file.read_text())
                for r in refl:
                    u = r.get('url', '')
                    if u and u not in seen:
                        urls.append(u); seen.add(u)
            except Exception:
                pass

        for url in _read_candidates(out_dir, 'sqli'):
            if url and url not in seen and '?' in url:
                urls.append(url); seen.add(url)
        return urls

    async def _run_sqlmap(self, urls: List[str], out_dir: Path, budget: float) -> List[dict]:
        """Light sqlmap probe per URL — level=1 risk=1, no enum, batch only."""
        if not shutil.which('sqlmap'):
            self.log.debug("sqlmap not installed — skipping SQLi validation")
            return []

        results: List[dict] = []
        per_target_budget = max(60, int(budget / max(1, len(urls))))
        sem = asyncio.Semaphore(2)  # sqlmap is heavy — only 2 in parallel
        sqlmap_dir = out_dir / "sqlmap"
        sqlmap_dir.mkdir(exist_ok=True)
        deadline = time.time() + budget

        # Threading: 4 concurrent requests per URL is fine on normal targets
        # but trips IDS / rate-limit under stealth. CLAUDE.md OPSEC mandates
        # singling things up when stealth is on.
        sqlmap_threads = '1' if self.stealth else '4'

        async def check(url: str):
            if time.time() > deadline:
                return
            async with sem:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        'sqlmap',
                        '-u', url,
                        '--batch',
                        '--random-agent',
                        '--level=1',
                        '--risk=1',
                        f'--threads={sqlmap_threads}',
                        '--timeout=8',
                        '--retries=1',
                        '--smart',                  # skip non-injectable
                        '--disable-coloring',
                        '--output-dir', str(sqlmap_dir),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=per_target_budget)
                    out = stdout.decode(errors='ignore')
                    # Detect "the back-end DBMS is" or "is vulnerable" lines
                    if 'is vulnerable' in out.lower() or 'back-end DBMS' in out:
                        dbms = ''
                        for line in out.splitlines():
                            if 'back-end DBMS' in line:
                                dbms = line.split(':',1)[1].strip()[:60]
                                break
                        evidence = '\n'.join(l for l in out.splitlines()
                                             if 'Parameter' in l or 'Type:' in l or 'Title:' in l
                                             or 'Payload:' in l or 'is vulnerable' in l.lower())[:600]
                        results.append({
                            'url':      url,
                            'dbms':     dbms or 'unknown',
                            'evidence': evidence,
                        })
                except asyncio.TimeoutError:
                    try: proc.kill()
                    except Exception: pass
                except Exception as e:
                    self.log.debug(f"sqlmap error on {url}: {e}")

        await asyncio.gather(*(check(u) for u in urls), return_exceptions=True)
        return results

    # ════════════════════════════════════════════════════════════════════════
    #  WSTG add-on probes
    # ════════════════════════════════════════════════════════════════════════

    # ── HTTP methods (WSTG-CONF-06) ─────────────────────────────────────────
    DANGEROUS_METHODS = {'PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL'}

    async def _probe_http_methods(self, urls: List[str], concurrency: int, timeout: int) -> List[dict]:
        """OPTIONS probe per host root. Flag dangerous methods in Allow."""
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=concurrency * 2)
        results: List[dict] = []
        seen: Set[str] = set()
        sem = asyncio.Semaphore(concurrency)
        async def probe(url):
            from urllib.parse import urlsplit
            base = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}/"
            if base in seen:
                return
            seen.add(base)
            async with sem:
                try:
                    async with aiohttp.ClientSession(connector=connector, connector_owner=False) as sess:
                        async with sess.options(base, timeout=aiohttp.ClientTimeout(total=timeout),
                                                allow_redirects=False) as r:
                            allow = r.headers.get('Allow') or r.headers.get('allow') or ''
                            if not allow:
                                return
                            methods = {m.strip().upper() for m in allow.split(',')}
                            dangerous = sorted(methods & self.DANGEROUS_METHODS)
                            if dangerous:
                                results.append({
                                    'url': base, 'allow': allow,
                                    'dangerous': dangerous, 'all_methods': sorted(methods),
                                })
                except Exception as e:
                    self.log.debug(f"OPTIONS {base}: {e}")
        await asyncio.gather(*(probe(u) for u in urls), return_exceptions=True)
        try: await connector.close()
        except Exception: pass
        return results

    # ── GraphQL introspection (WSTG-APIT-99) ────────────────────────────────
    GRAPHQL_INTROSPECTION_QUERY = (
        '{"query": "{__schema{queryType{name} mutationType{name} types{name fields{name}}}}"}'
    )
    GRAPHQL_PATH_HINTS = ('/graphql', '/graphiql', '/api/graphql', '/v1/graphql', '/query')

    def _collect_graphql_candidates(self, live_urls: List[str], out_dir: Path) -> List[str]:
        """Build a list of GraphQL endpoint URLs to probe.
        Sources:
          - URLs collected by m04 (urls_all.txt) that match /graphql etc.
          - For each live host root, probe the standard /graphql path.
        """
        from urllib.parse import urlsplit
        candidates: Set[str] = set()
        # 1. From m04 url collection
        urls_file = out_dir / "urls_all.txt"
        if urls_file.exists():
            try:
                for line in urls_file.read_text().splitlines():
                    line = line.strip()
                    if not line: continue
                    p = urlsplit(line).path.lower()
                    if any(p.endswith(h) or p == h for h in self.GRAPHQL_PATH_HINTS):
                        candidates.add(line)
            except Exception:
                pass
        # 2. From live hosts: append /graphql to each root
        for u in live_urls:
            try:
                s = urlsplit(u)
                if s.scheme and s.netloc:
                    candidates.add(f"{s.scheme}://{s.netloc}/graphql")
            except Exception:
                continue
        return sorted(candidates)

    async def _probe_graphql(self, endpoints: List[str], concurrency: int, timeout: int) -> List[dict]:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=concurrency * 2)
        sem = asyncio.Semaphore(concurrency)
        results: List[dict] = []

        # One session for the whole batch — the previous version opened a
        # fresh ClientSession per probe() call which defeats connection
        # pooling and triggers TLS handshake cost for every endpoint.
        async def probe(sess, url):
            async with sem:
                try:
                    async with sess.post(
                        url, data=self.GRAPHQL_INTROSPECTION_QUERY,
                        headers={'Content-Type': 'application/json'},
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        allow_redirects=False,
                    ) as r:
                        if r.status != 200:
                            return
                        ct = (r.headers.get('Content-Type') or '').lower()
                        if 'application/json' not in ct and 'text/json' not in ct:
                            return
                        try:
                            body = await r.json(content_type=None)
                        except Exception:
                            return
                        data = (body or {}).get('data') or {}
                        schema = data.get('__schema') or {}
                        qt = (schema.get('queryType') or {}).get('name')
                        if not qt:
                            return
                        mt = (schema.get('mutationType') or {}).get('name')
                        results.append({
                            'url': url, 'queryType': qt,
                            'mutations': bool(mt), 'mutationType': mt,
                            'types': len(schema.get('types') or []),
                        })
                except Exception as e:
                    self.log.debug(f"GraphQL probe {url}: {e}")

        async with aiohttp.ClientSession(connector=connector) as sess:
            await asyncio.gather(*(probe(sess, u) for u in endpoints),
                                 return_exceptions=True)
        return results

    # ── Host header injection (WSTG-INPV-17) ────────────────────────────────
    HH_HEADERS_TO_FUZZ = (
        'X-Forwarded-Host', 'X-Original-URL', 'X-Rewrite-URL',
        'X-HTTP-Host-Override', 'Forwarded',
    )

    async def _probe_host_header_injection(self, urls: List[str], concurrency: int, timeout: int) -> List[dict]:
        import secrets as _secrets
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=concurrency * 2)
        sem = asyncio.Semaphore(concurrency)
        results: List[dict] = []
        seen: Set[str] = set()
        # Test only host roots (not every URL) to keep noise + load reasonable.
        from urllib.parse import urlsplit
        async def probe(url):
            base_parts = urlsplit(url)
            base = f"{base_parts.scheme}://{base_parts.netloc}/"
            if base in seen:
                return
            seen.add(base)
            canary = f"argus-{_secrets.token_hex(4)}.canary.invalid"
            async with sem:
                for header in self.HH_HEADERS_TO_FUZZ:
                    try:
                        async with aiohttp.ClientSession(connector=connector, connector_owner=False) as sess:
                            value = f"for={canary}" if header == 'Forwarded' else canary
                            async with sess.get(base,
                                                headers={header: value},
                                                timeout=aiohttp.ClientTimeout(total=timeout),
                                                allow_redirects=False) as r:
                                # Reflection in Location header (open redirect via host header)
                                loc = r.headers.get('Location') or ''
                                if canary in loc:
                                    results.append({'url': base, 'header': header, 'where': 'Location',
                                                    'value': loc[:200]})
                                    return  # one finding per host suffices
                                # Reflection in body — sample 8KB to bound cost
                                body = await r.content.read(8192)
                                if canary.encode() in body:
                                    results.append({'url': base, 'header': header, 'where': 'body',
                                                    'value': canary})
                                    return
                    except Exception as e:
                        self.log.debug(f"HH probe {base} [{header}]: {e}")
                        continue
        await asyncio.gather(*(probe(u) for u in urls), return_exceptions=True)
        try: await connector.close()
        except Exception: pass
        return results
