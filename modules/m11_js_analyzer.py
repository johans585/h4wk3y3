"""
Argus V2 - Module 05: JavaScript Analyzer (v2)

Architecture:
  1. Discover JS URLs  — HTML parsing (M02b bodies) + urls_all.txt + common paths
  2. Fetch content     — aiohttp shared session, no external dependency
  3. Native analysis   — secrets + endpoints regex (always runs)
  4. jsluice           — optional enhancement on local temp files
  5. Source maps       — detect .js.map exposure + sourcesContent leak
"""

import asyncio
import aiohttp
import ssl
import json
import os
import re
import socket
import tempfile
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urljoin, urlparse
from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, Severity


# ── Secret patterns ──────────────────────────────────────────────────────────
# (name, severity, confidence, regex)
SECRET_PATTERNS: List[Tuple[str, Severity, float, str]] = [
    # AWS
    ("aws_access_key",    Severity.CRITICAL, 0.95,
     r"(?<![A-Z0-9])((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])"),
    ("aws_secret_key",    Severity.CRITICAL, 0.85,
     r'(?i)(?:aws|amazon).{0,30}["\']([A-Za-z0-9/+]{40})["\']'),
    # Google
    ("google_api_key",    Severity.HIGH, 0.95,
     r"AIza[0-9A-Za-z_\-]{35}"),
    ("google_oauth",      Severity.HIGH, 0.90,
     r"ya29\.[0-9A-Za-z_\-]{30,}"),
    # Private keys
    ("private_key",       Severity.CRITICAL, 0.99,
     r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----"),
    # JWT
    ("jwt_token",         Severity.MEDIUM, 0.90,
     r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
    # Stripe
    ("stripe_live_key",   Severity.CRITICAL, 0.99,
     r"sk_live_[0-9A-Za-z]{24,}"),
    ("stripe_test_key",   Severity.LOW, 0.99,
     r"sk_test_[0-9A-Za-z]{24,}"),
    # Firebase
    ("firebase_url",      Severity.MEDIUM, 0.90,
     r"[a-zA-Z0-9_-]+\.firebaseio\.com"),
    # Database URIs with credentials
    ("mongodb_uri",       Severity.CRITICAL, 0.95,
     r"mongodb(?:\+srv)?://[A-Za-z0-9_%+.-]+:[^@\s\"'<>]{3,}@[^\s\"'<>]{5,}"),
    ("postgresql_uri",    Severity.CRITICAL, 0.95,
     r"postgres(?:ql)?://[A-Za-z0-9_%+.-]+:[^@\s\"'<>]{3,}@[^\s\"'<>]{5,}"),
    ("mysql_uri",         Severity.CRITICAL, 0.95,
     r"mysql://[A-Za-z0-9_%+.-]+:[^@\s\"'<>]{3,}@[^\s\"'<>]{5,}"),
    # Generic — requires both keyword + value (stricter = fewer FP)
    ("generic_api_key",   Severity.HIGH, 0.70,
     r'(?i)(?:api_?key|apikey|client_?secret|access_?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,64})["\']'),
    ("hardcoded_password", Severity.HIGH, 0.65,
     r'(?i)(?:password|passwd)\s*[:=]\s*["\']([^"\']{8,64})["\']'),
    # S3
    ("s3_bucket",         Severity.MEDIUM, 0.85,
     r"[a-z0-9][a-z0-9\-]{2,62}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com"),
]

# ── Endpoint extraction patterns ──────────────────────────────────────────────
# Each pattern must have exactly 1 capture group for the URL
ENDPOINT_PATTERNS: List[str] = [
    r'fetch\s*\(\s*["`\']([^"`\'\s]{5,200})["`\']',
    r'axios\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*["`\']([^"`\'\s]{5,200})["`\']',
    r'axios\s*\(\s*\{[^}]{0,200}url\s*:\s*["`\']([^"`\'\s]{5,200})["`\']',
    r'\$\s*\.\s*(?:get|post|ajax|getJSON|getScript)\s*\(\s*["`\']([^"`\'\s]{5,200})["`\']',
    r'\.open\s*\(\s*["`\'][A-Z]+["`\']\s*,\s*["`\']([^"`\'\s]{5,200})["`\']',
    r'(?:request|superagent)\s*\.\s*(?:get|post|put|delete)\s*\(\s*["`\']([^"`\'\s]{5,200})["`\']',
    # Angular HttpClient
    r'this\s*\.\s*http\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["`\']([^"`\'\s]{5,200})["`\']',
    # Path string literals — /api/, /v1/, /graphql, /auth etc.
    r'["`\'](/(?:api|v\d+|rest|graphql|gql|admin|auth|oauth|login|logout|register|user|account|internal|private|upload|download)[^"`\'\s<>]{2,100})["`\']',
]

# ── Dangerous code patterns ───────────────────────────────────────────────────
DANGEROUS_PATTERNS: List[Tuple[str, Severity, float, str]] = [
    ("eval_non_literal",      Severity.HIGH,   0.70,
     r"eval\s*\([^)\"'`]{3,}\)"),
    ("inner_html_assign",     Severity.MEDIUM, 0.80,
     r"\.innerHTML\s*\+?=\s*(?![\"'`][^<\"'`]{0,50}[\"'`]\s*;)"),
    ("document_write",        Severity.MEDIUM, 0.80,
     r"document\.write\s*\("),
    ("postmessage_no_origin", Severity.MEDIUM, 0.60,
     r"addEventListener\s*\(\s*[\"']message[\"']"),
    ("open_redirect_js",      Severity.MEDIUM, 0.65,
     r"(?:window\.location|location\.href|location\.replace)\s*=\s*[^\"'/\s]"),
    ("sensitive_localstorage",Severity.LOW,    0.70,
     r"localStorage\.setItem\s*\(\s*[\"'](?:token|password|secret|api_?key|auth)[\"']"),
]

# Names from DANGEROUS_PATTERNS — used to route findings to JS_VULNERABILITY
# instead of JS_SECRET (these are anti-patterns, not credential leaks).
DANGEROUS_PATTERN_NAMES = {p[0] for p in DANGEROUS_PATTERNS}


# ── Source-map recovery patterns ─────────────────────────────────────────────
# These run ONLY on first-party source recovered from exposed .js.map files
# (the `sourcesContent` array). That code is UN-minified — real identifiers,
# comments and config objects — so we can be both broader and more precise than
# the minified-bundle regexes without the usual false-positive blow-up. Vendor
# sources (node_modules / webpack runtime) are skipped before analysis.

# High-value secrets credible even in client source (server-side tokens /
# private material / hardcoded literals). (name, severity, confidence, regex)
SOURCEMAP_SECRET_PATTERNS: List[Tuple[str, Severity, float, str]] = [
    ("slack_token",       Severity.CRITICAL, 0.95, r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("slack_webhook",     Severity.HIGH,     0.95, r"https://hooks\.slack\.com/services/[A-Za-z0-9_/]+"),
    ("discord_webhook",   Severity.HIGH,     0.90, r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"),
    ("github_token",      Severity.CRITICAL, 0.95, r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("gitlab_pat",        Severity.CRITICAL, 0.95, r"glpat-[A-Za-z0-9_-]{20,}"),
    ("npm_token",         Severity.CRITICAL, 0.90, r"npm_[A-Za-z0-9]{36}"),
    ("openai_key",        Severity.CRITICAL, 0.90, r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    ("twilio_account_sid",Severity.HIGH,     0.80, r"AC[0-9a-fA-F]{32}"),
    ("twilio_api_key",    Severity.CRITICAL, 0.90, r"SK[0-9a-fA-F]{32}"),
    ("sendgrid_key",      Severity.CRITICAL, 0.95, r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    ("mailgun_key",       Severity.CRITICAL, 0.85, r"key-[0-9a-f]{32}"),
    ("mapbox_secret",     Severity.HIGH,     0.85, r"sk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    ("square_token",      Severity.CRITICAL, 0.90, r"sq0(?:atp|csp)-[A-Za-z0-9_-]{22,}"),
    ("braintree_token",   Severity.HIGH,     0.85, r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    # Config-object credentials with a LITERAL value (not process.env / import).
    ("config_credential", Severity.HIGH,     0.70,
     r"(?i)(?:client_?secret|api_?secret|app_?secret|auth_?token|access_?token|"
     r"secret_?key|private_?key|encryption_?key|db_?password|database_?password)"
     r"\s*[:=]\s*[\"']([^\"'\s$]{8,120})[\"']"),
    ("hardcoded_password",Severity.HIGH,     0.60,
     r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"'\s$]{6,80})[\"']"),
    ("basic_auth_url",    Severity.HIGH,     0.85,
     r"https?://[A-Za-z0-9._%+-]+:[^@\s\"'/]{3,}@[A-Za-z0-9.-]+"),
]

# Internal / non-production backend hosts declared in source — recon gold:
# hidden APIs the public crawl never reaches.
INTERNAL_HOST_RE = re.compile(
    r"https?://[A-Za-z0-9.-]*\.(?:internal|intranet|corp|local|lan|"
    r"staging|stage|dev|qa|uat|preprod|pre-prod|test|sandbox)\b[A-Za-z0-9./_%-]*",
    re.IGNORECASE)
# baseURL / API base declarations → capture the literal backend URL.
API_BASE_RE = re.compile(
    r"(?i)(?:base_?url|api_?url|api_?base|api_?host|endpoint|backend|server_?url|"
    r"gateway_?url|graphql_?(?:uri|url|endpoint))\s*[:=]\s*[\"'](https?://[^\"'\s]{6,200})[\"']")
# process.env / import.meta.env names → expected config surface (inventory/info).
ENV_NAME_RE = re.compile(r"(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]{2,})")
# Router path definitions (Vue/React router etc.).
ROUTE_RE = re.compile(r"(?i)\bpath\s*:\s*[\"'](/[^\"'\s]{0,120})[\"']")
# GraphQL operations declared in source.
GQL_OP_RE = re.compile(r"(?i)\b(query|mutation|subscription)\s+([A-Za-z]\w{2,})\s*[\({]")
# Client-side access-control surface — flags authz logic worth re-testing on the
# server (client checks are bypassable; the names reveal roles/permissions).
ACCESS_CONTROL_RE = re.compile(
    r"(?i)\b(?:isAdmin|isSuperAdmin|hasRole|hasAnyRole|hasPermission|hasAuthority|"
    r"requireAuth|requireRole|checkPermission|isAuthenticated|"
    r"role\s*===?\s*[\"'][^\"']+[\"']|permissions?\s*\.\s*includes)")
# Suspicious comments left in source.
COMMENT_FLAG_RE = re.compile(
    r"(?im)//[^\n]*\b(?:TODO|FIXME|HACK|XXX|BUG|workaround|temporary|remove before|"
    r"do not commit|backdoor|hardcoded|password|secret|token|api[_-]?key)\b[^\n]*")
# Request shapes from recovered API-client code: HTTP method + path (+ the call
# site reveals the real param/body keys). Feeds m14 with confirmed endpoints
# and verbs instead of guessed param names.
REQUEST_SHAPE_RE = re.compile(
    r"""(?ix)
    (?:axios|http|api|client|\$http|request|superagent)
    \s*\.\s*(get|post|put|patch|delete|head)\s*\(\s*
    [`'"]([^`'"]{1,200})[`'"]""")
# Library/version banners present in recovered source — feed CVE correlation.
DEP_BANNER_RE = re.compile(
    r"(?i)(?:/\*!?|\*|//|@)\s*([a-z][a-z0-9_.-]{1,40})(?:\.js|\.min)?[\s@v]+v?"
    r"(\d+\.\d+(?:\.\d+)?)\b")
# package.json dependency block reconstructed in a chunk.
DEP_JSON_RE = re.compile(r'"([a-z0-9@/_.-]{2,60})"\s*:\s*"[~^>=<\s]*(\d+\.\d+(?:\.\d+)?)"')

# Source paths to skip during recovery — vendor / build runtime, not your code.
# NB: must strip the `webpack:///` *scheme* first (every source carries it),
# then match vendor *path components* — otherwise the scheme alone flags
# everything as vendor.
_VENDOR_SRC_RE = re.compile(
    r"(?:^|/)(?:node_modules|bower_components|jspm_packages|\.pnpm)(?:/|$)|"
    r"^webpack/(?:bootstrap|runtime)|/webpack/(?:bootstrap|runtime)|"
    r"^external\s", re.IGNORECASE)

# Recovered-source extensions worth deep-analysing (skip images/fonts/maps).
_SRC_ANALYSE_EXT = ('.js', '.jsx', '.ts', '.tsx', '.vue', '.mjs', '.cjs',
                    '.json', '.html', '.svelte', '.coffee')


def _is_vendor_source(path: str) -> bool:
    """True for 3rd-party / build-runtime source paths (node_modules etc.).

    The `webpack:///` (or similar) scheme is stripped first — it prefixes every
    source path, so matching it would flag all first-party code as vendor."""
    p = (path or "").lower()
    p = re.sub(r"^[a-z]+:/+", "", p)
    return ('node_modules' in p) or bool(_VENDOR_SRC_RE.search(p))


def _safe_source_path(src_path: str) -> str:
    """Map a `webpack:///./src/foo.js?hash` source path to a safe relative
    filesystem path (no scheme, no traversal, bounded depth/segment length)."""
    p = (src_path or "unknown").split("?")[0].split("#")[0]
    p = re.sub(r"^[a-z]+:/+", "", p, flags=re.IGNORECASE).replace("\\", "/")
    segs = [re.sub(r"[^A-Za-z0-9._@+-]", "_", s)[:80]
            for s in p.split("/") if s not in ("", ".", "..")]
    segs = [s for s in segs if s][-12:]
    return "/".join(segs) or "unknown.txt"

# CDN hostnames whose JS / sourcemaps should NEVER produce a finding —
# they're public 3rd-party libraries (Bootstrap, jQuery, etc.) shipped as-is.
# Match either the netloc exactly or as a suffix (".cdn.example.com").
CDN_HOSTS = {
    'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'c0.wp.com', 'c1.wp.com',
    's0.wp.com', 's1.wp.com', 's2.wp.com',
    'unpkg.com', 'registry.npmjs.org', 'cdn.bootcss.com',
    'maxcdn.bootstrapcdn.com', 'stackpath.bootstrapcdn.com',
    'cdn.datatables.net', 'code.jquery.com', 'ajax.googleapis.com',
    'fonts.googleapis.com', 'use.fontawesome.com', 'cdn.tiny.cloud',
    'cdn.ckeditor.com', 'cdn.tailwindcss.com', 'cdn.skypack.dev',
    'esm.sh', 'jspm.io', 'cdn.jsdelivr.com',
}

# Filename patterns that identify well-known public JS libraries. Findings
# from these files are noisy false positives (the library code is open and
# audited upstream — e.g. jQuery's .innerHTML usage isn't your bug).
LIB_FILE_PATTERNS = re.compile(
    r'/(?:'
    r'jquery(?:[.-][\w.]*)?\.min\.js|'
    r'bootstrap(?:[.-][\w.]*)?\.min\.js|'
    r'popper(?:[.-][\w.]*)?\.min\.js|'
    r'vue(?:[.-][\w.]*)?\.min\.js|'
    r'react(?:[.-][\w.]*)?\.(?:production\.)?min\.js|'
    r'angular(?:[.-][\w.]*)?\.min\.js|'
    r'lodash(?:[.-][\w.]*)?\.min\.js|'
    r'moment(?:[.-][\w.]*)?\.min\.js|'
    r'modernizr(?:[.-][\w.]*)?\.min\.js|'
    r'underscore(?:[.-][\w.]*)?\.min\.js|'
    r'tailwind(?:[.-][\w.]*)?\.min\.css|'
    r'fontawesome(?:[.-][\w.]*)?\.(?:min\.)?(?:js|css)|'
    r'(?:swiper|slick|owl\.carousel)(?:[.-][\w.]*)?\.min\.js'
    r')(?:\.map)?(?:[?#]|$)',
    re.IGNORECASE,
)


def _is_cdn_host(url: str) -> bool:
    """Return True if URL is hosted on a known 3rd-party CDN."""
    from urllib.parse import urlsplit
    try:
        host = (urlsplit(url).hostname or '').lower()
    except Exception:
        return False
    if host in CDN_HOSTS:
        return True
    return any(host.endswith('.' + c) for c in CDN_HOSTS)


def _is_lib_file(url: str) -> bool:
    """Return True if URL points to a known public-library file."""
    return bool(LIB_FILE_PATTERNS.search(url))


class JSAnalyzerModule(BaseModule):

    MODULE_ID   = "m11"
    MODULE_NAME = "JavaScript Analyzer"

    JSLUICE_AVAILABLE: bool = bool(__import__("shutil").which("jsluice"))

    # Source-map recovery memory bounds (overridable via js_analyzer config).
    _SM_CAPTURE_BUDGET = 24_000_000   # total recovered source held in memory
    _SM_FILE_CAP       = 1_000_000    # per-source-file cap

    async def run(self, target: ScanTarget) -> None:
        cfg     = self.config.get('js_analyzer', default={})
        out_dir = self._output_dir(target)
        # Per-run counter for the source-map capture budget (see _check_sourcemaps).
        self._sm_captured = 0
        self._SM_CAPTURE_BUDGET = int(cfg.get('sourcemap_capture_budget', self._SM_CAPTURE_BUDGET))
        self._SM_FILE_CAP        = int(cfg.get('sourcemap_file_cap', self._SM_FILE_CAP))

        if not target.live_hosts:
            self.log.warning("No live hosts from M02 — skipping JS analysis")
            return

        # ── 1. Discover JS URLs ──────────────────────────────
        js_urls = await self._discover_js_urls(target, out_dir, cfg)
        self.log.info(f"🔎 JS analysis — {len(js_urls)} JS files discovered")
        (out_dir / "js_files.txt").write_text('\n'.join(sorted(js_urls)))

        if not js_urls:
            self.log.warning("No JS files found — check live hosts and M02b output")
            return

        # ── 2. Fetch JS content ──────────────────────────────
        max_files = cfg.get('max_js_files', 500)
        js_content = await self._fetch_js_files(list(js_urls)[:max_files], cfg)
        self.log.info(f"   {len(js_content)}/{min(len(js_urls), max_files)} files fetched")

        if not js_content:
            self.log.warning("Could not fetch any JS content")
            return

        # ── 3. Inline <script> analysis from HTML bodies ─────
        inline_js = self._extract_inline_scripts(out_dir)
        if inline_js:
            self.log.info(f"   inline scripts: {len(inline_js)} blocks from HTML bodies")
            for pseudo_url, code in inline_js.items():
                js_content[pseudo_url] = code

        # ── 4. Native regex analysis ─────────────────────────
        # Skip well-known public libraries (jQuery / Bootstrap / etc.) and
        # 3rd-party CDN hosts — secret/vuln matches in those files are
        # always false positives (the library is audited upstream and
        # not under our control).
        all_secrets:   List[dict] = []
        all_endpoints: List[dict] = []
        skipped_lib = skipped_cdn = 0

        for url, content in js_content.items():
            if _is_cdn_host(url):
                skipped_cdn += 1
                continue
            if _is_lib_file(url):
                skipped_lib += 1
                # Endpoints from libs are still useful (JS API surface),
                # but secrets/vulns are noise — endpoint-only pass.
                _, e = self._analyze_content(content, url)
                all_endpoints.extend(e)
                continue
            s, e = self._analyze_content(content, url)
            all_secrets.extend(s)
            all_endpoints.extend(e)
        if skipped_cdn or skipped_lib:
            self.log.info(
                f"   skipped: {skipped_cdn} CDN-hosted, {skipped_lib} public-lib files "
                "(secrets/vulns ignored — endpoints kept)"
            )

        self.log.info(
            f"   native regex: {len(all_secrets)} secrets, {len(all_endpoints)} endpoints"
        )

        # ── 5. jsluice (optional, on temp files) ────────────
        if self.JSLUICE_AVAILABLE and cfg.get('jsluice', True):
            jl_secrets, jl_endpoints = await self._run_jsluice(js_content, cfg)
            self.log.info(
                f"   jsluice: +{len(jl_secrets)} secrets, +{len(jl_endpoints)} endpoints"
            )
            all_secrets.extend(jl_secrets)
            all_endpoints.extend(jl_endpoints)
        else:
            self.log.debug("jsluice not available or disabled")

        # ── 6. Source maps (live + Wayback-mined historical) ──
        archived = await self._wayback_sourcemaps(target, cfg)
        if archived:
            self.log.info(f"   wayback: {len(archived)} historical .js.map URL(s) to probe")
        sourcemaps = await self._check_sourcemaps(
            list(js_urls), js_content, cfg, archived_maps=archived)
        if sourcemaps:
            self.log.info(f"   source maps: {len(sourcemaps)} .js.map files exposed "
                          f"(live + archived)")

        # ── 6b. Source recovery ───────────────────────────────
        # When a map carries `sourcesContent`, the original un-minified
        # first-party source is embedded. Reconstruct it to disk and deep-
        # analyse it: clean code surfaces secrets, hidden/internal endpoints
        # and client-side access-control logic the minified bundle hides.
        if cfg.get('extract_sourcemaps', True):
            sm_secrets, sm_endpoints = self._recover_sourcemap_sources(
                sourcemaps, out_dir, target, cfg)
            if sm_secrets or sm_endpoints:
                all_secrets.extend(sm_secrets)
                all_endpoints.extend(sm_endpoints)

        # ── 7. Deduplicate ────────────────────────────────────
        secrets   = self._dedup_secrets(all_secrets)
        endpoints = self._dedup_endpoints(all_endpoints)

        # ── 8. Save outputs ───────────────────────────────────
        secrets_out = [
            {
                'type':       s.get('kind', s.get('type', '?')),
                'value':      str(s.get('value', s.get('data', {})))[:300],
                'filename':   s.get('filename', ''),
                'severity':   s.get('severity', 'high') if isinstance(s.get('severity'), str)
                              else s.get('severity', Severity.HIGH).value,
                'confidence': s.get('confidence', 0.75),
                'source':     s.get('source', 'native'),
            }
            for s in secrets
        ]
        endpoints_out = [
            {
                'value':  e.get('url', ''),
                'method': e.get('method', ''),
                'type':   e.get('type', 'endpoint'),
                'source': e.get('filename', ''),
            }
            for e in endpoints
            if e.get('url')
        ]
        # Scope-tag each endpoint. We keep out-of-scope ones in the raw
        # js_endpoints.json (useful for whitebox audit — knowing the app
        # talks to GA/Stripe/Auth0 is itself signal) but emit a separate
        # `_in_scope` list that downstream modules (m12/m14) should consume.
        scope = getattr(target, 'scope', None)
        if scope is not None:
            for e in endpoints_out:
                e['in_scope'] = scope.is_in_scope(e['value'])
            in_scope_endpoints = [e for e in endpoints_out if e['in_scope']]
            dropped = len(endpoints_out) - len(in_scope_endpoints)
            if dropped:
                self.log.info(
                    f"   scope: {len(in_scope_endpoints)}/{len(endpoints_out)} JS endpoints in scope "
                    f"({dropped} third-party dropped from downstream)"
                )
        else:
            in_scope_endpoints = endpoints_out
        (out_dir / "js_secrets.json").write_text(json.dumps(secrets_out, indent=2))
        # Promote js_secrets to the DB (scan_artefacts) — single source of truth
        # for the dashboard + diff/history. Disk write above is kept during the
        # migration as a fallback for old scans. Identity = (type, value,
        # filename): the same secret in the same file upserts across re-scans.
        saved = self._save_artefacts(
            target, "js_secret", secrets_out,
            key_fields=["type", "value", "filename"],
        )
        if saved:
            self.log.debug(f"   js_secrets → DB: {saved} artefacts persisted")
        (out_dir / "js_endpoints.json").write_text(json.dumps(endpoints_out, indent=2))
        self._save_artefacts(target, "js_endpoint", endpoints_out,
                             key_fields=["value", "method"])
        (out_dir / "js_endpoints_in_scope.json").write_text(json.dumps(in_scope_endpoints, indent=2))

        # Dump site-specific JS bodies (no CDN, no public lib) so M07 can
        # apply patterns.yaml on JS code — captures hardcoded secrets / SQL
        # errors / debug strings that aren't in HTML bodies (m10 only fetches
        # HTML and a small set of "interesting" extensions).
        # Cap each body at 2 MB to bound disk; skip empty content.
        JS_BODY_CAP = 2_000_000
        site_js_bodies = {}
        for url, content in js_content.items():
            if _is_cdn_host(url) or _is_lib_file(url):
                continue
            if not content or url.startswith('inline:'):
                continue
            site_js_bodies[url] = content[:JS_BODY_CAP]
        (out_dir / "js_bodies.json").write_text(json.dumps(site_js_bodies, indent=2))
        self.log.info(f"   js_bodies.json: {len(site_js_bodies)} site-specific JS files for M07 grep")

        if sourcemaps:
            sm_dir = out_dir / "sourcemaps"
            sm_dir.mkdir(exist_ok=True)
            (sm_dir / "sourcemaps.json").write_text(json.dumps(sourcemaps, indent=2))

        # ── 9. Add findings ───────────────────────────────────
        # Route DANGEROUS_PATTERNS (eval/innerHTML/postmessage/etc.) to
        # JS_VULNERABILITY — they're code anti-patterns, not credential leaks.
        # Real secrets (api_key/token/private_key/etc.) keep JS_SECRET.
        for secret in secrets:
            kind     = secret.get('kind', secret.get('type', 'unknown'))
            raw_sev  = secret.get('severity', Severity.HIGH)
            sev      = raw_sev if isinstance(raw_sev, Severity) \
                       else Severity(raw_sev) if raw_sev in [s.value for s in Severity] \
                       else Severity.HIGH
            evidence = str(secret.get('value', secret.get('data', '')))[:300]
            is_vuln = kind in DANGEROUS_PATTERN_NAMES
            self._add_finding(target, Finding(
                type=FindingType.JS_VULNERABILITY if is_vuln else FindingType.JS_SECRET,
                target=target.domain,
                url=secret.get('filename', ''),
                title=f"JS {'Vulnerability' if is_vuln else 'Secret'} [{kind}]",
                severity=sev,
                confidence=secret.get('confidence', 0.75),
                evidence=evidence,
                tags=['javascript', 'vulnerability' if is_vuln else 'secret', kind],
                metadata=secret,
            ))

        # Note: JS endpoints are NOT emitted as findings — they're inventory.
        # The full list is in js_endpoints.json and served via
        # /api/js-endpoints/{domain}. Real signal (secrets, vulnerabilities)
        # is emitted above as JS_SECRET / JS_VULNERABILITY.

        # Source-map exposures are aggregated PER HOST, not one finding per
        # .map file. A single webpack/Vue SPA ships hundreds of lazy-loaded
        # chunk *.js.map files; emitting one finding each drowns the report
        # (observed: 1167 rows for 7 hosts) and buries real signal. The
        # finding-worthy fact is "host X exposes its source maps" — one row per
        # host. The full per-map list stays in sourcemaps.json + scan_artefacts.
        from collections import defaultdict
        sm_by_host: Dict[str, List[dict]] = defaultdict(list)
        for sm in sourcemaps:
            url = sm.get('url', '') or ''
            try:
                host = (urlparse(url).hostname or target.domain).lower()
            except Exception:
                host = target.domain
            sm_by_host[host].append(sm)

        for host, maps in sm_by_host.items():
            lib_only = all(_is_lib_file(m.get('url', '') or '') for m in maps)
            with_src = [m for m in maps if m.get('has_sources_content')]
            sample   = [(m.get('url') or '')[:120] for m in maps[:5]]
            n, nsrc  = len(maps), len(with_src)
            # Public-lib maps are open upstream → INFO. Private source
            # recoverable (sourcesContent) → HIGH. Filenames only → MEDIUM.
            if lib_only:
                sev = Severity.INFO
            elif with_src:
                sev = Severity.HIGH
            else:
                sev = Severity.MEDIUM
            self._add_finding(target, Finding(
                type=FindingType.JS_SECRET,
                target=target.domain,
                url=f"https://{host}/",
                title=(f"Source maps exposed on {host} "
                       f"({n} file{'s' if n != 1 else ''}"
                       + (f", {nsrc} with embedded source)" if nsrc else ")")),
                severity=sev,
                confidence=0.95,
                evidence=(f"{n} .js.map exposed"
                          + (f"; {nsrc} contain sourcesContent (original source recoverable)"
                             if nsrc else "; original filenames only")
                          + (f" — e.g. {', '.join(sample)}" if sample else "")),
                tags=(['javascript', 'sourcemap']
                      + (['public-lib'] if lib_only else [])
                      + (['source-recoverable'] if with_src else [])),
                metadata={
                    'host': host,
                    'map_count': n,
                    'with_sources_content': nsrc,
                    'sample_urls': sample,
                },
            ))

        # ── 10. Validate high-value secrets ──────────────────────
        validated = await self._validate_secrets(secrets, out_dir, target)
        if validated:
            self.log.info(f"   validation: {len(validated)} secrets confirmed live")

        self.log.info(
            f"✅ M05 done — {len(js_content)} JS files | "
            f"{len(secrets)} secrets | {len(endpoints)} endpoints | "
            f"{len(sourcemaps)} source maps"
        )

    # ── Secret validation ─────────────────────────────────────────────────────

    async def _validate_secrets(self, secrets: List[dict], out_dir: Path, target: ScanTarget) -> List[dict]:
        """
        Validate high-value secrets found in JS:
          - JWT   : decode claims, flag sensitive roles, check expiry
          - S3    : HTTP HEAD to check public accessibility
          - AWS   : format + entropy check (live test requires credentials)
        Saves validation results to secrets_validated.json.
        """
        import aiohttp
        import ssl as _ssl
        import base64
        import datetime as _dt

        validated = []
        ssl_ctx   = _ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = _ssl.CERT_NONE
        timeout = aiohttp.ClientTimeout(total=8)

        def _decode_jwt(token: str) -> Optional[dict]:
            try:
                parts = token.split('.')
                if len(parts) != 3:
                    return None
                # Pad and decode header + payload
                def _b64(s):
                    s += '=' * (4 - len(s) % 4)
                    return json.loads(base64.urlsafe_b64decode(s))
                return {'header': _b64(parts[0]), 'payload': _b64(parts[1])}
            except Exception:
                return None

        jwt_secrets = [s for s in secrets if s.get('kind') == 'jwt_token']
        s3_secrets  = [s for s in secrets if s.get('kind') == 's3_bucket']

        # ── JWT decode ────────────────────────────────────────
        for sec in jwt_secrets:
            val   = str(sec.get('value', ''))
            token = re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', val)
            if not token:
                continue
            decoded = _decode_jwt(token.group(0))
            if not decoded:
                continue
            payload = decoded.get('payload', {})
            exp     = payload.get('exp')
            now     = int(_dt.datetime.now(_dt.timezone.utc).timestamp())
            expired = exp and exp < now
            sensitive_roles = any(
                str(payload.get(k, '')).lower() in ('true', 'admin', 'superuser', '1')
                for k in ('admin', 'is_admin', 'role', 'scope', 'superuser')
            )
            # IMPORTANT: payload claims are parsed but signature is NEVER
            # verified — we don't have the signing key. A "sensitive_role"
            # claim could be forged. Flag as unverified and downgrade the
            # paired Finding severity so we don't report admin-claim hits
            # at CRITICAL without manual confirmation.
            validated.append({
                'kind':    'jwt_decoded',
                'value':   val[:80],
                'source':  sec.get('filename', ''),
                'expired': expired,
                'exp':     exp,
                'issuer':  payload.get('iss', ''),
                'subject': payload.get('sub', ''),
                'roles':   {k: payload.get(k) for k in ('role','admin','scope','email') if k in payload},
                'sensitive_role': sensitive_roles,
                'signature_verified': False,
                'severity': 'high' if sensitive_roles and not expired else 'medium',
            })

            # ── WSTG-SESS-10 — JWT header weakness checks ──────────────
            header = decoded.get('header') or {}
            alg = str(header.get('alg', '')).lower()
            kid = header.get('kid')
            jku = header.get('jku')
            x5u = header.get('x5u')
            src = sec.get('filename', '')

            if alg == 'none':
                self._add_finding(target, Finding(
                    type=FindingType.JWT_WEAKNESS, target=target.domain, url=src,
                    title=f"JWT alg=none accepted in token from {src[:60]}",
                    severity=Severity.CRITICAL, confidence=0.95,
                    tags=['jwt', 'alg-none', 'wstg-sess-10'],
                    evidence=json.dumps(header),
                    metadata={'header': header, 'token_preview': val[:80]},
                ))
            elif alg.startswith('hs') and kid and isinstance(kid, str) and ('/' in kid or '..' in kid or kid.endswith('.pem') or kid.endswith('.key')):
                self._add_finding(target, Finding(
                    type=FindingType.JWT_WEAKNESS, target=target.domain, url=src,
                    title=f"JWT kid looks like a path — possible kid injection: {kid}",
                    severity=Severity.MEDIUM, confidence=0.6,
                    tags=['jwt', 'kid-path-injection', 'wstg-sess-10'],
                    evidence=json.dumps(header),
                    metadata={'header': header, 'kid': kid},
                ))
            if jku or x5u:
                self._add_finding(target, Finding(
                    type=FindingType.JWT_WEAKNESS, target=target.domain, url=src,
                    title=f"JWT references external key URL ({'jku' if jku else 'x5u'})",
                    severity=Severity.MEDIUM, confidence=0.7,
                    tags=['jwt', 'jku-x5u', 'wstg-sess-10'],
                    evidence=json.dumps(header),
                    metadata={'header': header, 'jku': jku, 'x5u': x5u},
                ))

        # ── S3 bucket accessibility ───────────────────────────
        async def check_s3(sess, sec):
            host = str(sec.get('value', ''))
            if not host or '.s3' not in host:
                return None
            url = f"https://{host}/" if not host.startswith('http') else host
            try:
                async with sess.get(url) as r:
                    body = await r.text(errors='ignore')
                    is_listed  = 'ListBucketResult' in body
                    is_public  = r.status == 200
                    is_denied  = r.status == 403
                    return {
                        'kind':       's3_bucket_check',
                        'value':      host,
                        'source':     sec.get('filename', ''),
                        'status':     r.status,
                        'public':     is_public,
                        'listed':     is_listed,
                        'forbidden':  is_denied,
                        'severity':   'critical' if is_listed else ('high' if is_public else 'medium'),
                    }
            except Exception:
                return None

        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            s3_tasks = [check_s3(sess, s) for s in s3_secrets]
            s3_results = await asyncio.gather(*s3_tasks, return_exceptions=True)
            validated.extend([r for r in s3_results if isinstance(r, dict)])

        if validated:
            (out_dir / "secrets_validated.json").write_text(json.dumps(validated, indent=2))
            # Upgrade severity of confirmed findings. A `listed` S3 bucket
            # is independently confirmed (anonymous list-objects worked) —
            # CRITICAL is right. A `sensitive_role` JWT claim was parsed
            # but the signature was NOT validated → can't be CRITICAL on
            # its own; downgrade to HIGH and flag unverified.
            for v in validated:
                if v.get('listed'):
                    self._add_finding(target, Finding(
                        type=FindingType.JS_SECRET,
                        target=target.domain,
                        url=v.get('source', ''),
                        title=f"Confirmed: {v['kind']} — {v['value'][:60]}",
                        severity=Severity.CRITICAL,
                        confidence=0.98,
                        evidence=str(v),
                        tags=['validated', v['kind']],
                        metadata=v,
                    ))
                elif v.get('sensitive_role'):
                    self._add_finding(target, Finding(
                        type=FindingType.JS_SECRET,
                        target=target.domain,
                        url=v.get('source', ''),
                        title=(
                            f"JWT with sensitive claim (UNVERIFIED sig) — "
                            f"{v['value'][:60]}"
                        ),
                        severity=Severity.HIGH,
                        confidence=0.65,
                        evidence=(
                            f"claims={v.get('roles')} | iss={v.get('issuer')} | "
                            "signature_verified=False — claim may be forged"
                        ),
                        tags=['validated', v['kind'], 'unverified-signature'],
                        metadata=v,
                    ))

        return validated

    # ── Inline script extraction ──────────────────────────────────────────────

    def _extract_inline_scripts(self, out_dir: Path) -> Dict[str, str]:
        """
        Extract <script> blocks from HTML bodies saved by M02b (bodies_snippets.json).
        Returns {pseudo_url: js_code} where pseudo_url identifies the source page.
        """
        snippets_path = out_dir / "bodies_snippets.json"
        if not snippets_path.exists():
            return {}
        try:
            snippets = json.loads(snippets_path.read_text())
        except Exception:
            return {}

        inline: Dict[str, str] = {}
        script_re = re.compile(
            r'<script(?:\s[^>]*)?>([^<]{20,})</script>',
            re.I | re.DOTALL
        )
        for page_url, html in snippets.items():
            if not html:
                continue
            for i, m in enumerate(script_re.finditer(html)):
                code = m.group(1).strip()
                # Skip pure JSON blobs and src-only tags
                if code.startswith('{') and code.endswith('}'):
                    continue
                pseudo = f"{page_url}#inline-{i}"
                inline[pseudo] = code
        return inline

    # ── Discovery ─────────────────────────────────────────────────────────────

    async def _discover_js_urls(
        self, target: ScanTarget, out_dir: Path, cfg: dict
    ) -> Set[str]:
        js_urls: Set[str] = set()
        live_urls = [h.get('url', '') for h in (target.live_hosts or []) if h.get('url')]

        # Track which hosts actually use JavaScript so we don't probe
        # common bundle paths on static-HTML sites that have no JS at all
        # (those probes always 404 and waste fetch budget).
        hosts_with_js: Set[str] = set()

        # Source 1: parse <script src> from M02b HTML bodies
        snippets_file = out_dir / "bodies_snippets.json"
        if snippets_file.exists():
            try:
                snippets = json.loads(snippets_file.read_text())
                for base_url, html in snippets.items():
                    if not html:
                        continue
                    # Any sign that this host runs JS — external <script src>,
                    # inline <script>, or modulepreload — qualifies.
                    if re.search(r'<script\b', html, re.I) or re.search(
                        r'<link[^>]+rel=["\']?(?:modulepreload|preload)["\']?[^>]+as=["\']?script', html, re.I
                    ):
                        hosts_with_js.add(base_url.rstrip('/'))
                    for src in re.findall(
                        r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I
                    ):
                        resolved = self._resolve_url(src, base_url)
                        if resolved:
                            js_urls.add(resolved)
            except Exception as e:
                self.log.debug(f"bodies_snippets parse error: {e}")

        # Source 2: .js files from M03 URL collection
        urls_file = out_dir / "urls_all.txt"
        if urls_file.exists():
            for u in urls_file.read_text().splitlines():
                u = u.strip()
                if u.startswith('http') and u.split('?')[0].endswith('.js'):
                    js_urls.add(u)

        # Source 3: common bundle paths — only on hosts that actually use JS.
        # Skipping static-HTML hosts here typically eliminates 100-300 dead
        # probes (10 paths × N static hosts) per scan.
        common_paths = cfg.get('common_js_paths', [
            '/bundle.js', '/app.js', '/main.js', '/index.js',
            '/static/js/main.js', '/assets/app.js', '/js/app.js',
            '/dist/bundle.js', '/build/main.js', '/webpack.js',
        ])
        skipped = 0
        for base in live_urls[:30]:
            base_n = base.rstrip('/')
            # No bodies snippet recorded → fall back to probing (we don't
            # know the host's shape). Otherwise require a JS signal.
            if snippets_file.exists() and base_n not in hosts_with_js:
                skipped += 1
                continue
            for path in common_paths:
                js_urls.add(base_n + path)
        if skipped:
            self.log.info(f"   skipped common-paths probe on {skipped} static host(s) (no <script> in body)")

        # Source 4: fallback — fetch HTML of live hosts directly if no snippets
        if not snippets_file.exists() and live_urls:
            self.log.debug("M02b bodies not found — fetching HTML directly for script tags")
            fetched = await self._fetch_scripts_from_html(live_urls[:20], cfg)
            js_urls.update(fetched)

        return js_urls

    async def _fetch_scripts_from_html(
        self, live_urls: List[str], cfg: dict
    ) -> Set[str]:
        found: Set[str] = set()
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE
        sem = asyncio.Semaphore(10)

        async def fetch_page(sess: aiohttp.ClientSession, url: str) -> None:
            async with sem:
                try:
                    async with sess.get(
                        url, allow_redirects=True, max_redirects=3,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            html = await resp.text(errors='ignore')
                            for src in re.findall(
                                r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I
                            ):
                                resolved = self._resolve_url(src, url)
                                if resolved:
                                    found.add(resolved)
                except Exception:
                    pass

        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=connector) as sess:
            await asyncio.gather(*[fetch_page(sess, u) for u in live_urls])
        return found

    # ── Fetching ──────────────────────────────────────────────────────────────

    async def _fetch_js_files(
        self, js_urls: List[str], cfg: dict
    ) -> Dict[str, str]:
        max_size   = cfg.get('max_js_size', 3_000_000)
        concurrent = cfg.get('concurrent', 20)
        timeout_s  = cfg.get('timeout', 20)
        connect_to = cfg.get('connect_timeout', 8)

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE

        # Same DNS issue as M02/M02b — local resolver saturates under load
        # and JS hosts are CDNs / static origins that M02 already validated.
        # Reuse http_validator nameservers as default.
        #
        # IMPORTANT: the public-DNS AsyncResolver only works when outbound
        # UDP/53 to those servers is permitted. In egress-filtered networks
        # (corporate proxies, sandboxes, CGNAT) it raises ClientConnectorDNSError
        # on *every* request, silently zeroing JS analysis. So we probe it once
        # against a real target host and fall back to the system resolver
        # (resolver=None → getaddrinfo, same path M10 uses successfully) on
        # failure. Set http_validator.dns_nameservers: [] to force system DNS.
        nameservers = (
            cfg.get('dns_nameservers')
            or self.config.get('http_validator', 'dns_nameservers', default=None)
            or ['8.8.8.8', '9.9.9.9', '149.112.112.112', '8.8.4.4']
        )
        resolver = None
        if nameservers:
            try:
                resolver = aiohttp.AsyncResolver(
                    nameservers=nameservers, timeout=4, tries=2,
                )
                # Probe: if the custom resolver can't reach its nameservers,
                # discard it now rather than failing all N fetches.
                probe_host = urlparse(js_urls[0]).hostname if js_urls else None
                if probe_host:
                    await resolver.resolve(probe_host, 443, family=socket.AF_INET)
            except Exception as e:
                self.log.debug(
                    f"custom DNS resolver unusable ({e!r}) — "
                    "falling back to system resolver"
                )
                if resolver is not None:
                    try:
                        await resolver.close()
                    except Exception:
                        pass
                resolver = None

        connector = aiohttp.TCPConnector(
            ssl=ssl_ctx,
            limit=concurrent,
            limit_per_host=4,
            ttl_dns_cache=300,
            resolver=resolver,
        )
        timeout   = aiohttp.ClientTimeout(total=timeout_s, connect=connect_to)
        sem       = asyncio.Semaphore(concurrent)
        results: Dict[str, str] = {}
        errors: List[str] = []

        async def fetch_one(sess: aiohttp.ClientSession, url: str) -> None:
            async with sem:
                try:
                    async with sess.get(
                        url, allow_redirects=True, max_redirects=3
                    ) as resp:
                        if resp.status != 200:
                            return
                        ctype = resp.headers.get('Content-Type', '').lower()
                        # Accept JS, plain text, octet-stream (CDN) — reject HTML/images
                        if ctype and not any(
                            x in ctype for x in
                            ('javascript', 'text/', 'octet-stream', 'application/json')
                        ):
                            return
                        raw = await resp.content.read(max_size)
                        content = raw.decode('utf-8', errors='ignore')
                        if len(content) > 30:
                            results[url] = content
                except Exception as e:
                    errors.append(repr(e))

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            await asyncio.gather(*[fetch_one(sess, u) for u in js_urls])

        # Surface a diagnostic when fetching wholesale-failed: a total miss on a
        # non-empty URL set almost always means a transport/DNS problem (e.g.
        # egress-blocked nameservers), not "no JS here". Don't let it stay silent.
        if js_urls and not results and errors:
            from collections import Counter
            top = Counter(errors).most_common(1)[0]
            self.log.warning(
                f"JS fetch: 0/{len(js_urls)} succeeded — dominant error "
                f"({top[1]}×): {top[0]}"
            )

        return results

    # ── Native analysis ───────────────────────────────────────────────────────

    def _analyze_content(
        self, content: str, file_url: str
    ) -> Tuple[List[dict], List[dict]]:
        secrets:   List[dict] = []
        endpoints: List[dict] = []

        # Secrets
        for name, severity, confidence, pattern in SECRET_PATTERNS:
            try:
                for m in re.finditer(pattern, content):
                    value = m.group(0)
                    # Skip test/placeholder values
                    if any(x in value.lower() for x in ('example', 'placeholder', 'your_', 'xxx')):
                        continue
                    secrets.append({
                        'kind':       name,
                        'value':      value[:200],
                        'severity':   severity,
                        'confidence': confidence,
                        'filename':   file_url,
                        'source':     'native',
                    })
            except re.error:
                pass

        # Dangerous patterns
        for name, severity, confidence, pattern in DANGEROUS_PATTERNS:
            try:
                for m in re.finditer(pattern, content):
                    secrets.append({
                        'kind':       name,
                        'value':      m.group(0)[:150],
                        'severity':   severity,
                        'confidence': confidence,
                        'filename':   file_url,
                        'source':     'native',
                    })
            except re.error:
                pass

        # Endpoints
        seen: Set[str] = set()
        for pattern in ENDPOINT_PATTERNS:
            try:
                for m in re.finditer(pattern, content, re.I):
                    url = m.group(1) if m.lastindex else m.group(0)
                    url = url.strip()
                    if not url or url in seen:
                        continue
                    if len(url) < 4:
                        continue
                    if url.startswith(('data:', 'blob:', 'javascript:', '#')):
                        continue
                    # Filter obvious non-paths
                    if url.startswith('/') and not re.match(r'/[a-zA-Z]', url):
                        continue
                    seen.add(url)
                    endpoints.append({
                        'url':      url,
                        'method':   '',
                        'type':     'native',
                        'filename': file_url,
                    })
            except re.error:
                pass

        return secrets, endpoints

    # ── jsluice ───────────────────────────────────────────────────────────────

    async def _run_jsluice(
        self, js_content: Dict[str, str], cfg: dict
    ) -> Tuple[List[dict], List[dict]]:
        secrets:   List[dict] = []
        endpoints: List[dict] = []
        sem = asyncio.Semaphore(cfg.get('jsluice_concurrent', 10))

        async def analyze_one(url: str, content: str) -> None:
            tmp = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.js', delete=False, encoding='utf-8'
                ) as f:
                    f.write(content)
                    tmp = f.name

                async with sem:
                    # Secrets
                    proc = await asyncio.create_subprocess_exec(
                        'jsluice', 'secrets', tmp,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
                    for line in stdout.decode().splitlines():
                        try:
                            item = json.loads(line)
                            item['filename'] = url
                            item['source']   = 'jsluice'
                            # Map jsluice severity string to our Severity enum
                            raw_sev = item.get('severity', 'low').lower()
                            item['severity'] = {
                                'critical': Severity.CRITICAL,
                                'high':     Severity.HIGH,
                                'medium':   Severity.MEDIUM,
                                'low':      Severity.LOW,
                                'info':     Severity.INFO,
                            }.get(raw_sev, Severity.HIGH)
                            item['confidence'] = 0.80
                            secrets.append(item)
                        except json.JSONDecodeError:
                            pass

                    # Endpoints
                    proc2 = await asyncio.create_subprocess_exec(
                        'jsluice', 'urls', tmp,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=20)
                    seen_ep: Set[str] = set()
                    for line in stdout2.decode().splitlines():
                        try:
                            item = json.loads(line)
                            ep_url = item.get('url', '')
                            if ep_url and ep_url not in seen_ep:
                                seen_ep.add(ep_url)
                                item['filename'] = url
                                item['source']   = 'jsluice'
                                endpoints.append(item)
                        except json.JSONDecodeError:
                            pass

            except asyncio.TimeoutError:
                self.log.debug(f"jsluice timeout on {url}")
            except Exception as e:
                self.log.debug(f"jsluice error on {url}: {e}")
            finally:
                if tmp:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass

        await asyncio.gather(*[analyze_one(u, c) for u, c in js_content.items()])
        return secrets, endpoints

    # ── Source maps ───────────────────────────────────────────────────────────

    async def _check_sourcemaps(
        self, js_urls: List[str], js_content: Dict[str, str], cfg: dict,
        archived_maps: Optional[List[dict]] = None,
    ) -> List[dict]:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE
        sem = asyncio.Semaphore(20)
        found: List[dict] = []

        async def probe_map(sess: aiohttp.ClientSession, fetch_url: str,
                            record_url: str, js_file: str) -> None:
            """GET `fetch_url` (live or Wayback snapshot) but record `record_url`
            (the original .map location) so host grouping + scope stay correct."""
            async with sem:
                try:
                    async with sess.get(
                        fetch_url,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=True,
                    ) as resp:
                        if resp.status == 200:
                            result: dict = {
                                'url':                record_url,
                                'js_file':            js_file,
                                'status':             200,
                                'has_sources_content': False,
                                'sources_count':      0,
                            }
                            try:
                                body = await resp.json(content_type=None)
                                srcs  = body.get('sources', []) or []
                                conts = body.get('sourcesContent') or []
                                result['sources_count']      = len(srcs)
                                result['has_sources_content'] = bool(conts)
                                result['sources_preview'] = srcs[:5]
                                # Capture first-party source for recovery (skip
                                # vendor + honour a process-wide memory budget).
                                if conts:
                                    rec: List[Tuple[str, str]] = []
                                    for sp, sc in zip(srcs, conts):
                                        if not sc or _is_vendor_source(sp):
                                            continue
                                        if self._sm_captured >= self._SM_CAPTURE_BUDGET:
                                            break
                                        sc = sc[:self._SM_FILE_CAP]
                                        rec.append((sp, sc))
                                        self._sm_captured += len(sc)
                                    if rec:
                                        result['_recovered'] = rec
                            except Exception:
                                pass
                            found.append(result)
                except Exception:
                    pass

        async def check_one(sess: aiohttp.ClientSession, url: str) -> None:
            # Resolve the .map URL for a live .js file (sourceMappingURL comment
            # first, then the `.map` convention) and probe it.
            content = js_content.get(url, '')
            map_url = None
            if content:
                m = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', content)
                if m:
                    ref = m.group(1).strip()
                    if not ref.startswith('data:'):
                        map_url = self._resolve_url(ref, url)
            if not map_url:
                map_url = url.split('?')[0] + '.map'
            await probe_map(sess, map_url, map_url, url)

        # Skip 3rd-party CDN-hosted JS — Bootstrap/jQuery/etc. publish their
        # sourcemaps on purpose, flagging them is pure noise.
        targets = [u for u in js_urls if u.startswith('http') and not _is_cdn_host(u)]
        skipped = len([u for u in js_urls if u.startswith('http')]) - len(targets)
        if skipped:
            self.log.debug(f"sourcemaps: skipped {skipped} CDN-hosted JS files")

        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=connector) as sess:
            tasks = [check_one(sess, u) for u in targets]
            # Wayback-mined maps: fetch the archived snapshot, but record the
            # ORIGINAL url so host grouping + scope stay correct. These often
            # expose source removed from the current production build.
            for am in (archived_maps or []):
                tasks.append(probe_map(sess, am['fetch'], am['original'], am['original']))
            await asyncio.gather(*tasks)

        return found

    async def _wayback_sourcemaps(self, target: ScanTarget, cfg: dict) -> List[dict]:
        """Mine the Wayback Machine for historical `*.js.map` URLs and return
        archived-snapshot fetch targets. Old maps often expose source (and the
        endpoints/secrets in it) that the current production build removed.
        Scope-filtered by original host. Returns [{'fetch','original'}]."""
        if not cfg.get('wayback_sourcemaps', True):
            return []
        limit = int(cfg.get('wayback_max', 1500))
        cdx = ("http://web.archive.org/cdx/search/cdx?"
               f"url={target.domain}&matchType=domain&collapse=urlkey"
               f"&fl=timestamp,original&output=text&limit={limit}"
               r"&filter=original:.*\.js\.map(\?.*)?$")
        out: List[dict] = []
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl.CERT_NONE
            conn = aiohttp.TCPConnector(ssl=ssl_ctx)
            async with aiohttp.ClientSession(connector=conn) as s:
                async with s.get(cdx, timeout=aiohttp.ClientTimeout(total=40)) as r:
                    if r.status != 200:
                        return []
                    text = await r.text()
            seen: Set[str] = set()
            scope = getattr(target, 'scope', None)
            for line in text.splitlines():
                parts = line.split()
                if len(parts) != 2:
                    continue
                ts, original = parts
                if '.js.map' not in original or original in seen:
                    continue
                if scope is not None and not scope.is_in_scope(original):
                    continue
                seen.add(original)
                # `id_` returns the raw archived bytes (no Wayback toolbar).
                out.append({'fetch': f"https://web.archive.org/web/{ts}id_/{original}",
                            'original': original})
        except Exception as e:
            self.log.debug(f"wayback sourcemaps: {e}")
        return out

    # ── Source-map recovery ───────────────────────────────────────────────────

    def _recover_sourcemap_sources(
        self, sourcemaps: List[dict], out_dir, target: ScanTarget, cfg: dict
    ) -> Tuple[List[dict], List[dict]]:
        """Reconstruct first-party source from `sourcesContent` and deep-analyse
        it. Writes the tree under ``sourcemaps/recovered/<host>/`` and a
        per-host ``recovered_intel.json``. Returns (secrets, endpoints) to merge
        into the module's main lists (so they flow through dedup + findings +
        artefacts). Recon intel (internal hosts / env vars / access-control /
        flagged comments) is summarised into ONE finding per host to stay
        signal-dense — the full detail lives on disk."""
        max_files = int(cfg.get('sourcemap_max_files', 1500))
        rec_root  = out_dir / "sourcemaps" / "recovered"
        secrets:   List[dict] = []
        endpoints: List[dict] = []
        per_host_intel: Dict[str, dict] = {}
        files_written = 0
        hosts: Set[str] = set()

        for sm in sourcemaps:
            recovered = sm.pop('_recovered', None)   # keep sourcemaps.json lean
            if not recovered:
                continue
            map_url = sm.get('url', '') or ''
            try:
                host = (urlparse(map_url).hostname or target.domain).lower()
            except Exception:
                host = target.domain
            intel = per_host_intel.setdefault(host, {
                'internal_hosts': set(), 'api_bases': set(), 'env_vars': set(),
                'routes': set(), 'graphql_ops': set(), 'access_control': set(),
                'requests': set(), 'deps': set(),
                'flagged_comments': [], 'files': 0,
            })
            for src_path, code in recovered:
                if files_written >= max_files:
                    self.log.info(f"   ⚠ source recovery cap: {max_files} files — truncated")
                    break
                rel  = _safe_source_path(src_path)
                dest = (rec_root / host / rel)
                try:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(code)
                except Exception:
                    pass
                files_written += 1
                intel['files'] += 1
                hosts.add(host)
                # Synthetic URL ties each finding back to the exact source file.
                syn = f"{map_url}#{rel}"
                # 1) reuse the base secret/endpoint engine (now on clean code)
                if not rel.endswith(_SRC_ANALYSE_EXT):
                    continue
                s, e = self._analyze_content(code, syn)
                for x in s:
                    x['source'] = 'sourcemap'
                    x.setdefault('tags', []).append('sourcemap-recovered')
                for x in e:
                    x['source'] = 'sourcemap'
                secrets.extend(s)
                endpoints.extend(e)
                # 2) refined source-only secrets (service tokens / config creds)
                secrets.extend(self._analyze_source_extra(code, syn))
                # 3) recon intel (not individual findings — aggregated per host)
                self._collect_source_intel(code, syn, intel, endpoints)

        if not files_written:
            return secrets, endpoints

        # Persist intel + emit one summary finding per host.
        intel_out = {}
        for host, intel in per_host_intel.items():
            if not intel['files']:
                continue
            ser = {
                'files_recovered':  intel['files'],
                'internal_hosts':   sorted(intel['internal_hosts'])[:100],
                'api_bases':        sorted(intel['api_bases'])[:100],
                'env_vars':         sorted(intel['env_vars'])[:200],
                'routes':           sorted(intel['routes'])[:300],
                'graphql_ops':      sorted(intel['graphql_ops'])[:200],
                'access_control':   sorted(intel['access_control'])[:200],
                'requests':         sorted(intel['requests'])[:400],
                'deps':             sorted(intel['deps'])[:300],
                'flagged_comments': intel['flagged_comments'][:100],
            }
            intel_out[host] = ser
            # Severity: HIGH if internal/staging backends leaked (real exposure),
            # else LOW (recon inventory pointer).
            sev = Severity.HIGH if ser['internal_hosts'] or ser['api_bases'] else Severity.LOW
            parts = [f"{intel['files']} source files"]
            for label, key in (("internal/staging URLs", 'internal_hosts'),
                               ("API base URLs", 'api_bases'),
                               ("request shapes", 'requests'),
                               ("env vars", 'env_vars'),
                               ("routes", 'routes'),
                               ("GraphQL ops", 'graphql_ops'),
                               ("access-control checks", 'access_control'),
                               ("dep versions", 'deps'),
                               ("flagged comments", 'flagged_comments')):
                if ser[key]:
                    parts.append(f"{len(ser[key])} {label}")
            self._add_finding(target, Finding(
                type=FindingType.JS_SECRET,
                target=target.domain,
                url=f"https://{host}/",
                title=f"Source recovered from maps on {host}: {', '.join(parts)}",
                severity=sev,
                confidence=0.9,
                evidence=("Reconstructed first-party source from exposed .js.map "
                          f"(sourcesContent). Detail: sourcemaps/recovered_intel.json. "
                          + ("Internal/staging backends: "
                             + ", ".join(ser['internal_hosts'][:5]) if ser['internal_hosts']
                             else "; ".join(ser['api_bases'][:5]))),
                tags=['javascript', 'sourcemap', 'source-recovered'],
                metadata={'host': host, **{k: ser[k] for k in
                          ('files_recovered', 'internal_hosts', 'api_bases')}},
            ))
        try:
            (out_dir / "sourcemaps" / "recovered_intel.json").write_text(
                json.dumps(intel_out, indent=2))
        except Exception:
            pass

        # ── recovered_targets.json — the active-testing feed (consumed by m13
        # nuclei + m14). Hosts and API URLs recovered from source that downstream
        # modules should probe. Kept raw here; m13/m14 apply the scope filter so
        # out-of-scope leaks (e.g. a raw-IP backend) are logged, not scanned. ──
        rec_hosts: Set[str] = set()
        rec_urls:  Set[str] = set()
        rec_deps:  Set[str] = set()
        for host, ser in intel_out.items():
            for base in ser['api_bases']:
                rec_urls.add(base)
                try:
                    h = urlparse(base).netloc
                    if h:
                        rec_hosts.add(h)
                except Exception:
                    pass
            for ih in ser['internal_hosts']:
                rec_urls.add(ih)
                try:
                    h = urlparse(ih).netloc
                    if h:
                        rec_hosts.add(h)
                except Exception:
                    pass
            rec_deps.update(ser['deps'])
        try:
            (out_dir / "recovered_targets.json").write_text(json.dumps({
                'hosts':   sorted(rec_hosts),
                'api_urls': sorted(rec_urls),
            }, indent=2))
            if rec_deps:
                (out_dir / "recovered_deps.json").write_text(
                    json.dumps(sorted(rec_deps), indent=2))
        except Exception:
            pass
        if rec_hosts or rec_urls:
            self.log.info(
                f"   🎯 recovered_targets: {len(rec_hosts)} host(s), "
                f"{len(rec_urls)} API URL(s) → fed to m13/m14"
                + (f" · {len(rec_deps)} dep versions → CVE" if rec_deps else ""))

        self.log.info(
            f"   📦 source recovery: {files_written} first-party files from "
            f"{len(hosts)} host(s) → +{len(secrets)} secrets, +{len(endpoints)} "
            f"endpoints (reconstructed in sourcemaps/recovered/)"
        )
        return secrets, endpoints

    def _analyze_source_extra(self, code: str, file_url: str) -> List[dict]:
        """Refined secret patterns tuned for clean (recovered) source — service
        tokens + literal config credentials. Returns secret dicts compatible
        with the main emit loop."""
        out: List[dict] = []
        for name, severity, confidence, pattern in SOURCEMAP_SECRET_PATTERNS:
            try:
                for m in re.finditer(pattern, code):
                    value = m.group(0)
                    low = value.lower()
                    if any(x in low for x in
                           ('example', 'placeholder', 'your_', 'xxxxx', 'changeme',
                            'dummy', 'process.env', 'import.meta', '${')):
                        continue
                    out.append({
                        'kind':       name,
                        'value':      value[:200],
                        'severity':   severity,
                        'confidence': confidence,
                        'filename':   file_url,
                        'source':     'sourcemap',
                        'tags':       ['javascript', 'secret', 'sourcemap-recovered', name],
                    })
            except re.error:
                pass
        return out

    def _collect_source_intel(self, code: str, file_url: str,
                              intel: dict, endpoints: List[dict]) -> None:
        """Harvest recon intel from a recovered source file into the per-host
        aggregate (internal hosts, API bases, env vars, routes, GraphQL ops,
        access-control sites, flagged comments). API bases & routes also feed
        the endpoint inventory (→ P4/P5)."""
        for m in INTERNAL_HOST_RE.finditer(code):
            intel['internal_hosts'].add(m.group(0)[:200])
        for m in API_BASE_RE.finditer(code):
            base = m.group(1)[:200]
            intel['api_bases'].add(base)
            endpoints.append({'url': base, 'filename': file_url, 'source': 'sourcemap'})
        for m in ENV_NAME_RE.finditer(code):
            intel['env_vars'].add(m.group(1))
        for m in ROUTE_RE.finditer(code):
            r = m.group(1)
            intel['routes'].add(r)
            endpoints.append({'url': r, 'filename': file_url, 'source': 'sourcemap'})
        for m in GQL_OP_RE.finditer(code):
            intel['graphql_ops'].add(f"{m.group(1).lower()} {m.group(2)}")
        for m in ACCESS_CONTROL_RE.finditer(code):
            intel['access_control'].add(m.group(0)[:120])
        for m in COMMENT_FLAG_RE.finditer(code):
            intel['flagged_comments'].append({'file': file_url, 'comment': m.group(0)[:200]})
        # Request shapes (method + path) → confirmed endpoints + verbs for m14.
        for m in REQUEST_SHAPE_RE.finditer(code):
            verb, path = m.group(1).upper(), m.group(2).strip()
            if path.startswith(('/', 'http')) and ' ' not in path:
                intel['requests'].add(f"{verb} {path[:160]}")
                endpoints.append({'url': path, 'method': verb,
                                  'filename': file_url, 'source': 'sourcemap'})
        # Dependency versions (banners + package.json blocks) → CVE correlation.
        for rx in (DEP_BANNER_RE, DEP_JSON_RE):
            for m in rx.finditer(code):
                name, ver = m.group(1).lower(), m.group(2)
                if name and ver and not name.isdigit() and len(name) > 1:
                    intel['deps'].add(f"{name}@{ver}")

    # ── Deduplication ─────────────────────────────────────────────────────────

    def _dedup_secrets(self, secrets: List[dict]) -> List[dict]:
        """Deduplicate secrets by (kind, value[:60]). jsluice wins over native."""
        seen: dict = {}
        for s in secrets:
            key = (s.get('kind', ''), str(s.get('value', s.get('data', '')))[:60])
            if key not in seen or s.get('source') == 'jsluice':
                seen[key] = s
        return list(seen.values())

    def _dedup_endpoints(self, endpoints: List[dict]) -> List[dict]:
        """Deduplicate endpoints by URL. jsluice result preferred (has method/type)."""
        seen: dict = {}
        for e in endpoints:
            url = e.get('url', '')
            if not url:
                continue
            if url not in seen or e.get('source') == 'jsluice':
                seen[url] = e
        return list(seen.values())

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_url(self, src: str, base_url: str) -> str:
        """Resolve a potentially relative URL against a base URL."""
        src = src.strip()
        if not src:
            return ''
        if src.startswith(('http://', 'https://')):
            return src
        if src.startswith('//'):
            scheme = base_url.split('://')[0] if '://' in base_url else 'https'
            return f"{scheme}:{src}"
        try:
            return urljoin(base_url, src)
        except Exception:
            return src
