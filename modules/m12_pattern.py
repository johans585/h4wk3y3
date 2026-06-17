"""
Argus V2 - Module 07: Pattern Analysis
Grep natif sur URLs + headers + body snippets.
Patterns basés sur tomnomnom/gf + customs.
Recherche regex custom depuis h4wk3y3.yaml.
+ reflection check: send a canary in each candidate parameter, mark reflected
  ones as high-confidence (drives M09 active validation).
"""

import asyncio
import json
import random
import re
import string
import ssl
import yaml
from pathlib import Path
from typing import List, Dict, Set
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

import aiohttp

from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, Severity
from core.utils import reap as _reap


SEV_MAP = {
    'critical': Severity.CRITICAL,
    'high':     Severity.HIGH,
    'medium':   Severity.MEDIUM,
    'low':      Severity.LOW,
    'info':     Severity.INFO,
}

# Patterns grep: {name: {regex, severity, flags, description, source}}
# source: 'url' = cherche dans les URLs, 'body' = cherche dans headers+body
GREP_PATTERNS = {
    # ── URL-based (paramètres suspects) ──────────────────────────────────────
    'rce': {
        'regex': r'[?&](cmd|exec|command|execute|ping|query|jump|code|reg|do|func|arg|option|payload|test|daemon|upload|cookie|delimiter|dir|download|ip|lang|to|name|out|resp|return|input)=',
        'severity': 'critical', 'source': 'url', 'flags': 'iE',
        'desc': 'Remote Code Execution - params pouvant executer des commandes',
    },
    'xss': {
        'regex': r'[?&](q|s|search|query|keyword|term|name|title|content|text|input|data|url|src|redirect|ref|page|view|id|value|val|msg|output|return|next|from|subject|body|comment|description)=',
        'severity': 'high', 'source': 'url', 'flags': 'iE',
        'desc': 'Cross-Site Scripting - params de recherche/affichage injectables',
    },
    'sqli': {
        'regex': r'[?&](id|page|report|dir|search|category|file|class|url|news|item|menu|lang|name|ref|title|view|topic|thread|type|date|form|main|nav|region)=[0-9]',
        'severity': 'high', 'source': 'url', 'flags': 'iE',
        'desc': 'SQL Injection - params numeriques (id, page, report)',
    },
    'ssrf': {
        'regex': r'[?&](url|uri|path|dest|redirect|to|from|src|source|host|callback|endpoint|proxy|image|load|fetch|request|open|file|document|target|site|html|feed|domain|out|view|port|next|data|reference|return|ref)=https?://',
        'severity': 'high', 'source': 'url', 'flags': 'iE',
        'desc': 'Server-Side Request Forgery - params pointant vers des URLs',
    },
    'lfi': {
        'regex': r'[?&](file|path|dir|document|folder|root|pg|page|cat|include|view|lang|conf|load|inc|locate|url|show|module|template|layout|src|resource|component)=(\.\.|/etc|/proc|php://|file://|zip://|expect://|data://)',
        'severity': 'high', 'source': 'url', 'flags': 'iE',
        'desc': 'Local File Inclusion - params de fichier/chemin',
    },
    'ssti': {
        'regex': r'[?&](template|view|layout|page|lang|name|theme|format|content|render|output|variable|item)=',
        'severity': 'high', 'source': 'url', 'flags': 'iE',
        'desc': 'Server-Side Template Injection - params de template/vue',
    },
    'idor': {
        'regex': r'[?&](id|user_id|account|number|order|no|doc|key|email|group|profile|edit|report|user|admin|member|uid|pid|oid|cid|rid|vid)=[0-9]+',
        'severity': 'medium', 'source': 'url', 'flags': 'iE',
        'desc': 'Insecure Direct Object Reference - params numeriques ID',
    },
    'redirect': {
        'regex': r'[?&](redirect|return|next|url|to|dest|destination|checkout|continue|forward|location|redir|ref|from|goto|link|out|view|logoff|target|fallback|callback|r|u)=(https?://|//|%2F%2F|\.\.|%252F)',
        'severity': 'medium', 'source': 'url', 'flags': 'iE',
        'desc': 'Open Redirect - params de redirection vers URLs externes',
    },
    # ── Body/header-based ────────────────────────────────────────────────────
    'cors': {
        'regex': r'Access-Control-Allow',
        'severity': 'medium', 'source': 'body', 'flags': 'iE',
        'desc': 'CORS - headers Access-Control presents dans les reponses',
    },
    'aws-keys': {
        'regex': r'(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}',
        'severity': 'critical', 'source': 'body', 'flags': 'E',
        'desc': 'Cles AWS exposees dans URLs ou reponses',
    },
    'firebase': {
        'regex': r'firebaseio\.com',
        'severity': 'high', 'source': 'body', 'flags': 'i',
        'desc': 'Endpoints Firebase potentiellement exposes',
    },
    's3-buckets': {
        'regex': r'[a-z0-9.-]+\.s3\.amazonaws\.com|//s3\.amazonaws\.com/[a-z0-9._-]+',
        'severity': 'medium', 'source': 'body', 'flags': 'iE',
        'desc': 'References a des buckets S3',
    },
    'takeovers': {
        'regex': r'(There is no app configured|NoSuchBucket|No Such Account|a GitHub Pages site here|project not found|InvalidBucketName|The specified bucket does not exist|Repository not found|Unrecognized domain|No such app)',
        'severity': 'high', 'source': 'body', 'flags': 'iE',
        'desc': 'CNAMEs pointant vers services non reclames',
    },
    'debug-pages': {
        'regex': r'(Application-Trace|Routing Error|DEBUG.*=.*True|Caused by:|stack trace:|Traceback|phpinfo|swaggerUi|on line [0-9]|SQLSTATE|Microsoft .NET Framework)',
        'severity': 'medium', 'source': 'body', 'flags': 'iE',
        'desc': 'Pages de debug/erreur exposees',
    },
    'upload-fields': {
        'regex': r'<input[^>]+type=["\']?file["\']?',
        'severity': 'medium', 'source': 'body', 'flags': 'iE',
        'desc': 'Champs upload de fichiers dans les pages',
    },
    'php-errors': {
        'regex': r'(php warning|php error|fatal error|uncaught exception|undefined index|undefined variable|stack trace:|Debug Trace)',
        'severity': 'low', 'source': 'body', 'flags': 'iE',
        'desc': 'Messages erreur PHP exposes',
    },
    'json-sec': {
        'regex': r'(api[_-]?key|aws_|secret|password|passwd|token)["\']?\s*[:=]\s*["\'][^"\']{8,}',
        'severity': 'medium', 'source': 'body', 'flags': 'iE',
        'desc': 'Credentials/secrets dans reponses JSON',
    },
    'http-auth': {
        'regex': r'[a-z0-9_/\.:-]+@[a-z0-9-]+\.[a-z0-9.-]+',
        'severity': 'low', 'source': 'body', 'flags': 'iE',
        'desc': 'Emails ou credentials HTTP dans les reponses',
    },
    'sec': {
        'regex': r'(aws_access|aws_secret|api[_-]?key|ListBucketResult|S3_ACCESS_KEY|Authorization:|RSA PRIVATE|Index of|ssh-rsa AA)',
        'severity': 'high', 'source': 'body', 'flags': 'iE',
        'desc': 'Secrets/credentials divers dans les reponses',
    },
    'js-secrets': {
        'regex': r'(localStorage|sessionStorage|eval\(|document\.write\(|innerHTML\s*=|\.cookie\s*=)',
        'severity': 'medium', 'source': 'body', 'flags': 'iE',
        'desc': 'Patterns dangereux dans le JavaScript',
    },
    'open-redirect-body': {
        'regex': r'(window\.location|location\.href|location\.replace)\s*=\s*["\'][^"\']*["\']',
        'severity': 'medium', 'source': 'body', 'flags': 'iE',
        'desc': 'Redirections JavaScript dans le code source',
    },
    'jwt': {
        'regex': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        'severity': 'medium', 'source': 'body', 'flags': 'E',
        'desc': 'Tokens JWT exposes dans les reponses',
    },
    'base64-secrets': {
        'regex': r'(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo)[%a-zA-Z0-9+/]{20,}={0,2}',
        'severity': 'info', 'source': 'body', 'flags': 'E',
        'desc': 'Donnees base64 potentiellement sensibles',
    },
}

GF_SEVERITY = {k: SEV_MAP.get(v['severity'], Severity.INFO) for k, v in GREP_PATTERNS.items()}

# ── False positive whitelist ──────────────────────────────────────────────────
# URL-source patterns are param-name guesses, not validation.
# Cap them at MEDIUM and skip known-noise endpoints entirely.
URL_SOURCE_GF = {'rce', 'xss', 'sqli', 'ssrf', 'lfi', 'ssti', 'idor', 'redirect'}

# Hard skip: WP/CMS endpoints where these param-name regexes always match but
# never indicate a real vuln (load-styles loader, oembed feeds, static assets).
URL_FP_PATTERNS = [
    re.compile(r'/wp-admin/(load-styles|load-scripts|admin-ajax)\.php', re.I),
    re.compile(r'/wp-json/(oembed|wp/v\d+|contact-form-7|jetpack)', re.I),
    re.compile(r'/wp-content/(uploads|themes|plugins)/', re.I),
    re.compile(r'/wp-includes/', re.I),
    re.compile(r'/xmlrpc\.php(\?|$)', re.I),
    # CMS feed/sitemap endpoints
    re.compile(r'/(feed|comments|sitemap)/?(\?|$)', re.I),
]


def _is_in_scope(url: str, apex: str, scope=None) -> bool:
    """
    Return True if URL's hostname is in scope.

    When `scope` is provided (the authoritative Scope object attached to
    the ScanTarget), defer entirely to it. Falls back to a simple apex
    match for unit-test fixtures that construct callers without a Scope.
    """
    if scope is not None:
        return scope.is_in_scope(url)
    if not apex:
        return True   # no scope info → don't filter
    try:
        host = (urlparse(url).hostname or '').lower()
    except Exception:
        return True
    apex_l = apex.lower()
    return host == apex_l or host.endswith('.' + apex_l)

# Feed/sitemap files: never report as config_file even though .xml matches.
FEED_FP_PATTERNS = [
    re.compile(r'/(feed|atom|rss|sitemap[^/]*|index|feeds/all\.atom|feeds/all\.rss|comments?)\.xml(\?|$)', re.I),
    re.compile(r'/feed/?(\?|$)', re.I),
    re.compile(r'[?&]feed=(rss2|atom|rdf)', re.I),
]


def _is_known_fp(url: str, pattern_name: str) -> bool:
    """True if this (url, pattern) pair is structurally noisy and should be dropped."""
    if pattern_name in URL_SOURCE_GF or pattern_name == 'cors':
        for fp in URL_FP_PATTERNS:
            if fp.search(url):
                return True
    if pattern_name == 'config_file':
        for fp in FEED_FP_PATTERNS:
            if fp.search(url):
                return True
    return False


def _cap_severity(pattern_name: str, source: str, declared: Severity) -> Severity:
    """
    URL-source pattern matches are *candidates* (param-name / path sniffs),
    not vulns. A `/admin` path or a `?url=` param is not a finding on its own —
    it is a hint to validate. Cap such matches to LOW so they don't crowd the
    medium/high buckets (observed: 194 `admin_panel` MEDIUM rows burying the
    real signal). The exception is a genuine sensitive *reference* embedded in
    the URL — declared HIGH/CRITICAL patterns like backup_file, config_file,
    .git, .env, sql_error — which keep their severity. Body-source matches
    (real strings like AKIA..., RSA PRIVATE) always keep their declared severity.
    """
    if source != 'url':
        return declared
    # Real file/secret/error reference literally present in the URL — keep it.
    if _sev_rank(declared) >= _sev_rank(Severity.HIGH):
        return declared
    # Param-name / path sniff (admin_panel, url_param, redirect_param, the gf
    # xss/sqli/… families) → candidate only, never above LOW.
    return Severity.LOW


def _is_url_pattern_candidate(match: dict) -> bool:
    """True if this match is a URL-param sniff (XSS/SQLi/SSRF/… in query
    string) that should be routed to m14 as a candidate instead of being
    surfaced as a finding.

    Body-source matches (real strings like AKIA..., debug-pages, JWT in
    response) stay as findings. URL-source matches that the reflection
    check promoted (tag `reflected`, `requires_validation=False`) also
    stay — those are confirmed echoes, not guesses.
    """
    if match.get('source') != 'url':
        return False
    if 'reflected' in (match.get('tags') or []):
        return False
    if match.get('requires_validation') is False:
        return False
    name = match.get('pattern', '')
    if name.startswith('gf:'):
        return name.split(':', 1)[1] in URL_SOURCE_GF
    return name in URL_SOURCE_GF


def _candidate_category(match: dict) -> str:
    """Extract the URL-pattern category (xss/sqli/ssrf/...) from a match."""
    name = match.get('pattern', '')
    if name.startswith('gf:'):
        return name.split(':', 1)[1]
    return name


_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
def _sev_rank(s: Severity) -> int:
    try:
        return _SEV_ORDER.index(s)
    except ValueError:
        return 0


class PatternModule(BaseModule):

    MODULE_ID   = "m12"
    MODULE_NAME = "PatternModule"

    GF_PATTERNS = list(GREP_PATTERNS.keys())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> List[dict]:
        patterns_file = Path(__file__).parent.parent / "config" / "patterns.yaml"
        try:
            with open(patterns_file) as f:
                data = yaml.safe_load(f)
            compiled = []
            for p in data.get('patterns', []):
                try:
                    p['_regex'] = re.compile(p['regex'], re.IGNORECASE)
                    compiled.append(p)
                except re.error as e:
                    self.log.warning(f"Invalid regex '{p.get('name')}': {e}")
            self.log.info(f"   Loaded {len(compiled)} custom patterns")
            return compiled
        except Exception as e:
            self.log.warning(f"Could not load patterns.yaml: {e}")
            return []

    async def run(self, target: ScanTarget) -> None:
        cfg     = self.config.get('pattern_analysis', default={})
        out_dir = self._output_dir(target)
        all_matches: List[dict] = []

        # Charge les URLs
        urls_file = out_dir / "urls_all.txt"
        if not urls_file.exists():
            self.log.warning("No URLs file found — skipping pattern analysis")
            return

        # Scope filter: drop URLs whose host isn't in scope. With a Scope
        # attached to the target we get the full check (apex + wildcards
        # file + explicit out-of-scope); fallback = apex match only.
        apex = target.domain or ''
        scope = getattr(target, 'scope', None)
        all_urls_raw = [l for l in urls_file.read_text().splitlines() if l.strip()]
        urls = [u for u in all_urls_raw if _is_in_scope(u, apex, scope=scope)]
        skipped_oos = len(all_urls_raw) - len(urls)
        self.log.info(
            f"🔍 Pattern analysis — {len(urls)} URLs"
            + (f" ({skipped_oos} out-of-scope skipped)" if skipped_oos else "")
        )

        # Charge headers et bodies par URL (dict {url: data})
        headers_data:  dict = {}
        snippets_data: dict = {}

        headers_file  = out_dir / "headers.json"
        snippets_file = out_dir / "bodies_snippets.json"

        if headers_file.exists():
            try:
                headers_data = json.loads(headers_file.read_text())
                # Same scope filter as snippets — drop headers from external
                # hosts (e.g. infomaniak.com pages reached via redirect).
                if apex or scope is not None:
                    headers_data = {u: h for u, h in headers_data.items()
                                    if _is_in_scope(u, apex, scope=scope)}
            except Exception:
                pass

        if snippets_file.exists():
            try:
                # Body complet — pas de troncature, grep sur tout le contenu
                snippets_data = json.loads(snippets_file.read_text())
                # Same scope filter on bodies (drop external host bodies)
                if apex or scope is not None:
                    snippets_data = {u: b for u, b in snippets_data.items()
                                     if _is_in_scope(u, apex, scope=scope)}
            except Exception:
                pass

        # ── 1. Grep patterns natif ────────────────────────────────────────────
        if cfg.get('gf_enabled', True):
            grep_matches = await self._run_grep_all(urls, headers_data, snippets_data, out_dir)
            total = sum(len(v) for v in grep_matches.values())
            self.log.info(f"   grep patterns: {total} matches dans {len(grep_matches)} catégories")
            for category, matched in grep_matches.items():
                declared_sev = GF_SEVERITY.get(category, Severity.INFO)
                for match_item in matched:
                    url    = match_item['url']
                    source = match_item.get('source', 'url')
                    if _is_known_fp(url, category):
                        continue  # WP loader, oembed, static asset — not signal
                    sev = _cap_severity(category, source, declared_sev)
                    all_matches.append({
                        'pattern':  f'gf:{category}',
                        'url':      url,
                        'match':    match_item.get('match', ''),
                        'severity': sev.value,
                        'source':   source,
                        'tags':     [category, 'grep', 'candidate'],
                        'requires_validation': True,
                        'confidence': 0.5,  # url-pattern candidates: low confidence
                    })

        # ── 2. Custom regex patterns.yaml ─────────────────────────────────────
        if cfg.get('analyze_urls', True) and self.patterns:
            url_matches = self._scan_urls(urls)
            self.log.info(f"   custom regex: {len(url_matches)} matches")
            all_matches.extend(url_matches)

        # ── 3. Body snippets custom patterns (HTML from m10) ────────────────
        if snippets_data and self.patterns:
            body_matches = []
            for url, body in snippets_data.items():
                for pattern in self.patterns:
                    try:
                        m = pattern['_regex'].search(body)
                        if m:
                            body_matches.append({
                                'pattern':    pattern['name'],
                                'url':        url,
                                'match':      m.group(0)[:200],
                                'severity':   pattern.get('severity', 'info'),
                                'confidence': pattern.get('confidence', 0.7),
                                'tags':       pattern.get('tags', []) + ['body'],
                                'source':     'body',
                            })
                    except Exception:
                        pass
            self.log.info(f"   body snippets: {len(body_matches)} matches")
            all_matches.extend(body_matches)

        # ── 3b. Site-specific JS bodies (from m11 — non-CDN, non-lib) ────────
        # Lets patterns.yaml catch hardcoded secrets / SQL errors / debug
        # strings inside JS code, not just HTML.
        js_bodies_file = out_dir / "js_bodies.json"
        if js_bodies_file.exists() and self.patterns:
            try:
                js_bodies = json.loads(js_bodies_file.read_text())
            except Exception:
                js_bodies = {}
            # Apex scope filter (drop any external JS that snuck in)
            if apex or scope is not None:
                js_bodies = {u: b for u, b in js_bodies.items()
                             if _is_in_scope(u, apex, scope=scope)}
            js_matches = []
            for url, body in js_bodies.items():
                for pattern in self.patterns:
                    try:
                        m = pattern['_regex'].search(body)
                        if m:
                            js_matches.append({
                                'pattern':    pattern['name'],
                                'url':        url,
                                'match':      m.group(0)[:200],
                                'severity':   pattern.get('severity', 'info'),
                                'confidence': pattern.get('confidence', 0.7),
                                'tags':       pattern.get('tags', []) + ['js'],
                                'source':     'js',
                            })
                    except Exception:
                        pass
            self.log.info(f"   js bodies ({len(js_bodies)} files): {len(js_matches)} matches")
            all_matches.extend(js_matches)

        # ── 4. Arjun parameter discovery ──────────────────────────────────────
        arjun_cfg = cfg.get('parameter_discovery', {})
        if arjun_cfg.get('enabled', False) and target.live_hosts:
            arjun_results = await self._run_arjun(target, out_dir, arjun_cfg)
            self.log.info(f"   arjun: {len(arjun_results)} endpoints with hidden params")
            all_matches.extend(arjun_results)

        # ── Reflection check on candidate URLs (XSS-positioning data for M09) ──
        # Send a canary in each "?param=" or arjun-discovered param; if echoed
        # in body, mark as reflected → much higher value for downstream testing.
        if cfg.get('reflection_check', True):
            reflected = await self._check_reflections(all_matches, out_dir)
            if reflected:
                self.log.info(f"   reflection: {len(reflected)} parameters echo input")
                (out_dir / "reflected_params.json").write_text(json.dumps(reflected, indent=2))
                # Promote reflected matches to higher severity / lower validation barrier
                refl_keys = {(r['url'], r['param']) for r in reflected}
                for m in all_matches:
                    url = m.get('url', '')
                    # Cheap param extraction from URL query string
                    if '?' not in url:
                        continue
                    qs = url.split('?', 1)[1]
                    for kv in qs.split('&'):
                        param = kv.split('=', 1)[0]
                        if (url, param) in refl_keys:
                            m.setdefault('tags', []).append('reflected')
                            m['confidence'] = max(m.get('confidence', 0.5), 0.85)
                            m['requires_validation'] = False  # confirmed reflection
                            break

        # ── Final scope filter (defense in depth: catches matches whose
        # source URL happens to be external — e.g. headers/body grep that
        # bled in despite per-source filtering). ─────────────────────────
        if apex or scope is not None:
            before = len(all_matches)
            all_matches = [m for m in all_matches if _is_in_scope(m.get('url', ''), apex, scope=scope)]
            dropped = before - len(all_matches)
            if dropped:
                self.log.info(f"   final scope filter: dropped {dropped} out-of-scope matches")

        # ── Save ─────────────────────────────────────────────────────────────
        # `patterns.json` keeps the full audit trail (every match, every
        # source). `m14_candidates.json` is the consolidated feed for the
        # active validator — URL-param sniffs that are not findings on their
        # own but are worth fuzzing if confirmed reflected / sqlmap-eligible.
        (out_dir / "patterns.json").write_text(json.dumps(all_matches, indent=2))
        self._save_artefacts(target, "pattern", all_matches,
                             key_fields=["url", "pattern"])

        candidates = [
            {
                'category':   _candidate_category(m),
                'url':        m.get('url', ''),
                'match':      m.get('match', ''),
                'source':     m.get('source', 'url'),
                'pattern':    m.get('pattern'),
                'confidence': float(m.get('confidence', 0.5)),
                'tags':       m.get('tags', []),
            }
            for m in all_matches
            if _is_url_pattern_candidate(m)
        ]
        (out_dir / "m14_candidates.json").write_text(json.dumps(candidates, indent=2))

        # Only emit findings for matches that are real signal (body source,
        # JS source, or URL-source promoted by the reflection check). The
        # URL-pattern guesses now live in m14_candidates.json + the
        # gf_<name>.txt files that m14 already consumes — they are not
        # `findings.json` material until validated.
        seen: Set[str] = set()
        finding_count = 0
        for m in all_matches:
            if _is_url_pattern_candidate(m):
                continue  # URL-param sniff → candidate only, not a finding
            key = f"{m.get('pattern')}:{m.get('url','')[:80]}"
            if key in seen:
                continue
            seen.add(key)
            sev_val = m.get('severity', 'info')
            sev = SEV_MAP.get(sev_val, Severity.INFO) if isinstance(sev_val, str)                   else (sev_val if isinstance(sev_val, Severity) else Severity.INFO)
            self._add_finding(target, Finding(
                type=FindingType.PATTERN_MATCH,
                target=target.domain,
                url=m.get('url', ''),
                title=f"{m.get('pattern','?')}: {m.get('url','')[:60]}",
                severity=sev,
                confidence=float(m.get('confidence', 0.7)),
                evidence=str(m.get('match', ''))[:300],
                tags=m.get('tags', []),
                metadata={
                    'source':              m.get('source', 'url'),
                    'pattern':             m.get('pattern'),
                    'requires_validation': bool(m.get('requires_validation', False)),
                },
                module_source='m12'
            ))
            finding_count += 1

        self.log.info(
            f"✅ M07 done — {len(all_matches)} matches | "
            f"{finding_count} findings | {len(candidates)} m14 candidates"
        )

    # ── Grep natif ────────────────────────────────────────────────────────────

    async def _run_grep_all(
        self,
        urls: List[str],
        headers_data: dict,
        snippets_data: dict,
        out_dir: Path
    ) -> Dict[str, List[dict]]:
        """
        Grep natif 100% Python.
        - source=url  : cherche uniquement dans les URLs collectées
        - source=body : cherche dans headers + body de chaque live host
        Résultat: {pattern -> [{url, match, source}]}
        """
        results: Dict[str, List[dict]] = {}

        async def grep_pattern(name: str, spec: dict) -> tuple:
            source  = spec.get('source', 'url')
            flag_i  = 'i' in spec.get('flags', 'i')
            try:
                rx = re.compile(spec['regex'], re.IGNORECASE if flag_i else 0)
            except re.error as e:
                self.log.debug(f"regex error [{name}]: {e}")
                return (name, [])

            matches = []

            if source == 'url':
                # Cherche uniquement dans les URLs
                for url in urls:
                    m = rx.search(url)
                    if m:
                        matches.append({
                            'url':    url,
                            'match':  m.group(0)[:120],
                            'source': 'url',
                        })

            else:
                # Cherche dans headers + body de chaque live host
                # headers_data: {url: {header_name: header_value, ...}}
                for host_url, hdrs in headers_data.items():
                    # Cherche dans chaque header
                    for k, v in hdrs.items():
                        line = f"{k}: {v}"
                        m = rx.search(line)
                        if m:
                            matches.append({
                                'url':    host_url,
                                'match':  m.group(0)[:120],
                                'source': 'header',
                            })
                            break  # 1 match par host suffit

                # Cherche dans le body complet de chaque live host
                for host_url, body in snippets_data.items():
                    if not body:
                        continue
                    m = rx.search(body)
                    if m:
                        # Évite doublons si déjà matché dans headers
                        if not any(x['url'] == host_url for x in matches):
                            matches.append({
                                'url':    host_url,
                                'match':  m.group(0)[:120],
                                'source': 'body',
                            })

            # Déduplique par url
            seen: Set[str] = set()
            deduped = []
            for item in matches:
                if item['url'] not in seen:
                    seen.add(item['url'])
                    deduped.append(item)

            return (name, deduped)

        tasks = [grep_pattern(n, s) for n, s in GREP_PATTERNS.items()]
        for result in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(result, tuple):
                name, matched = result
                if matched:
                    results[name] = matched
                    url_only = [x['url'] for x in matched if x['url'].startswith('http')]
                    if url_only:
                        (out_dir / f"gf_{name}.txt").write_text('\n'.join(url_only))

        return results


    async def _run_arjun(self, target: ScanTarget, out_dir: Path, cfg: dict) -> List[dict]:
        """
        Arjun — discover hidden GET/POST parameters on live endpoints.
        Runs only on hosts with interesting paths (forms, APIs) to limit noise.
        """
        import tempfile
        import os
        live_urls = [h.get('url', '') for h in (target.live_hosts or []) if h.get('url')]
        if not live_urls:
            return []

        # Only probe base URLs (not every crawled URL — too slow)
        concurrency = cfg.get('concurrency', 3)
        out_file    = out_dir / "arjun_results.json"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            tmp = f.name
            f.write('\n'.join(live_urls[:50]))  # cap à 50 hosts

        results = []
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                'arjun',
                '-i', tmp,
                '-t', str(concurrency),
                '--rate-limit', '10',
                '-oJ', str(out_file),
                '-q',
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)

            if out_file.exists():
                try:
                    data = json.loads(out_file.read_text())
                    # arjun output: {url: {params: [...]}} or [{url, params}]
                    items = data if isinstance(data, list) else [
                        {'url': u, 'params': p} for u, p in data.items()
                    ]
                    for item in items:
                        url    = item.get('url', '')
                        params = item.get('params', [])
                        if params:
                            results.append({
                                'pattern':    'arjun:hidden_params',
                                'url':        url,
                                'match':      ', '.join(str(p) for p in params[:20]),
                                'severity':   'medium',
                                'confidence': 0.85,
                                'source':     'arjun',
                                'tags':       ['parameter', 'arjun'],
                            })
                except Exception as e:
                    self.log.debug(f"arjun parse error: {e}")
        except asyncio.TimeoutError:
            self.log.debug("arjun timed out")
        except Exception as e:
            self.log.debug(f"arjun error: {e}")
        finally:
            # Kill + reap arjun if still running (asyncio cancels the await on
            # timeout but leaves the child detached otherwise).
            await _reap(proc)
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return results

    def _scan_urls(self, urls: List[str]) -> List[dict]:
        matches = []
        for url in urls:
            for pattern in self.patterns:
                try:
                    m = pattern['_regex'].search(url)
                    if not m:
                        continue
                    name = pattern['name']
                    if _is_known_fp(url, name):
                        continue
                    declared = SEV_MAP.get(pattern.get('severity', 'info'), Severity.INFO)
                    sev = _cap_severity(name, 'url', declared)
                    matches.append({
                        'pattern':    name,
                        'url':        url,
                        'match':      m.group(0)[:200],
                        'severity':   sev.value,
                        'confidence': pattern.get('confidence', 0.7),
                        'tags':       pattern.get('tags', []) + ['candidate'],
                        'source':     'url',
                        'requires_validation': True,
                    })
                except Exception:
                    pass
        return matches

    def _get_available_gf_patterns(self) -> Set[str]:
        """Compatibilité tests — retourne tous les patterns internes."""
        return set(GREP_PATTERNS.keys())

    # ── Reflection check ──────────────────────────────────────────────────────
    async def _check_reflections(self, all_matches: List[dict], out_dir: Path) -> List[dict]:
        """
        Pick URLs with parameters from candidate matches, replace each param value
        with a random canary, and check if it's echoed in the response body.
        Returns: [{url, param, canary, status, content_type}]

        Caps:
            - 200 unique (url, param) pairs probed (configurable)
            - 8s timeout per request, max 30 concurrent
        """
        targets: Dict[tuple, str] = {}  # (url_no_query, param) -> base_url
        for m in all_matches:
            url = m.get('url', '')
            if '?' not in url:
                continue
            try:
                p = urlparse(url)
                params = parse_qs(p.query, keep_blank_values=True)
                base_no_q = urlunparse((p.scheme, p.netloc, p.path, p.params, '', ''))
                for name in params:
                    if not name or len(name) > 64:
                        continue
                    key = (base_no_q, name)
                    if key not in targets:
                        targets[key] = url
                if len(targets) >= 200:
                    break
            except Exception:
                continue

        if not targets:
            return []

        canary_alphabet = string.ascii_lowercase + string.digits

        def _canary() -> str:
            return 'arg' + ''.join(random.choices(canary_alphabet, k=12)) + 'us'

        sem = asyncio.Semaphore(30)
        timeout = aiohttp.ClientTimeout(total=8, connect=4)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=60, ttl_dns_cache=300)

        reflected: List[dict] = []

        async def probe(session, base_url: str, param: str):
            async with sem:
                canary = _canary()
                try:
                    p = urlparse(base_url)
                    qs = parse_qs(p.query, keep_blank_values=True)
                    qs[param] = [canary]
                    new_q = urlencode([(k, v[0] if v else '') for k, v in qs.items()])
                    test_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, ''))
                    async with session.get(test_url, allow_redirects=True) as r:
                        body = await r.content.read(200_000)
                        if not body:
                            return None
                        if canary.encode() in body:
                            return {
                                'url': test_url,
                                'param': param,
                                'canary': canary,
                                'status': r.status,
                                'content_type': r.headers.get('Content-Type', ''),
                            }
                except Exception:
                    return None
            return None

        async with aiohttp.ClientSession(
            timeout=timeout, connector=connector,
            headers={'User-Agent': 'Argus/2.0 ReflectionCheck'},
        ) as session:
            tasks = [probe(session, url, param) for (url, param) in targets.keys()
                     if param]
            for coro in asyncio.as_completed(tasks):
                try:
                    r = await coro
                    if r:
                        reflected.append(r)
                except Exception:
                    pass
        return reflected
