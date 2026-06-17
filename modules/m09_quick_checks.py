"""
Argus V2 — Module 13: Quick Checks

5 high-signal atomic checks on live hosts, all surfacing distinct
FindingType values so the dashboard can filter cleanly:

  1. /graphql introspection — POST a minimal introspection query.
  2. /.git/ exposure        — HEAD/config readable on the web root.
  3. /.env exposure         — common env files served as static.
  4. JWT misconfig          — scan headers/cookies of live hosts for
                              JWTs, decode them, flag alg=none / weak hs256.
  5. Cloud bucket open      — extract S3/GCS/Azure URLs from m11 outputs
                              and test public list access.

Runs after m03 (needs live_hosts). Stage parallel with m07/m08/m04/m05/m06.

Design choice: stay self-contained. No new external binaries beyond aiohttp
(already in requirements). Each check is independent — if one raises, the
others continue.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import aiohttp

from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, Severity


# ── Probe helpers ──────────────────────────────────────────────────────


_SSL_PERMISSIVE = ssl.create_default_context()
_SSL_PERMISSIVE.check_hostname = False
_SSL_PERMISSIVE.verify_mode = ssl.CERT_NONE


def _root(url: str) -> str:
    """Return scheme://netloc/ with no path."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, '/', '', '', ''))


def _join(base: str, path: str) -> str:
    if path.startswith('/'):
        path = path[1:]
    if not base.endswith('/'):
        base = base + '/'
    return base + path


async def _get(session: aiohttp.ClientSession, url: str, timeout: float = 8.0,
               max_bytes: int = 65536) -> Optional[Tuple[int, dict, bytes]]:
    try:
        async with session.get(url, allow_redirects=False, timeout=timeout,
                               ssl=_SSL_PERMISSIVE) as r:
            body = await r.content.read(max_bytes)
            return r.status, dict(r.headers), body
    except Exception:
        return None


async def _post_json(session: aiohttp.ClientSession, url: str, payload: dict,
                     timeout: float = 8.0, max_bytes: int = 65536) -> Optional[Tuple[int, dict, bytes]]:
    try:
        async with session.post(url, json=payload, allow_redirects=False,
                                timeout=timeout, ssl=_SSL_PERMISSIVE) as r:
            body = await r.content.read(max_bytes)
            return r.status, dict(r.headers), body
    except Exception:
        return None


# ── Module ─────────────────────────────────────────────────────────────


class QuickChecksModule(BaseModule):
    MODULE_ID   = "m09"
    MODULE_NAME = "Quick Checks"

    # GraphQL endpoint candidates per host
    GRAPHQL_PATHS = ('/graphql', '/api/graphql', '/v1/graphql', '/query',
                     '/graphiql', '/api/v1/graphql')

    GIT_PATHS = ('/.git/HEAD', '/.git/config')

    ENV_PATHS = ('/.env', '/.env.local', '/.env.production', '/.env.dev')

    # JWT shape: three base64url-encoded parts.
    JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}')

    # Cloud storage URL patterns (covers public-bucket exposure surfaces).
    CLOUD_RE = re.compile(
        r'(?:[a-z0-9._-]+\.s3[\.-][a-z0-9-]+\.amazonaws\.com|'
        r's3\.amazonaws\.com/[a-z0-9._-]+|'
        r'storage\.googleapis\.com/[a-z0-9._-]+|'
        r'[a-z0-9-]+\.blob\.core\.windows\.net|'
        r'[a-z0-9-]+\.firebaseio\.com)',
        re.IGNORECASE,
    )

    async def run(self, target: ScanTarget) -> None:
        cfg = self.config.get('quick_checks', default={}) or {}
        if not cfg.get('enabled', True):
            self.log.info("m09 disabled in config — skipping")
            return

        raw_hosts: List[str] = sorted({
            _root(h.get('url'))
            for h in (target.live_hosts or [])
            if isinstance(h, dict) and h.get('url')
        })
        # Scope filter: 5 probes per host (.git, .env, GraphQL POST,
        # JWT scan, cloud bucket) is enough to step out-of-scope visibly.
        # m02/m03 already filter, but quick-checks is the last line.
        if target.scope is not None:
            before = len(raw_hosts)
            hosts = [h for h in raw_hosts if target.scope.is_in_scope(h)]
            if before - len(hosts):
                self.log.info(
                    f"   🛡 scope filter: −{before - len(hosts)} hosts dropped before quick checks"
                )
        else:
            hosts = raw_hosts
        if not hosts:
            self.log.info("no live hosts — skipping quick checks")
            return

        cap = int(cfg.get('max_hosts', 100))
        if len(hosts) > cap:
            self.log.info(f"capping quick checks to {cap}/{len(hosts)} hosts")
            hosts = hosts[:cap]

        connector = aiohttp.TCPConnector(limit=int(cfg.get('concurrency', 20)),
                                          ssl=False)
        timeout   = aiohttp.ClientTimeout(total=int(cfg.get('total_timeout', 600)))
        headers   = {
            'User-Agent': self.config.get('general', 'user_agent',
                default='Argus-V2-QuickChecks'),
        }

        results: Dict[str, Any] = {
            'graphql': [],
            'git':     [],
            'env':     [],
            'jwt':     [],
            'cloud':   [],
        }

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers,
        ) as session:
            sem = asyncio.Semaphore(int(cfg.get('per_check_concurrency', 8)))

            tasks: List[asyncio.Task] = []
            if cfg.get('graphql', True):
                tasks.extend(asyncio.create_task(self._check_graphql(session, sem, h, results['graphql'], target))
                             for h in hosts)
            if cfg.get('git', True):
                tasks.extend(asyncio.create_task(self._check_git(session, sem, h, results['git'], target))
                             for h in hosts)
            if cfg.get('env', True):
                tasks.extend(asyncio.create_task(self._check_env(session, sem, h, results['env'], target))
                             for h in hosts)

            await asyncio.gather(*tasks, return_exceptions=True)

            # JWT + cloud are extracted from data already in memory or on disk —
            # no per-host network needed.
            if cfg.get('jwt', True):
                results['jwt'] = self._check_jwt(target)
            if cfg.get('cloud_bucket', True):
                results['cloud'] = await self._check_cloud(session, target)

        try:
            (self._output_dir(target) / 'quick_checks.json').write_text(
                json.dumps(results, indent=2, default=str)
            )
        except Exception as e:
            self.log.warning(f"quick_checks.json write failed: {e}")

    # ── 1. GraphQL ────────────────────────────────────────────

    async def _check_graphql(self, session, sem, host: str,
                             bucket: List[dict], target: ScanTarget) -> None:
        async with sem:
            for path in self.GRAPHQL_PATHS:
                url = _join(host, path)
                # 1. Quick GET to see if endpoint exists (most GraphQL implementations
                # respond to GET with method-not-allowed or a UI).
                r = await _get(session, url, timeout=6)
                if r is None:
                    continue
                status, _, _ = r
                if status in (404, 410):
                    continue

                # 2. Send introspection query
                rec = await _post_json(session, url, {
                    'query': '{__schema{queryType{name} types{name}}}',
                }, timeout=8)
                if rec is None:
                    continue
                status, _, body = rec
                if status != 200:
                    continue
                try:
                    payload = json.loads(body.decode(errors='replace'))
                except Exception:
                    continue
                if not isinstance(payload, dict):
                    continue
                if payload.get('data', {}).get('__schema'):
                    type_count = len((payload['data']['__schema'].get('types') or []))
                    bucket.append({'host': host, 'path': path, 'types': type_count})
                    self._add_finding(target, Finding(
                        type=FindingType.GRAPHQL_INTROSPECTION,
                        target=urlparse(host).netloc,
                        url=url,
                        title=f"GraphQL introspection enabled ({type_count} types)",
                        severity=Severity.MEDIUM,
                        confidence=0.95,
                        evidence=body[:400].decode(errors='replace'),
                        metadata={'path': path, 'type_count': type_count},
                        tags=['quick-checks', 'graphql'],
                    ))
                    break  # one hit per host is enough

    # ── 2. /.git/ exposure ────────────────────────────────────

    async def _check_git(self, session, sem, host: str,
                         bucket: List[dict], target: ScanTarget) -> None:
        async with sem:
            # /.git/HEAD has a well-known content signature.
            url = _join(host, '/.git/HEAD')
            r = await _get(session, url, timeout=6)
            if r is None:
                return
            status, _, body = r
            if status != 200:
                return
            text = body.decode(errors='replace').strip()
            if not text.startswith('ref: refs/'):
                return

            # Confirm via /.git/config — guards against random apps that
            # return 200 for any path.
            confirm = await _get(session, _join(host, '/.git/config'), timeout=6)
            if not confirm or confirm[0] != 200:
                return
            cbody = confirm[2].decode(errors='replace')
            if '[core]' not in cbody:
                return

            bucket.append({'host': host, 'head': text[:80]})
            self._add_finding(target, Finding(
                type=FindingType.ACTIVE_FILE_EXPOSURE,
                target=urlparse(host).netloc,
                url=url,
                title=".git/ directory exposed — full repo dumpable",
                severity=Severity.HIGH,
                confidence=0.98,
                evidence=f"HEAD: {text[:80]} | config: {cbody[:120]}",
                metadata={'kind': 'git_exposure'},
                tags=['quick-checks', 'git'],
            ))

    # ── 3. /.env exposure ─────────────────────────────────────

    # Capture the KEY portion only — the previous match included leading
    # whitespace (newlines) which leaked into the keys list as "\nAPP_LOCALE".
    _ENV_LINE_RE = re.compile(rb'^\s*([A-Z][A-Z0-9_]+)\s*=', re.MULTILINE)

    async def _check_env(self, session, sem, host: str,
                         bucket: List[dict], target: ScanTarget) -> None:
        async with sem:
            for path in self.ENV_PATHS:
                url = _join(host, path)
                r = await _get(session, url, timeout=6)
                if r is None:
                    continue
                status, headers, body = r
                if status != 200:
                    continue
                # The body must look like KEY=VALUE lines AND not be HTML.
                ct = (headers.get('Content-Type') or '').lower()
                if 'html' in ct:
                    continue
                # findall now returns just the KEY (capture group) — clean,
                # no leading whitespace artefacts.
                keys = [k.decode(errors='replace') for k in self._ENV_LINE_RE.findall(body)]
                if len(keys) < 2:
                    continue
                # KEY=VALUE → keep KEY, drop VALUE entirely.
                # Cap key list so an enormous .env doesn't bloat findings.json.
                shown_keys = keys[:20]
                more = max(0, len(keys) - len(shown_keys))
                body_sha = hashlib.sha256(body).hexdigest()
                bucket.append({
                    'host': host, 'path': path, 'bytes': len(body),
                    'keys_count': len(keys), 'sha256': body_sha,
                })
                self._add_finding(target, Finding(
                    type=FindingType.ACTIVE_FILE_EXPOSURE,
                    target=urlparse(host).netloc,
                    url=url,
                    title=f"{path} exposed — environment file readable",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    # Redacted: keys only, never values. SHA256 lets the
                    # operator confirm the file content out-of-band.
                    evidence=(
                        f"{len(keys)} env vars, {len(body)} bytes | "
                        f"keys: {', '.join(shown_keys)}"
                        + (f" (+{more} more)" if more else "")
                        + f" | sha256={body_sha[:16]}"
                    ),
                    metadata={
                        'kind': 'env_exposure', 'path': path,
                        'keys_count': len(keys),
                        'keys_sample': shown_keys,
                        'body_bytes': len(body),
                        'sha256': body_sha,
                    },
                    tags=['quick-checks', 'env'],
                ))
                break

    # ── 4. JWT misconfig (no network — scan in-memory headers) ────

    def _check_jwt(self, target: ScanTarget) -> List[dict]:
        out: List[dict] = []
        for h in (target.live_hosts or []):
            if not isinstance(h, dict):
                continue
            haystack: List[str] = []
            # Headers (m03 stores select ones in `headers` dict)
            for v in (h.get('headers') or {}).values():
                if isinstance(v, str):
                    haystack.append(v)
            # cookie_issues may carry raw cookie payloads
            for v in (h.get('cookie_issues') or []):
                if isinstance(v, str):
                    haystack.append(v)
            # Sometimes the host record carries the auth token in metadata
            if isinstance(h.get('cors'), str):
                haystack.append(h['cors'])

            for blob in haystack:
                for m in self.JWT_RE.finditer(blob):
                    token = m.group(0)
                    weakness = self._classify_jwt(token)
                    if not weakness:
                        continue
                    # Redact the token. Persist sha256 (for correlation),
                    # alg (public, in the header), and the *claim names*
                    # only — never claim VALUES. A valid JWT in evidence
                    # can be replayed by anyone reading the DB.
                    token_sha = hashlib.sha256(token.encode()).hexdigest()
                    claim_names = self._jwt_claim_names(token)
                    claims_str = ', '.join(claim_names[:8]) + (
                        f' (+{len(claim_names)-8} more)' if len(claim_names) > 8 else ''
                    )
                    out.append({
                        'host': h.get('url'),
                        'token_sha256': token_sha,
                        'token_length': len(token),
                        'weakness': weakness,
                    })
                    self._add_finding(target, Finding(
                        type=FindingType.JWT_WEAKNESS,
                        target=h.get('domain') or '?',
                        url=h.get('url'),
                        title=f"JWT weakness: {weakness['reason']}",
                        severity=weakness['severity'],
                        confidence=0.9,
                        evidence=(
                            f"alg={weakness.get('alg','?')} | reason={weakness['reason']} | "
                            f"claims=[{claims_str}] | token_sha256={token_sha[:16]}… "
                            f"({len(token)}B)"
                        ),
                        metadata={
                            'jwt_alg': weakness.get('alg'),
                            'reason': weakness['reason'],
                            'token_sha256': token_sha,
                            'token_length': len(token),
                            'claim_names': claim_names,
                        },
                        tags=['quick-checks', 'jwt'],
                    ))
        return out

    @staticmethod
    def _jwt_claim_names(token: str) -> List[str]:
        """Return the claim *names* (keys) of a JWT payload — never values."""
        try:
            _, payload_b64, _ = token.split('.', 2)
            payload_b64 += '=' * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode()))
            if isinstance(payload, dict):
                return [str(k) for k in payload.keys()]
        except Exception:
            pass
        return []

    @staticmethod
    def _classify_jwt(token: str) -> Optional[dict]:
        """Decode header + payload; return weakness dict or None if OK."""
        try:
            header_b64, payload_b64, _sig = token.split('.', 2)

            def _b64dec(s: str) -> bytes:
                # Restore padding
                s = s + '=' * (-len(s) % 4)
                return base64.urlsafe_b64decode(s.encode())

            header  = json.loads(_b64dec(header_b64))
            payload = json.loads(_b64dec(payload_b64))
        except Exception:
            return None

        alg = (header.get('alg') or '').upper()
        # alg=none → critical
        if alg == 'NONE':
            return {'severity': Severity.CRITICAL,
                    'reason': 'alg=none (unsigned JWT accepted)',
                    'alg': alg}
        # Missing exp → medium
        if 'exp' not in payload:
            return {'severity': Severity.MEDIUM,
                    'reason': 'no exp claim — token never expires',
                    'alg': alg}
        # kid header that looks like a path (path traversal)
        kid = header.get('kid', '')
        if isinstance(kid, str) and ('..' in kid or kid.startswith('/')):
            return {'severity': Severity.HIGH,
                    'reason': f'suspicious kid="{kid}" — possible path injection',
                    'alg': alg}
        # JKU/X5U headers → server fetches public key from URL = SSRF surface
        if 'jku' in header or 'x5u' in header:
            return {'severity': Severity.HIGH,
                    'reason': 'jku/x5u header present — server fetches signing key over network',
                    'alg': alg}
        return None

    # ── 5. Cloud bucket exposure ──────────────────────────────

    async def _check_cloud(self, session, target: ScanTarget) -> List[dict]:
        """Extract cloud URLs from m11 outputs + JS endpoints. Test public list."""
        candidates: set = set()
        out_dir = self._output_dir(target)

        # Pull from disk outputs of upstream modules (m11).
        for name in ('js_endpoints.json', 'js_secrets.json'):
            p = out_dir / name
            if not p.exists():
                continue
            try:
                raw = p.read_text()
            except Exception:
                continue
            for m in self.CLOUD_RE.finditer(raw):
                candidates.add(m.group(0).lower())

        # Also scan in-memory URLs from m04.
        for u in (target.urls or []):
            if not isinstance(u, str):
                continue
            for m in self.CLOUD_RE.finditer(u):
                candidates.add(m.group(0).lower())

        if not candidates:
            return []

        # Scope filter: cloud bucket hosts (s3.amazonaws.com/foo,
        # foo.blob.core.windows.net…) are NOT covered by *.target.tld and
        # therefore look out-of-scope by default. Probing a 3rd-party
        # bucket extracted from a page is a BBP violation. Operator who
        # wants to test cloud assets owned by the org must whitelist them
        # via scopes/<apex>.yaml `scope.in`.
        if target.scope is not None:
            before = len(candidates)
            candidates = {c for c in candidates if target.scope.is_in_scope(c)}
            if before - len(candidates):
                self.log.info(
                    f"   🛡 scope filter: −{before - len(candidates)} cloud bucket "
                    f"candidates dropped (whitelist via scopes/<apex>.yaml to test)"
                )
        if not candidates:
            return []

        cap = 20
        if len(candidates) > cap:
            candidates = set(list(candidates)[:cap])

        results: List[dict] = []
        for endpoint in candidates:
            # Reach a list URL and look for the bucket-list XML/JSON signature.
            # Naïve: GET https://<endpoint>/ — public buckets return their
            # ListBucket XML with <Contents> or "items" JSON.
            url = f"https://{endpoint}"
            r = await _get(session, url, timeout=8, max_bytes=4096)
            if r is None:
                continue
            status, headers, body = r
            ct = (headers.get('Content-Type') or '').lower()
            sample = body[:512].decode(errors='replace')

            public = False
            severity = Severity.MEDIUM
            if status == 200 and ('<ListBucketResult' in sample
                                  or '<EnumerationResults' in sample
                                  or '"kind": "storage#objects"' in sample
                                  or 'storage#objects' in sample):
                public = True
                severity = Severity.HIGH
            elif status == 200 and ('xml' in ct or 'json' in ct):
                # Weaker signal — bucket responds but maybe not a list page.
                public = True
                severity = Severity.LOW

            if public:
                results.append({'endpoint': endpoint, 'status': status,
                                'severity': severity.value})
                self._add_finding(target, Finding(
                    type=FindingType.CLOUD_BUCKET,
                    target=target.domain,
                    url=url,
                    title=f"Cloud bucket world-readable: {endpoint}",
                    severity=severity,
                    confidence=0.85,
                    evidence=sample[:400],
                    metadata={'endpoint': endpoint, 'status': status,
                              'content_type': ct},
                    tags=['quick-checks', 'cloud-bucket'],
                ))
        return results
