"""
Argus V2 - Module 02b: Fast Full Fetcher (style fff/tomnomnom)
Fetch headers + body de tous les live hosts en masse, ultra-rapide via aiohttp.
Output: fetch_results.json + headers.json + bodies/ (optionnel)
Utilisé par M07 pour pattern matching sur le contenu réel des pages.
"""

import asyncio
import aiohttp
import ssl
import json
import hashlib
import re
from collections import Counter
from typing import List, Dict, Optional
from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, Severity
from core.dns_resolver import make_cached_aiohttp_resolver
# Share INTERESTING_EXT with M03 instead of maintaining a separate (drifted) list
from modules.m04_url_collector import INTERESTING_EXT


class FastFetcherModule(BaseModule):

    MODULE_ID   = "m10"
    MODULE_NAME = "Fast Full Fetcher"

    async def run(self, target: ScanTarget) -> None:
        cfg     = self.config.get('fetcher', default={})
        out_dir = self._output_dir(target)

        # Input: live hosts depuis M02 ou URLs depuis M03
        sources = []
        if target.live_hosts:
            sources = [h.get('url', '') for h in target.live_hosts if h.get('url')]

        # Option: fetch aussi les URLs intéressantes de M03 (extension match
        # via INTERESTING_EXT shared with M03 — single source of truth).
        urls_file = out_dir / "urls_all.txt"
        extra_urls: List[str] = []
        # Default 800 (was 2000) — la majorité du signal est dans les
        # premières centaines (m12 patterns, m11 endpoints). Au-delà, on
        # paye le fetch pour des URLs à faible valeur. Bumper en YAML
        # (fetcher.max_extra_urls) pour les BBP intensives.
        max_extra = cfg.get('max_extra_urls', 800)
        if urls_file.exists() and cfg.get('fetch_extra_urls', True):
            all_urls = urls_file.read_text().splitlines()
            for u in all_urls:
                path = u.split('?')[0]
                ext  = path.rsplit('.', 1)[-1].lower() if '.' in path.split('/')[-1] else ''
                if not ext or ext in INTERESTING_EXT:
                    extra_urls.append(u)
                if len(extra_urls) >= max_extra:
                    break

        all_targets = list(dict.fromkeys(sources + extra_urls))  # deduplique, préserve ordre
        self.log.info(f"⚡ Fast fetch — {len(all_targets)} URLs ({len(sources)} hosts + {len(extra_urls)} interesting)")

        concurrent   = cfg.get('concurrent', 40)
        timeout_s    = cfg.get('timeout', 15)
        connect_to   = cfg.get('connect_timeout', 10)
        max_body     = cfg.get('max_body_size', 2_000_000)   # 2 MB — was 500K
        # snippet cap controls how much of `body` lands in body_snippet
        # (and thus bodies_snippets.json — read by m11 inline-script extract
        # and m12 pattern matching). 0 = keep the whole fetched body.
        # Caps the disk footprint of bodies_snippets.json at the cost of
        # missing patterns deeper in long HTML/JS. Set to e.g. 64 if disk
        # bloat hits, or 256 for a comfortable balance.
        snippet_max_kb = int(cfg.get('snippet_max_kb', 0))
        snippet_cap    = snippet_max_kb * 1024 if snippet_max_kb > 0 else None
        save_bodies  = cfg.get('save_bodies', False)

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE

        # Cached resolver seeded with IPs M02 already discovered. Avoids
        # the second DNS pass that previously timed out hosts M02 had
        # validated as live (same network, fresher cache).
        ip_map: Dict[str, str] = {}
        for h in target.live_hosts or []:
            host = (h.get('domain') or '').strip()
            ip   = (h.get('ip')     or '').strip()
            if host and ip:
                ip_map[host] = ip
        resolver = make_cached_aiohttp_resolver(ip_map)

        connector = aiohttp.TCPConnector(
            ssl=ssl_ctx,
            limit=concurrent,
            limit_per_host=4,
            ttl_dns_cache=300,
            resolver=resolver,
        )
        # connect/sock_read aligned with M02 — was 4s/6s and dropped hosts
        # that M02 had just validated as live (same network, longer total
        # timeout in M02). Keep them in sync.
        timeout   = aiohttp.ClientTimeout(total=timeout_s, connect=connect_to, sock_read=timeout_s)
        headers_ua = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

        results: List[Dict] = []
        sem = asyncio.Semaphore(concurrent)

        async def _attempt(sess: aiohttp.ClientSession, url: str) -> Optional[Dict]:
            try:
                async with sess.get(url, allow_redirects=True, max_redirects=5) as resp:
                    body_bytes = await resp.content.read(max_body)
                    body = body_bytes.decode('utf-8', errors='ignore')
                    title_m = re.search(r'<title[^>]*>([^<]{0,200})</title>', body, re.I)
                    title   = title_m.group(1).strip() if title_m else ''
                    body_hash = hashlib.md5(body.encode()).hexdigest()
                    return {
                        'url':           str(resp.url),
                        'original_url':  url,
                        'status':        resp.status,
                        'title':         title,
                        'length':        len(body),
                        'body_hash':     body_hash,
                        'headers':       dict(resp.headers),
                        'body':          body if save_bodies else '',
                        # body_snippet feeds bodies_snippets.json which is
                        # read by m11 (script extraction) and m12 (pattern
                        # matching) — capping it too aggressively would
                        # miss patterns deeper in the body. Default: keep
                        # the whole body (`snippet_max_kb=0`). Set the
                        # config knob if the JSON file gets too big.
                        'body_snippet':  body[:snippet_cap] if snippet_cap else body,
                    }
            except asyncio.TimeoutError as e:
                return {'url': url, 'status': 0, '_exc': e, '_kind': 'timeout',
                        'headers': {}, 'body': '', 'body_snippet': ''}
            except aiohttp.ClientConnectorDNSError as e:
                return {'url': url, 'status': 0, '_exc': e, '_kind': 'dns',
                        'headers': {}, 'body': '', 'body_snippet': ''}
            except (aiohttp.ServerDisconnectedError, aiohttp.ClientOSError) as e:
                return {'url': url, 'status': 0, '_exc': e, '_kind': 'reset',
                        'headers': {}, 'body': '', 'body_snippet': ''}
            except aiohttp.ClientSSLError as e:
                return {'url': url, 'status': 0, '_exc': e, '_kind': 'ssl',
                        'headers': {}, 'body': '', 'body_snippet': ''}
            except Exception as e:
                return {'url': url, 'status': 0, '_exc': e, '_kind': 'other',
                        'headers': {}, 'body': '', 'body_snippet': ''}

        async def fetch_one(sess: aiohttp.ClientSession, url: str) -> Optional[Dict]:
            async with sem:
                r = await _attempt(sess, url)
                # Retry once on transient (timeout/dns/reset) — recovers the
                # majority of network blips at minimal cost when the host is
                # actually up. SSL/4xx-from-server are NOT retried.
                if r.get('status') == 0 and r.get('_kind') in ('timeout', 'dns', 'reset'):
                    await asyncio.sleep(0.5)
                    r2 = await _attempt(sess, url)
                    if r2.get('status') != 0:
                        r2['_retried'] = True
                        return r2
                # Strip internal markers before persistence
                if r.get('status') == 0:
                    r['error'] = r.get('_kind', 'other')
                r.pop('_exc', None)
                return r

        # Session partagée pour tous les fetches
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers_ua
        ) as sess:
            # Run en batches pour ne pas ouvrir 2000 connexions simultanées
            BATCH = 200
            for i in range(0, len(all_targets), BATCH):
                batch   = all_targets[i:i+BATCH]
                batch_r = await asyncio.gather(*[fetch_one(sess, u) for u in batch], return_exceptions=True)
                for r in batch_r:
                    if isinstance(r, dict):
                        results.append(r)
                done = min(i + BATCH, len(all_targets))
                self.log.info(f"   fetched {done}/{len(all_targets)} ...")

        # Stats — error breakdown by transport class + retry recovery rate
        ok       = [r for r in results if r.get('status', 0) not in (0,)]
        retried  = sum(1 for r in ok if r.pop('_retried', False))
        errors   = [r for r in results if r.get('status', 0) == 0]
        err_dist = Counter(r.get('error', 'other') for r in errors)
        status_dist: Dict[int, int] = {}
        for r in ok:
            s = r.get('status', 0)
            status_dist[s] = status_dist.get(s, 0) + 1

        if retried:
            self.log.info(f"   OK: {len(ok)} ({retried} after retry) | Errors: {len(errors)}")
        else:
            self.log.info(f"   OK: {len(ok)} | Errors: {len(errors)}")
        self.log.info(f"   Status dist: {dict(sorted(status_dist.items()))}")
        if errors:
            self.log.info(f"   Error breakdown: {dict(err_dist)}")

        # ── Findings: 401/403 = auth-protected endpoint (low signal value
        # but useful pre-flag for M07/M09 brute-force / cred-stuffing) ──
        seen_protected = set()
        for r in ok:
            if r.get('status') in (401, 403) and r.get('url') not in seen_protected:
                seen_protected.add(r.get('url'))
                self._add_finding(target, Finding(
                    type=FindingType.MISCONFIGURATION,
                    target=target.domain,
                    url=r.get('url') or r.get('original_url'),
                    title=f"Auth-protected endpoint: {r.get('status')} {r.get('url')}",
                    severity=Severity.INFO, confidence=0.9,
                    tags=['auth-required', f"http-{r.get('status')}"],
                    metadata={
                        'status': r.get('status'),
                        'title':  r.get('title', ''),
                        'server': r.get('headers', {}).get('Server', ''),
                    },
                ))

        # Save: fetch_results.json — exclude `body` AND `body_snippet`
        # (snippets are persisted separately to bodies_snippets.json — keeping
        # them here doubled disk usage for no reader). Drop internal _ keys too.
        lite_results = [
            {k: v for k, v in r.items() if k not in ('body', 'body_snippet')
             and not k.startswith('_')}
            for r in results
        ]

        (out_dir / "fetch_results.json").write_text(json.dumps(lite_results, indent=2))

        # headers.json: mapping url -> headers (pratique pour grep patterns)
        headers_map = {r['url']: r.get('headers', {}) for r in results if r.get('headers')}
        (out_dir / "headers.json").write_text(json.dumps(headers_map, indent=2))

        # bodies_snippets.json: url -> 2KB snippet (pour pattern matching)
        snippets = {r['url']: r.get('body_snippet', '') for r in results if r.get('body_snippet')}
        (out_dir / "bodies_snippets.json").write_text(json.dumps(snippets, indent=2))

        # Si save_bodies: écrit les fichiers individuels
        if save_bodies:
            bodies_dir = out_dir / "bodies"
            bodies_dir.mkdir(exist_ok=True)
            for r in results:
                if r.get('body') and r.get('url'):
                    safe = r['url'].replace('://', '_').replace('/', '_')[:80]
                    (bodies_dir / f"{safe}.html").write_text(r['body'])

        self.log.info(f"✅ M02b done — {len(ok)} pages fetched | headers.json + bodies_snippets.json ready")

        # Expose les snippets sur target pour que M07 puisse les utiliser
        target.stats['fetch_results'] = len(ok)
        target.stats['bodies_snippets_path'] = str(out_dir / "bodies_snippets.json")
