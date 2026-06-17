"""
Argus V2 - Module 03: URL Collector (upgraded)
Passive : gau (waybackurls disabled by default — redundant)
Active  : katana -list -jc -jsl -kf all (gospider disabled by default — redundant)
Dedup   : uro (smart URL dedup)

Resource-safety fixes (2026-05):
  - waybackurls now bounded by a Semaphore so we don't fork-bomb on N hosts.
  - katana/gospider receive batched host lists (HOSTS_PER_BATCH).
  - adaptive concurrency scales down when live_hosts > MEDIUM/LARGE thresholds.
  - memory guard: hard cap on total URLs accumulated in RAM before next stage.
  - process-wide ulimit nofile raised when permitted (best-effort).
"""

import asyncio
import json
import resource
import shutil
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import List, Set, Dict, Optional
from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, Severity


@lru_cache(maxsize=1)
def _resolve_httpx_bin() -> Optional[str]:
    """
    Locate the ProjectDiscovery httpx binary.

    On Kali, /usr/bin/httpx is the *Python* httpx CLI (HTTP client) — it
    rejects the PD flags (-l, -fc, ...). The PD binary is shipped as
    `httpx-toolkit` to avoid the conflict. Other distros may have either.
    We probe candidate names and inspect --version output to confirm.
    """
    for name in ('httpx-toolkit', 'httpx-pd', 'httpx'):
        bin_path = shutil.which(name)
        if not bin_path:
            continue
        try:
            r = subprocess.run(
                [bin_path, '-version'],
                capture_output=True, text=True, timeout=5
            )
            blob = (r.stdout + r.stderr).lower()
            # PD httpx prints "projectdiscovery" or "current httpx version"
            if 'projectdiscovery' in blob or 'current httpx version' in blob:
                return bin_path
        except Exception:
            pass
    return None


BLACKLIST_EXT = {
    'png','jpg','jpeg','gif','svg','ico','woff','woff2','ttf','eot',
    'mp4','mp3','avi','mov','zip','gz','tar','dmg','exe',
    'css','less','scss','map'
}

# Extensions worth a finding. `.txt` removed: matched mostly robots.txt
# (high noise, low signal). Robots.txt is handled as a dedicated INFO finding.
INTERESTING_EXT = {
    # Server-side scripts
    'php','asp','aspx','jsp','jspx','do','action','cfm',
    # Config / data
    'json','xml','yaml','yml','config','conf','env',
    # Backups / dumps
    'bak','backup','sql','log','old','swp','orig',
    # Source-control / IaC
    'git','svn','hg','dockerfile','tf','tfstate','tfvars',
    # Secrets / keys / certs
    'pem','key','crt','cer','p12','pfx','jks','kdbx','keystore',
    # Web auth
    'htaccess','htpasswd',
}

# URL query-string parameters that frequently leak secrets/credentials.
# Match → finding LOW (often pre-flag for M07/M09 deep checks).
SENSITIVE_PARAMS = {
    'token','access_token','api_key','apikey','api-key','password','passwd',
    'pwd','secret','client_secret','auth','jwt','session','sid','key',
    'signature','hash','code','authorization','bearer',
}

# ── Resource safety constants ──────────────────────────────────────────────
WAYBACK_PARALLEL  = 10        # max waybackurls subprocesses at once
HOSTS_PER_BATCH   = 50        # katana/gospider host chunk size
MEDIUM_HOSTS      = 100       # threshold to halve concurrency
LARGE_HOSTS       = 300       # threshold to quarter concurrency
URL_HARD_CAP      = 500_000   # abort accumulation past this (memory guard)


def _try_raise_nofile(target: int = 8192) -> int:
    """Best-effort raise of RLIMIT_NOFILE so we can hold many sockets at once."""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_soft = min(target, hard)
        if new_soft > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            return new_soft
        return soft
    except Exception:
        return -1


_try_raise_nofile()


def _scale(value: int, n_hosts: int) -> int:
    """Adaptive scaling: halve at MEDIUM, quarter at LARGE."""
    if n_hosts >= LARGE_HOSTS:
        return max(1, value // 4)
    if n_hosts >= MEDIUM_HOSTS:
        return max(1, value // 2)
    return value


def _chunks(seq: List, size: int):
    """Yield successive chunks of `size` items."""
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


class URLCollectorModule(BaseModule):

    MODULE_ID   = "m04"
    MODULE_NAME = "URLCollectorModule"

    async def run(self, target: ScanTarget) -> None:
        cfg     = self.config.get('url_collector', default={})
        out_dir = self._output_dir(target)

        if not target.live_hosts:
            self.log.warning("No live hosts — skipping URL collection")
            return

        live_domains = list({h.get('domain','') for h in target.live_hosts if h.get('domain')})
        live_urls    = [h.get('url','') for h in target.live_hosts if h.get('url')]
        max_per      = cfg.get('max_urls_per_domain', 5000)   # cap mémoire

        n_hosts = len(live_urls)
        self.log.info(f"🔗 URL collection — {len(live_domains)} domains / {n_hosts} hosts")
        if n_hosts >= LARGE_HOSTS:
            self.log.info(f"   Large target detected — concurrency divided by 4 (>{LARGE_HOSTS} hosts)")
        elif n_hosts >= MEDIUM_HOSTS:
            self.log.info(f"   Medium target detected — concurrency halved (>{MEDIUM_HOSTS} hosts)")

        all_urls: Set[str] = set()

        def _add(label: str, items: Set[str]):
            """Memory-guarded set extension."""
            if not items:
                return
            self.log.info(f"   {label}: {len(items)} URLs")
            remaining = URL_HARD_CAP - len(all_urls)
            if remaining <= 0:
                self.log.warning(f"   URL hard cap reached ({URL_HARD_CAP}) — skipping further additions")
                return
            if len(items) > remaining:
                self.log.warning(
                    f"   URL hard cap nearing — only keeping {remaining} of {len(items)} from {label}"
                )
                # Take a deterministic sample to stay below cap
                items = set(list(items)[:remaining])
            all_urls.update(items)

        # ── Passive + Active en parallèle ─────────────────────
        # Avant : passive (gau) → wait → active (katana) en série, ce qui
        # additionnait les temps. Comme katana n'a besoin que de live_urls
        # (pas de l'output gau) et que la cap URL_HARD_CAP est rare en
        # pratique, on lance tout en parallèle. Si la cap se déclenche
        # post-merge, le filtre + URO downstream s'en charge.
        all_tasks = []
        all_labels: List[str] = []
        if cfg.get('gau', {}).get('enabled', True):
            all_tasks.append(self._run_gau(live_domains, cfg.get('gau', {})))
            all_labels.append('gau')
        # waybackurls is now off by default — gau already queries the Wayback
        # Machine (plus CommonCrawl, AlienVault, URLScan). Re-enable in
        # h4wk3y3.yaml: url_collector.waybackurls: true if you want a second pass.
        if cfg.get('waybackurls', False):
            all_tasks.append(self._run_waybackurls(live_domains))
            all_labels.append('waybackurls')
        if cfg.get('katana', {}).get('enabled', True) and live_urls:
            all_tasks.append(self._run_katana(live_urls, cfg.get('katana', {})))
            all_labels.append('katana')
        if cfg.get('gospider', {}).get('enabled', False) and live_urls:
            all_tasks.append(self._run_gospider(live_urls, cfg.get('gospider', {})))
            all_labels.append('gospider')

        if all_tasks:
            results = await asyncio.gather(*all_tasks, return_exceptions=True)
            for label, result in zip(all_labels, results):
                if isinstance(result, set):
                    _add(label, result)
                elif isinstance(result, Exception):
                    self.log.warning(f"   {label} failed: {result}")

        # ── Scope filter — drop third-party / out-of-scope URLs ─
        # gau/katana/waybackurls aggressively return URLs that reference
        # CDN assets, shared analytics, oauth providers, etc. Those are
        # NOT in scope for active testing — letting them survive here
        # would cascade into m12/m14 and produce out-of-scope traffic.
        all_urls = set(self._filter_in_scope(target, all_urls, label="collected URLs"))

        # ── Filter ────────────────────────────────────────────
        filtered = self._filter_urls(all_urls)
        self.log.info(f"   After filter: {len(filtered)} URLs")

        # ── URO dedup (smart — supprime les doublons paramétriques) ──
        if len(filtered) > 1000 and cfg.get('uro', True):
            deduped = await self._run_uro(filtered)
            if deduped:
                self.log.info(f"   uro dedup: {len(filtered)} → {len(deduped)} URLs")
                filtered = deduped

        # ── Group + cap par domaine ────────────────────────────
        # Use urlsplit().hostname so the port is stripped — avoids splitting
        # the same host into "x.com" + "x.com:80" buckets.
        from urllib.parse import urlsplit
        urls_by_domain: Dict[str, List[str]] = {}
        for url in filtered:
            try:
                host = urlsplit(url).hostname or ''
                if host:
                    urls_by_domain.setdefault(host, []).append(url)
            except Exception:
                pass

        final_urls: Set[str] = set()
        for domain, urls in urls_by_domain.items():
            capped = urls[:max_per]
            final_urls.update(capped)
            urls_by_domain[domain] = capped

        # ── httpx probe — drop dead URLs (404/410/timeouts) ───
        probe_cfg  = cfg.get('probe_live', {})
        probe_on   = probe_cfg.get('enabled', True)
        probe_max  = probe_cfg.get('max_urls', 20000)
        live_urls_set: Set[str] = set()
        if probe_on and final_urls:
            to_probe = set(list(final_urls)[:probe_max])
            probed   = await self._probe_live_urls(to_probe, probe_cfg)
            if probed:
                reduction = len(to_probe) - len(probed)
                self.log.info(
                    f"   httpx probe: {len(to_probe)} → {len(probed)} URLs "
                    f"(-{reduction} dead / 404)"
                )
                live_urls_set = probed
                # URLs au-delà du cap ne sont pas sondées — on les conserve telles quelles
                if len(final_urls) > probe_max:
                    live_urls_set.update(final_urls - to_probe)
            else:
                self.log.debug("   httpx probe returned nothing — keeping all URLs")

        target.urls = sorted(live_urls_set if live_urls_set else final_urls)

        # ── Save ──────────────────────────────────────────────
        (out_dir / "urls_all.txt").write_text('\n'.join(sorted(final_urls)))
        if live_urls_set:
            (out_dir / "urls_live.txt").write_text('\n'.join(sorted(live_urls_set)))
        (out_dir / "urls_stats.json").write_text(json.dumps({
            "total": len(final_urls),
            "by_domain": {d: len(u) for d, u in urls_by_domain.items()}
        }, indent=2))
        (out_dir / "urls_by_domain.json").write_text(json.dumps(urls_by_domain, indent=2))

        # ── API spec discovery (Swagger / OpenAPI / GraphQL) ─────────────
        api_specs = await self._probe_api_specs(live_urls)
        if api_specs:
            (out_dir / "api_specs.json").write_text(json.dumps(api_specs, indent=2))
            self._save_artefacts(target, "api_spec", api_specs,
                                 key_fields=["url", "type"])
            self.log.info(f"   API specs: {len(api_specs)} endpoints discovered")
            for spec in api_specs:
                self._add_finding(target, Finding(
                    type=FindingType.MISCONFIGURATION,
                    target=target.domain,
                    url=spec['url'],
                    title=f"API spec exposed: {spec['type']} @ {spec['url']}",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    tags=['api', spec['type'].lower(), 'exposure'],
                    metadata=spec,
                ))

        # ── Findings ─────────────────────────────────────────────────
        # 1) Interesting URLs by extension (server-side / config / secrets)
        # 2) robots.txt → grouped INFO finding (1 per host max, deduped)
        # 3) URLs carrying sensitive query params (?token=, ?password=, ...)
        from urllib.parse import urlsplit, parse_qs
        robots_seen: Set[str] = set()
        for url in sorted(final_urls):
            try:
                u = urlsplit(url)
            except Exception:
                continue
            path = u.path or ''
            ext = path.rsplit('.', 1)[-1].lower() if '.' in path.rsplit('/', 1)[-1] else ''

            # robots.txt — single INFO finding per host (no spam)
            if path.endswith('/robots.txt'):
                if u.hostname not in robots_seen:
                    robots_seen.add(u.hostname or '')
                    self._add_finding(target, Finding(
                        type=FindingType.MISCONFIGURATION, target=target.domain, url=url,
                        title=f"robots.txt exposed: {u.hostname}",
                        severity=Severity.INFO, confidence=1.0,
                        tags=['robots.txt'],
                    ))
                continue  # don't double-flag as interesting

            # Only HIGH-SIGNAL extensions become findings. A .env / .sql / .key /
            # .pem URL is a real lead. Generic .php/.xml/.json/.do/.action URLs
            # are pure inventory (already in the URL collection at /api/urls);
            # emitting one LOW finding per such URL drowned the real findings
            # (198 LOW on anpe.bj alone — signal/noise fix, QA 2026-06-03).
            _SECRET_EXT = {
                'pem', 'key', 'crt', 'cer', 'p12', 'pfx', 'jks', 'kdbx',
                'keystore', 'env', 'htaccess', 'htpasswd', 'sql', 'tfstate',
                'bak', 'old', 'swp', 'config', 'conf', 'ini', 'log',
            }
            if ext in _SECRET_EXT:
                self._add_finding(target, Finding(
                    type=FindingType.MISCONFIGURATION, target=target.domain, url=url,
                    title=f"Interesting URL: .{ext}", severity=Severity.MEDIUM,
                    confidence=0.8, tags=[ext, 'interesting_file']
                ))

            # Sensitive params in query string
            if u.query:
                try:
                    params = {k.lower() for k in parse_qs(u.query, keep_blank_values=True).keys()}
                except Exception:
                    params = set()
                hits = params & SENSITIVE_PARAMS
                if hits:
                    self._add_finding(target, Finding(
                        type=FindingType.MISCONFIGURATION, target=target.domain, url=url,
                        title=f"URL with sensitive param: {', '.join(sorted(hits))}",
                        severity=Severity.LOW, confidence=0.85,
                        tags=['sensitive_param'] + sorted(hits),
                        metadata={'params': sorted(hits)},
                    ))

        self.log.info(f"✅ M03 done — {len(final_urls)} URLs collected")

    # ── Tool wrappers ─────────────────────────────────────────

    async def _run_gau(self, domains: List[str], gau_cfg: dict) -> Set[str]:
        """
        gau — historique URLs depuis Wayback, CommonCrawl, AlienVault, URLScan.

        gau est volatile : ses sources externes (Wayback / CommonCrawl) ont
        des outages réguliers. Mesuré sur arcep.bj : 2236 URLs un scan,
        0 URLs le suivant. 1 retry après 5s sauve la majorité des cas
        transitoires sans pénaliser le happy-path (~0s coût si OK direct).
        """
        urls: Set[str] = set()
        blacklist = ','.join(gau_cfg.get('blacklist', list(BLACKLIST_EXT)))
        input_data = '\n'.join(domains).encode()

        async def _attempt(attempt_n: int) -> Set[str]:
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    'gau', '--threads', '10', '--blacklist', blacklist,
                    '--subs',
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(input=input_data), timeout=180)
                return {l.strip() for l in stdout.decode().splitlines() if l.strip()}
            except asyncio.TimeoutError:
                self.log.debug(f"gau attempt {attempt_n} timed out (180s)")
                if proc:
                    try: proc.kill()
                    except Exception: pass
                return set()
            except Exception as e:
                self.log.debug(f"gau attempt {attempt_n} error: {e}")
                return set()

        urls = await _attempt(1)
        if not urls:
            self.log.info("   gau: empty result, retrying in 5s...")
            await asyncio.sleep(5)
            urls = await _attempt(2)
            if urls:
                self.log.info(f"   gau: recovered on retry ({len(urls)} URLs)")
        return urls

    async def _run_waybackurls(self, domains: List[str]) -> Set[str]:
        """waybackurls — bounded parallel (avoids fork-bombing on N domains)."""
        sem = asyncio.Semaphore(WAYBACK_PARALLEL)

        async def fetch(domain: str) -> List[str]:
            async with sem:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        'waybackurls', domain,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
                    return [l.strip() for l in stdout.decode(errors='ignore').splitlines() if l.strip()]
                except asyncio.TimeoutError:
                    try: proc.kill()
                    except Exception: pass
                    return []
                except Exception as e:
                    self.log.debug(f"waybackurls error ({domain}): {e}")
                    return []

        results = await asyncio.gather(*[fetch(d) for d in domains], return_exceptions=True)
        urls: Set[str] = set()
        for r in results:
            if isinstance(r, list):
                urls.update(r)
        return urls

    async def _run_katana(self, live_urls: List[str], katana_cfg: dict) -> Set[str]:
        """katana — JS-aware crawl, batched + adaptive concurrency."""
        found: Set[str] = set()
        depth       = katana_cfg.get('depth', 3)
        concurrency = _scale(katana_cfg.get('concurrency', 20), len(live_urls))
        parallelism = _scale(katana_cfg.get('parallelism', 3),  len(live_urls))
        batch_size  = katana_cfg.get('batch_size', HOSTS_PER_BATCH)
        # Default 240s per batch (was 600s) — caps the worst-case crawl
        # without losing depth on cooperative hosts. Configurable in YAML
        # via url_collector.katana.batch_timeout for slow targets.
        per_batch_timeout = katana_cfg.get('batch_timeout', 240)

        async def crawl_batch(batch: List[str]) -> Set[str]:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                tmp = f.name
                f.write('\n'.join(batch))
            local: Set[str] = set()
            try:
                proc = await asyncio.create_subprocess_exec(
                    'katana',
                    '-list', tmp,
                    '-d', str(depth),
                    '-c', str(concurrency),
                    '-p', str(parallelism),
                    '-jc', '-jsl',
                    '-kf', 'all',
                    '-ef', 'png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3,css',
                    '-silent',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=per_batch_timeout)
                for line in stdout.decode(errors='ignore').splitlines():
                    if line.strip():
                        local.add(line.strip())
            except asyncio.TimeoutError:
                self.log.warning(f"katana batch timeout ({len(batch)} hosts) — partial results kept")
                try: proc.kill()
                except Exception: pass
            except Exception as e:
                self.log.debug(f"katana batch error: {e}")
            finally:
                Path(tmp).unlink(missing_ok=True)
            return local

        batches = list(_chunks(live_urls, batch_size))
        if len(batches) > 1:
            self.log.info(f"   katana: {len(batches)} batches × {batch_size} hosts (c={concurrency}, p={parallelism})")
        for i, batch in enumerate(batches, 1):
            local = await crawl_batch(batch)
            found.update(local)
            if len(found) >= URL_HARD_CAP:
                self.log.warning(f"   katana: hard cap hit at batch {i}/{len(batches)} — stopping")
                break
        return found

    async def _run_gospider(self, live_urls: List[str], gs_cfg: dict) -> Set[str]:
        """gospider — batched + adaptive (off by default; redundant with katana)."""
        found: Set[str] = set()
        concurrency = _scale(gs_cfg.get('concurrency', 30), len(live_urls))
        threads     = _scale(gs_cfg.get('threads', 20),     len(live_urls))
        depth       = gs_cfg.get('depth', 3)
        batch_size  = gs_cfg.get('batch_size', HOSTS_PER_BATCH)
        per_batch_timeout = gs_cfg.get('batch_timeout', 300)

        async def crawl_batch(batch: List[str]) -> Set[str]:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                tmp = f.name
                f.write('\n'.join(batch))
            local: Set[str] = set()
            try:
                proc = await asyncio.create_subprocess_exec(
                    'gospider',
                    '-S', tmp,
                    '-c', str(concurrency),
                    '-d', str(depth),
                    '-t', str(threads),
                    '--js', '--sitemap', '--robots', '-q',
                    '--blacklist', 'png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,css,eot',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=per_batch_timeout)
                for line in stdout.decode(errors='ignore').splitlines():
                    parts = line.strip().split(' - ')
                    for part in parts:
                        part = part.strip().strip('[]')
                        if part.startswith('http'):
                            local.add(part)
            except asyncio.TimeoutError:
                self.log.warning(f"gospider batch timeout ({len(batch)} hosts) — partial results kept")
                try: proc.kill()
                except Exception: pass
            except Exception as e:
                self.log.debug(f"gospider batch error: {e}")
            finally:
                Path(tmp).unlink(missing_ok=True)
            return local

        for batch in _chunks(live_urls, batch_size):
            local = await crawl_batch(batch)
            found.update(local)
            if len(found) >= URL_HARD_CAP:
                break
        return found

    async def _run_uro(self, urls: Set[str]) -> Set[str]:
        """uro — déduplique intelligemment les URLs avec paramètres similaires."""
        try:
            input_data = '\n'.join(urls).encode()
            proc = await asyncio.create_subprocess_exec(
                'uro',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=input_data), timeout=120)
            result = {l.strip() for l in stdout.decode().splitlines() if l.strip()}
            return result if result else urls
        except Exception as e:
            self.log.debug(f"uro error: {e}")
            return urls

    async def _probe_live_urls(self, urls: Set[str], probe_cfg: dict) -> Set[str]:
        """
        Use httpx to filter out dead URLs (404, 410, connection errors, timeouts).
        Keeps: 2xx, 3xx, 4xx (except 404/410), 5xx — anything that proves the URL exists.
        Drops: 404, 410, and anything that doesn't respond at all.
        """
        if not urls:
            return set()
        # Scale concurrency by URL count to stay well under ulimit nofile.
        n = len(urls)
        base_c = probe_cfg.get('concurrency', 150)
        if n > 50_000:   concurrency = max(50,  base_c // 4)
        elif n > 10_000: concurrency = max(75,  base_c // 2)
        else:            concurrency = base_c
        timeout     = probe_cfg.get('timeout', 5)
        rate_limit  = probe_cfg.get('rate_limit', 300)

        httpx_bin = _resolve_httpx_bin()
        if not httpx_bin:
            self.log.warning(
                "ProjectDiscovery httpx not found (looked for httpx-toolkit, "
                "httpx-pd, httpx) — skipping live-URL probe, dead URLs will "
                "leak through to M07/M09"
            )
            return set()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            tmp = f.name
            f.write('\n'.join(urls))
        try:
            # PD httpx flag names: `-t` (threads / concurrency), `-rl` (rate
            # limit), `-fc` (filter status codes), `-nc` (no color). Older
            # docs used `-c` for concurrency — that was renamed.
            proc = await asyncio.create_subprocess_exec(
                httpx_bin,
                '-l', tmp,
                '-fc', '404,410',
                '-silent',
                '-t', str(concurrency),
                '-timeout', str(timeout),
                '-rl', str(rate_limit),
                '-nc',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=600  # 10 min max
            )
            live = set()
            for line in stdout.decode().splitlines():
                url = line.strip().split(' ')[0]  # httpx may append [status] — keep only URL
                if url.startswith('http'):
                    live.add(url)
            return live
        except asyncio.TimeoutError:
            self.log.warning("httpx probe timed out — keeping unprobed URLs")
            return set()
        except Exception as e:
            self.log.warning(f"httpx probe error ({httpx_bin}): {e}")
            return set()
        finally:
            Path(tmp).unlink(missing_ok=True)

    async def _probe_api_specs(self, live_urls: List[str]) -> List[dict]:
        """
        Probe common API spec paths on each live host.
        Detects: Swagger UI, OpenAPI JSON/YAML, GraphQL introspection,
        Redoc, Rapidoc, Stoplight, AsyncAPI.

        Capped at API_SPECS_MAX_HOSTS (50) to keep request count bounded
        — beyond that the probe burns minutes for diminishing returns.
        """
        import aiohttp
        import ssl as _ssl

        API_SPECS_MAX_HOSTS = 50

        API_PATHS = [
            # OpenAPI / Swagger
            ('/swagger.json',           'OpenAPI/Swagger'),
            ('/swagger.yaml',           'OpenAPI/Swagger'),
            ('/swagger/v1/swagger.json','OpenAPI/Swagger'),
            ('/openapi.json',           'OpenAPI'),
            ('/openapi.yaml',           'OpenAPI'),
            ('/api/swagger.json',       'OpenAPI/Swagger'),
            ('/api/openapi.json',       'OpenAPI'),
            ('/api/docs',               'API Docs'),
            ('/api-docs',               'API Docs'),
            ('/v1/api-docs',            'API Docs'),
            ('/v2/api-docs',            'API Docs'),
            ('/docs',                   'API Docs'),
            ('/swagger',                'API Docs'),
            ('/swagger-ui',             'Swagger UI'),
            ('/swagger-ui.html',        'Swagger UI'),
            # Redoc / Rapidoc / Stoplight (HTML viewers)
            ('/redoc',                  'API Docs'),
            ('/api/redoc',              'API Docs'),
            ('/rapidoc',                'API Docs'),
            ('/elements',               'API Docs'),
            # AsyncAPI
            ('/asyncapi.json',          'AsyncAPI'),
            ('/asyncapi.yaml',          'AsyncAPI'),
            # GraphQL
            ('/graphql',                'GraphQL'),
            ('/api/graphql',            'GraphQL'),
            ('/v1/graphql',             'GraphQL'),
            ('/query',                  'GraphQL'),
        ]

        GRAPHQL_INTROSPECTION = '{"query":"{__schema{queryType{name}}}"}'

        ssl_ctx = _ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = _ssl.CERT_NONE

        sem   = asyncio.Semaphore(20)
        timeout = aiohttp.ClientTimeout(total=8, connect=4)

        # Deduplicate base URLs, cap at API_SPECS_MAX_HOSTS
        bases = sorted({u.rstrip('/') for u in live_urls if u.startswith('http')})
        if len(bases) > API_SPECS_MAX_HOSTS:
            self.log.info(
                f"   API spec probe: {len(bases)} hosts → capping to "
                f"{API_SPECS_MAX_HOSTS} (sorted, deterministic)"
            )
            bases = bases[:API_SPECS_MAX_HOSTS]

        async def probe(sess, base, path, kind):
            url = base + path
            async with sem:
                try:
                    if kind == 'GraphQL':
                        async with sess.post(
                            url,
                            data=GRAPHQL_INTROSPECTION,
                            headers={'Content-Type': 'application/json'},
                        ) as r:
                            if r.status == 200:
                                body = await r.text(errors='ignore')
                                if '__schema' in body or 'queryType' in body:
                                    return {'url': url, 'type': 'GraphQL', 'status': 200}
                    else:
                        async with sess.get(url) as r:
                            if r.status != 200:
                                return None
                            body = await r.text(errors='ignore')
                            low = body.lower()
                            # Swagger UI / Swagger UI variants
                            if 'swagger-ui' in low or 'swaggerui' in low:
                                return {'url': url, 'type': 'Swagger UI', 'status': 200}
                            # Redoc
                            if 'redoc-container' in low or 'redoc.init(' in low or '<redoc' in low:
                                return {'url': url, 'type': 'Redoc', 'status': 200}
                            # Rapidoc
                            if '<rapi-doc' in low or 'rapidoc-container' in low:
                                return {'url': url, 'type': 'Rapidoc', 'status': 200}
                            # Stoplight Elements
                            if 'stoplight-elements' in low or '<elements-api' in low:
                                return {'url': url, 'type': 'Stoplight', 'status': 200}
                            # AsyncAPI
                            if '"asyncapi"' in low or 'asyncapi:' in low:
                                return {'url': url, 'type': 'AsyncAPI', 'status': 200}
                            # OpenAPI JSON/YAML raw spec
                            if '"openapi"' in low or '"swagger"' in low or low.startswith('openapi:'):
                                return {'url': url, 'type': kind, 'status': 200}
                except Exception:
                    pass
            return None

        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=20)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            tasks = [probe(sess, b, p, k) for b in bases for p, k in API_PATHS]
            raw   = await asyncio.gather(*tasks, return_exceptions=True)

        return [r for r in raw if isinstance(r, dict)]

    def _filter_urls(self, urls: Set[str]) -> Set[str]:
        filtered = set()
        for url in urls:
            url = url.strip()
            if not url.startswith(('http://', 'https://')):
                continue
            path = url.split('?')[0].split('#')[0]
            ext  = path.rsplit('.', 1)[-1].lower() if '.' in path.split('/')[-1] else ''
            if ext in BLACKLIST_EXT:
                continue
            filtered.add(url)
        return filtered
