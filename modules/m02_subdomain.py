"""
Argus V2 - Module 01: Subdomain Enumeration (upgraded)
Passive : subfinder -dL + assetfinder + crt.sh + chaos
Active  : shuffledns (brute-force wordlist) + dnsx CNAME bulk
"""

import asyncio
import json
import time
import urllib.request
from pathlib import Path
from typing import List, Set, Dict, Optional
from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, Severity

# dnsx parfois force la couleur même sans tty → strip ANSI avant parsing.
# NO_COLOR=1 désactive la couleur sur tous les outils ProjectDiscovery.
from core.utils import DNSX_ENV as _DNSX_ENV, run_cmd as _run_cmd  # noqa: E402


class SubdomainModule(BaseModule):

    MODULE_ID   = "m02"
    MODULE_NAME = "SubdomainModule"

    async def run(self, target: ScanTarget) -> None:
        domain  = target.domain
        out_dir = self._output_dir(target)
        cfg     = self.config.get('subdomain', default={})

        self.log.info(f"🔍 Subdomain enum — {domain}")
        all_subs: Set[str] = set()

        # ── Passive (parallel, multi-source) ──────────────────
        # Strategy: run every available source in parallel. Each source
        # has its own failure mode (crt.sh = 5xx, certspotter = rate limit,
        # subfinder = no API keys, findomain = local-only) so combining
        # them is the only way to keep coverage when one is degraded.
        passive_cfg = cfg.get('passive', {})
        passive_tasks = []
        passive_labels = []
        if passive_cfg.get('subfinder', True):
            passive_tasks.append(self._run_subfinder(domain)); passive_labels.append('subfinder')
        if passive_cfg.get('assetfinder', True):
            passive_tasks.append(self._run_assetfinder(domain)); passive_labels.append('assetfinder')
        if passive_cfg.get('findomain', True):
            passive_tasks.append(self._run_findomain(domain)); passive_labels.append('findomain')
        if passive_cfg.get('crtsh', True):
            passive_tasks.append(self._run_crtsh(domain, out_dir)); passive_labels.append('crt.sh')
        if passive_cfg.get('certspotter', True):
            passive_tasks.append(self._run_certspotter(domain)); passive_labels.append('certspotter')
        if passive_cfg.get('chaos', True):
            passive_tasks.append(self._run_chaos(domain)); passive_labels.append('chaos')

        results = await asyncio.gather(*passive_tasks, return_exceptions=True)

        # Per-source health summary — operator sees instantly which sources
        # contributed and which failed/returned 0.
        source_counts: Dict[str, int] = {}
        for label, result in zip(passive_labels, results):
            if isinstance(result, list):
                source_counts[label] = len(result)
                self.log.info(f"   {label}: {len(result)} subdomains")
                all_subs.update(result)
            else:
                source_counts[label] = 0
                self.log.warning(f"   {label}: FAILED ({type(result).__name__}: {result})")

        all_subs = self._clean(all_subs, domain)
        ok_sources = sum(1 for n in source_counts.values() if n > 0)
        self.log.info(
            f"   Total passive: {len(all_subs)} unique "
            f"({ok_sources}/{len(passive_labels)} sources contributed)"
        )

        # ── Active: shuffledns brute-force + alterx permutations ─────
        # Both gated by `active.enabled`. Off by default — bulk DNS brute
        # force is slow (5–8 min for shuffledns 110k + alterx 180s) and
        # rarely yields new subs once passive sources are healthy. Enable
        # explicitly in YAML when targeting a domain you suspect has
        # internal naming patterns no public source has indexed.
        active_cfg = cfg.get('active', {})
        if active_cfg.get('enabled', False):
            if active_cfg.get('shuffledns', True):
                brute_subs = await self._run_shuffledns(domain, out_dir, active_cfg)
                new_brute = brute_subs - all_subs if brute_subs else set()
                all_subs.update(brute_subs or set())
                self.log.info(f"   shuffledns: {len(brute_subs or set())} resolved ({len(new_brute)} new)")

            if active_cfg.get('alterx', True) and all_subs:
                perm_subs = await self._run_alterx(domain, all_subs, active_cfg)
                new_perm = perm_subs - all_subs if perm_subs else set()
                all_subs.update(perm_subs or set())
                self.log.info(f"   alterx: {len(perm_subs or set())} permutations resolved ({len(new_perm)} new)")
        else:
            self.log.info("   active brute-force disabled (set subdomain.active.enabled=true to enable)")

        # ── DNS-dependent enrichment (MX/TXT, email posture, A/CNAME/PTR) ──
        # BOUNDED as a single phase. Every step here depends on the resolver
        # chain; when it's slow or unreachable (rate-limit, dead NS, blocked
        # egress :53) the whole phase can run for many minutes — and it runs
        # BEFORE the save below, so an overrun used to cancel the module and
        # discard every passive sub found (observed: m02 hit the 900s module
        # budget → 0 live hosts → m03–m14 all skipped). We give the WHOLE phase
        # ONE deadline well under the module budget and, on overrun, save the
        # passive subs anyway (M03 still HTTP-probes them). The save step is
        # therefore always reached, whichever DNS sub-step is the slow one.
        # ip_map: {sub: [ip, ip, ...]} — empty = NXDOMAIN / no A record.
        dnsx_cfg = cfg.get('dnsx', {})
        mx_txt: dict = {}
        ip_map: Dict[str, List[str]] = {}
        cnames: dict = {}
        ptrs: Dict[str, str] = {}
        live_subs = all_subs
        enrich_budget = int(cfg.get('dns_enrich_budget_sec', 300) or 300)

        async def _dns_enrich() -> None:
            nonlocal mx_txt, ip_map, cnames, ptrs, live_subs
            # MX / TXT records (third-party services, SPF secrets).
            if dnsx_cfg.get('mx', True) or dnsx_cfg.get('txt', True):
                mx_txt = await self._run_dnsx_mx_txt(domain, dnsx_cfg)
                if mx_txt:
                    (out_dir / "dns_records.json").write_text(json.dumps(mx_txt, indent=2))
                    self.log.info(f"   dnsx MX/TXT: {len(mx_txt.get('mx',[]))} MX, {len(mx_txt.get('txt',[]))} TXT")

            # Email security posture (SPF / DMARC) → findings.
            email_issues = await self._analyze_email_security(domain, mx_txt.get('txt', []))
            if email_issues:
                (out_dir / "email_security.json").write_text(json.dumps(email_issues, indent=2))
                self._save_artefacts(target, "email_security", email_issues,
                                     key_fields=["title"])
                for issue in email_issues:
                    self._add_finding(target, Finding(
                        type=FindingType.MISCONFIGURATION,
                        target=domain,
                        title=issue['title'],
                        severity=Severity(issue['severity']),
                        confidence=0.95,
                        evidence=issue['evidence'],
                        tags=['email', 'spf', 'dmarc'],
                        metadata=issue,
                    ))

            # A records (also captures IPs).
            if dnsx_cfg.get('a', True) and all_subs:
                ip_map = await self._run_dnsx_a(list(all_subs))
                if ip_map:
                    resolved = set(ip_map.keys())
                    dead = len(all_subs) - len(resolved)
                    drop_ratio = dead / len(all_subs)
                    # If dnsx drops a suspicious majority, the resolver chain
                    # is probably rate-limited or broken. Trust the unfiltered
                    # list — M03 will weed out non-responders by HTTP confidence.
                    if drop_ratio > 0.85 and len(all_subs) >= 20:
                        self.log.warning(
                            f"   dnsx A: only {len(resolved)}/{len(all_subs)} resolve "
                            f"({int(drop_ratio*100)}% dropped) — DNS likely rate-limited, "
                            "keeping all subs and letting M03 filter by HTTP"
                        )
                    else:
                        self.log.info(f"   dnsx A: {len(resolved)} resolve ({dead} dropped)")
                        live_subs = resolved
                else:
                    self.log.debug("   dnsx A: no results — keeping all subs")

            # CNAME bulk.
            if dnsx_cfg.get('cname', True) and live_subs:
                cnames = await self._run_dnsx_cname(list(live_subs))
                self.log.info(f"   dnsx CNAME: {len(cnames)} records")

            # PTR (reverse DNS) on the unique IP set — surfaces hosting provider
            # names (cloudflare, awsglobal, ovh.net…) for co-location clustering
            # and takeover candidates where IP/PTR diverge from CNAME.
            if dnsx_cfg.get('ptr', True) and ip_map:
                unique_ips = sorted({ip for ips in ip_map.values() for ip in ips})
                if unique_ips:
                    ptrs = await self._run_dnsx_ptr(unique_ips)
                    if ptrs:
                        self.log.info(f"   dnsx PTR: {len(ptrs)}/{len(unique_ips)} reverse records")

        # Run unconditionally: MX/TXT + email posture query the apex even when
        # passive enum found no subs. The whole phase is wrapped in one deadline.
        try:
            await asyncio.wait_for(_dns_enrich(), timeout=enrich_budget)
        except asyncio.TimeoutError:
            self.log.warning(
                f"   ⏱ DNS enrichment exceeded {enrich_budget}s — proceeding "
                f"with {len(all_subs)} passive subs unresolved (M03 probes by HTTP)"
            )
            ip_map, cnames, ptrs, live_subs = {}, {}, {}, all_subs

        # ── Scope filter ──────────────────────────────────────
        # Multi-source passive enum (assetfinder, certspotter, crt.sh, …)
        # can surface subs that match the apex string but aren't in scope —
        # eg. `*.staging.example.com` excluded by the YAML scope, or apex
        # variants registered to a different org. Drop them BEFORE any
        # downstream module touches them.
        if target.scope is not None:
            before_all, before_live = len(all_subs), len(live_subs)
            all_subs  = {s for s in all_subs  if target.scope.is_in_scope(s)}
            live_subs = {s for s in live_subs if target.scope.is_in_scope(s)}
            dropped_all  = before_all  - len(all_subs)
            dropped_live = before_live - len(live_subs)
            if dropped_all or dropped_live:
                self.log.info(
                    f"   🛡 scope filter: −{dropped_all} subs / −{dropped_live} live "
                    f"out-of-scope dropped"
                )

        # ── Save ──────────────────────────────────────────────
        sorted_subs = sorted(all_subs)         # full list for DB tracking / findings
        target.subdomains_discovered = sorted_subs  # all discovered → summary count
        target.subdomains = sorted(live_subs)  # only resolved subs go to M02

        new_subs = self.db.upsert_subdomains(target.scan_id, domain, sorted_subs)
        self.log.info(f"   🆕 New subdomains: {len(new_subs)}")

        (out_dir / "subdomains.txt").write_text('\n'.join(sorted_subs))
        (out_dir / "enum_stats.json").write_text(json.dumps(
            {"total": len(sorted_subs), "new": len(new_subs),
             "cnames": len(cnames), "ips": len(ip_map),
             "ptrs": len(ptrs)}, indent=2))
        if cnames:
            (out_dir / "cnames.json").write_text(json.dumps(cnames, indent=2))
        if ip_map:
            (out_dir / "ips.json").write_text(json.dumps(ip_map, indent=2))
        if ptrs:
            (out_dir / "ptrs.json").write_text(json.dumps(ptrs, indent=2))

        # Note: subdomains are persisted in the `subdomains` table (with
        # `first_seen` for diffing) and exposed via /api/subdomains/{domain}.
        # We deliberately don't emit a Finding per sub — that would just
        # pollute the findings view (1 INFO row per sub) for what is pure
        # asset inventory, already surfaced in the dedicated Subdomains tab.

        # ── Cloud bucket discovery (WSTG-CONF-11) — opt-in ──────────
        if cfg.get('cloud_buckets', {}).get('enabled', True):
            t = time.time()
            buckets = await self._discover_cloud_buckets(domain,
                concurrency=cfg.get('cloud_buckets', {}).get('concurrency', 20),
                timeout=cfg.get('cloud_buckets', {}).get('timeout', 6))
            if buckets:
                (out_dir / "cloud_buckets.json").write_text(json.dumps(buckets, indent=2))
            for b in buckets:
                sev = {
                    'public-listable': Severity.HIGH,
                    'public':          Severity.MEDIUM,
                    'exists-private':  Severity.INFO,
                }.get(b['state'], Severity.INFO)
                self._add_finding(target, Finding(
                    type=FindingType.CLOUD_BUCKET, target=target.domain, url=b['url'],
                    title=f"Cloud bucket {b['state']}: {b['provider']} {b['name']}",
                    severity=sev, confidence=0.85,
                    tags=['wstg-conf-11', 'cloud', b['provider']],
                    evidence=f"HTTP {b.get('status')} on {b['url']}",
                    metadata=b,
                ))
            self.log.info(f"   cloud buckets: {len(buckets)} hits in {int(time.time()-t)}s")

        self.log.info(f"✅ M01 done — {len(sorted_subs)} subdomains ({len(new_subs)} new)")

    # ── Tool wrappers ─────────────────────────────────────────

    async def _run_subfinder(self, domain: str) -> List[str]:
        # Routed through core.utils.run_cmd → kills + reaps the child on
        # timeout (previously subfinder leaked detached on slow targets).
        rc, out, err = await _run_cmd(['subfinder', '-d', domain, '-silent', '-all'],
                                      timeout=120)
        if rc != 0:
            self.log.debug(f"subfinder rc={rc}: {err.strip()}")
            return []
        return [l.strip() for l in out.splitlines() if l.strip()]

    async def _run_assetfinder(self, domain: str) -> List[str]:
        rc, out, err = await _run_cmd(['assetfinder', '--subs-only', domain],
                                      timeout=60)
        if rc != 0:
            self.log.debug(f"assetfinder rc={rc}: {err.strip()}")
            return []
        return [l.strip() for l in out.splitlines() if l.strip()]

    async def _run_crtsh(self, domain: str, out_dir: Path) -> List[str]:
        """
        Pull CT-log subdomains from crt.sh, resilient to its frequent 5xx.

        crt.sh is Cloudflare-fronted and notoriously unstable: 502/520/524
        bursts last from minutes to hours. Strategy:
          - 5 attempts with exponential backoff (5/15/30/60/120s)
          - timeout 180s per attempt
          - on success, persist result to disk cache (TTL 24h)
          - on failure, fall back to fresh-enough cache + log warning
        Realistic browser UA reduces 403/429 rates.
        """
        url = f"https://crt.sh/?q={domain}&output=json"
        ua  = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
               '(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36')
        cache_dir  = out_dir / ".cache"
        cache_file = cache_dir / "crtsh.json"
        CACHE_TTL  = 24 * 3600   # 24h

        def _fetch_blocking() -> bytes:
            req = urllib.request.Request(url, headers={
                'User-Agent': ua,
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
            })
            return urllib.request.urlopen(req, timeout=180).read()

        loop = asyncio.get_event_loop()
        last_exc: Optional[Exception] = None
        raw: Optional[bytes] = None
        backoffs = [5, 15, 30, 60, 120]   # 5 attempts total
        for attempt, backoff in enumerate(backoffs, start=1):
            try:
                raw = await loop.run_in_executor(None, _fetch_blocking)
                break
            except Exception as e:
                last_exc = e
                self.log.debug(f"crt.sh attempt {attempt}/{len(backoffs)} failed: {e}")
                if attempt < len(backoffs):
                    await asyncio.sleep(backoff)

        # Fallback to disk cache if all fetches failed
        if raw is None:
            self.log.warning(f"crt.sh all attempts failed (last: {last_exc})")
            try:
                if cache_file.exists():
                    age = time.time() - cache_file.stat().st_mtime
                    if age < CACHE_TTL:
                        raw = cache_file.read_bytes()
                        self.log.info(f"   crt.sh: using cache ({int(age/60)}min old)")
                    else:
                        self.log.debug(f"crt.sh cache too old ({int(age/3600)}h)")
            except Exception as e:
                self.log.debug(f"crt.sh cache read error: {e}")
            if raw is None:
                return []

        try:
            data = json.loads(raw)
        except Exception as e:
            self.log.debug(f"crt.sh JSON parse error: {e}")
            return []

        # Persist successful response to cache for next run.
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file.write_bytes(raw)
        except Exception as e:
            self.log.debug(f"crt.sh cache write error: {e}")

        subs: Set[str] = set()
        for entry in data:
            for field in ('name_value', 'common_name'):
                for name in (entry.get(field, '') or '').split('\n'):
                    name = name.strip().lower().lstrip('*.').rstrip('.')
                    if name.endswith(f'.{domain}') or name == domain:
                        subs.add(name)
        return sorted(subs)

    async def _run_certspotter(self, domain: str) -> List[str]:
        """
        SSLMate certspotter — second CT-log source, independent of crt.sh.

        Free tier: ~100 req/h without API key. Returns issuance entries
        with `dns_names` arrays. Diversifies the CT-log risk: when crt.sh
        is 502, certspotter is usually still up.
        """
        url = (f"https://api.certspotter.com/v1/issuances?"
               f"domain={domain}&include_subdomains=true&expand=dns_names")
        ua = 'argus-recon/2.0'

        def _fetch_blocking() -> bytes:
            req = urllib.request.Request(url, headers={
                'User-Agent': ua, 'Accept': 'application/json',
            })
            return urllib.request.urlopen(req, timeout=60).read()

        loop = asyncio.get_event_loop()
        for attempt in (1, 2):
            try:
                raw = await loop.run_in_executor(None, _fetch_blocking)
                break
            except Exception as e:
                if attempt == 1:
                    await asyncio.sleep(5)
                    continue
                self.log.debug(f"certspotter error: {e}")
                return []
        try:
            data = json.loads(raw)
        except Exception as e:
            self.log.debug(f"certspotter JSON parse: {e}")
            return []
        subs: Set[str] = set()
        for entry in data:
            for name in entry.get('dns_names', []) or []:
                name = (name or '').strip().lower().lstrip('*.').rstrip('.')
                if name.endswith(f'.{domain}') or name == domain:
                    subs.add(name)
        return sorted(subs)

    async def _run_findomain(self, domain: str) -> List[str]:
        """
        findomain — Rust subdomain enum, uses ~10 free CT/cert sources.
        Skipped silently if binary missing.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                'findomain', '--target', domain, '--quiet',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return [l.strip().lower() for l in stdout.decode(errors='ignore').splitlines()
                    if l.strip()]
        except FileNotFoundError:
            self.log.debug("findomain not installed — skipping")
            return []
        except asyncio.TimeoutError:
            self.log.warning("findomain timeout (120s)")
            try: proc.kill()
            except Exception: pass
            return []
        except Exception as e:
            self.log.debug(f"findomain error: {e}")
            return []

    async def _run_chaos(self, domain: str) -> List[str]:
        """ProjectDiscovery Chaos — base de subs pré-indexée, instantané."""
        try:
            proc = await asyncio.create_subprocess_exec(
                'chaos', '-d', domain, '-silent',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            return [l.strip() for l in stdout.decode().splitlines() if l.strip()]
        except Exception as e:
            self.log.debug(f"chaos error (besoin d'API key?): {e}")
            return []

    async def _run_shuffledns(self, domain: str, out_dir: Path, active_cfg: dict) -> Set[str]:
        """Brute-force DNS avec shuffledns + wordlist SecLists.

        Default wordlist upgraded from 5k → 110k entries (subdomains-top1million-110000)
        which is roughly the canonical bug-bounty enum baseline. Fall back gracefully
        through the mid-tier (20k) and original (5k) lists.
        """
        wordlist = active_cfg.get('wordlist',
            '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt')
        resolvers = active_cfg.get('resolvers',
            './data/resolvers/resolvers.txt')

        # Cascade wordlist fallbacks (largest → smallest available).
        if not Path(wordlist).exists():
            for fallback in [
                '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt',
                '/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt',
                '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
                '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
                '/usr/share/wordlists/dirb/common.txt',
            ]:
                if Path(fallback).exists():
                    wordlist = fallback
                    break
            else:
                self.log.debug("shuffledns: no wordlist found, skipping brute-force")
                return set()
        try:
            wl_size = sum(1 for _ in open(wordlist))
            self.log.info(f"   shuffledns wordlist: {Path(wordlist).name} ({wl_size} entries)")
        except Exception:
            pass

        # Fallback resolvers
        if not Path(resolvers).exists():
            resolvers_content = "\n".join([
                "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                "9.9.9.9", "208.67.222.222", "208.67.220.220"
            ])
            resolvers = str(out_dir / "resolvers.tmp")
            Path(resolvers).write_text(resolvers_content)

        try:
            proc = await asyncio.create_subprocess_exec(
                'shuffledns', '-d', domain,
                '-w', wordlist,
                '-r', resolvers,
                '-silent',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            return {l.strip() for l in stdout.decode().splitlines() if l.strip()}
        except Exception as e:
            self.log.debug(f"shuffledns error: {e}")
            return set()

    async def _run_alterx(self, domain: str, known_subs: Set[str], active_cfg: dict) -> Set[str]:
        """Generate permutations of known subdomains with alterx, resolve via dnsx.

        alterx pipes wordlists of permutation patterns (dev-{sub}, {sub}-staging,
        etc.) — we then probe the result with dnsx to keep only resolvable hosts.
        Caps:
            - input subs: 200 (alterx scales O(n²) with patterns)
            - generated:  50_000 (avoid blowing dnsx)
        """
        max_input = active_cfg.get('alterx_max_input', 200)
        max_generated = active_cfg.get('alterx_max_generated', 50_000)
        timeout = active_cfg.get('alterx_timeout', 180)

        # Use only subs of the target domain; cap input to control cost.
        relevant = [s for s in known_subs if s.endswith('.' + domain) or s == domain]
        relevant.sort()
        if len(relevant) > max_input:
            relevant = relevant[:max_input]
        if not relevant:
            return set()

        try:
            input_data = '\n'.join(relevant).encode()
            # alterx: read subs on stdin, emit permutations to stdout
            alterx = await asyncio.create_subprocess_exec(
                'alterx', '-silent',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                alterx.communicate(input=input_data), timeout=timeout)
            generated = [l.strip() for l in stdout.decode(errors='ignore').splitlines()
                         if l.strip()]
        except FileNotFoundError:
            self.log.debug("alterx not installed — skipping permutations")
            return set()
        except asyncio.TimeoutError:
            self.log.warning("alterx timeout — skipping permutations")
            try: alterx.kill()
            except Exception: pass
            return set()
        except Exception as e:
            self.log.debug(f"alterx error: {e}")
            return set()

        if not generated:
            return set()
        if len(generated) > max_generated:
            self.log.info(f"   alterx generated {len(generated)} hosts — capping to {max_generated}")
            generated = generated[:max_generated]

        # Resolve via dnsx (A record) — only keep hosts that actually exist.
        # Both passes route through run_cmd (input_data=stdin) so a hung dnsx
        # is killed + reaped on timeout instead of leaking detached.
        dnsx_input = '\n'.join(generated).encode()
        rc, _out, err = await _run_cmd(
            ['dnsx', '-silent', '-a', '-resp-only'],
            timeout=timeout, env=_DNSX_ENV, input_data=dnsx_input)
        if rc == -2:
            self.log.debug("dnsx not installed — skipping alterx resolve")
            return set()
        if rc != 0:
            self.log.debug(f"alterx dnsx pass1 rc={rc}: {err.strip()}")
            return set()

        # Second pass: get the host names that resolve.
        rc2, out2, err2 = await _run_cmd(
            ['dnsx', '-silent', '-a'],
            timeout=timeout, env=_DNSX_ENV, input_data=dnsx_input)
        if rc2 != 0:
            self.log.debug(f"alterx dnsx pass2 rc={rc2}: {err2.strip()}")
            return set()
        resolved = set()
        for line in out2.splitlines():
            # dnsx default output: "host [A] ip"
            parts = line.strip().split()
            if parts and (parts[0].endswith('.' + domain) or parts[0] == domain):
                resolved.add(parts[0])
        return resolved

    async def _analyze_email_security(self, domain: str, _ignored=None) -> List[dict]:
        """
        SPF + DMARC analysis using dnspython multi-NS.

        Crucially distinguishes "record absent" (HIGH — spoofable) from
        "could not verify" (INFO — egress DNS failed). Previous version used
        the rate-limited dnsx pipeline and produced false-positive HIGH
        findings whenever DNS itself was the failure (verified manually
        against arcep.bj which DOES publish v=spf1 but was reported missing).
        """
        from core.dns_resolver import resolve_txt, _Status

        issues: List[dict] = []
        ns = self.config.get('subdomain', 'dns_nameservers', default=None)
        spf_summary = "?"
        dmarc_summary = "?"

        # ── SPF ────────────────────────────────────────────────
        status, txts = await resolve_txt(domain, ns, timeout=5.0)
        if status == _Status.UNVERIFIED:
            spf_summary = "unverified"
            issues.append({
                'title':    f"SPF check unverified — DNS query failed for {domain}",
                'severity': 'info',
                'evidence': 'All public resolvers timed out / SERVFAIL',
                'check':    'spf_unverified',
            })
        else:
            spf = next((r for r in txts if 'v=spf1' in r.lower()), None)
            if status == _Status.NXDOMAIN:
                # Apex NXDOMAIN means the domain itself is gone — caller will
                # see other failures cascade. Don't pile on an SPF finding.
                spf_summary = "nxdomain"
            elif spf is None:
                # status is OK or NODATA — TXT records (or none) but no SPF
                spf_summary = "missing"
                issues.append({
                    'title':    f"No SPF record — {domain} is spoofable",
                    'severity': 'high',
                    'evidence': 'No TXT record with v=spf1 found',
                    'check':    'spf_missing',
                })
            elif '~all' in spf:
                spf_summary = "softfail (~all)"
                issues.append({
                    'title':    "SPF SoftFail (~all) — emails may bypass filters",
                    'severity': 'medium',
                    'evidence': spf,
                    'check':    'spf_softfail',
                })
            elif '?all' in spf or '+all' in spf:
                spf_summary = "permissive"
                issues.append({
                    'title':    f"SPF neutral/allow-all — {domain} fully spoofable",
                    'severity': 'high',
                    'evidence': spf,
                    'check':    'spf_permissive',
                })
            elif '-all' in spf:
                spf_summary = "strict (-all)"
            else:
                spf_summary = "present"

        # ── DMARC ─────────────────────────────────────────────
        dmarc_status, dmarc_txts = await resolve_txt(f'_dmarc.{domain}', ns, timeout=5.0)
        dmarc_record = next(
            (t for t in dmarc_txts if 'v=dmarc1' in t.lower()), None
        )
        if dmarc_status == _Status.UNVERIFIED:
            dmarc_summary = "unverified"
            issues.append({
                'title':    f"DMARC check unverified — DNS query failed for _dmarc.{domain}",
                'severity': 'info',
                'evidence': 'All public resolvers timed out / SERVFAIL',
                'check':    'dmarc_unverified',
            })
        elif dmarc_record is None:
            dmarc_summary = "missing"
            issues.append({
                'title':    "No DMARC record — no email spoofing protection",
                'severity': 'high',
                'evidence': f'No TXT at _dmarc.{domain}',
                'check':    'dmarc_missing',
            })
        elif 'p=none' in dmarc_record.lower():
            dmarc_summary = "p=none"
            issues.append({
                'title':    "DMARC p=none — monitoring only, no enforcement",
                'severity': 'medium',
                'evidence': dmarc_record,
                'check':    'dmarc_none',
            })
        elif 'p=reject' in dmarc_record.lower():
            dmarc_summary = "p=reject"
        elif 'p=quarantine' in dmarc_record.lower():
            dmarc_summary = "p=quarantine"
        else:
            dmarc_summary = "present"

        self.log.info(f"   email security: SPF={spf_summary} DMARC={dmarc_summary} ({len(issues)} issue(s))")
        return issues

    async def _run_dnsx_mx_txt(self, domain: str, dnsx_cfg: dict) -> dict:
        """
        Fetch MX and TXT records for the apex domain via dnspython multi-NS.

        Replaces the dnsx subprocess: same reliability gain as A/CNAME/PTR
        rewrites — public NS rotation per record type, no silent drops on
        flaky resolvers.
        """
        from core.dns_resolver import resolve_mx, resolve_txt, _Status
        records: dict = {}
        ns = self.config.get('subdomain', 'dns_nameservers', default=None)

        if dnsx_cfg.get('mx', True):
            status, mx_list = await resolve_mx(domain, ns, timeout=5.0)
            if status == _Status.OK and mx_list:
                records['mx'] = mx_list
        if dnsx_cfg.get('txt', True):
            status, txt_list = await resolve_txt(domain, ns, timeout=5.0)
            if status == _Status.OK and txt_list:
                records['txt'] = txt_list
        return records

    async def _run_dnsx_a(self, subdomains: List[str]) -> Dict[str, List[str]]:
        """Resolve A records via dnspython multi-NS public DNS.

        Returns: {sub: [ip, ip, ...]} for subs that resolve; missing key
        means NXDOMAIN, no A record, OR all-NS-timeout (caller has no way
        to disambiguate without re-querying — see resolve_subs_parallel
        which returns a separate status field for that).

        Concurrency default 10 (NOT 50): the resolver doc explicitly warns
        that c=50 saturates upstream NS and drops 60% of queries on flaky
        networks. We start conservative; if drop ratio is still > 50%, we
        do a third aggressive-low-concurrency pass below.
        """
        if not subdomains:
            return {}
        from core.dns_resolver import resolve_subs_parallel, resolve_a, _Status
        ns = self.config.get('subdomain', 'dns_nameservers', default=None)
        concurrency = self.config.get('subdomain', 'dns_concurrency', default=10)
        timeout     = self.config.get('subdomain', 'dns_timeout', default=5.0)

        try:
            resolved = await resolve_subs_parallel(
                subdomains, nameservers=ns,
                concurrency=concurrency, timeout=timeout,
            )
        except Exception as e:
            self.log.debug(f"resolve_subs_parallel error: {e}")
            return {}

        # Third-pass retry: re-probe missing subs at very low concurrency with
        # a long timeout. Public NS rate-limit UDP under burst load — going slow
        # recovers most drops on constrained networks.
        #
        # BUT this pass is O(N) at up to ~30s/sub (concurrency=3, retries=2):
        # left unbounded it can consume the entire module budget and get the
        # whole module killed, discarding every passive sub found (observed:
        # m02 timed out at 900s, scan produced 0 live hosts). Two guards:
        #   1. If the bulk pass resolved NOTHING, the resolver chain is almost
        #      certainly unreachable (egress :53 blocked / all NS down) — a slow
        #      retry of every sub is pure budget burn. Skip it.
        #   2. Cap the number of subs re-probed so a huge cert-transparency list
        #      can't blow the budget either.
        missing = [s for s in subdomains if s not in resolved]
        _RETRY_CAP = int(self.config.get('subdomain', 'dns_retry_cap',
                                         default=250) or 250)
        if missing and not resolved:
            self.log.warning(
                f"   dns A: bulk resolved 0/{len(subdomains)} — resolver chain "
                "unreachable, skipping slow retry (would burn the module budget)"
            )
            missing = []
        if missing and len(missing) > _RETRY_CAP:
            self.log.warning(
                f"   dns A: {len(missing)} unresolved — capping slow retry to "
                f"{_RETRY_CAP} (resolver likely degraded)"
            )
            missing = missing[:_RETRY_CAP]
        if missing:
            self.log.info(
                f"   dns A: {len(resolved)}/{len(subdomains)} from bulk, "
                f"retrying {len(missing)} at concurrency=3, timeout=10s"
            )
            sem = asyncio.Semaphore(3)
            recovered = 0
            async def _slow(sub: str):
                nonlocal recovered
                async with sem:
                    status, ips = await resolve_a(sub, ns, timeout=10.0, retries=2)
                    if status == _Status.OK and ips:
                        resolved[sub] = ips
                        recovered += 1
            try:
                await asyncio.gather(*(_slow(s) for s in missing),
                                     return_exceptions=False)
                self.log.info(f"   dns A retry: recovered {recovered}/{len(missing)}")
            except Exception as e:
                self.log.debug(f"slow retry error: {e}")

        return resolved

    async def _run_dnsx_ptr(self, ips: List[str]) -> Dict[str, str]:
        """Reverse-DNS lookup via dnspython multi-NS. Returns {ip: ptr_name}."""
        if not ips:
            return {}
        from core.dns_resolver import resolve_ptrs_parallel
        ns = self.config.get('subdomain', 'dns_nameservers', default=None)
        try:
            return await resolve_ptrs_parallel(
                ips, nameservers=ns,
                concurrency=self.config.get('subdomain', 'dns_concurrency', default=30),
                timeout=self.config.get('subdomain', 'dns_timeout', default=4.0),
            )
        except Exception as e:
            self.log.debug(f"resolve_ptrs_parallel error: {e}")
            return {}

    # Cache the resolvers path so we materialise the fallback only once per run.
    _resolvers_cached: Optional[str] = None

    def _resolvers_path(self) -> Optional[str]:
        """
        Return a path to a non-empty resolvers file. If the configured one
        is missing OR empty, materialise a default list of public resolvers.
        """
        if self._resolvers_cached:
            return self._resolvers_cached
        cfg_path = self.config.get('subdomain', 'active', default={}).get(
            'resolvers', './data/resolvers/resolvers.txt')
        try:
            p = Path(cfg_path)
            if p.exists() and p.read_text().strip():
                self._resolvers_cached = str(p)
                return self._resolvers_cached
        except Exception:
            pass

        # Materialise a curated public resolver list — fast, free, well-known.
        default_resolvers = [
            "1.1.1.1", "1.0.0.1",          # Cloudflare
            "8.8.8.8", "8.8.4.4",          # Google
            "9.9.9.9", "149.112.112.112",  # Quad9
            "208.67.222.222", "208.67.220.220",  # OpenDNS
            "94.140.14.14", "94.140.15.15",      # AdGuard
            "76.76.2.0",                          # Control D
        ]
        target_path = Path('./data/resolvers/resolvers.txt')
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text('\n'.join(default_resolvers) + '\n')
            self.log.info(f"   resolvers.txt empty/missing — wrote {len(default_resolvers)} public resolvers")
            self._resolvers_cached = str(target_path)
            return self._resolvers_cached
        except Exception as e:
            self.log.debug(f"could not write resolvers fallback: {e}")
            return None

    async def _run_dnsx_cname(self, subdomains: List[str]) -> Dict[str, str]:
        """CNAME lookup via dnspython multi-NS. Returns {sub: cname_target}.

        Concurrency aligned with _run_dnsx_a (10) — c=50 saturates upstream
        NS and silently drops queries on flaky networks (resolver doc).
        """
        if not subdomains:
            return {}
        from core.dns_resolver import resolve_cnames_parallel
        ns = self.config.get('subdomain', 'dns_nameservers', default=None)
        try:
            return await resolve_cnames_parallel(
                subdomains, nameservers=ns,
                concurrency=self.config.get('subdomain', 'dns_concurrency', default=10),
                timeout=self.config.get('subdomain', 'dns_timeout', default=5.0),
            )
        except Exception as e:
            self.log.debug(f"resolve_cnames_parallel error: {e}")
            return {}

    def _clean(self, subs: Set[str], domain: str) -> Set[str]:
        cleaned = set()
        for sub in subs:
            sub = sub.strip().lower().lstrip('*.')
            if sub and (sub.endswith(f'.{domain}') or sub == domain):
                cleaned.add(sub)
        return cleaned

    # ── Cloud bucket discovery (WSTG-CONF-11) ──────────────────────────────

    CLOUD_VARIANTS = (
        '', '-prod', '-staging', '-dev', '-stage', '-qa', '-test',
        '-assets', '-static', '-media', '-uploads', '-files',
        '-backup', '-backups', '-data', '-logs', '-archive',
        '-private', '-public', '-internal',
        'prod-', 'staging-', 'dev-', 'assets-', 'static-', 'backup-', 'data-',
    )
    CLOUD_TEMPLATES = (
        # AWS S3
        ('aws-s3', 'https://{name}.s3.amazonaws.com/'),
        ('aws-s3', 'https://s3.amazonaws.com/{name}/'),
        ('aws-s3', 'https://{name}.s3.eu-west-1.amazonaws.com/'),
        ('aws-s3', 'https://{name}.s3.us-west-2.amazonaws.com/'),
        # Azure Blob
        ('azure-blob', 'https://{name}.blob.core.windows.net/'),
        # Google Cloud Storage
        ('gcs',     'https://storage.googleapis.com/{name}/'),
        # Firebase Realtime DB (rules ouvertes = JSON renvoyé)
        ('firebase-rtdb',    'https://{name}.firebaseio.com/.json'),
        ('firebase-storage', 'https://{name}.firebasestorage.app/'),
        # DigitalOcean Spaces
        ('do-spaces', 'https://{name}.nyc3.digitaloceanspaces.com/'),
        ('do-spaces', 'https://{name}.fra1.digitaloceanspaces.com/'),
    )

    def _bucket_candidates(self, domain: str) -> List[str]:
        """Generate ~15-20 candidate bucket names for a target domain.
        Examples for `acme.com`:
            acme, acme-prod, acme-staging, acme-assets, prod-acme, ...
        """
        base = domain.split('.')[0]  # 'acme.com' → 'acme'
        names: Set[str] = set()
        for v in self.CLOUD_VARIANTS:
            if v.startswith('-'):
                names.add(base + v)
            elif v.endswith('-'):
                names.add(v + base)
            else:
                names.add(base + v)
        # Also include the full apex (e.g. 'acme.com') — some buckets use it
        names.add(domain)
        return sorted(n for n in names if n)

    async def _discover_cloud_buckets(self, domain: str, concurrency: int, timeout: int) -> List[dict]:
        """HEAD each (provider, candidate) combination. Classify via status:
          200 → public (or 200 + listing XML → public-listable)
          301/302/307 → exists (region redirect)
          403 → exists-private (ACL'd)
          400 → exists (AWS InvalidBucketName etc.)
          404 → doesn't exist (skip)
        Returns list of hits with state classification.
        """
        import aiohttp
        import ssl
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=concurrency * 2)
        sem = asyncio.Semaphore(concurrency)
        candidates = self._bucket_candidates(domain)
        hits: List[dict] = []

        EXISTS_BUT_PRIVATE = {403}
        EXISTS_REDIRECT    = {301, 302, 307, 308}
        EXISTS_OTHER       = {400, 405, 409}
        PUBLIC             = {200}

        async def probe(provider: str, template: str, name: str):
            url = template.format(name=name)
            async with sem:
                try:
                    async with aiohttp.ClientSession(connector=connector, connector_owner=False) as sess:
                        async with sess.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                            allow_redirects=False) as r:
                            status = r.status
                            if status == 404:
                                return
                            state = None
                            if status in PUBLIC:
                                # Sample first 4 KB and check for ListBucketResult
                                body = (await r.content.read(4096)).decode(errors='ignore')
                                if '<ListBucketResult' in body or '<EnumerationResults' in body or '"items"' in body:
                                    state = 'public-listable'
                                else:
                                    state = 'public'
                            elif status in EXISTS_BUT_PRIVATE:
                                state = 'exists-private'
                            elif status in EXISTS_REDIRECT or status in EXISTS_OTHER:
                                state = 'exists'
                            else:
                                return
                            hits.append({
                                'provider': provider, 'name': name, 'url': url,
                                'status': status, 'state': state,
                            })
                except Exception:
                    return  # silently drop network errors (false candidates noise)

        tasks = []
        for provider, tmpl in self.CLOUD_TEMPLATES:
            for n in candidates:
                tasks.append(probe(provider, tmpl, n))
        await asyncio.gather(*tasks, return_exceptions=True)
        try: await connector.close()
        except Exception: pass
        return hits
