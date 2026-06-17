"""
Argus V2 — Async multi-DNS resolver

Why this exists: aiohttp's AsyncResolver wraps c-ares but bottlenecks on a
single configured nameserver, and the default loop.getaddrinfo path saturates
the thread pool when probing 100+ subs in parallel. On lab/NAT/VM networks
the local resolver in /etc/resolv.conf is often the slow link — verified
against curl, hosts that aiohttp marks "Cannot connect" actually resolve
fine via 8.8.8.8.

This module bypasses both layers by using dnspython directly:
  - issue parallel UDP queries to N public nameservers per host
  - first valid response wins (NS rotation on timeout/SERVFAIL)
  - aggressive but bounded (semaphore + per-NS timeout)
  - distinguishes NXDOMAIN (authoritative absence) from
    "all-NS-timed-out" so the caller can downgrade noisy "missing record"
    findings to "could-not-verify" when DNS itself is the failure.
"""
from __future__ import annotations

import asyncio
import random
from typing import Dict, List, Optional, Sequence, Tuple

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver


DEFAULT_NAMESERVERS: List[str] = [
    '8.8.8.8',          # Google primary
    '9.9.9.9',          # Quad9 primary
    '8.8.4.4',          # Google secondary
    '208.67.222.222',   # OpenDNS
    # 1.1.1.1 deliberately omitted: blocked on many NAT/lab networks.
]

# Resolved once per process by default_nameservers(): either DEFAULT_NAMESERVERS
# (public, preferred) or the system resolver from /etc/resolv.conf (fallback).
_EFFECTIVE_NS_CACHE: Optional[List[str]] = None


def system_nameservers() -> List[str]:
    """Nameservers the OS itself uses (parsed from /etc/resolv.conf)."""
    try:
        r = dns.resolver.Resolver(configure=True)
        return [ns for ns in (r.nameservers or []) if ns]
    except Exception:
        return []


def _ns_reachable(nameservers: Sequence[str],
                  control: str = 'one.one.one.one') -> bool:
    """True if at least one NS answers an A query for a stable control name.

    Synchronous + quick (2s/NS, first success wins). Used once at startup to
    decide whether the hardcoded public resolvers are usable on this network.
    """
    for ns in nameservers:
        try:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = [ns]
            r.timeout = r.lifetime = 2.0
            if r.resolve(control, 'A'):
                return True
        except Exception:
            continue
    return False


def default_nameservers() -> List[str]:
    """Public resolvers when reachable, else the system resolver.

    Public DNS is preferred (avoids split-horizon internal views that hide
    SPF/DMARC for OSINT). But on networks that block direct egress to public
    resolvers — VPN kill-switches (e.g. Mullvad *Lockdown Mode*), corporate
    egress filtering, captive portals — every public query times out, which
    used to make subdomain DNS resolution and SPF/DMARC checks fail wholesale
    (false "record missing" + multi-minute m02 hangs). In that case fall back
    to the system resolver from /etc/resolv.conf, which IS reachable (it's how
    the OS and the HTTP recon tools resolve). Probed once, then cached.
    """
    global _EFFECTIVE_NS_CACHE
    if _EFFECTIVE_NS_CACHE is not None:
        return _EFFECTIVE_NS_CACHE
    if _ns_reachable(DEFAULT_NAMESERVERS):
        _EFFECTIVE_NS_CACHE = list(DEFAULT_NAMESERVERS)
    else:
        sys_ns = [ns for ns in system_nameservers()
                  if ns not in DEFAULT_NAMESERVERS]
        # Fall back to the system resolver; if resolv.conf is itself empty/only
        # the public IPs, keep the public list (nothing better to try).
        _EFFECTIVE_NS_CACHE = sys_ns or list(DEFAULT_NAMESERVERS)
    return _EFFECTIVE_NS_CACHE


# ── Resolution status returned by the per-record helpers ─────────────────────
# - 'ok':         got at least one record
# - 'nxdomain':   authoritative "no such name"
# - 'nodata':     name exists but no record of the requested type
# - 'unverified': all NS errored (timeout/SERVFAIL) — caller can't conclude
class _Status:
    OK         = 'ok'
    NXDOMAIN   = 'nxdomain'
    NODATA     = 'nodata'
    UNVERIFIED = 'unverified'


async def _query(
    name:        str,
    rdtype:      str,
    nameservers: Sequence[str],
    timeout:     float,
) -> Tuple[str, List[str]]:
    """
    Issue a single-record-type query against each NS, first-success-wins.

    The NS list is **shuffled per call** so concurrent queries spread their
    load across all upstream resolvers instead of all hammering ns[0]
    first. Without this, 10 concurrent queries each hit 8.8.8.8 first; 8.8.8.8
    starts UDP-dropping at ~50 qps → cascade of timeouts and we fall to the
    next NS only after each timeout fires. With shuffling, the load is
    distributed and round-1 success rate jumps from ~40% to ~90%.

    NXDOMAIN/NoAnswer terminate immediately (authoritative). All-NS
    failures return UNVERIFIED so the caller can avoid emitting a false
    "missing record" finding.
    """
    ns_order = list(nameservers)
    random.shuffle(ns_order)
    for ns in ns_order:
        r = dns.asyncresolver.Resolver(configure=False)
        r.nameservers = [ns]
        r.timeout  = timeout
        r.lifetime = timeout
        try:
            answer = await r.resolve(name, rdtype)
            return _Status.OK, [rr.to_text().strip('"') for rr in answer]
        except dns.resolver.NXDOMAIN:
            return _Status.NXDOMAIN, []
        except dns.resolver.NoAnswer:
            return _Status.NODATA, []
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            continue
        except Exception:
            continue
    return _Status.UNVERIFIED, []


async def _query_with_retry(
    name:        str,
    rdtype:      str,
    nameservers: Sequence[str],
    timeout:     float,
    retries:     int = 1,
) -> Tuple[str, List[str]]:
    """
    Single-name lookup with retry on UNVERIFIED. Used by single-record-type
    helpers (resolve_txt, resolve_mx, resolve_a) where a one-shot timeout
    is much more impactful than in bulk lookups (one missed lookup =
    a false-negative finding for the whole module).
    """
    for attempt in range(retries + 1):
        status, recs = await _query(name, rdtype, nameservers, timeout)
        if status != _Status.UNVERIFIED:
            return status, recs
        # Brief jittered backoff so retries don't stampede the upstream NS
        # at the exact same moment as everyone else's retries.
        await asyncio.sleep(0.5 + random.random() * 0.8)
    return _Status.UNVERIFIED, []


# ── Bulk subdomain resolution ────────────────────────────────────────────────

async def resolve_subs_parallel(
    subs:        Sequence[str],
    nameservers: Optional[Sequence[str]] = None,
    concurrency: int   = 10,        # was 50 — too aggressive, saturates upstream NS
    timeout:     float = 4.0,
    retry_unverified: bool = True,
) -> Dict[str, List[str]]:
    """
    Resolve N subdomains in parallel. Returns {sub: [ips]}, omits empty.

    Empirically: at concurrency=50 against 40 subs we lost ~60% to
    upstream-NS saturation (8.8.8.8 starts dropping UDP under load).
    At concurrency=10 we recover ~70% of subs from the same set.
    The bottleneck is the upstream resolver, not local CPU/sockets, so
    going wider is counter-productive.

    `retry_unverified=True` runs a second pass at lower concurrency on
    subs whose first attempt timed out everywhere — recovers another
    10–20% on flaky networks. NXDOMAIN/NoAnswer are NOT retried.
    """
    nameservers = list(nameservers or default_nameservers())
    sem = asyncio.Semaphore(concurrency)
    out:        Dict[str, List[str]] = {}
    unverified: List[str]            = []

    async def task(sub: str) -> None:
        async with sem:
            status, ips = await _query(sub, 'A', nameservers, timeout)
            if status == _Status.OK and ips:
                out[sub] = ips
            elif status == _Status.UNVERIFIED:
                unverified.append(sub)

    await asyncio.gather(*(task(s) for s in subs), return_exceptions=False)

    if retry_unverified and unverified:
        # Round 2: half the concurrency, longer timeout. Catches subs
        # that lost a UDP packet to upstream-NS rate limiting in round 1.
        sem2 = asyncio.Semaphore(max(1, concurrency // 2))

        async def retry(sub: str) -> None:
            async with sem2:
                status, ips = await _query(sub, 'A', nameservers, timeout * 1.5)
                if status == _Status.OK and ips:
                    out[sub] = ips

        await asyncio.gather(*(retry(s) for s in unverified), return_exceptions=False)

    return out


async def resolve_cnames_parallel(
    subs:        Sequence[str],
    nameservers: Optional[Sequence[str]] = None,
    concurrency: int   = 10,        # was 50 — see resolve_subs_parallel rationale
    timeout:     float = 4.0,
) -> Dict[str, str]:
    """Bulk CNAME lookup. Returns {sub: cname_target} for subs with a CNAME."""
    nameservers = list(nameservers or default_nameservers())
    sem = asyncio.Semaphore(concurrency)
    out: Dict[str, str] = {}
    unverified: List[str] = []

    async def task(sub: str) -> None:
        async with sem:
            status, recs = await _query(sub, 'CNAME', nameservers, timeout)
            if status == _Status.OK and recs:
                # rdata.to_text() returns e.g. "webmail1.infomaniak.ch."
                out[sub] = recs[0].rstrip('.')
            elif status == _Status.UNVERIFIED:
                unverified.append(sub)

    await asyncio.gather(*(task(s) for s in subs), return_exceptions=False)

    if unverified:
        sem2 = asyncio.Semaphore(max(1, concurrency // 2))

        async def retry(sub: str) -> None:
            async with sem2:
                status, recs = await _query(sub, 'CNAME', nameservers, timeout * 1.5)
                if status == _Status.OK and recs:
                    out[sub] = recs[0].rstrip('.')

        await asyncio.gather(*(retry(s) for s in unverified), return_exceptions=False)

    return out


async def resolve_ptrs_parallel(
    ips:         Sequence[str],
    nameservers: Optional[Sequence[str]] = None,
    concurrency: int   = 30,
    timeout:     float = 3.0,
) -> Dict[str, str]:
    """Reverse DNS for a list of IPs. Returns {ip: ptr_name}."""
    nameservers = list(nameservers or default_nameservers())
    sem = asyncio.Semaphore(concurrency)
    out: Dict[str, str] = {}

    async def task(ip: str) -> None:
        async with sem:
            try:
                arpa = dns.reversename.from_address(ip).to_text()
            except Exception:
                return
            status, recs = await _query(arpa, 'PTR', nameservers, timeout)
            if status == _Status.OK and recs:
                out[ip] = recs[0].rstrip('.')

    # Imported lazily to avoid hard-loading the reversename submodule when
    # PTR lookups aren't requested by the caller.
    import dns.reversename  # noqa: F401  (used in task)

    await asyncio.gather(*(task(i) for i in ips), return_exceptions=False)
    return out


# ── Single-domain helpers (TXT/MX) — used by M01 email-sec checks ────────────

async def resolve_txt(
    name:        str,
    nameservers: Optional[Sequence[str]] = None,
    timeout:     float = 5.0,
    retries:     int   = 2,
) -> Tuple[str, List[str]]:
    """
    Returns (status, [txt_records]). Status one of OK/NXDOMAIN/NODATA/UNVERIFIED
    so callers can distinguish "no record" from "could not check".

    Uses retry-on-unverified because a single missed TXT (especially the
    SPF/DMARC lookup) flipped a HIGH "missing record" finding to a false
    positive in arcep.bj — the record IS published, we just timed out.
    """
    return await _query_with_retry(
        name, 'TXT', list(nameservers or default_nameservers()), timeout, retries,
    )


async def resolve_mx(
    name:        str,
    nameservers: Optional[Sequence[str]] = None,
    timeout:     float = 5.0,
    retries:     int   = 2,
) -> Tuple[str, List[str]]:
    """Returns (status, ['10 mta-gw.example.com.', ...])."""
    return await _query_with_retry(
        name, 'MX', list(nameservers or default_nameservers()), timeout, retries,
    )


async def resolve_a(
    name:        str,
    nameservers: Optional[Sequence[str]] = None,
    timeout:     float = 5.0,
    retries:     int   = 2,
) -> Tuple[str, List[str]]:
    """Returns (status, [ip, ...])."""
    return await _query_with_retry(
        name, 'A', list(nameservers or default_nameservers()), timeout, retries,
    )


# ── aiohttp cached resolver (used by m03 enrich + m10 fetcher) ──────────────
def make_cached_aiohttp_resolver(ip_map: Dict[str, str]):
    """
    Build an aiohttp resolver pre-seeded with `{host: ip}` mappings.
    Avoids the 5–10s timeout penalty when aiohttp's default resolver
    re-queries hosts whose A records were already discovered upstream.

    Falls back to system getaddrinfo on cache miss; raises OSError if
    that also fails (matches aiohttp's expected contract).

    Returned object implements aiohttp.abc.AbstractResolver — pass it to
    aiohttp.TCPConnector(resolver=...).
    """
    import socket
    import aiohttp.abc

    class _CachedResolver(aiohttp.abc.AbstractResolver):
        def __init__(self, ips: Dict[str, str]):
            self._ips = ips

        async def resolve(self, host, port=0, family=socket.AF_INET):
            ip = self._ips.get(host)
            if not ip:
                try:
                    ip = socket.gethostbyname(host)
                except socket.gaierror as e:
                    raise OSError(f"DNS resolution failed for {host}") from e
            return [{
                'hostname': host, 'host': ip, 'port': port,
                'family': family, 'proto': 0, 'flags': 0,
            }]

        async def close(self):
            pass

    return _CachedResolver(ip_map)
