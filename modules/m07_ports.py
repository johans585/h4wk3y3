"""
Argus V2 — Module 11: Port & Service Discovery

Runs after m03 (needs IPs from live_hosts). Stages in parallel with
m04/m05/m06 (different network footprint).

Capabilities:
  1. naabu — top-1000 TCP ports on unique IPs (excludes 80/443 already
     covered by m03).
  2. nmap -sV — service banner / version detection on the discovered
     ports (limited to a budget of N ports).
  3. cdncheck — flag IPs that look like origin (not behind CDN) when
     the corresponding host was identified as CDN-fronted by m03.

Tools wrapped:
  - naabu (projectdiscovery)
  - nmap
  - cdncheck (projectdiscovery)

Failure model: missing tool → warning + skip that capability. Module
never aborts the pipeline.

Outputs:
  - data per host in ports.json
  - SERVICE_EXPOSED Finding per non-trivial open port
  - ORIGIN_IP_LEAK Finding when a CDN-fronted live_host has an IP that
    cdncheck classifies as non-CDN.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, Severity


# Ports already covered by m03 (web probe) — no need to flag again unless
# the service banner is unusual.
_WEB_PORTS_COVERED = {80, 443, 8080, 8443, 8000, 8888, 9000, 3000, 5000, 8081, 8090, 9090, 7000, 8001}


def _which(b: str) -> Optional[str]:
    return shutil.which(b)


from core.utils import run_cmd as _run_cmd  # noqa: E402


def _is_private_ip(ip: str) -> bool:
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


class PortsModule(BaseModule):
    MODULE_ID   = "m07"
    MODULE_NAME = "Ports & Service Discovery"

    async def run(self, target: ScanTarget) -> None:
        cfg = self.config.get('ports', default={}) or {}
        if not cfg.get('enabled', True):
            self.log.info("m07 disabled in config — skipping")
            return

        out_dir = self._output_dir(target)

        # ── Collect unique IPs ───────────────────────────────────
        # Defense-in-depth: m02/m03 should already have filtered out-of-scope
        # hosts, but a port scan against an out-of-scope IP is a BBP-breaking
        # action we must never take. Drop hosts the scope rejects before we
        # ever feed naabu/rustscan/nmap.
        scope_drops = 0
        ips: Dict[str, List[str]] = {}  # ip -> list of hosts mapping to it
        for h in target.live_hosts or []:
            if not isinstance(h, dict):
                continue
            ip   = h.get('ip')
            host = h.get('url') or h.get('domain')
            if not ip or _is_private_ip(ip):
                continue
            if target.scope is not None and host and not target.scope.is_in_scope(host):
                scope_drops += 1
                continue
            ips.setdefault(ip, []).append(host or '?')
        if scope_drops:
            self.log.info(f"   🛡 scope filter: −{scope_drops} live_hosts dropped before port scan")

        if not ips:
            self.log.warning("No public IPs in live_hosts — skipping port scan")
            return

        max_ips = int(cfg.get('max_ips', 50))
        if len(ips) > max_ips:
            self.log.info(f"capping port scan to {max_ips}/{len(ips)} IPs")
            ips = dict(list(ips.items())[:max_ips])

        self.log.info(f"port scan on {len(ips)} unique IP(s)")

        results: Dict[str, Any] = {
            'started_at': datetime.now(timezone.utc).isoformat(),
            'ips': list(ips.keys()),
            'open_ports': {},  # ip -> [ports]
            'services':   {},  # ip -> [{port, banner, version}]
            'cdn':        {},  # ip -> cdn name or null
        }

        # ── 1. Port discovery (rustscan, fallback naabu, fallback TCP) ──
        # rustscan is ~5–10× faster than naabu on the same host count and
        # respects --ulimit / --batch-size for rate control. Naabu kept as
        # fallback for hosts where rustscan isn't installed.
        results['open_ports'] = await self._discover_ports(list(ips.keys()), cfg)

        # ── 2. nmap -sV on the open ports ────────────────────────
        if cfg.get('nmap_service_detect', True):
            services = await self._nmap_services(results['open_ports'], cfg)
            results['services'] = services
        else:
            services = {}

        # ── 3. cdncheck ──────────────────────────────────────────
        if cfg.get('cdncheck', True):
            results['cdn'] = await self._cdncheck(list(ips.keys()))

        # ── Emit findings ────────────────────────────────────────
        self._emit_service_findings(target, ips, services, cfg)
        self._emit_origin_leak_findings(target, ips, results['cdn'])

        results['finished_at'] = datetime.now(timezone.utc).isoformat()
        try:
            (out_dir / 'ports.json').write_text(json.dumps(results, indent=2, default=str))
        except Exception as e:
            self.log.warning(f"ports.json write failed: {e}")

    # ── Port discovery dispatcher ──────────────────────────────

    async def _discover_ports(self, ips: List[str], cfg: dict) -> Dict[str, List[int]]:
        """Order of preference: rustscan → naabu → TCP-connect fallback."""
        if cfg.get('prefer', 'rustscan') == 'rustscan' and _which('rustscan'):
            try:
                return await self._rustscan(ips, cfg)
            except Exception as e:
                self.log.warning(f"rustscan failed ({e}) — falling back to naabu")
        if _which('naabu'):
            return await self._naabu(ips, cfg)
        return await self._fallback_tcp_connect(ips, cfg)

    # ── rustscan ───────────────────────────────────────────────

    async def _rustscan(self, ips: List[str], cfg: dict) -> Dict[str, List[int]]:
        """rustscan port discovery. --greppable yields one "IP -> [p1,p2,...]"
        line per host. Under stealth we tighten batch-size and lengthen the
        per-probe timeout so we don't trip IDS/WAF rate detection."""
        # Defaults: top-1000-equivalent range with operator overrides.
        rs_cfg     = cfg.get('rustscan', {}) or {}
        # Full range by default — the whole point of rustscan over the naabu
        # top-1000 fallback. Operators tighten via config if they want speed.
        port_range = rs_cfg.get('range', '1-65535')
        ulimit     = str(rs_cfg.get('ulimit', 5000))
        if self.stealth:
            batch    = str(rs_cfg.get('batch_stealth', 500))
            timeout  = str(rs_cfg.get('timeout_ms_stealth', 3000))
        else:
            batch    = str(rs_cfg.get('batch', 1500))
            timeout  = str(rs_cfg.get('timeout_ms', 1500))

        cmd = [
            'rustscan',
            '-a', ','.join(ips),
            '--range', port_range,
            '--ulimit', ulimit,
            '-b', batch,
            '-t', timeout,
            '--greppable',
            '--no-banner',
        ]
        wall_timeout = int(cfg.get('rustscan_timeout_sec', 300))
        rc, out, err = await _run_cmd(cmd, timeout=wall_timeout)
        # rustscan exits non-zero when no ports found on some IPs even with
        # other IPs open; we still parse stdout.
        if rc < 0:
            raise RuntimeError(f"rustscan timeout/kill ({err.strip()[:120]})")
        ports: Dict[str, List[int]] = {}
        for line in out.splitlines():
            line = line.strip()
            if not line or '->' not in line:
                continue
            # Format: "1.2.3.4 -> [22,80,443]"
            try:
                ip, ports_part = line.split('->', 1)
                ip = ip.strip()
                ports_part = ports_part.strip().lstrip('[').rstrip(']')
                plist = [int(p) for p in ports_part.split(',') if p.strip().isdigit()]
            except Exception:
                continue
            if ip and plist:
                ports.setdefault(ip, []).extend(plist)
        for ip in ports:
            ports[ip] = sorted(set(ports[ip]))
        self.log.info(
            f"rustscan: {sum(len(v) for v in ports.values())} open ports "
            f"across {len(ports)}/{len(ips)} IPs "
            f"(range={port_range} batch={batch} stealth={self.stealth})"
        )
        return ports

    # ── naabu ──────────────────────────────────────────────────

    async def _naabu(self, ips: List[str], cfg: dict) -> Dict[str, List[int]]:
        if not _which('naabu'):
            self.log.warning("naabu missing — falling back to TCP-connect on common ports")
            return await self._fallback_tcp_connect(ips, cfg)

        # naabu wants \n-separated IPs on stdin or via -list. We use a temp file.
        import tempfile
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(ips))
            list_path = f.name

        try:
            top_ports = str(cfg.get('top_ports', 1000))
            rate      = str(cfg.get('rate', 1000))
            timeout   = int(cfg.get('naabu_timeout_sec', 300))
            cmd = ['naabu', '-list', list_path,
                   '-top-ports', top_ports,
                   '-rate', rate, '-silent', '-json']
            rc, out, err = await _run_cmd(cmd, timeout=timeout)
            if rc < 0 or rc == -2:
                self.log.warning(f"naabu failed ({err.strip()})")
                return {}
        finally:
            try:
                os.unlink(list_path)
            except Exception:
                pass

        ports: Dict[str, List[int]] = {}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            ip = rec.get('ip') or rec.get('host')
            port = rec.get('port')
            if ip and port:
                ports.setdefault(ip, []).append(int(port))
        for ip in ports:
            ports[ip] = sorted(set(ports[ip]))
        self.log.info(f"naabu: {sum(len(v) for v in ports.values())} open ports across {len(ports)} IPs")
        return ports

    async def _fallback_tcp_connect(self, ips: List[str], cfg: dict) -> Dict[str, List[int]]:
        """Minimal fallback when naabu absent — TCP-connect probe on a tiny list."""
        common = [21, 22, 25, 53, 110, 143, 445, 587, 993, 995, 1433, 3306, 3389, 5432, 6379, 9200, 11211, 27017]
        ports: Dict[str, List[int]] = {}

        async def _probe(ip: str, port: int) -> Optional[Tuple[str, int]]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=2.5)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return (ip, port)
            except Exception:
                return None

        tasks = [_probe(ip, p) for ip in ips for p in common]
        for fut in asyncio.as_completed(tasks):
            res = await fut
            if res:
                ip, port = res
                ports.setdefault(ip, []).append(port)
        for ip in ports:
            ports[ip] = sorted(set(ports[ip]))
        return ports

    # ── nmap -sV ──────────────────────────────────────────────

    async def _nmap_services(self, open_ports: Dict[str, List[int]],
                             cfg: dict) -> Dict[str, List[dict]]:
        if not _which('nmap'):
            self.log.warning("nmap missing — service detection skipped")
            return {}

        budget = int(cfg.get('nmap_port_budget', 100))
        services: Dict[str, List[dict]] = {}

        # Build flat (ip, port) list, exclude already-known web ports
        # since m03 covered them.
        targets: List[Tuple[str, int]] = []
        for ip, ports in open_ports.items():
            for p in ports:
                if p in _WEB_PORTS_COVERED:
                    continue
                targets.append((ip, p))
                if len(targets) >= budget:
                    break
            if len(targets) >= budget:
                break

        if not targets:
            return {}

        # Group by ip → comma-separated ports for nmap.
        per_ip: Dict[str, List[int]] = {}
        for ip, port in targets:
            per_ip.setdefault(ip, []).append(port)

        # OPSEC: stealth → -T1 (paranoid), normal → -T2 (polite). -T4
        # tripped IDS on multiple BBP targets — see CLAUDE.md OPSEC rules.
        timing = '-T1' if self.stealth else cfg.get('nmap_timing', '-T2')

        async def _scan_ip(ip: str, ports: List[int]) -> None:
            port_arg = ','.join(str(p) for p in sorted(ports))
            cmd = ['nmap', '-sV', '-Pn', timing, '--open',
                   '-p', port_arg, '-oX', '-', ip]
            timeout = int(cfg.get('nmap_timeout_sec', 180))
            rc, out, err = await _run_cmd(cmd, timeout=timeout)
            if rc < 0:
                self.log.debug(f"nmap {ip}: {err.strip()[:120]}")
                return
            services[ip] = self._parse_nmap_xml(out)

        # Run a few in parallel
        sem = asyncio.Semaphore(int(cfg.get('nmap_concurrency', 4)))

        async def _bounded(ip, ports):
            async with sem:
                await _scan_ip(ip, ports)

        await asyncio.gather(*(_bounded(ip, ports) for ip, ports in per_ip.items()))
        return services

    @staticmethod
    def _parse_nmap_xml(xml: str) -> List[dict]:
        """Minimal nmap XML parse — no external lib, just regex on <port>...<service .../></port>."""
        out: List[dict] = []
        for m in re.finditer(
            r'<port\s+protocol="(\w+)"\s+portid="(\d+)">.*?'
            r'<state\s+state="(\w+)".*?'
            r'(?:<service\s+([^/]*?)/?>)?',
            xml, re.DOTALL,
        ):
            proto, port, state, svc_attrs = m.group(1), int(m.group(2)), m.group(3), m.group(4) or ''
            if state != 'open':
                continue
            attrs = dict(re.findall(r'(\w+)="([^"]*)"', svc_attrs))
            out.append({
                'port': port, 'proto': proto, 'state': state,
                'name':    attrs.get('name', ''),
                'product': attrs.get('product', ''),
                'version': attrs.get('version', ''),
                'extrainfo': attrs.get('extrainfo', ''),
            })
        return out

    # ── cdncheck ──────────────────────────────────────────────

    async def _cdncheck(self, ips: List[str]) -> Dict[str, Optional[str]]:
        if not _which('cdncheck'):
            self.log.info("cdncheck missing — origin leak detection limited")
            return {ip: None for ip in ips}

        import tempfile
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(ips))
            list_path = f.name

        try:
            cmd = ['cdncheck', '-l', list_path, '-resp', '-jsonl', '-silent']
            rc, out, err = await _run_cmd(cmd, timeout=120)
            if rc < 0:
                self.log.warning(f"cdncheck failed: {err.strip()}")
                return {ip: None for ip in ips}
        finally:
            try:
                os.unlink(list_path)
            except Exception:
                pass

        cdn_by_ip: Dict[str, Optional[str]] = {ip: None for ip in ips}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            ip = rec.get('input') or rec.get('ip')
            # cdncheck output keys vary by version — handle both shapes
            cdn = rec.get('cdn_name') or rec.get('value')
            if rec.get('cdn') or rec.get('type') == 'cdn':
                cdn_by_ip[ip] = cdn or 'unknown'
        return cdn_by_ip

    # ── Findings emission ─────────────────────────────────────

    def _emit_service_findings(self, target: ScanTarget,
                               ips: Dict[str, List[str]],
                               services: Dict[str, List[dict]],
                               cfg: dict) -> None:
        risky_services = {
            'ssh': Severity.LOW,            # exposed SSH = info unless very weird
            'telnet': Severity.HIGH,
            'ftp': Severity.MEDIUM,
            'smtp': Severity.LOW,
            'mysql': Severity.HIGH,
            'mssql': Severity.HIGH,
            'postgresql': Severity.HIGH,
            'redis': Severity.HIGH,
            'mongodb': Severity.HIGH,
            'memcached': Severity.HIGH,
            'elasticsearch': Severity.HIGH,
            'rdp': Severity.MEDIUM,
            'vnc': Severity.HIGH,
            'snmp': Severity.MEDIUM,
        }

        for ip, svc_list in services.items():
            hosts = ips.get(ip, [])
            for svc in svc_list:
                name = (svc.get('name') or '').lower()
                port = svc.get('port')
                sev = risky_services.get(name, Severity.INFO)
                if sev == Severity.INFO and not cfg.get('emit_info_services', False):
                    continue
                banner = ' '.join(filter(None, [
                    svc.get('product'), svc.get('version'), svc.get('extrainfo'),
                ])) or name or '?'
                title = f"{name or 'service'}/{port} exposed — {banner}"[:160]
                self._add_finding(target, Finding(
                    type=FindingType.SERVICE_EXPOSED,
                    target=hosts[0] if hosts else ip,
                    title=title,
                    severity=sev,
                    confidence=0.9,
                    evidence=f"{ip}:{port} {banner}",
                    metadata={
                        'ip': ip, 'port': port, 'service': name,
                        'product': svc.get('product'),
                        'version': svc.get('version'),
                        'hosts': hosts,
                    },
                    tags=['ports', name] if name else ['ports'],
                ))

    def _emit_origin_leak_findings(self, target: ScanTarget,
                                   ips: Dict[str, List[str]],
                                   cdn_by_ip: Dict[str, Optional[str]]) -> None:
        """Flag IPs that are NOT behind CDN but whose hostnames have CDN
        markers at m03 — likely origin leak.

        Heuristic: if any live_host with WAF=cloudflare/akamai/etc OR
        cname pointing to a CDN provider has an A record on a NON-CDN
        IP, we mark that IP as a candidate origin leak.
        """
        cdn_hosts: Set[str] = set()
        for h in target.live_hosts or []:
            if not isinstance(h, dict):
                continue
            waf  = (h.get('waf') or '').lower()
            cname = (h.get('cname') or '').lower()
            if any(k in waf or k in cname for k in (
                'cloudflare', 'akamai', 'fastly', 'cloudfront', 'azure', 'sucuri',
                'incapsula', 'imperva',
            )):
                ip = h.get('ip')
                if ip:
                    cdn_hosts.add(ip)

        for ip in cdn_hosts:
            if cdn_by_ip.get(ip):
                continue  # cdncheck confirms IP is CDN — no leak
            hosts = ips.get(ip, [])
            self._add_finding(target, Finding(
                type=FindingType.ORIGIN_IP_LEAK,
                target=hosts[0] if hosts else ip,
                title=f"Probable origin IP leak: {ip}",
                severity=Severity.MEDIUM,
                confidence=0.55,  # heuristic, FP-prone
                evidence=f"{ip} responds for CDN-marked host(s); cdncheck did not classify it as CDN",
                metadata={'ip': ip, 'hosts': hosts},
                tags=['ports', 'origin-leak'],
            ))
