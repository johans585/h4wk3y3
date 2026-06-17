"""
Argus V2 — Module 12: TLS Audit

Wraps testssl.sh to audit each HTTPS live host. Runs in parallel with m13
(both network-bound, no shared state).

Capabilities (per host):
  - Protocol coverage (SSLv2/3, TLS 1.0/1.1 — all considered weak today)
  - Weak/insecure ciphers (RC4, 3DES, EXPORT, NULL, MD5 MAC, anonymous)
  - Certificate posture: expired, expiring <30d, self-signed, weak key,
    hostname mismatch
  - HSTS missing / weak

testssl.sh is slow (~2 min/host). We cap to N hosts (default 10),
pick a representative sample (apex + a few subs by hostname length).

Failure model:
  - testssl.sh binary missing → warning + emit a single INFO finding
    pointing at the install command, then skip.
  - per-host timeout → log + skip that host, continue with next.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, Severity


def _which(b: str) -> Optional[str]:
    return shutil.which(b)


from core.utils import run_cmd as _run_cmd  # noqa: E402


_TESTSSL_SEV = {
    'CRITICAL': Severity.CRITICAL,
    'HIGH':     Severity.HIGH,
    'MEDIUM':   Severity.MEDIUM,
    'LOW':      Severity.LOW,
    'WARN':     Severity.LOW,
    'INFO':     Severity.INFO,
    'OK':       Severity.INFO,
}


class TLSModule(BaseModule):
    MODULE_ID   = "m08"
    MODULE_NAME = "TLS Audit"

    async def run(self, target: ScanTarget) -> None:
        cfg = self.config.get('tls', default={}) or {}
        if not cfg.get('enabled', True):
            self.log.info("m08 disabled in config — skipping")
            return

        # testssl.sh is loud (full cipher enumeration, dozens of connections
        # per host). Respect the global stealth flag: skip entirely unless
        # the operator opted in to run it under stealth via config.
        if self.stealth and not cfg.get('run_under_stealth', False):
            self.log.info(
                "m08 skipped — stealth mode, testssl.sh is too noisy. "
                "Set tls.run_under_stealth=true in h4wk3y3.yaml to override."
            )
            return

        # Collect unique HTTPS endpoints from live_hosts.
        hosts = self._pick_https_hosts(target, cfg)
        if not hosts:
            self.log.info("no HTTPS live hosts — skipping TLS audit")
            return

        bin_path = _which('testssl.sh') or _which('testssl')
        if not bin_path:
            self.log.warning("testssl.sh missing — apt install testssl.sh (or git clone). Skipping TLS audit.")
            return

        out_dir = self._output_dir(target)
        report_dir = out_dir / 'tls'
        report_dir.mkdir(parents=True, exist_ok=True)

        per_host: Dict[str, Any] = {}
        concurrency = int(cfg.get('concurrency', 2))  # testssl is heavy
        sem = asyncio.Semaphore(concurrency)
        timeout = int(cfg.get('per_host_timeout_sec', 300))

        async def _audit(host: str) -> None:
            async with sem:
                rec = await self._testssl_one(bin_path, host, report_dir, timeout)
                per_host[host] = rec
                if rec.get('findings'):
                    self._emit_findings(target, host, rec['findings'])

        self.log.info(f"testssl.sh on {len(hosts)} host(s), concurrency={concurrency}")
        await asyncio.gather(*(_audit(h) for h in hosts))

        summary = {
            'started_at': datetime.now(timezone.utc).isoformat(),
            'hosts_audited': len(per_host),
            'per_host': {h: {'findings': len(r.get('findings', []))} for h, r in per_host.items()},
        }
        try:
            (out_dir / 'tls_summary.json').write_text(json.dumps(summary, indent=2, default=str))
        except Exception as e:
            self.log.warning(f"tls_summary.json write failed: {e}")

    # ── Host selection ─────────────────────────────────────────

    def _pick_https_hosts(self, target: ScanTarget, cfg: dict) -> List[str]:
        cap = int(cfg.get('max_hosts', 10))
        candidates: List[str] = []
        seen: set = set()
        scope_drops = 0
        for h in target.live_hosts or []:
            if not isinstance(h, dict):
                continue
            url = h.get('url') or ''
            if not url.startswith('https://'):
                continue
            try:
                netloc = urlparse(url).netloc
            except Exception:
                continue
            if not netloc or netloc in seen:
                continue
            # Scope check — never audit TLS on a host the operator has not
            # cleared. m02/m03 should have filtered already; belt-and-braces.
            if target.scope is not None and not target.scope.is_in_scope(netloc):
                scope_drops += 1
                continue
            seen.add(netloc)
            candidates.append(netloc)
        if scope_drops:
            self.log.info(f"   🛡 scope filter: −{scope_drops} HTTPS hosts dropped before testssl")

        # Prefer apex first, then shortest hostnames (more "interesting" usually).
        apex = target.domain
        candidates.sort(key=lambda n: (0 if n == apex else 1, len(n)))
        return candidates[:cap]

    # ── Single host audit ──────────────────────────────────────

    async def _testssl_one(self, bin_path: str, host: str,
                           report_dir: Path, timeout: int) -> dict:
        out_json = report_dir / f"{host.replace(':', '_')}.json"
        cmd = [
            bin_path,
            '--quiet', '--color', '0',
            '--severity', 'LOW',     # threshold (testssl reports >=LOW)
            '--jsonfile-pretty', str(out_json),
            host,
        ]
        rc, _, err = await _run_cmd(cmd, timeout=timeout)
        if rc < 0:
            self.log.warning(f"testssl {host}: {err.strip()[:200]}")
            return {'available': True, 'host': host, 'error': err.strip(), 'findings': []}

        try:
            data = json.loads(out_json.read_text())
        except Exception as e:
            return {'available': True, 'host': host, 'error': f'parse: {e}', 'findings': []}

        # testssl JSON shape: a top-level list of {id, ip, port, severity, finding, ...}
        # (older versions wrap it in {"scanResult": [...]}).
        items = data if isinstance(data, list) else (data.get('scanResult') or [])
        if isinstance(items, list) and items and isinstance(items[0], dict) and 'serverDefaults' in items[0]:
            # Newer testssl shape: list of scanResult objects with sub-sections.
            flat: List[dict] = []
            for entry in items:
                for section_key in (
                    'serverDefaults', 'protocols', 'cipherOrder', 'cipherTests',
                    'ciphers', 'cipher_order', 'fs', 'vulnerabilities', 'headerResponse',
                    'pretest', 'grease', 'rating',
                ):
                    sec = entry.get(section_key) or []
                    if isinstance(sec, list):
                        flat.extend(sec)
            items = flat

        # Filter to the things we care about + classify.
        findings = self._classify_testssl(items)
        return {'available': True, 'host': host, 'findings': findings,
                'raw_count': len(items)}

    @staticmethod
    def _classify_testssl(items: List[dict]) -> List[dict]:
        """Pick relevant rows + map testssl severity → our enum."""
        out: List[dict] = []
        for it in items or []:
            if not isinstance(it, dict):
                continue
            sev_raw = (it.get('severity') or '').upper()
            sev = _TESTSSL_SEV.get(sev_raw, Severity.INFO)
            if sev == Severity.INFO:
                continue  # drop noise
            tid = it.get('id') or it.get('test') or 'unknown'
            finding_msg = it.get('finding') or it.get('cve') or ''
            kind = 'TLS_WEAK'
            tid_lower = tid.lower()
            if 'cert' in tid_lower or 'expiration' in tid_lower or 'chain' in tid_lower:
                kind = 'TLS_CERT_ISSUE'
            elif 'hsts' in tid_lower:
                kind = 'HSTS'
            out.append({
                'id':       tid,
                'kind':     kind,
                'severity': sev.value,
                'message':  finding_msg[:300],
                'cve':      it.get('cve'),
            })
        return out

    # ── Findings emission ──────────────────────────────────────

    def _emit_findings(self, target: ScanTarget, host: str, items: List[dict]) -> None:
        for it in items:
            sev = Severity(it.get('severity', 'low'))
            kind = it.get('kind', 'TLS_WEAK')
            if kind == 'TLS_CERT_ISSUE':
                ftype = FindingType.TLS_CERT_ISSUE
                tags = ['tls', 'certificate']
            elif kind == 'HSTS':
                ftype = FindingType.MISCONFIGURATION
                tags = ['tls', 'hsts']
            else:
                ftype = FindingType.TLS_WEAK
                tags = ['tls']

            cve = it.get('cve')
            if cve:
                tags.append('cve')

            self._add_finding(target, Finding(
                type=ftype,
                target=host,
                url=f"https://{host}",
                title=f"TLS: {it.get('id', 'issue')} — {it.get('message', '')[:120]}",
                severity=sev,
                confidence=0.9,
                evidence=it.get('message', '')[:500],
                metadata={'test_id': it.get('id'), 'cve': cve},
                tags=tags,
            ))
