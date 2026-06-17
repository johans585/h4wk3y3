"""
Argus V2 — Module 10: OSINT

Passive-only intelligence on the target domain BEFORE active subdomain
enumeration. Designed to run in parallel/before m02: depends on
target.domain only.

Capabilities:
  1. WHOIS / RDAP — registrar, dates, nameservers (info-level inventory).
  2. Email auth posture — SPF / DMARC / DKIM record parse → EMAIL_SPOOFABLE.
  3. GitHub org secrets — trufflehog scan (requires GITHUB_TOKEN env +
     osint.github_org config). Skipped silently otherwise.
  4. HIBP domain breach — emails from breach corpora (requires HIBP_API_KEY).

Tools wrapped (all optional):
  - whois          (apt: whois)
  - dnspython      (already in requirements.txt for m02/m03)
  - trufflehog     (apt or go install)
  - aiohttp        (for HIBP API)

Failure model: every capability degrades gracefully. Missing tool / API key
→ warning + skip; the module never aborts the pipeline.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from modules.base import BaseModule
from core.models import ScanTarget, Finding, FindingType, Severity


# ── Helpers ───────────────────────────────────────────────────────────


def _which(bin_name: str) -> Optional[str]:
    return shutil.which(bin_name)


from core.utils import run_cmd as _run_cmd  # noqa: E402


# ── SPF / DMARC / DKIM parsing ─────────────────────────────────────────

_SPF_RE  = re.compile(r'^"?v=spf1\b', re.IGNORECASE)
_DMARC_RE = re.compile(r'\bp=(none|quarantine|reject)\b', re.IGNORECASE)


def _classify_spf(txt: str) -> tuple[Severity, str]:
    """Return (severity, reason)."""
    lower = txt.lower()
    if '-all' in lower:
        return Severity.INFO, 'SPF strict (-all)'
    if '~all' in lower:
        return Severity.LOW, 'SPF soft-fail (~all) — partially spoofable'
    if '?all' in lower:
        return Severity.MEDIUM, 'SPF neutral (?all) — effectively no policy'
    if '+all' in lower:
        return Severity.HIGH, 'SPF permits any sender (+all) — fully spoofable'
    return Severity.MEDIUM, 'SPF record present but no all-mechanism'


def _classify_dmarc(txt: str) -> tuple[Severity, str]:
    m = _DMARC_RE.search(txt)
    if not m:
        return Severity.HIGH, 'DMARC record missing p= policy'
    policy = m.group(1).lower()
    if policy == 'reject':
        return Severity.INFO, 'DMARC p=reject'
    if policy == 'quarantine':
        return Severity.LOW, 'DMARC p=quarantine (acceptable)'
    return Severity.HIGH, 'DMARC p=none — no enforcement, spoofable'


# ── Module ─────────────────────────────────────────────────────────────


class OSINTModule(BaseModule):
    MODULE_ID   = "m01"
    MODULE_NAME = "OSINT"

    async def run(self, target: ScanTarget) -> None:
        cfg = self.config.get('osint', default={}) or {}
        if not cfg.get('enabled', True):
            self.log.info("m01 disabled in config — skipping")
            return

        out_dir = self._output_dir(target)
        results: Dict[str, Any] = {
            'domain': target.domain,
            'started_at': datetime.now(timezone.utc).isoformat(),
        }

        # ── 1. WHOIS ────────────────────────────────────────────
        if cfg.get('whois', True):
            results['whois'] = await self._whois(target)

        # ── 2. Email auth posture ───────────────────────────────
        if cfg.get('email_auth', True):
            results['email_auth'] = await self._email_auth(target, cfg)

        # ── 3. GitHub org secrets ───────────────────────────────
        gh_org = cfg.get('github_org')
        gh_token = os.environ.get('GITHUB_TOKEN') or cfg.get('github_token')
        if gh_org and gh_token and cfg.get('github_secrets', True):
            results['github_secrets'] = await self._trufflehog_github(
                target, gh_org, gh_token, cfg
            )
        elif cfg.get('github_secrets', True):
            self.log.info("github secrets skipped (need osint.github_org + GITHUB_TOKEN)")

        # ── 4. HIBP domain breach ───────────────────────────────
        hibp_key = os.environ.get('HIBP_API_KEY') or cfg.get('hibp_api_key')
        if hibp_key and cfg.get('hibp', True):
            results['hibp'] = await self._hibp(target, hibp_key)
        elif cfg.get('hibp', True):
            self.log.info("HIBP skipped (set HIBP_API_KEY)")

        results['finished_at'] = datetime.now(timezone.utc).isoformat()
        try:
            (out_dir / 'osint.json').write_text(json.dumps(results, indent=2, default=str))
        except Exception as e:
            self.log.warning(f"osint.json write failed: {e}")

    # ── 1. WHOIS ────────────────────────────────────────────────

    async def _whois(self, target: ScanTarget) -> dict:
        if not _which('whois'):
            self.log.info("whois binary missing — skipping (apt install whois)")
            return {'available': False}

        rc, out, err = await _run_cmd(['whois', target.domain], timeout=30)
        if rc != 0:
            return {'available': True, 'error': err.strip() or 'whois failed'}

        parsed = self._parse_whois(out)
        # Emit DOMAIN_INFO at INFO severity — inventory, not a vuln.
        if parsed.get('registrar') or parsed.get('created'):
            self._add_finding(target, Finding(
                type=FindingType.DOMAIN_INFO,
                target=target.domain,
                title=f"WHOIS: {parsed.get('registrar', 'unknown registrar')}",
                severity=Severity.INFO,
                confidence=0.9,
                evidence=json.dumps(parsed, default=str)[:500],
                metadata=parsed,
                tags=['osint', 'whois'],
            ))
        return parsed

    @staticmethod
    def _parse_whois(raw: str) -> dict:
        """Best-effort flat parse — registries return wildly different formats."""
        fields = {
            'registrar': [r'^\s*Registrar:\s*(.+)$'],
            'created':   [r'^\s*Creation Date:\s*(.+)$', r'^\s*created:\s*(.+)$'],
            'expires':   [r'^\s*Registry Expiry Date:\s*(.+)$', r'^\s*Expir(?:y|ation) Date:\s*(.+)$'],
            'updated':   [r'^\s*Updated Date:\s*(.+)$'],
            'status':    [r'^\s*Domain Status:\s*(.+)$'],
        }
        out: dict = {}
        for k, patterns in fields.items():
            for pat in patterns:
                m = re.search(pat, raw, re.IGNORECASE | re.MULTILINE)
                if m:
                    out[k] = m.group(1).strip()
                    break
        # Nameservers — multi-line
        ns = re.findall(r'^\s*Name Server:\s*(.+)$', raw, re.IGNORECASE | re.MULTILINE)
        if ns:
            out['nameservers'] = sorted({n.strip().lower() for n in ns})
        return out

    # ── 2. Email auth posture ───────────────────────────────────

    async def _email_auth(self, target: ScanTarget, cfg: dict) -> dict:
        """Lookup SPF (TXT @ apex), DMARC (TXT @ _dmarc), DKIM selectors."""
        try:
            import dns.asyncresolver
            import dns.resolver
        except ImportError:
            self.log.warning("dnspython missing — install dnspython>=2.4.0")
            return {'available': False}

        resolver = dns.asyncresolver.Resolver()
        # Prefer public resolvers — local resolv.conf may have split-horizon
        # views that hide DMARC records — but fall back to the system resolver
        # when public DNS is unreachable (VPN kill-switch / filtered egress),
        # otherwise SPF/DMARC checks fail wholesale. See dns_resolver.default_nameservers.
        from core.dns_resolver import default_nameservers
        ns = cfg.get('dns_nameservers') or default_nameservers()
        resolver.nameservers = ns
        resolver.lifetime = 8

        result: dict = {}

        # SPF (looked up at apex)
        spf_ok, spf_txts = await self._txt(resolver, target.domain)
        spf = next((t for t in spf_txts if _SPF_RE.match(t)), None)
        if spf:
            sev, reason = _classify_spf(spf)
            result['spf'] = {'value': spf, 'severity': sev.value, 'reason': reason}
            if sev != Severity.INFO:
                self._add_finding(target, Finding(
                    type=FindingType.EMAIL_SPOOFABLE,
                    target=target.domain,
                    title=f"SPF weak: {reason}",
                    severity=sev,
                    confidence=0.95,
                    evidence=spf[:300],
                    metadata={'record': 'SPF', 'value': spf},
                    tags=['osint', 'spf'],
                ))
        elif not spf_ok:
            # DNS lookup failed — cannot conclude the record is absent. Do NOT
            # emit a "missing → spoofable HIGH" finding (false positive on
            # egress-DNS failure). m02 emits the INFO "unverified" finding.
            result['spf'] = {'value': None, 'severity': Severity.INFO.value,
                             'reason': 'unverified — SPF DNS lookup failed'}
        else:
            result['spf'] = {'value': None, 'severity': Severity.HIGH.value, 'reason': 'SPF missing'}
            self._add_finding(target, Finding(
                type=FindingType.EMAIL_SPOOFABLE,
                target=target.domain,
                title="SPF record missing",
                severity=Severity.HIGH,
                confidence=0.95,
                evidence='no TXT record matching v=spf1 at apex',
                metadata={'record': 'SPF'},
                tags=['osint', 'spf'],
            ))

        # DMARC (looked up at _dmarc.<domain>)
        dmarc_ok, dmarc_txts = await self._txt(resolver, f"_dmarc.{target.domain}")
        dmarc = next((t for t in dmarc_txts if 'dmarc1' in t.lower()), None)
        if dmarc:
            sev, reason = _classify_dmarc(dmarc)
            result['dmarc'] = {'value': dmarc, 'severity': sev.value, 'reason': reason}
            if sev != Severity.INFO:
                self._add_finding(target, Finding(
                    type=FindingType.EMAIL_SPOOFABLE,
                    target=target.domain,
                    title=f"DMARC weak: {reason}",
                    severity=sev,
                    confidence=0.95,
                    evidence=dmarc[:300],
                    metadata={'record': 'DMARC', 'value': dmarc},
                    tags=['osint', 'dmarc'],
                ))
        elif not dmarc_ok:
            # DNS lookup failed — presence unknown, no FP HIGH (see SPF above).
            result['dmarc'] = {'value': None, 'severity': Severity.INFO.value,
                               'reason': 'unverified — DMARC DNS lookup failed'}
        else:
            result['dmarc'] = {'value': None, 'severity': Severity.HIGH.value, 'reason': 'DMARC missing'}
            self._add_finding(target, Finding(
                type=FindingType.EMAIL_SPOOFABLE,
                target=target.domain,
                title="DMARC record missing",
                severity=Severity.HIGH,
                confidence=0.95,
                evidence=f'no TXT record at _dmarc.{target.domain}',
                metadata={'record': 'DMARC'},
                tags=['osint', 'dmarc'],
            ))

        # DKIM — selectors are arbitrary, we probe a few common ones.
        selectors = cfg.get('dkim_selectors') or [
            'default', 'google', 'k1', 'mail', 'selector1', 'selector2', 's1',
        ]
        dkim_found = []
        dkim_any_resolved = False
        for sel in selectors:
            ok, txts = await self._txt(resolver, f"{sel}._domainkey.{target.domain}")
            if ok:
                dkim_any_resolved = True
            for t in txts:
                if 'v=dkim1' in t.lower() or 'k=rsa' in t.lower() or 'p=' in t.lower():
                    dkim_found.append({'selector': sel, 'value': t[:200]})
                    break
        result['dkim'] = {'selectors_checked': selectors, 'found': dkim_found}
        # Only report "no DKIM" when at least one selector actually resolved;
        # if every lookup failed (egress DNS down) presence is unknown → no FP.
        if not dkim_found and dkim_any_resolved:
            self._add_finding(target, Finding(
                type=FindingType.EMAIL_SPOOFABLE,
                target=target.domain,
                title="DKIM: no record found on common selectors",
                severity=Severity.MEDIUM,
                confidence=0.6,  # selectors are user-defined, false-negative-prone
                evidence=f"checked: {', '.join(selectors)}",
                metadata={'record': 'DKIM', 'selectors_tried': selectors},
                tags=['osint', 'dkim'],
            ))

        return result

    @staticmethod
    async def _txt(resolver, name: str) -> Tuple[bool, List[str]]:
        """Resolve TXT records. Returns ``(resolved, [values])``.

        ``resolved`` distinguishes the two empty-list cases the caller MUST
        treat differently:
          - ``True, []``  → the lookup succeeded but the record is genuinely
            absent (NoAnswer / NXDOMAIN) — safe to report "missing".
          - ``False, []`` → the lookup itself failed (timeout / SERVFAIL / no
            nameservers / egress blocked). The record's presence is UNKNOWN —
            reporting "missing → spoofable HIGH" here is a false positive
            (this exact bug fired on egress-DNS failure).
        """
        import dns.resolver as _dns_resolver
        try:
            ans = await resolver.resolve(name, 'TXT')
        except (_dns_resolver.NoAnswer, _dns_resolver.NXDOMAIN):
            return True, []      # resolved, record genuinely absent
        except Exception:
            return False, []     # lookup failed — presence unknown
        out: List[str] = []
        for r in ans:
            try:
                parts = [b.decode(errors='replace') if isinstance(b, bytes) else str(b)
                         for b in r.strings]
                out.append(''.join(parts))
            except Exception:
                out.append(str(r))
        return True, out

    # ── 3. trufflehog GitHub ────────────────────────────────────

    async def _trufflehog_github(self, target: ScanTarget, org: str,
                                 token: str, cfg: dict) -> dict:
        if not _which('trufflehog'):
            self.log.info("trufflehog binary missing — skipping GitHub scan")
            return {'available': False}

        timeout = int(cfg.get('github_timeout_sec', 600))
        cmd = ['trufflehog', 'github',
               f'--org={org}',
               f'--token={token}',
               '--only-verified', '--json', '--no-update']

        self.log.info(f"trufflehog github org={org} (verified-only, timeout {timeout}s)")
        rc, out, err = await _run_cmd(cmd, timeout=timeout)
        if rc < 0:
            return {'available': True, 'error': err.strip()}

        secrets = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            detector = rec.get('DetectorName') or rec.get('detector_name', 'unknown')
            src = rec.get('SourceMetadata', {}).get('Data', {}).get('Github', {})
            repo = src.get('repository') or rec.get('repo', 'unknown')
            file = src.get('file', '?')
            line_no = src.get('line', 0)
            secrets.append({
                'detector': detector, 'repo': repo,
                'file': file, 'line': line_no,
            })
            self._add_finding(target, Finding(
                type=FindingType.GIT_SECRET,
                target=target.domain,
                title=f"GitHub leaked secret ({detector}) in {repo}:{file}",
                severity=Severity.HIGH,
                confidence=0.95,  # trufflehog --only-verified = live secret
                url=f"https://github.com/{repo}/blob/HEAD/{file}#L{line_no}" if repo != 'unknown' else None,
                evidence=f"detector={detector} repo={repo} file={file} line={line_no}",
                metadata={'detector': detector, 'repo': repo, 'file': file, 'line': line_no},
                tags=['osint', 'github', 'verified'],
            ))
        return {'available': True, 'org': org, 'verified_secrets': len(secrets), 'samples': secrets[:10]}

    # ── 4. HIBP domain breaches ──────────────────────────────────

    async def _hibp(self, target: ScanTarget, api_key: str) -> dict:
        try:
            import aiohttp
        except ImportError:
            return {'available': False, 'error': 'aiohttp missing'}

        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{target.domain}"
        headers = {
            'hibp-api-key': api_key,
            'user-agent': 'Argus-V2-OSINT',
        }
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url, headers=headers, timeout=20) as r:
                    if r.status == 404:
                        return {'available': True, 'breaches': []}
                    if r.status == 401:
                        self.log.warning("HIBP: 401 — API key invalid")
                        return {'available': True, 'error': 'invalid api key'}
                    if r.status != 200:
                        return {'available': True, 'error': f'HTTP {r.status}'}
                    data = await r.json()
        except Exception as e:
            return {'available': True, 'error': str(e)}

        # data is {email_local_part: [breach_name, ...]}
        breach_total = sum(len(b) for b in (data or {}).values())
        if breach_total:
            self._add_finding(target, Finding(
                type=FindingType.BREACHED_CREDENTIAL,
                target=target.domain,
                title=f"HIBP: {len(data)} emails in {breach_total} breaches",
                severity=Severity.HIGH,
                confidence=0.95,
                evidence=f"{len(data)} unique mailboxes affected",
                metadata={'emails_affected': len(data), 'breach_count': breach_total},
                tags=['osint', 'hibp'],
            ))
        return {'available': True, 'emails_affected': len(data or {}), 'breach_count': breach_total}
