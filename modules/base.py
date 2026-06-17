"""Argus V2 - Base Module Interface"""

import asyncio
import json
import random
from abc import ABC, abstractmethod
from urllib.parse import urlsplit
from core.config import ArgusConfig
from core.database import ArgusDB
from core.logger import get_logger
from core.models import ScanTarget, Finding


class BaseModule(ABC):
    """All modules inherit from this. Provides common helpers."""

    MODULE_ID   = "mXX"
    MODULE_NAME = "Base Module"

    def __init__(self, config: ArgusConfig, db: ArgusDB, stealth: bool = False):
        self.config  = config
        self.db      = db
        self.stealth = stealth
        self.log     = get_logger(
            self.MODULE_ID,
            level=config.get('general', 'log_level', default='INFO'),
            log_file=config.get('general', 'log_file')
        )

    @abstractmethod
    async def run(self, target: ScanTarget) -> None:
        """Execute the module. Modifies target in-place."""
        ...

    async def _stealth_delay(self, base: float = 0.5, variance: float = 1.0):
        """Random delay for stealth mode."""
        if self.stealth:
            delay = base + random.uniform(0, variance)
            await asyncio.sleep(delay)

    def _add_finding(self, target: ScanTarget, finding: Finding) -> None:
        """Add finding and persist to DB."""
        finding.module_source = self.MODULE_ID
        target.add_finding(finding)
        if target.scan_id:
            self.db.save_finding(finding, target.domain)

    def _save_artefacts(self, target: ScanTarget, kind: str,
                        items: list, key_fields: list) -> int:
        """Persist structured per-item module output to the DB (scan_artefacts).

        The DB counterpart to the legacy ``output/<domain>/<kind>.json`` dumps:
        promotes module detail (js_secrets, takeovers, patterns, …) into a
        single queryable, diff-tracked table so the dashboard reads one source
        of truth. No-op (returns 0) when there's no scan_id (e.g. ad-hoc reruns)
        or nothing to write, so callers can keep their disk write unconditionally
        during the migration.
        """
        if not target.scan_id or not items:
            return 0
        return self.db.upsert_artefacts(
            target.scan_id, target.domain, self.MODULE_ID,
            kind, items, key_fields,
        )

    def _output_dir(self, target: ScanTarget):
        return self.config.output_dir(target.domain)

    def _load_recovered_targets(self, out_dir, target: ScanTarget):
        """Read m11's ``recovered_targets.json`` (hosts + API URLs extracted
        from source maps) and return (in_scope_urls, out_of_scope_count).

        Closes the loop: backends/endpoints the public crawl never reached get
        actively probed by m13/m14. Scope-filtered here (defense-in-depth) so an
        out-of-scope leak — e.g. a raw-IP backend — is counted/logged but never
        scanned. Returns ([], 0) when the file is absent."""
        f = out_dir / "recovered_targets.json"
        if not f.exists():
            return [], 0
        try:
            data = json.loads(f.read_text()) or {}
        except Exception:
            return [], 0
        cands = set(data.get("api_urls") or [])
        for h in (data.get("hosts") or []):
            if h:
                cands.add(h if "://" in h else f"https://{h}")
        scope = getattr(target, "scope", None)
        in_scope, dropped = [], 0
        for u in sorted(cands):
            host = urlsplit(u if "://" in u else f"https://{u}").netloc
            if scope is not None and host and not scope.is_in_scope(host):
                dropped += 1
                self.log.debug(f"   recovered target out-of-scope: {u}")
                continue
            in_scope.append(u)
        return in_scope, dropped

    def _filter_in_scope(self, target: ScanTarget, urls, label: str = "urls"):
        """Filter an iterable of URLs/hosts through target.scope.

        Returns the kept list. Logs the top-3 dropped hosts at INFO level
        when anything was dropped, at DEBUG level when nothing dropped.
        Behaves as identity (no filtering) when scope is missing, so that
        test fixtures or one-shot reruns don't get blocked.
        """
        urls = list(urls)
        scope = getattr(target, "scope", None)
        if scope is None:
            return urls
        kept, drops = scope.filter_urls(urls)
        dropped_total = sum(drops.values())
        if dropped_total:
            top = sorted(drops.items(), key=lambda x: -x[1])[:3]
            top_str = ", ".join(f"{h}×{n}" for h, n in top)
            self.log.info(
                f"   scope: kept {len(kept)}/{len(urls)} {label}, "
                f"dropped {dropped_total} across {len(drops)} hosts (top: {top_str})"
            )
        else:
            self.log.debug(f"   scope: all {len(urls)} {label} in scope")
        return kept
