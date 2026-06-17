"""
Argus V2 — lightweight periodic scheduler (no APScheduler dependency).

Runs inside the dashboard's asyncio loop. When enabled in config it refreshes
the CVE feeds (m15) and re-correlates them against live_hosts (m17) on a fixed
interval, logging the delta of asset↔CVE matches each cycle. The heavy work is
shelled out to the existing, tested CLI scripts in a thread executor so the
event loop is never blocked, and the loop is cancellable on shutdown.

Config (h4wk3y3.yaml):

    scheduler:
      enabled: false              # master switch
      feed_refresh_hours: 24      # interval between CVE refresh cycles
      first_run_delay_sec: 30     # grace period after boot before first run
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path

import sqlalchemy as sa

from core import orm

ROOT = Path(__file__).resolve().parents[1]


class ArgusScheduler:
    def __init__(self, config, db, log):
        self.config = config
        self.db = db
        self.log = log
        sc = config.get("scheduler", default={}) or {}
        self.enabled = bool(sc.get("enabled", False))
        self.feed_hours = float(sc.get("feed_refresh_hours", 24) or 24)
        self.first_delay = float(sc.get("first_run_delay_sec", 30) or 30)
        self._task: asyncio.Task | None = None

    # ── lifecycle ────────────────────────────────────────────────────────
    def start(self) -> None:
        if not self.enabled:
            self.log.info("⏰ scheduler disabled (set scheduler.enabled=true to activate)")
            return
        self._task = asyncio.ensure_future(self._loop())
        self.log.info(
            f"⏰ scheduler started — CVE feed refresh + correlate every {self.feed_hours}h"
        )

    async def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ── loop ─────────────────────────────────────────────────────────────
    async def _loop(self) -> None:
        try:
            await asyncio.sleep(self.first_delay)
            while True:
                try:
                    await self._refresh_cves()
                except Exception as e:           # never let one cycle kill the loop
                    self.log.warning(f"⏰ scheduled cycle failed (continuing): {e}")
                await asyncio.sleep(self.feed_hours * 3600)
        except asyncio.CancelledError:
            self.log.info("⏰ scheduler stopped")
            raise

    async def _refresh_cves(self) -> None:
        loop = asyncio.get_event_loop()
        before = self._match_count()
        self.log.info("⏰ scheduled CVE feed refresh starting…")
        rc1 = await loop.run_in_executor(
            None, self._run_script, "scripts/cve_pull.py", ["--recent-only"])
        rc2 = await loop.run_in_executor(
            None, self._run_script, "scripts/cve_correlate.py", [])
        after = self._match_count()
        delta = after - before
        msg = (f"⏰ CVE refresh done (pull rc={rc1}, correlate rc={rc2}); "
               f"matches {before}→{after}")
        if delta > 0:
            self.log.warning(msg + f"  🚨 {delta} NEW asset↔CVE match(es)")
        else:
            self.log.info(msg)

    # ── helpers ──────────────────────────────────────────────────────────
    def _run_script(self, rel: str, args: list) -> int:
        try:
            r = subprocess.run(
                [sys.executable, str(ROOT / rel), *args],
                cwd=str(ROOT), capture_output=True, text=True, timeout=1800,
            )
            if r.returncode != 0:
                self.log.warning(f"scheduler: {rel} rc={r.returncode}: {r.stderr.strip()[:200]}")
            return r.returncode
        except Exception as e:
            self.log.warning(f"scheduler: {rel} failed: {e}")
            return -1

    def _match_count(self) -> int:
        try:
            t = orm.CVEMatch.__table__
            with self.db.engine.connect() as c:
                return int(c.execute(sa.select(sa.func.count()).select_from(t)).scalar() or 0)
        except Exception:
            return 0
