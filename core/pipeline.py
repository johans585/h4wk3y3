"""
Argus V2 - Pipeline Orchestrator
Manages module execution order, parallelism, and state passing.
"""

import asyncio
import time
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timezone
from core.config import ArgusConfig
from core.database import ArgusDB
from core.logger import get_logger
from core.models import ScanTarget
from core.notifier import Notifier
from core.scope import (
    ScopeYamlError,
    build_scope_for_target,
    find_scope_file,
    load_scope_yaml,
)


class Pipeline:
    """
    Orchestrates the 14-module reconnaissance pipeline.

    Execution order (see STAGES below for the real graph):
        pre-stage  : m01 (osint) || m02 (subdomain)
        stage 1    : m03 (http validator + tech)
        stage 2    : m04 (urls) || m05 (screenshot) || m06 (takeover) ||
                     m07 (ports) || m08 (tls) || m09 (quick checks)
        stage 3    : m10 (body fetcher)
        stage 4    : m11 (js analyzer)
        stage 5    : m12 (pattern) || m13 (nuclei)
        stage 6    : m14 (active validation)
    """

    # Listed in numeric order — the actual orchestration uses STAGES, not
    # the position in this list. Keep numeric for readability.
    MODULE_ORDER = [
        ('m01', 'modules.m01_osint',          'OSINTModule'),
        ('m02', 'modules.m02_subdomain',      'SubdomainModule'),
        ('m03', 'modules.m03_http_validator', 'HTTPValidatorModule'),
        ('m04', 'modules.m04_url_collector',  'URLCollectorModule'),
        ('m05', 'modules.m05_screenshot',     'ScreenshotModule'),
        ('m06', 'modules.m06_takeover',       'TakeoverModule'),
        ('m07', 'modules.m07_ports',          'PortsModule'),
        ('m08', 'modules.m08_tls',            'TLSModule'),
        ('m09', 'modules.m09_quick_checks',   'QuickChecksModule'),
        ('m10', 'modules.m10_fetcher',        'FastFetcherModule'),
        ('m11', 'modules.m11_js_analyzer',    'JSAnalyzerModule'),
        ('m12', 'modules.m12_pattern',        'PatternModule'),
        ('m13', 'modules.m13_nuclei',         'NucleiModule'),
        ('m14', 'modules.m14_active',         'ActiveValidationModule'),
    ]

    # Stages: each entry is either a module ID (sequential) or a tuple
    # of module IDs to run concurrently. Dependencies must be respected:
    #   - m01 needs nothing (target.domain) → runs in pre-stage with m02
    #   - m03 needs m02 (subs)
    #   - m10/m04/m05/m06/m07/m08 all consume target.live_hosts (m03 output)
    #     → can run in parallel
    #   - m11 needs m10 (bodies)
    #   - m12 needs m10 + m04
    #   - m13 needs m03 (live_hosts/tech)
    #   - m14 needs m12 + m13
    STAGES = (
        'm03',
        ('m04', 'm05', 'm06', 'm07', 'm08', 'm09'),  # parallel — all post-m03 readers
        'm10',                                       # post-m04 (may use m04 URLs)
        'm11',                                        # post-m10 (bodies)
        ('m12', 'm13'),                               # parallel : m12 file-IO, m13 network
        'm14',
    )

    def __init__(self, config: ArgusConfig, db: ArgusDB):
        self.config = config
        self.db     = db
        self.log    = get_logger('pipeline',
                                 level=config.get('general', 'log_level', default='INFO'),
                                 log_file=config.get('general', 'log_file'))

    @classmethod
    def _staged_ids(cls) -> set:
        """Module IDs that are dispatched by the STAGES loop. Anything not
        in this set runs in the pre-stage pass (today: m02 only)."""
        ids = set()
        for stage in cls.STAGES:
            if isinstance(stage, str):
                ids.add(stage)
            else:
                ids.update(stage)
        return ids

    async def run(
        self,
        target: ScanTarget,
        modules: Optional[List[str]] = None,
        stealth: bool = False
    ) -> ScanTarget:
        """
        Run the full pipeline (or a subset) on the given target.
        Args:
            target:  ScanTarget to populate
            modules: List of module IDs to run (None = all enabled)
            stealth: Enable rate-limiting & random delays
        """
        partial = modules is not None  # subset run — don't wipe previous state

        self.log.info(
            f"{'🔧 Module run' if partial else '🚀 Starting scan'} — "
            f"target: {target.domain} | scan_id: {target.scan_id}"
        )

        # ── Attach Scope (authoritative in-scope check) ─────────
        # Précédence (Étapes 2.1 multi-org + 2.2 scope-as-code) :
        #   1. targets.scope_file_override (target row, par apex)
        #   2. organisations.scope_file (via target → org)
        #   3. config.general.scope_file (override global)
        #   4. scopes/<apex>.yaml (auto-discovery)
        #   5. wildcards plat (legacy)
        # Downstream modules MUST consult target.scope.filter_urls() before
        # pushing URLs/hosts further in the pipeline (see core/scope.py).
        if target.scope is None:
            project_root = Path(__file__).resolve().parents[1]
            apex         = target.domain
            scope_path   = None
            source_label = None  # for logging: "target", "org:<name>", "config", "auto"

            # 1. Per-target override
            try:
                from core.organisation import get_target, organisation_for_target
                target_row = get_target(self.db, apex)
            except Exception:
                target_row = None
            if target_row and target_row.get("scope_file_override"):
                p = Path(target_row["scope_file_override"])
                scope_path = p if p.is_absolute() else (project_root / p)
                source_label = "target-override"

            # 2. Organisation default
            if scope_path is None:
                try:
                    org_row = organisation_for_target(self.db, apex)
                except Exception:
                    org_row = None
                if org_row and org_row.get("scope_file"):
                    p = Path(org_row["scope_file"])
                    scope_path = p if p.is_absolute() else (project_root / p)
                    source_label = f"org:{org_row['name']}"

            # 3. Global config override
            if scope_path is None:
                cfg_scope = self.config.get("general", "scope_file", default=None)
                if cfg_scope:
                    p = Path(cfg_scope)
                    scope_path = p if p.is_absolute() else (project_root / p)
                    source_label = "config"

            # 4. Auto-discovery scopes/<apex>.yaml
            if scope_path is None:
                scope_path = find_scope_file(apex, project_root / "scopes")
                if scope_path:
                    source_label = "auto"

            if scope_path and scope_path.exists():
                try:
                    target.scope = load_scope_yaml(scope_path, apex_override=apex)
                    self.log.info(
                        f"🛡 scope: source=yaml [{source_label}] ({scope_path.name}) "
                        f"org={target.scope.organisation} apex={target.scope.apex} "
                        f"+{len(target.scope.extra_in_scope)} extra "
                        f"−{len(target.scope.out_of_scope)} excl "
                        f"{len(target.scope.restrictions)} restr"
                    )
                except ScopeYamlError as e:
                    self.log.warning(
                        f"⚠ scope: failed to load {scope_path} ({e}); "
                        f"falling back to wildcards file"
                    )
                    target.scope = None

            if target.scope is None:
                wildcards_path = project_root / "wildcards"
                target.scope = build_scope_for_target(
                    apex=apex,
                    wildcards_path=wildcards_path,
                    out_of_scope=self.config.get("general", "out_of_scope", default=[]) or [],
                )
                self.log.info(
                    f"🛡 scope: source=wildcards apex={target.scope.apex} "
                    f"+{len(target.scope.extra_in_scope)} extra "
                    f"−{len(target.scope.out_of_scope)} excl"
                )

        # Nettoie les scans "running" bloqués pour ce domaine
        try:
            import sqlalchemy as sa
            from core import orm
            t = orm.Scan.__table__
            with self.db.engine.begin() as c:
                c.execute(sa.update(t)
                            .where(t.c.domain == target.domain)
                            .where(t.c.status == "running")
                            .values(status="abandoned"))
        except Exception:
            pass

        if partial:
            # Restore state from previous scan output so modules have their dependencies
            self._restore_state(target)
            self.log.info(
                f"   State restored: {len(target.subdomains)} subs, "
                f"{len(target.live_hosts)} hosts, {len(target.urls)} URLs"
            )
        else:
            # Full scan — archive previous and start fresh
            self._archive_previous(target.domain)

        self.db.create_scan(target.scan_id, target.domain)
        # Register the apex as a target so it shows up in the dashboard
        # (Targets / Attack-Surface / Orgs) and so post-scan attribution has
        # an apex to resolve against. No-op if already imported/linked.
        self.db.ensure_target(target.domain)

        start = time.time()
        interrupted = False

        # Everything from here to the finalize block is wrapped so the scan is
        # ALWAYS closed out — even on exception, Ctrl-C or asyncio cancellation
        # (per-module timeout escalation, outer wait_for). Without this, an
        # interrupted scan stayed stuck on status='running' with NULL stats and
        # NULL attribution, which broke /api/scans and every org-scoped view.
        try:
            # Filter which modules to run
            to_run = self._select_modules(modules)

            # Pre-stage pass: modules without dependencies in STAGES (today
            # m01 OSINT + m02 subdomain). They consume `target.domain` only,
            # so we gather() them in parallel — m01 ~30-60s of WHOIS/DKIM was
            # previously hidden behind sequential m02.
            # Set is derived from STAGES so the two never drift.
            staged = self._staged_ids()
            pre_stage = [
                (mid, mod_path, cls_name)
                for mid, mod_path, cls_name in to_run if mid not in staged
            ]
            if pre_stage:
                if len(pre_stage) == 1:
                    mid, mod_path, cls_name = pre_stage[0]
                    await self._run_module(mid, mod_path, cls_name, target, stealth)
                else:
                    self.log.info(
                        f"⚡ Pre-stage parallel: {', '.join(m[0] for m in pre_stage)}"
                    )
                    await asyncio.gather(*(
                        self._run_module(mid, mod_path, cls_name, target, stealth)
                        for mid, mod_path, cls_name in pre_stage
                    ), return_exceptions=False)

            # ── Pipeline staged: dépendances respectées ──────────
            # Each stage entry is either a single module ID (sequential) or
            # a tuple of IDs to gather() concurrently. See class STAGES doc.
            for stage in self.STAGES:
                stage_ids = (stage,) if isinstance(stage, str) else tuple(stage)
                modules_in_stage = [
                    (mid, mod_path, cls_name)
                    for mid, mod_path, cls_name in to_run
                    if mid in stage_ids
                ]
                if not modules_in_stage:
                    continue
                if len(modules_in_stage) == 1:
                    mid, mod_path, cls_name = modules_in_stage[0]
                    await self._run_module(mid, mod_path, cls_name, target, stealth)
                else:
                    # Parallel group: gather all enabled modules of this stage.
                    self.log.info(
                        f"⚡ Parallel stage: {', '.join(m[0] for m in modules_in_stage)}"
                    )
                    await asyncio.gather(*(
                        self._run_module(mid, mod_path, cls_name, target, stealth)
                        for mid, mod_path, cls_name in modules_in_stage
                    ), return_exceptions=False)
        except (asyncio.CancelledError, KeyboardInterrupt):
            interrupted = True
            self.log.warning("⚠  scan interrupted — finalizing partial results")
            raise
        except Exception as e:
            interrupted = True
            self.log.error(f"❌ scan aborted by error ({e}) — finalizing partial results")
            raise
        finally:
            # ── Attribution post-scan (best-effort) ──────────────
            # Rattache chaque subdomain/live_host/finding du scan courant au
            # `targets.apex` le plus spécifique (longest-suffix). Crucial pour
            # les scans de shared apex (gouv.bj couvre 29 ministères). Runs in
            # the finally so even an interrupted scan attributes what it gathered
            # (subs/hosts already carry a fallback apex from their upsert).
            try:
                attr_stats = self._attribute_assets(target.scan_id)
                self.log.info(
                    f"🎯 attribution: {attr_stats['subs']} subs · "
                    f"{attr_stats['hosts']} hosts · {attr_stats['findings']} findings "
                    f"→ {attr_stats['orgs']} org(s) · {attr_stats['orphans']} orphan(s)"
                )
            except Exception as e:
                self.log.warning(f"⚠  attribution refinement failed (non-fatal): {e}")

            # ── Finalise (ALWAYS — clean finish or interrupted) ──
            elapsed = round(time.time() - start, 1)
            target.finished_at = datetime.now(timezone.utc).isoformat()
            stats = target.summary()
            stats['elapsed_seconds'] = elapsed
            stats['interrupted'] = interrupted
            self.db.finish_scan(
                target.scan_id, stats,
                status=("partial" if interrupted else "done"),
            )
            self._print_summary(target, elapsed)
            self._save_output(target, partial=(partial or interrupted))

        return target

    def _attribute_assets(self, scan_id: str) -> dict:
        """Hook post-scan : rattache subs/hosts/findings du scan au
        `targets.apex` le plus spécifique via longest-suffix match.

        Returns stats dict: {subs, hosts, findings, orgs, orphans}.
        """
        import sqlalchemy as sa
        from core.attribution import (
            resolve_apex, load_apexes_sorted, extract_host_from_url,
        )
        from core import orm

        apexes = load_apexes_sorted(self.db)
        if not apexes:
            return {"subs": 0, "hosts": 0, "findings": 0, "orgs": 0, "orphans": 0}

        subs_t  = orm.Subdomain.__table__
        lh_t    = orm.LiveHost.__table__
        find_t  = orm.Finding.__table__

        attributed_set: set[str] = set()
        orphans  = 0
        counts   = {"subs": 0, "hosts": 0, "findings": 0}

        with self.db.engine.begin() as c:
            # 1. Subdomains du scan courant
            rows = c.execute(
                sa.select(subs_t.c.id, subs_t.c.subdomain)
                  .where(subs_t.c.scan_id == scan_id)
            ).fetchall()
            for sid, sub in rows:
                attr = resolve_apex(sub, apexes)
                c.execute(
                    sa.update(subs_t).where(subs_t.c.id == sid)
                      .values(attributed_apex=attr)
                )
                counts["subs"] += 1
                if attr is None: orphans += 1
                else:            attributed_set.add(attr)

            # 2. Live hosts du scan courant (domain = full hostname déjà)
            rows = c.execute(
                sa.select(lh_t.c.id, lh_t.c.domain)
                  .where(lh_t.c.scan_id == scan_id)
            ).fetchall()
            for lid, host in rows:
                attr = resolve_apex(host, apexes)
                c.execute(
                    sa.update(lh_t).where(lh_t.c.id == lid)
                      .values(attributed_apex=attr)
                )
                counts["hosts"] += 1
                if attr is None: orphans += 1
                else:            attributed_set.add(attr)

            # 3. Findings du scan courant : essai d'attribution via finding.url,
            #    sinon fallback sur finding.domain (apex du scan).
            rows = c.execute(
                sa.select(find_t.c.id, find_t.c.url, find_t.c.domain)
                  .where(find_t.c.scan_id == scan_id)
            ).fetchall()
            for fid, furl, fdomain in rows:
                host = extract_host_from_url(furl)
                attr = resolve_apex(host, apexes) if host else None
                if attr is None and fdomain:
                    # Le finding n'a pas d'URL (DNS, SPF, email…) → on essaie
                    # quand même de l'attribuer à son domain (qui PEUT être
                    # un apex connu, ex. una.bj).
                    attr = resolve_apex(fdomain, apexes)
                c.execute(
                    sa.update(find_t).where(find_t.c.id == fid)
                      .values(attributed_apex=attr)
                )
                counts["findings"] += 1
                if attr is None: orphans += 1
                else:            attributed_set.add(attr)

        return {
            "subs":     counts["subs"],
            "hosts":    counts["hosts"],
            "findings": counts["findings"],
            "orgs":     len(attributed_set),
            "orphans":  orphans,
        }

    # Per-module hard ceilings (seconds). A hung subprocess (DNS lookups,
    # testssl, sqlmap, …) used to wedge the entire scan because there was
    # no top-level timeout. These are belt-and-braces over each module's
    # internal timeouts — set generously, ~3× expected runtime.
    _DEFAULT_TIMEOUTS = {
        'm01':  300,   # osint — whois + DKIM + HIBP
        'm02':  900,   # subdomain enum + DNS retries
        'm03':  900,   # httpx + tech detection
        'm04':  900,   # url collector — gau + katana
        'm05':  600,   # screenshot — playwright
        'm06':  600,   # takeover
        'm07':  900,   # ports — rustscan + nmap
        'm08':  1800,  # tls — testssl is the slowest
        'm09':  600,   # quick checks
        'm10':  600,   # body fetcher
        'm11':  900,   # js analyzer + jsluice
        'm12':  600,   # patterns
        'm13':  1800,  # nuclei big template runs
        'm14':  1800,  # active validation — dalfox + sqlmap
    }

    async def _run_module(
        self,
        mid: str,
        mod_path: str,
        cls_name: str,
        target: ScanTarget,
        stealth: bool
    ):
        """Dynamically import and execute one module."""
        import importlib
        try:
            module_cfg  = self.config.get(self._cfg_key(mid), default={})

            if not module_cfg.get('enabled', True):
                self.log.info(f"⏭  {mid} disabled — skipping")
                return

            self.log.info(f"▶  Running {mid} ({cls_name})")
            t0 = time.time()

            mod  = importlib.import_module(mod_path)
            cls  = getattr(mod, cls_name)
            inst = cls(self.config, self.db, stealth=stealth)

            # Per-module overall timeout. Operator can override via
            # `<cfg_key>.module_timeout_sec` in h4wk3y3.yaml.
            timeout = int(
                module_cfg.get('module_timeout_sec')
                or self._DEFAULT_TIMEOUTS.get(mid, 900)
            )
            try:
                await asyncio.wait_for(inst.run(target), timeout=timeout)
            except asyncio.TimeoutError:
                self.log.error(
                    f"⏱ {mid} hit module timeout after {timeout}s — aborted, "
                    f"scan continues. Tune {self._cfg_key(mid)}.module_timeout_sec "
                    f"if this is a legit long-running target."
                )
                return

            elapsed = round(time.time() - t0, 1)
            # Exact module_source match — `mid in str` used to match
            # substrings (m02 ⊂ "m011" etc.).
            findings = sum(
                1 for f in target.findings
                if f.module_source and (
                    f.module_source == mid or f.module_source.startswith(f"{mid}_")
                )
            )
            self.log.info(f"✅ {mid} done in {elapsed}s | +{findings} findings")

        except ModuleNotFoundError:
            self.log.warning(f"⚠️  {mid} module file not yet implemented — skipping")
        except Exception as e:
            # log.exception() prints the stacktrace at ERROR level — without it
            # a crashing module just printed "❌ mXX failed: <message>" with no
            # file/line, making INFO-level triage impossible.
            self.log.exception(f"❌ {mid} failed: {e}")
            # Re-raise in DEBUG to abort the whole scan for triage; swallow in
            # INFO so a single crashing module doesn't kill the run.
            if str(self.config.get('general', 'log_level', default='INFO')).upper() == 'DEBUG':
                raise

    def _cfg_key(self, mid: str) -> str:
        """Map module ID to config key."""
        mapping = {
            'm01': 'osint',
            'm02': 'subdomain',
            'm03': 'http_validator',
            'm04': 'url_collector',
            'm05': 'screenshot',
            'm06': 'takeover',
            'm07': 'ports',
            'm08': 'tls',
            'm09': 'quick_checks',
            'm10': 'fetcher',
            'm11': 'js_analyzer',
            'm12': 'pattern_analysis',
            'm13': 'nuclei',
            'm14': 'active_validation',
        }
        return mapping.get(mid, mid)

    def _select_modules(self, modules: Optional[List[str]]) -> list:
        if not modules:
            return self.MODULE_ORDER
        return [(mid, path, cls) for mid, path, cls in self.MODULE_ORDER if mid in modules]

    def _print_summary(self, target: ScanTarget, elapsed: float):
        s = target.summary()
        self.log.info("─" * 50)
        self.log.info(f"📊 SCAN COMPLETE — {target.domain}")
        self.log.info(f"   Subdomains:  {s['subdomains']}")
        self.log.info(f"   Live hosts:  {s['live_hosts']}")
        self.log.info(f"   URLs:        {s['urls']}")
        self.log.info(f"   Findings:    {s['findings']}")
        for sev, cnt in s['by_severity'].items():
            if cnt:
                emoji = {'critical':'🔴','high':'🟠','medium':'🟡','low':'🔵','info':'⚪'}
                self.log.info(f"     {emoji.get(sev,'·')} {sev.upper()}: {cnt}")
        self.log.info(f"   Time:        {elapsed}s")
        self.log.info("─" * 50)

    def _restore_state(self, target: ScanTarget) -> None:
        """
        Reload state from the previous scan's output files so that
        individual module reruns have all their dependencies available.

        Populates:
          target.subdomains  ← subdomains.txt
          target.live_hosts  ← live_hosts.json
          target.urls        ← urls_live.txt (or urls_all.txt)
        """
        import json
        out_dir = self.config.output_dir(target.domain)

        # Subdomains
        subs_file = out_dir / "subdomains.txt"
        if subs_file.exists():
            target.subdomains = [
                l.strip() for l in subs_file.read_text().splitlines() if l.strip()
            ]

        # Live hosts
        hosts_file = out_dir / "live_hosts.json"
        if hosts_file.exists():
            try:
                target.live_hosts = json.loads(hosts_file.read_text())
            except Exception:
                pass

        # URLs — prefer live (probed) over all
        for fname in ("urls_live.txt", "urls_all.txt"):
            urls_file = out_dir / fname
            if urls_file.exists():
                target.urls = [
                    l.strip() for l in urls_file.read_text().splitlines() if l.strip()
                ]
                break

    def _archive_previous(self, domain: str) -> None:
        """
        Archive scan_summary.json du scan précédent en .prev avant écrasement.
        Permet de voir rapidement ce qui a changé entre deux scans.
        """
        import shutil
        out_dir = self.config.output_dir(domain)
        summary = out_dir / "scan_summary.json"
        if summary.exists():
            try:
                shutil.copy2(str(summary), str(out_dir / "scan_summary.prev.json"))
            except Exception:
                pass

    def _save_output(self, target: ScanTarget, partial: bool = False):
        """Compute the scan summary, fire the notifier, optionally export JSON.

        Since the DB-canonical refactor (2026-05), the **Postgres DB is the
        single source of truth** for findings / live_hosts / subdomains /
        scans. The JSON files emitted here are an *export* — a convenient
        side-channel for offline inspection (jq, git-versioned reference
        scans, manual debugging) but the dashboard reads from the DB.

        Behaviour controlled by ``general.export_json_artefacts`` in
        ``h4wk3y3.yaml`` (default: true). Setting it to false skips the JSON
        emission entirely — useful for large scans where the 20 MB of
        JSON write per scan is just dead weight.
        """
        import json
        out_dir = self.config.output_dir(target.domain)
        # Note: full scans already archived scan_summary.json at run-start
        # (run() → _archive_previous). We intentionally do NOT re-archive
        # here — it would just copy the same stale file a second time.

        # Augmente le summary avec un split candidate / solid pour le dashboard
        summary = target.summary()
        candidate, solid = 0, 0
        for f in target.findings:
            if (f.metadata or {}).get('requires_validation'):
                candidate += 1
            else:
                solid += 1
        summary['by_status'] = {'solid': solid, 'candidate': candidate}

        # Diff vs previous scan. Source of truth = DB (find findings by
        # fingerprint across scans). See core/database.py:save_finding().
        diff_new, diff_gone = self._compute_diff(target)
        summary['diff'] = {
            'previous_scan_id': self.db.get_previous_scan_id(target.domain,
                                                             target.scan_id),
            'new':  len(diff_new),
            'gone': len(diff_gone),
        }

        # JSON export (default on). Can be disabled via config for
        # high-volume operators.
        export = bool(self.config.get('general', 'export_json_artefacts',
                                      default=True))
        if export:
            with open(out_dir / "scan_summary.json", 'w') as f:
                json.dump(summary, f, indent=2)

            all_findings = [f.to_dict() for f in target.findings]
            with open(out_dir / "findings.json", 'w') as f:
                json.dump(all_findings, f, indent=2)
            with open(out_dir / "findings_solid.json", 'w') as f:
                json.dump([d for d in all_findings
                           if not (d.get('metadata') or {}).get('requires_validation')],
                          f, indent=2)
            with open(out_dir / "findings_candidates.json", 'w') as f:
                json.dump([d for d in all_findings
                           if (d.get('metadata') or {}).get('requires_validation')],
                          f, indent=2)
            with open(out_dir / "diff_new.json", 'w') as f:
                json.dump(diff_new, f, indent=2)
            with open(out_dir / "diff_gone.json", 'w') as f:
                json.dump(diff_gone, f, indent=2)
        else:
            # Even with exports disabled, callers downstream (subdomain
            # filter, hand-off scripts) sometimes still want the summary.
            # Keeping it is cheap (~1 KB) and lets ``scan_summary.prev.json``
            # archival continue to work.
            with open(out_dir / "scan_summary.json", 'w') as f:
                json.dump(summary, f, indent=2)

        self.log.info(
            f"💾 DB persisted ({len(target.findings)} findings, "
            f"diff +{len(diff_new)} / -{len(diff_gone)})"
            + (f" | JSON export → {out_dir}" if export else " | JSON export disabled")
        )

        # Fire notifier ONLY on the diff_new list (filtered ≥ medium by default
        # via notifications.notify_on in h4wk3y3.yaml). Skip on partial reruns —
        # those are module reruns, not real new observations.
        if not partial:
            self._notify_diff(target, diff_new)

    def _compute_diff(self, target: ScanTarget):
        """Return ``(diff_new, diff_gone)`` for this scan vs the previous one.

        Falls back gracefully if the DB lookup fails (corrupted row, schema
        mismatch on legacy DBs) — diff is a nice-to-have, the scan output
        itself must still be written.
        """
        try:
            return self.db.diff_findings(target.domain, target.scan_id)
        except Exception as e:
            self.log.warning(f"diff computation failed: {e}")
            return [], []

    def _notify_diff(self, target: ScanTarget, diff_new: list) -> None:
        """Fan-out new findings to Discord/Slack webhooks if configured.

        Only fires on findings whose severity is in
        ``notifications.notify_on`` (default: critical, high). The diff filter
        already excludes findings seen in a previous scan, so this is the
        single source of truth for "send me an alert".
        """
        if not diff_new:
            return
        cfg = self.config.get("notifications", default={}) or {}
        discord = cfg.get("discord_webhook") or ""
        slack = cfg.get("slack_webhook") or ""
        if not discord and not slack:
            return
        notify_on = cfg.get("notify_on") or ["critical", "high"]
        notifier = Notifier(
            discord_webhook=discord,
            slack_webhook=slack,
            notify_severities=notify_on,
        )

        # Build a lookup from DB row → in-memory Finding object so the embed
        # has the canonical fields. The DB rows are dicts; we re-import to
        # Finding to reuse send_discord/send_slack formatting unchanged.
        from core.models import Finding, FindingType, Severity as _Sev
        sent = 0
        for row in diff_new:
            try:
                f = Finding(
                    type=FindingType(row["type"]),
                    target=target.domain,
                    title=row.get("title") or row["type"],
                    severity=_Sev(row.get("severity") or "info"),
                    confidence=row.get("confidence") or 0.0,
                    url=row.get("url"),
                    evidence=row.get("evidence"),
                    module_source=row.get("module_source"),
                    metadata=row.get("metadata") or {},
                    tags=row.get("tags") or [],
                    timestamp=row.get("timestamp") or "",
                )
                if notifier.should_notify(f):
                    notifier.notify(f, target.domain)
                    sent += 1
            except Exception as e:
                self.log.debug(f"notifier skip on row: {e}")
        if sent:
            self.log.info(f"📣 Notifier: {sent} new finding(s) sent ≥ {notify_on}")
