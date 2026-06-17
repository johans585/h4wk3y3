"""
Argus V2 - Dashboard Backend (FastAPI)
Serves scan results as REST API for the frontend.
"""

from fastapi import FastAPI, HTTPException, Query, Body, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pathlib import Path
from typing import Optional, Dict
from urllib.parse import urlparse
from io import StringIO
import json
import shutil
import re
import yaml

from core.config   import ArgusConfig
from core.database import ArgusDB
from core.audit    import log_action, ACTIONS
from core.logger   import get_logger
from dashboard.backend.scan_manager import (
    ScanManager, MODES, MODULE_CATALOG, is_valid_domain,
)
from dashboard.backend.auth_routes  import install_auth
from dashboard.backend.users_routes import install_users_routes
from dashboard.backend.audit_routes import install_audit_routes
from dashboard.backend.orgs_routes            import install_orgs_routes
from dashboard.backend.attack_surface_routes  import install_attack_surface_routes
from dashboard.backend.cve_routes             import install_cve_routes
from dashboard.backend.clientip               import client_ip as _request_ip


def create_app(config: ArgusConfig, db: ArgusDB) -> FastAPI:
    app = FastAPI(title="Argus V2 Dashboard", version="2.0.0")
    log = get_logger('dashboard')

    # Self-heal scans left on 'running' by a previous hard-killed process
    # (SIGKILL/OOM/power loss) so they don't poison /api/scans and the active-
    # scan UI. Age-gated, so a legitimately-running concurrent scan is untouched.
    try:
        fixed = db.abandon_stale_scans()
        if fixed:
            log.warning(f"🧹 marked {fixed} stale 'running' scan(s) as abandoned at startup")
    except Exception as e:
        log.debug(f"stale-scan sweep skipped: {e}")

    # Periodic CVE feed refresh + correlation (off by default; scheduler.enabled).
    # Started/stopped with the FastAPI app so it lives in the running event loop.
    from core.scheduler import ArgusScheduler
    _scheduler = ArgusScheduler(config, db, log)

    @app.on_event("startup")
    async def _start_scheduler():
        _scheduler.start()

    @app.on_event("shutdown")
    async def _stop_scheduler():
        await _scheduler.stop()

    # No CORS middleware: dashboard serves its own SPA from the same origin
    # via StaticFiles. Re-enable explicitly with a restricted allow_origins
    # list if a separate frontend dev server is added.

    output_dir   = Path(config.get('general', 'output_dir', default='./output'))
    project_root = Path(__file__).resolve().parents[2]

    # Scan manager — bind context decides whether we accept arbitrary targets.
    bind_host    = str(config.get('dashboard', 'host', default='127.0.0.1'))
    allow_remote = bind_host not in ('127.0.0.1', 'localhost', '::1')
    wildcards    = []
    wc_path = project_root / 'wildcards'
    if wc_path.exists():
        wildcards = [l.strip() for l in wc_path.read_text().splitlines() if l.strip() and not l.startswith('#')]
    if allow_remote and not wildcards:
        log.warning(
            "⚠ dashboard binds to %s (remote-exposed) but no wildcards/ allowlist "
            "is present — any reachable client can request scans of arbitrary "
            "targets. Restrict via firewall/VPN or populate %s.",
            bind_host, wc_path,
        )
    scan_mgr = ScanManager(project_root=project_root, allow_remote=allow_remote,
                           wildcards=wildcards, db=db)

    _SAFE_SEG_RE = re.compile(r"^[A-Za-z0-9._-]+$")

    def _dir(domain: str) -> Path:
        """Resolve <output_dir>/<domain>, validating the domain and enforcing
        path containment. Central guard for every file-serving route — without
        it, routes that build paths from {domain}/{filename}/{category} relied
        solely on the ASGI server's path normalisation (fragile). Rejects
        invalid domains (400) and any path escaping output_dir (404)."""
        if not is_valid_domain(domain):
            raise HTTPException(400, "invalid domain")
        p = output_dir / domain
        root = output_dir.resolve(strict=False)
        rp = p.resolve(strict=False)
        if rp != root and root not in rp.parents:
            raise HTTPException(404, "not found")
        return p

    def _safe_segment(seg: str, kind: str = "path component") -> str:
        """Allowlist a single path segment (filename/category). Blocks
        traversal, separators and NULs."""
        if not seg or seg in (".", "..") or not _SAFE_SEG_RE.match(seg):
            raise HTTPException(400, f"invalid {kind}")
        return seg

    def _read(path: Path, default=None):
        """Safe JSON read — returns default if missing or broken."""
        try:
            if path.exists():
                return json.loads(path.read_text())
        except Exception:
            pass
        return default

    # ── Health ────────────────────────────────────────────────

    @app.get("/api/health")
    def health():
        """Liveness/readiness probe. Returns:
          - status: "ok" / "degraded" / "down"
          - db_ok, output_writable, tools: detail per check.

        Used by uptime monitors, dashboard footer, and Docker HEALTHCHECK.
        Never raises — degraded components are reported, not hidden.
        """
        import shutil as _shutil
        import time as _time

        checks: Dict[str, dict] = {}
        status = "ok"

        # 1) DB ping
        try:
            import sqlalchemy as _sa
            t0 = _time.perf_counter()
            with db.engine.connect() as _c:
                _c.execute(_sa.text("SELECT 1")).scalar()
            checks["db"] = {
                "ok": True,
                "latency_ms": round((_time.perf_counter() - t0) * 1000, 2),
            }
        except Exception as e:
            checks["db"] = {"ok": False, "error": str(e)}
            status = "down"  # DB down = service down

        # 2) Output dir writable + free disk
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            usage = _shutil.disk_usage(output_dir)
            free_gb = round(usage.free / (1024 ** 3), 2)
            test = output_dir / ".health-write-test"
            test.write_text("ok")
            test.unlink()
            checks["output"] = {
                "ok": True,
                "path": str(output_dir.resolve()),
                "free_gb": free_gb,
            }
            if free_gb < 1.0:
                status = "degraded"
                checks["output"]["warning"] = "less than 1 GB free"
        except Exception as e:
            checks["output"] = {"ok": False, "error": str(e)}
            status = "degraded"

        # 3) External tool availability (presence only — no exec)
        required_tools = [
            "subfinder", "assetfinder", "httpx", "nuclei",
            "katana", "gau", "dnsx",
        ]
        optional_tools = [
            "findomain", "shuffledns", "alterx", "naabu", "nmap",
            "testssl.sh", "dalfox", "sqlmap", "jsluice", "arjun",
        ]
        tools = {}
        missing_required = []
        for t in required_tools:
            present = _shutil.which(t) is not None
            tools[t] = {"present": present, "required": True}
            if not present:
                missing_required.append(t)
        for t in optional_tools:
            tools[t] = {"present": _shutil.which(t) is not None, "required": False}
        if missing_required:
            status = "degraded" if status == "ok" else status
        checks["tools"] = tools
        checks["missing_required"] = missing_required

        # 4) Scan-manager view: how many runs in flight
        try:
            runs = scan_mgr.list_runs()
            live = [r for r in runs if r.get("state") in ("starting", "running")]
            checks["scans"] = {"in_flight": len(live), "total_tracked": len(runs)}
        except Exception as e:
            checks["scans"] = {"error": str(e)}

        # 5) Persisted scan status (independent of the in-memory manager) so a
        # monitor surfaces rows stuck on 'running' from a crashed process.
        try:
            import sqlalchemy as _sa2
            from core import orm as _orm2
            st = _orm2.Scan.__table__
            with db.engine.connect() as _c:
                rows = _c.execute(
                    _sa2.select(st.c.status, _sa2.func.count()).group_by(st.c.status)
                ).all()
            checks["scan_status"] = {s: int(n) for s, n in rows}
        except Exception as e:
            checks["scan_status"] = {"error": str(e)}

        # 6) Scheduler state
        _sc = config.get("scheduler", default={}) or {}
        checks["scheduler"] = {"enabled": bool(_sc.get("enabled", False))}

        return {"status": status, "checks": checks}

    # ── Domains ───────────────────────────────────────────────

    @app.get("/api/domains")
    def list_domains():
        """Scanned domains, DB-first.

        The DB is the source of truth: a domain with at least one scan row has
        live, coherent data and is listed first with ``has_data: true``. Stale
        ``output/<domain>/`` directories left over from past sessions (no DB
        scan after a reseed/wipe) are listed AFTER, flagged ``has_data: false``
        and ``stale: true`` — they used to sort alphabetically first and make
        the UI land on a domain showing incoherent half-disk/half-DB numbers.
        """
        domains = []
        seen = set()
        # 1. DB-backed domains (real current data), most-recent scan first.
        for dom in dict.fromkeys(s["domain"] for s in db.get_scans()):
            domains.append({"domain": dom, "has_data": True, "stale": False})
            seen.add(dom)
        # 2. Legacy on-disk output dirs not present in the DB.
        if output_dir.exists():
            for d in sorted(output_dir.iterdir()):
                if d.is_dir() and not d.name.startswith('.') and d.name not in seen:
                    domains.append({
                        "domain":   d.name,
                        "has_data": False,
                        "stale":    True,
                    })
        return domains

    @app.delete("/api/domains/{domain}")
    def delete_domain(domain: str):
        """Delete all data for a domain — output files + DB records."""
        # Two-layer guard: domain syntax + resolved path must stay inside output_dir.
        # Without this, a domain like "../etc" would resolve outside the sandbox
        # and shutil.rmtree() would happily walk the parent tree.
        if not is_valid_domain(domain):
            raise HTTPException(400, "invalid domain")
        try:
            output_root = output_dir.resolve(strict=False)
            domain_dir  = (output_dir / domain).resolve(strict=False)
        except Exception:
            raise HTTPException(400, "invalid domain")
        if output_root not in domain_dir.parents:
            raise HTTPException(400, "invalid domain")

        if domain_dir.exists():
            shutil.rmtree(str(domain_dir))
        try:
            import sqlalchemy as _sa
            from core import orm as _orm
            with db.engine.begin() as _c:
                for tbl in (_orm.Finding, _orm.Subdomain, _orm.LiveHost, _orm.Scan):
                    t = tbl.__table__
                    _c.execute(_sa.delete(t).where(t.c.domain == domain))
        except Exception as e:
            # DB cleanup best-effort — directory already deleted
            log.warning("DB cleanup after delete_domain(%s) failed: %s", domain, e)
        return {"deleted": domain, "ok": True}

    # ── Summary & findings ────────────────────────────────────

    @app.get("/api/summary/{domain}")
    def get_summary(domain: str):
        """Scan summary built from DB state (post-canonical refactor).

        Each row in the ``scans`` table for `domain` carries a JSON ``stats``
        blob captured at ``finish_scan`` time. We return the most recent
        scan's stats + the one before it as ``prev_summary`` so the
        dashboard can render the delta.

        If no scan exists in DB but a legacy ``scan_summary.json`` is still
        on disk (pre-reseed installs), fall back to that file so the UI
        stays usable while the operator runs ``scripts/reseed_pg_from_output.py``.
        """
        scans = db.get_scans(domain)
        if not scans:
            data = _read(_dir(domain) / "scan_summary.json")
            if data is None:
                raise HTTPException(404, "No scan found for this domain")
            prev = _read(_dir(domain) / "scan_summary.prev.json")
            if prev:
                data["prev_summary"] = prev
            return data

        latest = scans[0]
        stats = {}
        if latest.get("stats"):
            try:
                stats = json.loads(latest["stats"])
            except (ValueError, TypeError):
                stats = {}

        # Always include base fields the frontend expects, even if stats
        # blob was empty (older reseeded scans).
        data = {
            "scan_id":     latest["scan_id"],
            "domain":      domain,
            "started_at":  latest.get("started_at"),
            "finished_at": latest.get("finished_at"),
            # Live counts straight from DB so the numbers stay honest even
            # if the operator wiped JSON files.
            "subdomains":  len(db.get_subdomains(domain)),
            # Live-host count straight from the DB (matches /api/live-hosts and
            # the subdomains/findings counts above). Reading it from the on-disk
            # live_hosts.json here was a split-brain: when DB and disk diverged
            # (e.g. findings deleted, JSON stale) the Overview showed e.g.
            # "LIVE HOSTS 20" next to "SUBDOMAINS 0 / FINDINGS 0".
            "live_hosts":  len(_live_hosts_from_db(domain)),
            "findings":    sum(db.stats_for_domain(domain).values()),
            "by_severity": db.stats_for_domain(domain),
        }
        data.update(stats)
        # DB is the source of truth — restore the canonical counts AFTER merging
        # the stored stats blob. That blob holds in-memory counts captured at
        # finish_scan and can diverge from the DB (e.g. dedup collapses N
        # findings to fewer rows). Without this the Overview showed findings=6
        # from the blob next to a by_severity summing to 3 from the DB.
        # (`urls` has no DB table, so it legitimately stays from the blob.)
        _sev = db.stats_for_domain(domain)
        data["by_severity"] = _sev
        data["findings"]    = sum(_sev.values())
        data["subdomains"]  = len(db.get_subdomains(domain))
        data["live_hosts"]  = len(_live_hosts_from_db(domain))

        # Previous scan summary for diff rendering.
        if len(scans) >= 2:
            try:
                prev_stats = json.loads(scans[1].get("stats") or "{}")
                data["prev_summary"] = {
                    "scan_id":     scans[1]["scan_id"],
                    "started_at":  scans[1].get("started_at"),
                    "finished_at": scans[1].get("finished_at"),
                    **prev_stats,
                }
            except (ValueError, TypeError):
                pass
        return data

    # Asset-inventory types — these used to be emitted as findings but are
    # now considered pure inventory (already exposed via /api/subdomains,
    # /api/live-hosts, /api/screenshots, etc.). Filter them out at load
    # time so legacy JSON files (from scans run before the cleanup) don't
    # leak them back into the findings view.
    _ASSET_TYPES = {
        'subdomain', 'live_host', 'url', 'screenshot',
        'technology', 'js_endpoint', 'parameter',
    }

    @app.get("/api/findings")
    def get_findings(
        domain:           Optional[str] = Query(None),
        org:              Optional[str] = Query(None, description="filter by organisation name (Étape 2.1)"),
        severity:         Optional[str] = Query(None),
        type:             Optional[str] = Query(None),
        status:           Optional[str] = Query(None, description="solid|candidate|all"),
        include_assets:   bool          = Query(False, description="include asset/inventory rows"),
        active:           bool          = Query(True, description="only findings still present in the latest scan (drops 'gone' history)"),
        limit:            int           = Query(500, le=10000)
    ):
        """Findings from the Postgres DB (single source of truth).

        Filters applied here (severity/type) push down to SQL via
        ``ArgusDB.get_findings``. The ``status`` filter is evaluated
        client-side here because it reads metadata.requires_validation,
        which is JSON-encoded server-side — a metadata->>... predicate
        would be cleaner once we move metadata to JSONB.
        """
        # ── ?org=<name> resolves to a set of apex domains ───────
        # When `domain` is also set, we intersect: only findings on that
        # domain AND only if it belongs to that org (empty result otherwise).
        org_domains: Optional[set] = None
        if org:
            from core import organisation as _O
            if _O.get_org(db, org) is None:
                raise HTTPException(404, f"organisation {org!r} not found")
            org_domains = {t["apex"] for t in _O.list_targets_for_org(db, org)}
            if not org_domains:
                return []
            if domain and domain not in org_domains:
                return []

        # Pull from DB. limit*2 is a heuristic: when status filter is set
        # we may drop ~half of rows, so over-fetch a bit to keep the cap
        # meaningful — capped at the configured `limit` after filtering.
        # When filtering by org without a specific domain, pull a wider
        # window then filter client-side; per-apex SQL fan-out would also
        # work but the result set is bounded by `limit` anyway.
        sql_limit = limit if not (status or org_domains or active) else min(limit * 4, 10000)
        # Active = only findings still present in the latest scan. For a single
        # domain we push it to SQL (scan_id == latest); for org/all views we
        # post-filter against a per-domain latest-scan map (a finding is active
        # iff its last_seen_scan_id is its domain's latest scan).
        scan_filter = None
        latest_by_domain: dict = {}
        if active and domain:
            scan_filter = db.latest_scan_id(domain)
        rows = db.get_findings(domain=domain, severity=severity,
                               finding_type=type, scan_id=scan_filter,
                               limit=sql_limit)

        if active and not domain:
            for r in rows:
                d = r.get("domain")
                if d and d not in latest_by_domain:
                    latest_by_domain[d] = db.latest_scan_id(d)
            rows = [r for r in rows
                    if r.get("last_seen_scan_id") == latest_by_domain.get(r.get("domain"))]

        if org_domains is not None:
            rows = [r for r in rows if r.get("domain") in org_domains]
        if not include_assets:
            rows = [r for r in rows if r.get('type') not in _ASSET_TYPES]
        if status:
            want_candidate = (status == "candidate")
            rows = [
                r for r in rows
                if bool((r.get('metadata') or {}).get('requires_validation'))
                   == want_candidate
            ]
        return rows[:limit]

    @app.get("/api/findings/stats")
    def findings_stats(domain: Optional[str] = Query(None),
                       org:    Optional[str] = Query(None),
                       active: bool          = Query(True, description="only count findings present in the latest scan")):
        if org:
            from core import organisation as _O
            if _O.get_org(db, org) is None:
                raise HTTPException(404, f"organisation {org!r} not found")
            apexes = [t["apex"] for t in _O.list_targets_for_org(db, org)]
            # Optional intersection with `domain` filter
            if domain:
                apexes = [a for a in apexes if a == domain]
            return {a: db.stats_for_domain(a, active=active) for a in apexes}
        if domain:
            return db.stats_for_domain(domain, active=active)
        all_scans = db.get_scans()
        return {s['domain']: db.stats_for_domain(s['domain'], active=active)
                for s in all_scans}

    # ── Subdomains ────────────────────────────────────────────

    @app.get("/api/subdomains/{domain}")
    def get_subdomains(domain: str):
        """
        Merge per-subdomain data: DNS state (NXDOMAIN/RESOLVES), HTTP state
        (UP/DOWN), CNAME, IPs, PTR. Frontend uses this to render the IP
        column, click-to-filter co-located hosts, and the 4-state status.
        """
        subs    = db.get_subdomains(domain)
        cnames  = _read(_dir(domain) / "cnames.json", default={}) or {}
        ips_map = _read(_dir(domain) / "ips.json",    default={}) or {}
        ptrs    = _read(_dir(domain) / "ptrs.json",   default={}) or {}
        dns     = _read(_dir(domain) / "dns_records.json", default={}) or {}
        # Per-sub HTTP status from the DB (source of truth), so the status
        # column stays correct even if live_hosts.json is stale/absent. Falls
        # back to the on-disk file only for legacy domains with no DB scan.
        live    = _live_hosts_from_db(domain)
        if not live and not db.get_scans(domain):
            live = _read(_dir(domain) / "live_hosts.json", default=[]) or []
        unreach = _read(_dir(domain) / "unreachable.json", default=[]) or []

        # Index live_hosts by their probed-domain (LiveHost.domain matches
        # the original subdomain — even after redirects).
        live_index = {}
        for h in live:
            d = (h or {}).get("domain", "")
            if d:
                live_index[d] = {
                    "url":          h.get("url"),
                    "status_code":  h.get("status_code"),
                    "title":        h.get("title"),
                    "technologies": h.get("technologies", []),
                }
        # A sub appears in unreachable.json if at least one probe failed.
        # (Note: a sub can be both unreachable on https AND alive on http,
        # in which case it ends up in live_index too — live wins.)
        unreach_subs = set()
        for u in unreach:
            try:
                # url is e.g. "https://sub.example.com" — extract host
                host = (u.get("url") or "").split("://", 1)[-1].split("/")[0]
                if host:
                    unreach_subs.add(host)
            except Exception:
                pass

        # Build per-sub records.
        records = []
        for sub in sorted(subs):
            sub_ips = ips_map.get(sub, []) or []
            cname   = cnames.get(sub) or None
            # PTR for the first IP if available (most common case is 1 IP).
            ptr     = ptrs.get(sub_ips[0]) if sub_ips else None
            live_h  = live_index.get(sub)

            # 4-state HTTP status:
            #   "http_up"   — M02 reached it
            #   "http_down" — resolves but every probe failed
            #   "resolves"  — has IP, never tried HTTP (or no probes)
            #   "nxdomain"  — no A record at all
            if live_h:
                http_state = "http_up"
            elif sub in unreach_subs:
                http_state = "http_down"
            elif sub_ips:
                http_state = "resolves"
            else:
                http_state = "nxdomain"

            records.append({
                "subdomain":  sub,
                "cname":      cname,
                "ips":        sub_ips,
                "ptr":        ptr,
                "http_state": http_state,
                "live":       live_h,  # null if no live response
            })

        # Co-location summary: ip → list of subs sharing it.
        ip_clusters: Dict[str, list] = {}
        for r in records:
            for ip in r["ips"]:
                ip_clusters.setdefault(ip, []).append(r["subdomain"])

        return {
            "domain":      domain,
            "count":       len(subs),
            "subdomains":  subs,            # legacy: flat list
            "records":     records,         # new: enriched per-sub
            "cnames":      cnames,
            "ips":         ips_map,
            "ptrs":        ptrs,
            "ip_clusters": ip_clusters,
            "dns_records": dns,
        }

    # ── Live hosts ────────────────────────────────────────────

    def _live_hosts_from_db(domain: str) -> list:
        """Pull live_hosts rows from Postgres and reshape to the JSON contract
        the frontend expects. ``technologies`` is JSON-encoded in storage
        (legacy from SQLite TEXT), decode on the way out.

        Note: unlike ``findings.domain`` / ``subdomains.domain`` which store
        the apex (scan-key), ``live_hosts.domain`` is the *per-host*
        hostname (set by ``LiveHost.domain`` in M02). So a request for the
        apex must fan out to ``apex`` + ``*.apex`` to surface every host
        captured under that scan. Strict equality used to return only the
        apex row (1/20 on una.bj)."""
        import sqlalchemy as _sa
        from core import orm as _orm
        t = _orm.LiveHost.__table__
        stmt = _sa.select(t).where(_sa.or_(
            t.c.domain == domain,
            t.c.domain.like(f"%.{domain}"),
        ))
        out: list = []
        with db.engine.connect() as _c:
            for r in _c.execute(stmt):
                row = dict(r._mapping)
                techs = row.get("technologies")
                if isinstance(techs, str) and techs:
                    try:
                        row["technologies"] = json.loads(techs)
                    except (ValueError, TypeError):
                        row["technologies"] = []
                elif techs is None:
                    row["technologies"] = []
                out.append(row)
        return out

    @app.get("/api/live-hosts/{domain}")
    def get_live_hosts(domain: str):
        """Live hosts from the DB. Enrichment fields (favicon_hash, csp_issues,
        cookie_issues…) the M02 dataclass carries are not yet persisted —
        they remain in ``output/<domain>/live_hosts.json`` as a complement
        until a JSONB column is added (Phase 2 work item)."""
        rows = _live_hosts_from_db(domain)
        # Only fall back to the on-disk JSON for *legacy* domains that have no
        # DB scan at all (pre-reseed installs). When a DB scan exists, the DB is
        # authoritative — an empty result means genuinely zero live hosts, not
        # "go read stale disk". This keeps the count consistent with /summary
        # and /subdomains (which never silently fall back), killing the
        # split-brain where live-hosts showed disk data and subdomains showed 0.
        if not rows and not db.get_scans(domain):
            return _read(_dir(domain) / "live_hosts.json", default=[]) or []
        return rows

    @app.get("/api/live-hosts-full/{domain}")
    def get_live_hosts_full(domain: str):
        """Full live host objects — same DB query as /live-hosts/, merged
        with the JSON enrichment for fields not yet persisted (favicon hash,
        CSP issues, security headers, …)."""
        db_rows = _live_hosts_from_db(domain)
        # Legacy-only disk fallback (see /api/live-hosts): never shadow a real
        # (possibly empty) DB scan with stale JSON.
        if not db_rows and not db.get_scans(domain):
            return _read(_dir(domain) / "live_hosts.json", default=[]) or []

        # Merge: JSON enrichment by URL key, DB row wins on basic fields.
        json_by_url = {h.get("url"): h
                       for h in (_read(_dir(domain) / "live_hosts.json", default=[]) or [])
                       if h.get("url")}
        merged = []
        for r in db_rows:
            extras = json_by_url.get(r.get("url"), {})
            # Don't let the JSON overwrite anything authoritative from DB.
            for k, v in extras.items():
                r.setdefault(k, v)
            merged.append(r)
        return merged

    # ── Technologies ──────────────────────────────────────────

    @app.get("/api/tech/{domain}")
    def get_tech(domain: str):
        """Tech map `{url: [tech, …]}` derived from live_hosts in DB."""
        rows = _live_hosts_from_db(domain)
        if not rows and not db.get_scans(domain):
            return _read(_dir(domain) / "tech_report.json", default={})
        return {r["url"]: r.get("technologies") or [] for r in rows if r.get("url")}

    # ── URLs ──────────────────────────────────────────────────

    @app.get("/api/urls/{domain}")
    def get_urls(domain: str, limit: int = Query(50000, le=100000),
                 all: bool = Query(False, description="Return all URLs including dead ones")):
        d = _dir(domain)
        live_file = d / "urls_live.txt"
        all_file  = d / "urls_all.txt"
        # Use probed live URLs by default; fall back to all if probe not run
        if not all and live_file.exists():
            urls_file = live_file
            probed = True
        elif all_file.exists():
            urls_file = all_file
            probed = live_file.exists()
        else:
            return {"domain": domain, "count": 0, "urls": [], "probed": False}
        urls = [l for l in urls_file.read_text().splitlines() if l.strip()]
        total_all = len([l for l in all_file.read_text().splitlines() if l.strip()]) \
                    if all_file.exists() and probed else len(urls)
        return {
            "domain":    domain,
            "count":     len(urls),
            "total_all": total_all,
            "probed":    probed,
            "urls":      urls[:limit],
        }

    # ── Screenshots ───────────────────────────────────────────

    @app.get("/api/screenshots/{domain}")
    def get_screenshots(domain: str):
        return _read(_dir(domain) / "screenshots.json", default=[])

    @app.get("/api/screenshots/{domain}/{filename}")
    def get_screenshot_file(domain: str, filename: str):
        safe = _safe_segment(filename, "filename")
        shots_dir = _dir(domain) / "screenshots"
        # M05 writes thumbnails into a `thumbs/` subdir but the API exposes them
        # under a flat filename (`*_thumb.jpg`). Resolve those from thumbs/ first,
        # falling back to the flat dir for full-size captures.
        candidates = (
            [shots_dir / "thumbs" / safe, shots_dir / safe]
            if safe.endswith("_thumb.jpg")
            else [shots_dir / safe]
        )
        img_path = next((p for p in candidates if p.exists()), None)
        if img_path is None:
            raise HTTPException(404, "Screenshot not found")
        return FileResponse(str(img_path))

    # ── JS ────────────────────────────────────────────────────

    def _artefacts_or_disk(domain: str, kind: str, module: str,
                           disk_name: str, default=None):
        """Read a module artefact from the DB (source of truth), falling back to
        the legacy output/<domain>/<file>.json only for pre-migration domains.

        An *empty* DB result is authoritative when the domain has any artefacts
        at all (it was scanned with artefact-writing code → the current scan
        genuinely found zero). We only fall back to disk when the domain has no
        artefacts whatsoever, so a clean current scan never resurfaces stale
        items from an older on-disk dump.
        """
        rows = db.get_artefacts(domain, kind, module=module)
        if rows or db.has_artefacts(domain):
            return rows
        return _read(_dir(domain) / disk_name, default=[] if default is None else default)

    @app.get("/api/js-secrets/{domain}")
    def get_js_secrets(domain: str):
        return _artefacts_or_disk(domain, "js_secret", "m11", "js_secrets.json")

    @app.get("/api/js-endpoints/{domain}")
    def get_js_endpoints(domain: str):
        return _artefacts_or_disk(domain, "js_endpoint", "m11", "js_endpoints.json")

    @app.get("/api/js-files/{domain}")
    def get_js_files(domain: str):
        """List of JS files discovered and analyzed by M05."""
        js_files_path = _dir(domain) / "js_files.txt"
        if not js_files_path.exists():
            return []
        urls = [l.strip() for l in js_files_path.read_text().splitlines() if l.strip()]
        return [{"url": u} for u in urls]

    # ── Email security ────────────────────────────────────────

    @app.get("/api/email-security/{domain}")
    def get_email_security(domain: str):
        return _artefacts_or_disk(domain, "email_security", "m02", "email_security.json")

    # ── API specs ─────────────────────────────────────────────

    @app.get("/api/api-specs/{domain}")
    def get_api_specs(domain: str):
        return _artefacts_or_disk(domain, "api_spec", "m04", "api_specs.json")

    # ── Validated secrets ─────────────────────────────────────

    @app.get("/api/secrets-validated/{domain}")
    def get_secrets_validated(domain: str):
        return _read(_dir(domain) / "secrets_validated.json", default=[])

    # ── Takeovers ─────────────────────────────────────────────

    @app.get("/api/takeovers/{domain}")
    def get_takeovers(domain: str):
        return _artefacts_or_disk(domain, "takeover", "m06", "takeovers.json")

    # ── Patterns & GF ─────────────────────────────────────────

    @app.get("/api/patterns/{domain}")
    def get_patterns(domain: str):
        return _artefacts_or_disk(domain, "pattern", "m12", "patterns.json")

    @app.get("/api/gf/{domain}")
    def get_gf_categories(domain: str):
        """List all gf_*.txt files with their counts."""
        d = _dir(domain)
        if not d.exists():
            return []
        cats = []
        for f in sorted(d.glob("gf_*.txt")):
            cat   = f.stem[3:]  # strip "gf_"
            lines = [l for l in f.read_text().splitlines() if l.strip()]
            if lines:
                cats.append({"category": cat, "count": len(lines)})
        return sorted(cats, key=lambda x: -x["count"])

    @app.get("/api/gf/{domain}/{category}")
    def get_gf_results(domain: str, category: str):
        gf_file = _dir(domain) / f"gf_{_safe_segment(category, 'category')}.txt"
        if not gf_file.exists():
            return {"urls": [], "count": 0}
        urls = [l for l in gf_file.read_text().splitlines() if l.strip()]
        return {"urls": urls, "count": len(urls)}

    # ── Source Viewer (M02b) ──────────────────────────────────

    @app.get("/api/fetch-results/{domain}")
    def get_fetch_results(domain: str):
        """
        Source Viewer: list of fetched pages with status, headers, body snippet.

        Prefer fetch_results.json (rich per-URL data from M02b) when available;
        fall back to the legacy join of bodies_snippets.json + live_hosts.json
        on older scans.
        """
        d = _dir(domain)
        fr = _read(d / "fetch_results.json", default=None)
        snippets = _read(d / "bodies_snippets.json", default={}) or {}

        if isinstance(fr, list) and fr:
            # Index snippets by url (snippets are typically truncated bodies).
            result = []
            for entry in fr:
                u = entry.get("url") or entry.get("original_url") or ""
                if not u:
                    continue
                body = snippets.get(u) or ""
                result.append({
                    "url":          u,
                    "status":       entry.get("status") or 0,
                    "title":        entry.get("title") or "",
                    "headers":      entry.get("headers") or {},
                    "body_snippet": body,
                    "length":       entry.get("length") or len(body),
                })
            # Sort: real status codes first (sorted ascending), failed (0) last.
            result.sort(key=lambda x: ((x.get("status") or 0) == 0, x.get("status") or 0, x.get("url")))
            return result

        # Legacy fallback
        headers    = _read(d / "headers.json", default={}) or {}
        live_hosts = _read(d / "live_hosts.json", default=[]) or []
        if not snippets:
            return []
        lh_index = {h.get("url", ""): h for h in live_hosts if h.get("url")}
        result = []
        for url, body in snippets.items():
            lh = lh_index.get(url, {})
            result.append({
                "url":          url,
                "status":       lh.get("status_code") or 0,
                "title":        lh.get("title", ""),
                "headers":      headers.get(url, {}),
                "body_snippet": body,
                "length":       len(body),
            })
        # Sort: real status codes first (sorted ascending), failed (0) last.
        result.sort(key=lambda x: ((x.get("status") or 0) == 0, x.get("status") or 0, x.get("url")))
        return result

    @app.get("/api/bodies-snippets/{domain}")
    def get_bodies_snippets(domain: str):
        return _read(_dir(domain) / "bodies_snippets.json", default={})

    @app.get("/api/headers/{domain}")
    def get_headers(domain: str):
        return _read(_dir(domain) / "headers.json", default={})

    # ── Scans ─────────────────────────────────────────────────

    @app.get("/api/scans")
    def list_scans(domain: Optional[str] = Query(None)):
        return db.get_scans(domain)

    @app.get("/api/export/{domain}")
    def export_findings(domain: str, fmt: str = Query("json")):
        findings = db.get_findings(domain=domain, limit=10000)
        if fmt == "csv":
            import csv
            import io
            out = io.StringIO()
            if findings:
                w = csv.DictWriter(out, fieldnames=list(findings[0].keys()))
                w.writeheader(); w.writerows(findings)
            return JSONResponse(content={"csv": out.getvalue()})
        return findings

    @app.get("/api/export/{domain}/burp-scope")
    def export_burp_scope(domain: str):
        """Export live hosts as Burp Suite scope XML."""
        live = _read(_dir(domain) / "live_hosts.json", default=[])
        items = []
        seen = set()
        for h in (live or []):
            url = h.get("url", "")
            if not url:
                continue
            try:
                p = urlparse(url)
                host_key = f"{p.scheme}://{p.netloc}"
                if host_key in seen:
                    continue
                seen.add(host_key)
                protocol = p.scheme.upper()
                host_val = p.hostname or ""
                port_val = p.port or (443 if p.scheme == "https" else 80)
                items.append(
                    f"    <item>"
                    f"<enabled>true</enabled>"
                    f"<host>{host_val}</host>"
                    f"<port>{port_val}</port>"
                    f"<protocol>{protocol}</protocol>"
                    f"<file>^/.*</file>"
                    f"</item>"
                )
            except Exception:
                continue
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<BurpSuite>\n'
            '  <scope>\n'
            '    <excludes/>\n'
            '    <includes>\n'
            + "\n".join(items) + "\n"
            '    </includes>\n'
            '  </scope>\n'
            '</BurpSuite>'
        )
        from fastapi.responses import Response
        return Response(
            content=xml,
            media_type="application/xml",
            headers={"Content-Disposition": f'attachment; filename="{domain}-burp-scope.xml"'}
        )

    @app.get("/api/export/{domain}/nuclei-targets")
    def export_nuclei_targets(domain: str):
        """Export live host URLs as a plain-text nuclei target list."""
        live = _read(_dir(domain) / "live_hosts.json", default=[])
        urls = sorted({h.get("url", "") for h in (live or []) if h.get("url")})
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(
            content="\n".join(urls),
            headers={"Content-Disposition": f'attachment; filename="{domain}-nuclei-targets.txt"'}
        )

    # ── Active validation (M09) ───────────────────────────────

    @app.get("/api/active/{domain}")
    def get_active_findings(domain: str):
        """Return M09 active_findings.json — confirmed vulns post-validation."""
        return _read(_dir(domain) / "active_findings.json", default=[])

    # ── Diff between scans (Étape 1.2) ────────────────────────

    @app.get("/api/diff/{domain}")
    def get_diff(domain: str, since: Optional[str] = Query(None)):
        """Return findings ``new`` since `since` (default: latest scan vs the
        one before it) and findings ``gone`` (present in `since` but not in
        the latest scan).

        Query params:
          since: scan_id to diff against. Defaults to the previous scan.

        Response:
          { "domain": ..., "current_scan_id": ..., "since_scan_id": ...,
            "new": [...findings...], "gone": [...findings...] }
        """
        if not is_valid_domain(domain):
            raise HTTPException(400, "invalid domain")
        scans = db.get_scans(domain)
        if not scans:
            raise HTTPException(404, "no scans for domain")
        current_scan_id = scans[0]["scan_id"]

        # "since" semantics: if the caller specifies one, only count as "new"
        # the findings whose first_seen is AFTER it. Otherwise default to
        # diff_findings() which compares against the most recent prior scan.
        if since:
            import sqlalchemy as _sa
            from core import orm as _orm
            ft = _orm.Finding.__table__
            st = _orm.Scan.__table__

            # Subquery: started_at of the `since` scan.
            since_started = _sa.select(st.c.started_at).where(
                st.c.scan_id == since
            ).scalar_subquery()
            # Sub-subquery: scan_ids strictly after `since` on this domain.
            later_scans = _sa.select(st.c.scan_id).where(
                st.c.domain == domain,
                st.c.started_at > since_started,
            ).scalar_subquery()

            new_stmt = _sa.select(ft).where(
                ft.c.domain == domain,
                ft.c.first_seen_scan_id.is_not(None),
                ft.c.first_seen_scan_id != since,
                ft.c.last_seen_scan_id.is_not(None),
                ft.c.first_seen_scan_id.in_(later_scans),
            )
            gone_stmt = _sa.select(ft).where(
                ft.c.domain == domain,
                ft.c.last_seen_scan_id == since,
                ft.c.last_seen_scan_id != current_scan_id,
            )
            with db.engine.connect() as _c:
                new_rows = list(_c.execute(new_stmt))
                gone_rows = list(_c.execute(gone_stmt))
            new = [db._decode_finding_row(r) for r in new_rows]
            gone = [db._decode_finding_row(r) for r in gone_rows]
            since_scan_id = since
        else:
            new, gone = db.diff_findings(domain, current_scan_id)
            since_scan_id = db.get_previous_scan_id(domain, current_scan_id)

        return {
            "domain":          domain,
            "current_scan_id": current_scan_id,
            "since_scan_id":   since_scan_id,
            "new":             new,
            "gone":            gone,
        }

    # ── Scan management ───────────────────────────────────────

    @app.get("/api/scan/modes")
    def scan_modes():
        return {
            "modes":   list(MODES.keys()),
            "modules": [
                {"id": mid, "label": label, "desc": desc, "deps": deps}
                for (mid, label, desc, deps) in MODULE_CATALOG
            ],
            "allow_remote": allow_remote,
            "wildcards": wildcards if allow_remote else None,
        }

    @app.post("/api/scan/start")
    def scan_start(request: Request, payload: dict = Body(...)):
        target  = (payload.get("target") or "").strip()
        mode    = (payload.get("mode") or "full").strip()
        modules = payload.get("modules") or None
        if not target:
            raise HTTPException(400, "target is required")
        run, err = scan_mgr.start(target, mode, modules=modules)
        if err:
            raise HTTPException(400, err)
        # Audit
        u = getattr(request.state, "user", {})
        log_action(db, u.get("username"), _request_ip(request),
                   ACTIONS.SCAN_STARTED, target=target,
                   details={"mode": mode, "modules": modules, "run_id": run.id})
        return run.to_dict()

    @app.get("/api/scan/runs")
    def scan_runs():
        return scan_mgr.list_runs()

    @app.get("/api/scan/status/{run_id}")
    def scan_status(run_id: str):
        run = scan_mgr.get(run_id)
        if not run:
            raise HTTPException(404, "no such run")
        return run.to_dict(include_log=True)

    @app.post("/api/scan/stop/{run_id}")
    def scan_stop(run_id: str, request: Request):
        err = scan_mgr.stop(run_id)
        if err:
            raise HTTPException(400, err)
        run = scan_mgr.get(run_id)
        u = getattr(request.state, "user", {})
        log_action(db, u.get("username"), _request_ip(request),
                   ACTIONS.SCAN_STOPPED, target=(run.target if run else None),
                   details={"run_id": run_id})
        return run.to_dict() if run else {"id": run_id, "stopped": True}

    @app.get("/api/scan/active/{target}")
    def scan_active(target: str):
        rid = scan_mgr.active_for_target(target)
        return {"target": target, "active_run_id": rid}

    # ── Frontend ──────────────────────────────────────────────

    frontend_dir  = Path(__file__).parent.parent / "frontend"
    frontend_dist = frontend_dir / "dist"
    serve_dir = frontend_dist if (frontend_dist / "index.html").exists() \
                else (frontend_dir if (frontend_dir / "index.html").exists() else None)

    # Force-refresh: no-store on dashboard HTML so users always pick up new UI.
    # ── Config: read / update / reload ───────────────────────────
    # YAML config is the single source of truth. The dashboard exposes it
    # so the operator can tune toggles, caps and timeouts without dropping
    # to a terminal. Every spawned scan re-reads the file on startup, so
    # /reload only refreshes the dashboard process's own view (output_dir,
    # log_level, etc.) — but all NEW scans pick up changes automatically.
    #
    # We use ruamel.yaml (round-trip mode) instead of PyYAML so saving from
    # the UI doesn't wipe the operator's comments. The disk file keeps its
    # original structure; only the values that actually changed are mutated
    # in place.
    from ruamel.yaml import YAML as _RuamelYAML
    _rt_yaml = _RuamelYAML()
    _rt_yaml.preserve_quotes = True
    _rt_yaml.indent(mapping=2, sequence=4, offset=2)
    _rt_yaml.width = 120

    @app.get("/api/config")
    def get_config():
        try:
            data = _rt_yaml.load(config.path.read_text()) or {}
            # Round-trip through plain dict so JSON serialisation works
            # (ruamel CommentedMap is JSON-friendly but lists of plain
            # strings are most predictable).
            return json.loads(json.dumps(data))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Cannot read config: {e}")

    def _merge_in_place(target, payload):
        """Mutate `target` (ruamel CommentedMap) so its values match `payload`,
        keeping comments and key order intact. Adds new keys appended to the
        end, removes keys absent from `payload`."""
        # Add or update
        for k, v in payload.items():
            if isinstance(v, dict) and isinstance(target.get(k), dict):
                _merge_in_place(target[k], v)
            else:
                target[k] = v
        # Remove keys not in payload
        for k in list(target.keys()):
            if k not in payload:
                del target[k]

    @app.put("/api/config")
    def put_config(request: Request, payload: dict = Body(...)):
        # 1. Backup current config (single rolling .bak — overwritten each
        #    save; sufficient for "oops" recovery). For deep history, use git.
        bak_path = config.path.with_suffix(config.path.suffix + ".bak")
        try:
            bak_path.write_text(config.path.read_text())
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Cannot write backup: {e}")

        # 2. Load existing YAML in round-trip mode (preserves comments +
        #    structure), apply the payload diff, write back.
        try:
            existing = _rt_yaml.load(config.path.read_text()) or {}
            _merge_in_place(existing, payload)
            buf = StringIO()
            _rt_yaml.dump(existing, buf)
            yaml_text = buf.getvalue()
            # 3. Sanity: re-parse with strict pyyaml to catch any corruption.
            yaml.safe_load(yaml_text)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")

        try:
            config.path.write_text(yaml_text)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Cannot write config: {e}")

        u = getattr(request.state, "user", {})
        log_action(db, u.get("username"), _request_ip(request),
                   ACTIONS.CONFIG_UPDATED,
                   details={"keys": sorted(list(payload.keys()))})
        return {"ok": True, "backup": str(bak_path)}

    @app.post("/api/config/reload")
    def reload_config(request: Request):
        try:
            config.reload()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Reload failed: {e}")
        u = getattr(request.state, "user", {})
        log_action(db, u.get("username"), _request_ip(request),
                   ACTIONS.CONFIG_RELOADED)
        return {"ok": True, "path": str(config.path)}

    @app.middleware("http")
    async def no_cache_ui(request, call_next):
        resp = await call_next(request)
        if request.url.path.startswith("/ui") or request.url.path == "/":
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Expires"] = "0"
        return resp

    if serve_dir:
        app.mount("/ui", StaticFiles(directory=str(serve_dir), html=True), name="frontend")

    @app.get("/")
    def root():
        # Trailing slash matters: the index.html loads scripts via relative
        # paths (api.js, *.jsx, styles.css). Without /, the browser resolves
        # them at the parent level and gets 404s → blank screen.
        return RedirectResponse(url="/ui/")

    @app.get("/favicon.ico")
    def favicon():
        # Browsers auto-request /favicon.ico at the site root regardless of
        # the <link rel="icon"> in the HTML — serve the SVG to silence 404s.
        if serve_dir:
            svg_path = serve_dir / "favicon.svg"
            if svg_path.is_file():
                return FileResponse(str(svg_path), media_type="image/svg+xml")
        raise HTTPException(404, "favicon not configured")

    # ── Auth wiring (must come AFTER all routes are registered so the
    # global auth middleware and the role gate see every endpoint) ──
    install_users_routes(app, db)
    install_audit_routes(app, db)
    install_orgs_routes(app, db)
    install_attack_surface_routes(app, db)
    install_cve_routes(app, db)
    install_auth(app, db, str(db.db_path))

    return app
