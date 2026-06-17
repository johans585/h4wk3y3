"""
Argus V2 — CVE intelligence routes.

GET endpoints, user-level (lecture).

  GET  /api/cves                        list with filters + counts
  GET  /api/cves/stats                  global counters (page header)
  GET  /api/cves/vendors                vendor list with counts (filter dropdown)
  GET  /api/cves/{id}                   detail + cve_matches
  POST /api/cves/pull                   trigger m15 feeds pull (admin only)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request, Depends

from core import cves as C
from dashboard.backend.auth_routes import require_role


def install_cve_routes(app: FastAPI, db) -> None:

    @app.get("/api/cves")
    def cves_list(
        kev_only:     bool             = Query(False),
        ransomware:   bool             = Query(False),
        min_cvss:     Optional[float]  = Query(None, ge=0, le=10),
        min_epss:     Optional[float]  = Query(None, ge=0, le=1),
        vendor:       Optional[str]    = Query(None),
        search:       Optional[str]    = Query(None),
        has_template: Optional[bool]   = Query(None),
        has_matches:  Optional[bool]   = Query(None),
        sort:         str              = Query("epss"),
        limit:        int              = Query(100, ge=1, le=500),
        offset:       int              = Query(0,   ge=0),
    ):
        return C.list_cves(
            db,
            kev_only=kev_only,
            ransomware=ransomware,
            min_cvss=min_cvss,
            min_epss=min_epss,
            vendor=vendor,
            search=search,
            has_template=has_template,
            has_matches=has_matches,
            sort=sort,
            limit=limit,
            offset=offset,
        )

    @app.get("/api/cves/stats")
    def cves_stats():
        return C.cve_global_stats(db)

    @app.get("/api/cves/vendors")
    def cves_vendors(limit: int = Query(50, ge=1, le=200)):
        return C.list_vendors(db, limit=limit)

    @app.get("/api/cves/{cve_id}")
    def cves_show(cve_id: str):
        cve = C.get_cve(db, cve_id)
        if cve is None:
            raise HTTPException(404, "cve not found")
        matches = C.list_matches_for_cve(db, cve_id)
        return {
            "cve":     cve,
            "matches": matches,
        }

    @app.post("/api/cves/pull")
    def cves_pull(
        recent_only: bool = Query(True,
            description="Fast mode (default): pull only KEV+EPSS+nuclei+NVD-recent "
                        "(~10 MB, ~10s). Set to false for a full year-feeds pull "
                        "(~60 MB, ~30s)."),
        years: Optional[str] = Query(None,
            description="Comma-separated NVD years (full mode only), e.g. '2024,2025,2026'."),
        correlate: bool = Query(True,
            description="Auto-run m17 correlator after pull so new CVEs immediately "
                        "produce matches against live_hosts. Default true."),
        _admin: dict = Depends(require_role("admin")),
    ):
        """Synchronous m15 pull (+ optional correlate). Returns combined stats.

        Admin-only: enforced explicitly here (not just via the middleware
        default-deny fallback) so this stays correct if path→role mapping
        changes."""
        from modules.m15_cve_feeds  import CVEFeedsModule
        from modules.m17_cve_correlator import CVECorrelatorModule
        parsed_years: Optional[list[int]] = None
        if years:
            try:
                parsed_years = [int(y.strip()) for y in years.split(",") if y.strip()]
            except ValueError:
                raise HTTPException(400, "years must be a comma list of integers")
        log = logging.getLogger("m15-via-api")
        pull_stats: dict = {}
        corr_stats: dict = {}
        try:
            pull_mod = CVEFeedsModule(
                engine      = db.engine,
                years       = parsed_years,
                with_nvd    = True,
                recent_only = recent_only,
                log         = log,
            )
            pull_stats = pull_mod.run()
        except Exception:
            log.exception("CVE feed pull failed")
            raise HTTPException(500, "CVE feed pull failed (see server logs)")

        if correlate:
            try:
                corr_log = logging.getLogger("m17-via-api")
                corr_mod = CVECorrelatorModule(engine=db.engine, log=corr_log)
                corr_stats = corr_mod.run()
            except Exception as e:
                log.exception("CVE correlator failed after pull")
                # Non-fatal : the pull succeeded, just flag the failure
                corr_stats = {"error": str(e)}

        return {"pull": pull_stats, "correlate": corr_stats}

    @app.post("/api/cves/correlate")
    def cves_correlate(
        limit_cves: Optional[int] = Query(None,
            description="Cap number of CVE evaluated (debug). Default: all."),
        _admin: dict = Depends(require_role("admin")),
    ):
        """Synchronous m17 correlator (no pull). Admin-only. For when CVE
        catalog is fresh but live_hosts has changed (new scan, new
        constituent imported)."""
        from modules.m17_cve_correlator import CVECorrelatorModule
        log = logging.getLogger("m17-via-api")
        try:
            mod = CVECorrelatorModule(engine=db.engine, limit_cves=limit_cves, log=log)
            return mod.run()
        except Exception:
            log.exception("CVE correlator failed")
            raise HTTPException(500, "CVE correlation failed (see server logs)")

    @app.post("/api/cves/{cve_id}/validate")
    def cves_validate(cve_id: str, request: Request,
                      _admin: dict = Depends(require_role("admin"))):
        """m18 validator : runs nuclei -t <template> against internal in-scope
        matches of this CVE. Upgrades hits to validation_state='validated'
        with confidence=0.95. Synchronous (1-5 min). Returns stats."""
        from modules.m18_cve_validator import CVEValidatorModule
        # OPSEC: load rate_limit from h4wk3y3.yaml nuclei section
        try:
            from core.config import ArgusConfig
            cfg = ArgusConfig()
            rate_limit       = int(cfg.get("nuclei", "rate_limit", default=10))
            timeout_per_req  = int(cfg.get("nuclei", "timeout",    default=10))
            retries          = int(cfg.get("nuclei", "retries",    default=1))
            wall_timeout_sec = int(cfg.get("nuclei", "module_timeout_sec", default=600))
        except Exception:
            rate_limit, timeout_per_req, retries, wall_timeout_sec = 10, 10, 1, 600

        # validated_by = current authenticated user (best-effort)
        u = getattr(request.state, "user", None)
        validated_by = (u or {}).get("username", "argus-m18") if isinstance(u, dict) else "argus-m18"

        log = logging.getLogger("m18-via-api")
        try:
            mod = CVEValidatorModule(
                engine            = db.engine,
                rate_limit        = rate_limit,
                timeout_per_req   = timeout_per_req,
                retries           = retries,
                wall_timeout_sec  = wall_timeout_sec,
                validated_by      = validated_by,
                log               = log,
            )
            result = mod.validate(cve_id)
        except Exception:
            log.exception("CVE validator failed")
            raise HTTPException(500, "CVE validation failed (see server logs)")

        if "error" in result:
            raise HTTPException(400, result["error"])
        return result
