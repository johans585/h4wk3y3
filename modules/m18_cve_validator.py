"""
Argus V2 — m18 : CVE validator (nuclei).

Lance le template nuclei associé à une CVE sur les `cve_matches` internal
in-scope, parse les findings, et upgrade les rows validées :
  validation_state = 'validated', confidence = 0.95, validated_at,
  evidence (matched-at + extracted-results).

Les hosts probés sans hit restent en `candidate` (on ne devine pas
"false_positive" automatiquement — un échec nuclei peut être un faux
négatif réseau).

OPSEC :
  - Lit `nuclei.rate_limit` depuis config (default 10 req/s).
  - Force rate_limit = 5 si --stealth.
  - module_timeout_sec = wall-clock cap (default 600s = 10 min).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import sqlalchemy as sa


# Base directory where nuclei templates live. `cves.nuclei_template`
# is stored as a relative path like "http/cves/2021/CVE-2021-41773.yaml".
DEFAULT_NUCLEI_TEMPLATES_DIR = "/home/kali/.local/nuclei-templates"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_template(template_rel: str,
                        base_dir: str = DEFAULT_NUCLEI_TEMPLATES_DIR) -> Optional[str]:
    """Try to resolve `cves.nuclei_template` to an absolute path on disk.
    Returns None if not found."""
    if not template_rel:
        return None
    candidates = [
        os.path.join(base_dir, template_rel),
        # Backup : check network/cves path too (m15 currently indexes http/cves only)
        os.path.join(base_dir, template_rel.replace("http/cves", "network/cves", 1)),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def _target_from_asset(asset_url: str | None, asset_host: str | None) -> Optional[str]:
    """Build a target URL nuclei can probe. Prefer asset_url (full URL with
    scheme), fall back to https://<host>."""
    if asset_url and "://" in asset_url:
        # Strip trailing slash for consistency
        return asset_url.rstrip("/")
    if asset_host:
        return f"https://{asset_host}"
    return None


class CVEValidatorModule:
    """Standalone validator for a single CVE."""

    def __init__(
        self,
        engine,
        nuclei_dir:        str = DEFAULT_NUCLEI_TEMPLATES_DIR,
        rate_limit:        int = 10,
        timeout_per_req:   int = 10,
        retries:           int = 1,
        wall_timeout_sec:  int = 600,
        validated_by:      str = "argus-m18",
        log:               logging.Logger | None = None,
    ) -> None:
        self.engine            = engine
        self.nuclei_dir        = nuclei_dir
        self.rate_limit        = rate_limit
        self.timeout_per_req   = timeout_per_req
        self.retries           = retries
        self.wall_timeout_sec  = wall_timeout_sec
        self.validated_by      = validated_by
        self.log               = log or logging.getLogger("m18")

    # ────────────────────────────────────────────────────────────────────
    # DB queries
    # ────────────────────────────────────────────────────────────────────

    def _load_cve(self, cve_id: str) -> Optional[dict]:
        with self.engine.connect() as c:
            row = c.execute(sa.text("""
                SELECT cve_id, nuclei_template, vendor, description, kev_flag, kev_ransomware
                  FROM cves WHERE cve_id = :id
            """), {"id": cve_id}).fetchone()
        if not row:
            return None
        return dict(row._mapping)

    def _load_internal_matches(
        self, cve_id: str, match_ids: list[int] | None,
    ) -> list[dict]:
        """Load matches internal in-scope (attributed_apex not null)."""
        sql = """
            SELECT id, asset_host, asset_url, attributed_apex, organisation_id,
                   match_method, validation_state
              FROM cve_matches
             WHERE cve_id = :cve_id
               AND match_source = 'internal'
               AND attributed_apex IS NOT NULL
        """
        params: dict = {"cve_id": cve_id}
        if match_ids:
            sql += " AND id = ANY(:ids)"
            params["ids"] = match_ids
        with self.engine.connect() as c:
            rows = c.execute(sa.text(sql), params).fetchall()
        return [dict(r._mapping) for r in rows]

    def _upgrade_match(
        self, match_id: int, evidence: dict,
    ) -> None:
        """Upgrade a match to validated state."""
        now = _now_iso()
        with self.engine.begin() as c:
            c.execute(sa.text("""
                UPDATE cve_matches
                   SET validation_state = 'validated',
                       confidence       = 0.95,
                       validated_at     = :now,
                       validated_by     = :by,
                       evidence         = :ev,
                       last_seen_at     = :now
                 WHERE id = :id
            """), {
                "id":  match_id,
                "now": now,
                "by":  self.validated_by,
                "ev":  json.dumps(evidence, ensure_ascii=False),
            })

    # ────────────────────────────────────────────────────────────────────
    # Nuclei runner
    # ────────────────────────────────────────────────────────────────────

    def _run_nuclei(
        self,
        template_path: str,
        targets:       list[str],
    ) -> list[dict]:
        """Run nuclei -t <template> -l <targets.txt> -jsonl -silent.
        Returns parsed list of finding dicts."""
        nuclei_bin = shutil.which("nuclei")
        if not nuclei_bin:
            raise RuntimeError("nuclei binary not found in PATH")

        with tempfile.TemporaryDirectory() as tmp:
            targets_file = os.path.join(tmp, "targets.txt")
            output_file  = os.path.join(tmp, "out.jsonl")
            with open(targets_file, "w") as f:
                f.write("\n".join(targets) + "\n")

            cmd = [
                nuclei_bin,
                "-t",          template_path,
                "-l",          targets_file,
                "-o",          output_file,
                "-jsonl",
                "-silent",
                "-disable-update-check",
                "-rate-limit", str(self.rate_limit),
                "-timeout",    str(self.timeout_per_req),
                "-retries",    str(self.retries),
                # Surface-only OPSEC : pas de fuzz/intrusive même via template
                "-exclude-tags", "dos,intrusive,fuzz",
            ]

            self.log.info(f"  nuclei cmd: {' '.join(cmd[:9])} ... ({len(targets)} targets)")
            t0 = time.time()
            try:
                subprocess.run(
                    cmd,
                    timeout=self.wall_timeout_sec,
                    capture_output=True,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                self.log.warning(f"  ⚠ nuclei timeout @ {self.wall_timeout_sec}s")
            elapsed = time.time() - t0

            # Parse jsonl
            findings: list[dict] = []
            if os.path.isfile(output_file):
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            self.log.info(f"  ✓ nuclei {len(findings)} finding(s) in {elapsed:.1f}s")
            return findings

    # ────────────────────────────────────────────────────────────────────
    # Orchestrator
    # ────────────────────────────────────────────────────────────────────

    def validate(self, cve_id: str, match_ids: list[int] | None = None) -> dict:
        """Validate a single CVE against its internal matches.

        Returns stats dict: {validated, targets, findings, elapsed_seconds, ...}
        """
        t0 = time.time()
        self.log.info("═" * 64)
        self.log.info(f"  m18 validator : {cve_id}")
        self.log.info("═" * 64)

        cve = self._load_cve(cve_id)
        if cve is None:
            return {"error": f"CVE {cve_id} not found in catalog"}

        template_rel = cve.get("nuclei_template")
        if not template_rel:
            return {"error": f"no nuclei template for {cve_id}"}

        template_abs = _resolve_template(template_rel, self.nuclei_dir)
        if not template_abs:
            return {"error": f"template not found on disk: {template_rel}"}
        self.log.info(f"▶ template : {template_abs}")

        matches = self._load_internal_matches(cve_id, match_ids)
        if not matches:
            return {"error": "no internal in-scope matches to validate"}

        # Build target list (dedupe by URL)
        target_to_matches: dict[str, list[int]] = {}
        for m in matches:
            target = _target_from_asset(m.get("asset_url"), m.get("asset_host"))
            if not target:
                continue
            target_to_matches.setdefault(target, []).append(m["id"])
        targets = sorted(target_to_matches.keys())
        if not targets:
            return {"error": "no resolvable targets from matches"}
        self.log.info(f"▶ targets  : {len(targets)} unique URLs covering {len(matches)} matches")

        # Run nuclei
        findings = self._run_nuclei(template_abs, targets)

        # Map findings → match_ids → upgrade
        validated_match_ids: set[int] = set()
        for f in findings:
            host = f.get("host") or f.get("matched-at", "").split("/")[0] if f.get("matched-at") else None
            # Try multiple matching strategies
            matched_target: Optional[str] = None
            if host:
                # nuclei's `host` is the input target (e.g., 'https://www.una.bj')
                # may have trailing slash variations
                for t in targets:
                    if t == host or t.rstrip("/") == host.rstrip("/"):
                        matched_target = t
                        break
            # Fallback : try via matched-at hostname
            if not matched_target:
                m_at = f.get("matched-at") or f.get("matched_at")
                if m_at:
                    try:
                        h = urlparse(m_at).hostname
                        for t in targets:
                            if h and h == urlparse(t).hostname:
                                matched_target = t
                                break
                    except Exception:
                        pass
            if not matched_target:
                self.log.warning(f"  ⚠ couldn't map finding host={host} to a target")
                continue

            for mid in target_to_matches[matched_target]:
                if mid in validated_match_ids:
                    continue
                validated_match_ids.add(mid)
                evidence = {
                    "validated_via":      "nuclei",
                    "template":           template_rel,
                    "matched_at":         f.get("matched-at") or f.get("matched_at"),
                    "extracted_results":  f.get("extracted-results") or f.get("extracted_results"),
                    "info":               f.get("info"),
                    "type":               f.get("type"),
                }
                self._upgrade_match(mid, evidence)

        stats = {
            "cve_id":            cve_id,
            "template":          template_rel,
            "targets":           len(targets),
            "matches_considered": len(matches),
            "findings":          len(findings),
            "validated":         len(validated_match_ids),
            "elapsed_seconds":   round(time.time() - t0, 1),
        }
        self.log.info("═" * 64)
        self.log.info(f"  ✔ validated {stats['validated']}/{stats['matches_considered']} "
                      f"matches ({stats['findings']} nuclei findings) in {stats['elapsed_seconds']}s")
        self.log.info("═" * 64)
        return stats
