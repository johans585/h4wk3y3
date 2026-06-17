"""
Argus V2 — Persistence layer (Postgres-only).

Toutes les queries passent par SQLAlchemy Core contre les tables ORM
définies dans ``core/orm.py``. Le schéma est géré par Alembic ; ArgusDB
ne fait plus de DDL.

Toutes les opérations passent par ``self.engine`` (``with self._begin()`` /
``engine.connect()``). Il n'y a plus de connexion DBAPI maintenue à vie.
"""

import hashlib
import json
from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.exc import IntegrityError

from core.models import Finding
from core import orm


# Fingerprint cap on evidence string — huge bodies (HTML, dumps) would dominate
# the hash input, dilute the canonical key, and make dedup pointless. 4 KB is
# enough to disambiguate distinct findings without making the hash unstable
# across cosmetic whitespace edits in long evidence blobs.
_EVIDENCE_HASH_LEN = 4000

# Finding types where (domain, type, url) IS the identity — the evidence
# string can vary between modules (different wording of the same fact) but
# the underlying observation is identical. Two modules detecting these
# converge to a single row at save time; the secondary modules are recorded
# via `metadata.detected_by` so we keep defence-in-depth without bloating
# findings.json with cosmetic dupes.
#
# Why keep the redundancy at all: a single point of failure on safety-critical
# checks (.env leak, exposed bucket, JWT alg=none, …) is worse than a
# duplicate row. m09 and m14 both probe `.env*` on purpose — if one times
# out / scope-drops / silently swallows an aiohttp error, the other still
# emits and the finding survives.
ATOMIC_FINDING_TYPES: set[str] = {
    "active_file_exposure",  # m09 + m14 both probe .env / .git / ...
    "cloud_bucket",           # m09 cloud probe; could be detected elsewhere
    "jwt_weakness",           # m09 inspects headers; m11 inspects JS tokens
    "subdomain_takeover",     # m06 nuclei takeover templates
    "service_exposed",        # m07 ports — IP+port identity
    "origin_ip_leak",         # m07 cdncheck
    # NB: email_spoofable is intentionally NOT atomic. SPF, DMARC and DKIM are
    # three distinct, co-existing issues on the same domain — collapsing them by
    # (domain,type,url) silently dropped two of three (and could drop the HIGH
    # ones in favour of a MEDIUM, last-write-wins). They are disambiguated via
    # the `discriminant` arg to finding_fingerprint (metadata.record/check).
}


def finding_fingerprint(domain: str, ftype: str,
                        url: Optional[str], evidence: Optional[str],
                        discriminant: Optional[str] = None) -> str:
    """Deterministic dedup key for findings across scans.

    Composed of `(domain, type, url, [discriminant], sha256-prefix(evidence))`.
    Two findings sharing this key are considered the same observation —
    re-running a scan upserts in place instead of creating a duplicate row.

    For ``ATOMIC_FINDING_TYPES`` we drop the evidence component: two modules
    that observe the same exposed asset (e.g. `/.env`) produce identical
    fingerprints regardless of how each formats the evidence string. See
    ``ArgusDB.save_finding`` for the merge logic that preserves the FIRST
    writer's evidence and records secondary modules in metadata.

    ``discriminant`` (optional) is a stable sub-identity for finding classes
    where several legitimately-distinct findings share (domain, type, url) and
    may even share identical evidence — e.g. SPF/DMARC/DKIM posture (passed as
    metadata.record / metadata.check). When empty the key format is unchanged,
    so fingerprints for every other finding type are byte-for-byte identical to
    before (no cross-scan duplication regression).
    """
    if ftype in ATOMIC_FINDING_TYPES:
        h = "atomic"
    else:
        ev = (evidence or "")[:_EVIDENCE_HASH_LEN]
        h = hashlib.sha256(ev.encode("utf-8", errors="replace")).hexdigest()[:16]
    disc = (discriminant or "").strip()
    if disc:
        return f"{domain}|{ftype}|{url or ''}|{disc}|{h}"
    return f"{domain}|{ftype}|{url or ''}|{h}"


_SEVERITY_RANK = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def _max_severity(a: Optional[str], b: Optional[str]) -> str:
    """Return the higher-severity label of two strings, default 'info'."""
    ra = _SEVERITY_RANK.get((a or "").lower(), 0)
    rb = _SEVERITY_RANK.get((b or "").lower(), 0)
    return (a if ra >= rb else b) or "info"


def _pg_safe_text(s: Optional[str]) -> Optional[str]:
    """Strip NUL bytes — Postgres TEXT/VARCHAR rejects them.

    Findings sometimes carry binary blobs in `evidence` (e.g. raw bytes
    from /.DS_Store, weird favicon dumps, etc.). The replacement is
    lossy on purpose: we'd rather drop NULs than fail the insert.
    Keeps everything else (UTF-8 multibyte, control chars, …).
    """
    if s is None:
        return None
    if "\x00" not in s:
        return s
    return s.replace("\x00", "")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Data directory for sibling files (.session_secret, .first_admin).
# Postgres-only runtime n'a plus de fichier DB on-disk, mais on garde
# ce sentier comme **anchor** : ``self.db_path.parent`` reste ``./data/``,
# le dossier où les callers (auth bootstrap) déposent leurs secrets.
_DATA_DIR_SENTINEL = Path("./data/argus.db").resolve()


class ArgusDB:
    """Postgres-backed persistence with diff tracking.

    Must be constructed with a pre-built SQLAlchemy ``engine`` (typically
    via ``core.db_engine.build_engine(config)``). The schema must already
    exist — production runs ``alembic upgrade head``, tests rely on the
    conftest ``pg_engine`` fixture which calls
    ``Base.metadata.create_all`` once per session.
    """

    def __init__(self, *, engine: Engine):
        self.engine = engine
        # Anchor pour ``self.db_path.parent`` → ``./data/`` (utilisé par
        # ``get_or_create_session_secret`` et ``ensure_super_admin_bootstrap``
        # pour placer les fichiers d'auth à côté du runtime).
        self.db_path = _DATA_DIR_SENTINEL

    # ── Helpers ───────────────────────────────────────────────

    def _begin(self):
        """Open an autocommit-style transactional connection.

        Use as ``with self._begin() as c: c.execute(...)``. Commits on exit,
        rolls back on exception. Centralised so behaviour stays consistent
        across methods.
        """
        return self.engine.begin()

    # ── Scans ─────────────────────────────────────────────────

    def create_scan(self, scan_id: str, domain: str) -> None:
        """Open a new scan row. Does NOT purge previous findings/hosts.

        Findings & live_hosts are kept across scans so the diff engine can
        tell which entries are *new* (this scan introduced them) and which
        are *gone* (last seen in the previous scan but not this one).
        Re-creating a scan with the same scan_id overwrites the timestamp
        (replays during tests).
        """
        t = orm.Scan.__table__
        with self._begin() as c:
            # Portable INSERT-OR-UPDATE via delete + insert (low volume; one
            # row per scan call). Avoids dialect-specific ON CONFLICT syntax.
            c.execute(sa.delete(t).where(t.c.scan_id == scan_id))
            c.execute(sa.insert(t).values(
                scan_id=scan_id, domain=domain, started_at=_now(),
                status="running",
            ))

    def ensure_target(self, apex: str) -> None:
        """Register an apex in the ``targets`` table if not already present.

        Scanning ``h4wk3y3.py -t <apex>`` should make the domain appear in the
        dashboard's Targets / Attack-Surface / Org views and give the post-scan
        attribution step something to resolve against — otherwise the findings
        are orphaned from the asset inventory (targets stayed empty unless the
        apex was pre-imported via import_data.py / `argus org link`).

        Never overwrites an existing row: it may carry an org link or a
        per-target scope override we must preserve.
        """
        apex = (apex or "").lower().strip().strip(".")
        if not apex:
            return
        t = orm.Target.__table__
        with self._begin() as c:
            exists = c.execute(
                sa.select(t.c.apex).where(t.c.apex == apex)
            ).first()
            if exists:
                return
            c.execute(sa.insert(t).values(apex=apex, created_at=_now()))

    def finish_scan(self, scan_id: str, stats: dict,
                    status: str = "done") -> None:
        """Close a scan row. ``status`` is ``done`` for a clean finish or
        ``partial`` when the pipeline was interrupted (the finalize-in-finally
        path still persists whatever was gathered so the scan never stays stuck
        on ``running`` with NULL stats)."""
        t = orm.Scan.__table__
        with self._begin() as c:
            c.execute(sa.update(t).where(t.c.scan_id == scan_id).values(
                finished_at=_now(),
                stats=json.dumps(stats),
                status=status,
            ))

    def abandon_stale_scans(self, older_than_hours: float = 6.0) -> int:
        """Mark scans stuck on ``running`` for more than ``older_than_hours`` as
        ``abandoned``.

        Covers the case the finalize-in-finally can't: a hard kill (SIGKILL /
        power loss / OOM) leaves the row stuck on ``running`` forever, poisoning
        /api/scans and the "active scan" UI. The age threshold makes it safe to
        call at startup even while a *legitimate* scan runs concurrently — a real
        scan never runs 6h, but a crashed orphan's row is older. Returns the
        number of rows fixed.
        """
        from datetime import datetime, timedelta, timezone as _tz
        cutoff = (datetime.now(_tz.utc) - timedelta(hours=older_than_hours)).isoformat()
        t = orm.Scan.__table__
        with self._begin() as c:
            res = c.execute(
                sa.update(t)
                  .where(t.c.status == "running")
                  .where(t.c.started_at < cutoff)
                  .values(status="abandoned", finished_at=_now())
            )
            return res.rowcount or 0

    def get_scans(self, domain: Optional[str] = None) -> List[dict]:
        t = orm.Scan.__table__
        stmt = sa.select(t).order_by(t.c.started_at.desc())
        if domain:
            stmt = stmt.where(t.c.domain == domain)
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(stmt)]

    def latest_scan_id(self, domain: str) -> Optional[str]:
        """Most recent scan_id for `domain` (by started_at), or None."""
        t = orm.Scan.__table__
        with self.engine.connect() as c:
            r = c.execute(
                sa.select(t.c.scan_id)
                  .where(t.c.domain == domain)
                  .order_by(t.c.started_at.desc())
                  .limit(1)
            ).first()
            return r.scan_id if r else None

    def get_previous_scan_id(self, domain: str, current_scan_id: str) -> Optional[str]:
        """Return the scan immediately preceding `current_scan_id` chronologically.

        "Preceding" = ``started_at`` strictly earlier than the current scan's
        own `started_at` (we never want to diff against a future scan even
        if one happens to exist in the DB).
        """
        t = orm.Scan.__table__
        with self.engine.connect() as c:
            cur = c.execute(
                sa.select(t.c.started_at).where(t.c.scan_id == current_scan_id)
            ).first()
            if not cur:
                return None
            row = c.execute(
                sa.select(t.c.scan_id)
                  .where(t.c.domain == domain)
                  .where(t.c.scan_id != current_scan_id)
                  .where(t.c.started_at < cur.started_at)
                  .order_by(t.c.started_at.desc())
                  .limit(1)
            ).first()
            return row.scan_id if row else None

    # ── Subdomains ────────────────────────────────────────────

    def upsert_subdomains(self, scan_id: str, domain: str,
                          subdomains: List[str]) -> List[str]:
        """Insert subdomains, return list of NEW ones (not seen before).

        Iterates one INSERT per sub so we know precisely which ones were
        newly created via the IntegrityError signal. Volumes are low
        enough (hundreds, not millions) that this is fine.
        """
        if not subdomains:
            return []
        new_subs: List[str] = []
        now = _now()
        # Fallback attribution (= scan apex) so org-scoped views work even if
        # the post-scan _attribute_assets hook never runs (interrupted/timed-out
        # scan). The hook later refines this via longest-suffix resolution.
        # Mirrors save_finding's fallback; without it, an interrupted scan left
        # subdomains NULL-attributed → empty org attack-surface / 0 counts.
        fallback_apex = (domain or "").lower().strip().strip(".") or None
        t = orm.Subdomain.__table__
        with self._begin() as c:
            for sub in subdomains:
                try:
                    sp = c.begin_nested()  # SAVEPOINT — rollback only this row on dup
                    c.execute(sa.insert(t).values(
                        scan_id=scan_id, domain=domain,
                        subdomain=sub, first_seen=now,
                        attributed_apex=fallback_apex,
                    ))
                    sp.commit()
                    new_subs.append(sub)
                except IntegrityError:
                    sp.rollback()
        return new_subs

    def get_subdomains(self, domain: str) -> List[str]:
        t = orm.Subdomain.__table__
        with self.engine.connect() as c:
            rows = c.execute(
                sa.select(t.c.subdomain).where(t.c.domain == domain)
            )
            return [r.subdomain for r in rows]

    # ── Live hosts ────────────────────────────────────────────

    @staticmethod
    def _canonical_url(url: str) -> str:
        """Canonicalise a host URL for stable de-dup across scans.

        Lowercases scheme+host, drops the default port (:443 for https,
        :80 for http) and normalises an empty path to '/'. Without this the
        same host persists twice when the URL form drifts between scans
        (e.g. ``https://h:443`` from one scan vs ``https://h/`` from the next),
        leaving a stale row that the dashboard shows alongside the fresh one.
        """
        try:
            p = urlsplit(url)
        except Exception:
            return url
        if not p.scheme or not p.hostname:
            return url
        host = p.hostname.lower()
        port = p.port
        if port is not None and not (
            (p.scheme == "https" and port == 443)
            or (p.scheme == "http" and port == 80)
        ):
            host = f"{host}:{port}"
        # Canonical root = no trailing slash, so 'https://h', 'https://h/' and
        # 'https://h:443' all collapse to the same key (matches the bare-URL
        # form the probes and the rest of the codebase store).
        path = "" if p.path == "/" else p.path
        return urlunsplit((p.scheme.lower(), host, path, p.query, ""))

    def upsert_live_hosts(self, scan_id: str, domain: str,
                          hosts: List[dict]) -> int:
        """Persist live hosts with diff tracking.

        On UNIQUE(url) conflict we UPDATE in place: keep ``first_seen`` +
        ``first_seen_scan_id``, refresh the mutable fields and bump
        ``last_seen_scan_id`` to the current scan. New hosts get both
        first/last = current scan.
        """
        if not hosts:
            return 0
        now = _now()
        # Fallback attribution (= scan apex); see upsert_subdomains. Filled on
        # insert and back-filled on update only when still NULL, so the post-scan
        # _attribute_assets refinement is never clobbered.
        fallback_apex = (domain or "").lower().strip().strip(".") or None
        t = orm.LiveHost.__table__
        n = 0
        with self._begin() as c:
            for h in hosts:
                url = h.get("url")
                if not url:
                    continue
                url = self._canonical_url(url)
                techs = h.get("technologies") or []
                host_domain = h.get("domain") or domain

                existing = c.execute(
                    sa.select(t.c.first_seen, t.c.first_seen_scan_id)
                      .where(t.c.url == url)
                ).first()

                if existing:
                    first_seen = existing.first_seen
                    first_scan = existing.first_seen_scan_id or scan_id
                    c.execute(sa.update(t).where(t.c.url == url).values(
                        scan_id=scan_id, domain=host_domain,
                        status_code=h.get("status_code"),
                        title=h.get("title"),
                        technologies=json.dumps(techs) if techs else None,
                        waf=h.get("waf"), cname=h.get("cname"),
                        first_seen=first_seen,
                        first_seen_scan_id=first_scan,
                        last_seen_scan_id=scan_id,
                        attributed_apex=sa.func.coalesce(
                            t.c.attributed_apex, fallback_apex),
                    ))
                else:
                    c.execute(sa.insert(t).values(
                        scan_id=scan_id, domain=host_domain, url=url,
                        status_code=h.get("status_code"),
                        title=h.get("title"),
                        technologies=json.dumps(techs) if techs else None,
                        waf=h.get("waf"), cname=h.get("cname"),
                        first_seen=now,
                        first_seen_scan_id=scan_id,
                        last_seen_scan_id=scan_id,
                        attributed_apex=fallback_apex,
                    ))
                n += 1
        return n

    # ── Findings ──────────────────────────────────────────────

    def save_finding(self, finding: Finding, domain: str) -> None:
        """Upsert a finding keyed by ``fingerprint``.

        Mutates ``finding.id`` / ``finding.is_new`` to reflect the canonical
        DB state. See ``finding_fingerprint()`` for the dedup key.
        """
        d = finding.to_dict()
        scan_id = d.get("scan_id") or d["id"]
        # Strip NULs from any text field — Postgres TEXT rejects them, and
        # findings sometimes carry binary blobs in evidence (e.g. /.DS_Store).
        d["title"]    = _pg_safe_text(d.get("title"))
        d["url"]      = _pg_safe_text(d.get("url"))
        d["evidence"] = _pg_safe_text(d.get("evidence"))
        # Stable sub-identity for finding classes that put several distinct
        # findings on the same (domain,type,url) — e.g. email posture writes
        # metadata.check (m02: spf_unverified/dmarc_missing/...) or
        # metadata.record (m01: SPF/DMARC/DKIM). Without this, those collapse.
        _meta = d.get("metadata")
        _meta = _meta if isinstance(_meta, dict) else {}
        discriminant = _meta.get("check") or _meta.get("record")
        fp = finding_fingerprint(domain, d["type"], d["url"], d["evidence"],
                                 discriminant)

        # Attribution fallback: never leave a finding NULL-attributed at write
        # time. `domain` is the scan apex (mirrors the pipeline's own fallback,
        # cf. _attribute_assets), so org_stats — which counts findings by
        # `attributed_apex` — stays correct even if the best-effort post-scan
        # attribution step is skipped (tests) or fails (its except is silent).
        # The pipeline later refines this via longest-suffix resolution; we
        # therefore never clobber an already-resolved value below.
        fallback_apex = (domain or "").lower().strip().strip(".") or None

        t = orm.Finding.__table__
        meta_col = t.c.metadata   # SQL name kept as `metadata` despite the ORM alias

        with self._begin() as c:
            existing = c.execute(
                sa.select(t.c.id, t.c.first_seen_scan_id, t.c.module_source,
                          t.c.evidence, t.c.severity, t.c.confidence, meta_col,
                          t.c.scan_id, t.c.title, t.c.attributed_apex)
                  .where(t.c.fingerprint == fp)
            ).first()

            if existing:
                first_seen = existing.first_seen_scan_id or scan_id
                is_new = 1 if first_seen == scan_id else 0
                is_atomic = d["type"] in ATOMIC_FINDING_TYPES

                # For ATOMIC types, two modules independently confirming the
                # same observation (e.g. m09 + m14 on `.env`) must merge into
                # one row. We keep the FIRST writer's evidence/title and
                # record the secondary module in `metadata.detected_by`.
                # Without this, m14 would overwrite m09's redacted evidence
                # with its own less-friendly version. Severity/confidence
                # take the max of the two.
                #
                # We only merge when:
                #   - it's an atomic type, AND
                #   - existing row was written in the SAME scan as us (i.e.
                #     this is the intra-scan dedup case). Cross-scan updates
                #     should still refresh the evidence to whatever the
                #     latest run produced.
                same_scan      = (existing.scan_id == scan_id)
                different_mod  = (existing.module_source != d["module_source"])
                if is_atomic and same_scan and different_mod:
                    try:
                        existing_meta = json.loads(existing[6] or "{}")
                    except Exception:
                        existing_meta = {}
                    detected_by = list(existing_meta.get("detected_by") or
                                       [existing.module_source])
                    if d["module_source"] and d["module_source"] not in detected_by:
                        detected_by.append(d["module_source"])
                    existing_meta["detected_by"] = detected_by
                    # Carry over confirmed_by_count for downstream telemetry.
                    existing_meta["confirmed_by_count"] = len(detected_by)
                    new_severity   = _max_severity(existing.severity, d["severity"])
                    new_confidence = max(existing.confidence or 0.0,
                                         d.get("confidence") or 0.0)
                    c.execute(sa.update(t).where(t.c.id == existing.id).values({
                        # Keep existing module_source/evidence/title; just
                        # bump severity/confidence and mark last-seen.
                        "severity":            new_severity,
                        "confidence":          new_confidence,
                        meta_col:              _pg_safe_text(json.dumps(existing_meta)),
                        "last_seen_scan_id":   scan_id,
                        "attributed_apex":     existing.attributed_apex or fallback_apex,
                    }))
                    finding.id = existing.id
                    finding.is_new = bool(is_new)
                    return

                # Default upsert path — overwrite all fields, preserve
                # first_seen_scan_id.
                c.execute(sa.update(t).where(t.c.id == existing.id).values({
                    "scan_id":            scan_id,
                    "domain":             domain,
                    "type":               d["type"],
                    "severity":           d["severity"],
                    "confidence":         d["confidence"],
                    "title":              d["title"],
                    "url":                d["url"],
                    "evidence":           d["evidence"],
                    "module_source":      d["module_source"],
                    "tags":               _pg_safe_text(json.dumps(d["tags"])),
                    meta_col:             _pg_safe_text(json.dumps(d["metadata"])),
                    "timestamp":          d["timestamp"],
                    "is_new":             is_new,
                    "fingerprint":        fp,
                    "first_seen_scan_id": first_seen,
                    "last_seen_scan_id":  scan_id,
                    # Preserve a previously-resolved (refined) apex; only fall
                    # back to the scan domain when none was set yet.
                    "attributed_apex":    existing.attributed_apex or fallback_apex,
                }))
                finding.id = existing.id
                finding.is_new = bool(is_new)
            else:
                c.execute(sa.insert(t).values({
                    "id":                 d["id"],
                    "scan_id":            scan_id,
                    "domain":             domain,
                    "type":               d["type"],
                    "severity":           d["severity"],
                    "confidence":         d["confidence"],
                    "title":              d["title"],
                    "url":                d["url"],
                    "evidence":           d["evidence"],
                    "module_source":      d["module_source"],
                    "tags":               _pg_safe_text(json.dumps(d["tags"])),
                    meta_col:             _pg_safe_text(json.dumps(d["metadata"])),
                    "timestamp":          d["timestamp"],
                    "is_new":             1,
                    "fingerprint":        fp,
                    "first_seen_scan_id": scan_id,
                    "last_seen_scan_id":  scan_id,
                    "attributed_apex":    fallback_apex,
                }))
                finding.is_new = True

    @staticmethod
    def _decode_finding_row(r) -> dict:
        """Decode a findings row: JSON fields → real Python objects."""
        d = dict(r._mapping) if hasattr(r, "_mapping") else dict(r)
        for k in ("tags", "metadata"):
            v = d.get(k)
            if isinstance(v, str) and v:
                try:
                    d[k] = json.loads(v)
                except (ValueError, TypeError):
                    pass
        return d

    def get_findings(
        self,
        domain: Optional[str] = None,
        severity: Optional[str] = None,
        finding_type: Optional[str] = None,
        scan_id: Optional[str] = None,
        is_new: Optional[bool] = None,
        limit: int = 1000,
    ) -> List[dict]:
        t = orm.Finding.__table__
        stmt = sa.select(t)
        if domain:
            stmt = stmt.where(t.c.domain == domain)
        if severity:
            stmt = stmt.where(t.c.severity == severity)
        if finding_type:
            stmt = stmt.where(t.c.type == finding_type)
        if scan_id:
            stmt = stmt.where(t.c.last_seen_scan_id == scan_id)
        if is_new is not None:
            stmt = stmt.where(t.c.is_new == (1 if is_new else 0))
        stmt = stmt.order_by(t.c.timestamp.desc()).limit(int(limit))
        with self.engine.connect() as c:
            return [self._decode_finding_row(r) for r in c.execute(stmt)]

    # ── Diff (Étape 1.2) ──────────────────────────────────────

    def diff_findings(self, domain: str,
                      current_scan_id: str) -> Tuple[List[dict], List[dict]]:
        """Return ``(new, gone)`` findings for `current_scan_id` vs the
        immediately preceding scan on the same domain."""
        t = orm.Finding.__table__
        with self.engine.connect() as c:
            new_rows = list(c.execute(
                sa.select(t)
                  .where(t.c.domain == domain)
                  .where(t.c.first_seen_scan_id == current_scan_id)
            ))
            prev_id = self.get_previous_scan_id(domain, current_scan_id)
            gone_rows: list = []
            if prev_id:
                gone_rows = list(c.execute(
                    sa.select(t)
                      .where(t.c.domain == domain)
                      .where(t.c.last_seen_scan_id == prev_id)
                ))
        return (
            [self._decode_finding_row(r) for r in new_rows],
            [self._decode_finding_row(r) for r in gone_rows],
        )

    def diff_live_hosts(self, domain: str,
                        current_scan_id: str) -> Tuple[List[dict], List[dict]]:
        """Same idea as ``diff_findings`` but for live hosts."""
        t = orm.LiveHost.__table__
        with self.engine.connect() as c:
            new_rows = list(c.execute(
                sa.select(t)
                  .where(t.c.domain == domain)
                  .where(t.c.first_seen_scan_id == current_scan_id)
            ))
            prev_id = self.get_previous_scan_id(domain, current_scan_id)
            gone_rows: list = []
            if prev_id:
                gone_rows = list(c.execute(
                    sa.select(t)
                      .where(t.c.domain == domain)
                      .where(t.c.last_seen_scan_id == prev_id)
                ))
        return (
            [dict(r._mapping) for r in new_rows],
            [dict(r._mapping) for r in gone_rows],
        )

    # ── Module artefacts (Étape 0006) ─────────────────────────

    @staticmethod
    def _artefact_dedup_key(item: dict, key_fields: List[str]) -> str:
        """Stable per-item identity within (domain, module, kind).

        Hash of the selected key fields (sorted, JSON-encoded) so the same
        logical item upserts in place across scans — enabling diff tracking,
        exactly like ``finding_fingerprint`` does for findings.
        """
        payload = json.dumps(
            {k: item.get(k) for k in sorted(key_fields)},
            ensure_ascii=False, sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:24]

    def upsert_artefacts(self, scan_id: str, domain: str, module: str,
                         kind: str, items: List[dict],
                         key_fields: List[str]) -> int:
        """Upsert a batch of structured module items into ``scan_artefacts``.

        Each item is keyed by ``_artefact_dedup_key(item, key_fields)`` within
        (domain, module, kind). Re-runs UPDATE in place (refresh ``data`` +
        ``last_seen_scan_id``, keep ``first_seen_scan_id``); brand-new items get
        first=last=scan_id. Returns the number of items written.

        Mirrors ``upsert_live_hosts``: per-row SAVEPOINT so one bad item never
        rolls back the whole batch.
        """
        if not items:
            return 0
        now = _now()
        t = orm.ScanArtefact.__table__
        n = 0
        with self._begin() as c:
            for item in items:
                if not isinstance(item, dict):
                    continue
                dk = self._artefact_dedup_key(item, key_fields)
                try:
                    sp = c.begin_nested()  # SAVEPOINT — isolate per-item failure
                    existing = c.execute(
                        sa.select(t.c.id, t.c.first_seen_scan_id)
                          .where(t.c.domain == domain)
                          .where(t.c.module == module)
                          .where(t.c.kind == kind)
                          .where(t.c.dedup_key == dk)
                    ).first()
                    if existing:
                        c.execute(sa.update(t).where(t.c.id == existing.id).values(
                            scan_id=scan_id,
                            data=item,
                            last_seen_scan_id=scan_id,
                            first_seen_scan_id=existing.first_seen_scan_id or scan_id,
                            updated_at=now,
                        ))
                    else:
                        c.execute(sa.insert(t).values(
                            scan_id=scan_id, domain=domain, module=module,
                            kind=kind, dedup_key=dk, data=item,
                            first_seen_scan_id=scan_id, last_seen_scan_id=scan_id,
                            created_at=now, updated_at=now,
                        ))
                    sp.commit()
                    n += 1
                except IntegrityError:
                    sp.rollback()
        return n

    def has_artefacts(self, domain: str) -> bool:
        """True if the domain has ≥1 scan_artefacts row (any kind).

        Used by the dashboard to decide whether an *empty* per-kind result is
        authoritative (domain was scanned with artefact-writing code → the
        current scan genuinely found zero) or just means "pre-migration domain,
        fall back to the legacy disk JSON". Without this gate, a domain whose
        latest scan legitimately found 0 items of some kind would wrongly
        surface stale items from an older on-disk dump.
        """
        t = orm.ScanArtefact.__table__
        with self.engine.connect() as c:
            return c.execute(
                sa.select(t.c.id).where(t.c.domain == domain).limit(1)
            ).first() is not None

    def get_artefacts(self, domain: str, kind: str,
                      module: Optional[str] = None,
                      scan_id: Optional[str] = None) -> List[dict]:
        """Return the ``data`` payloads for a domain's artefacts of ``kind``.

        Default returns the latest known state (every row for domain+kind).
        Pass ``scan_id`` to restrict to items last seen in that scan.
        """
        t = orm.ScanArtefact.__table__
        stmt = (sa.select(t.c.data)
                  .where(t.c.domain == domain)
                  .where(t.c.kind == kind))
        if module:
            stmt = stmt.where(t.c.module == module)
        if scan_id:
            stmt = stmt.where(t.c.last_seen_scan_id == scan_id)
        with self.engine.connect() as c:
            return [r.data for r in c.execute(stmt)]

    def diff_artefacts(self, domain: str, kind: str,
                       current_scan_id: str) -> Tuple[List[dict], List[dict]]:
        """``(new, gone)`` artefact payloads for ``kind`` vs the previous scan —
        same semantics as ``diff_findings``."""
        t = orm.ScanArtefact.__table__
        with self.engine.connect() as c:
            new_rows = list(c.execute(
                sa.select(t.c.data)
                  .where(t.c.domain == domain)
                  .where(t.c.kind == kind)
                  .where(t.c.first_seen_scan_id == current_scan_id)
            ))
            prev_id = self.get_previous_scan_id(domain, current_scan_id)
            gone_rows: list = []
            if prev_id:
                gone_rows = list(c.execute(
                    sa.select(t.c.data)
                      .where(t.c.domain == domain)
                      .where(t.c.kind == kind)
                      .where(t.c.last_seen_scan_id == prev_id)
                ))
        return ([r.data for r in new_rows], [r.data for r in gone_rows])

    # ── Stats ─────────────────────────────────────────────────

    def stats_for_domain(self, domain: str, active: bool = True) -> dict:
        """Severity histogram for a domain.

        active=True (default) counts only findings still present in the latest
        scan (``last_seen_scan_id`` == latest scan). Without this the histogram
        keeps growing with every "gone" finding from past scans, so a noisy old
        scan permanently inflates the dashboard counts even after the noise was
        fixed and re-scanned. active=False returns the full historical tally.
        """
        t = orm.Finding.__table__
        stmt = (sa.select(t.c.severity, sa.func.count().label("cnt"))
                  .where(t.c.domain == domain))
        if active:
            latest = self.latest_scan_id(domain)
            if latest is not None:
                stmt = stmt.where(t.c.last_seen_scan_id == latest)
        stmt = stmt.group_by(t.c.severity)
        with self.engine.connect() as c:
            return {r.severity: r.cnt for r in c.execute(stmt)}

    def close(self):
        """Dispose the engine's connection pool. Idempotent, never raises."""
        try:
            self.engine.dispose()
        except Exception:
            pass
