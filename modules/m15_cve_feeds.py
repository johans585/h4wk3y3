"""
Argus V2 — m15 : CVE intelligence feeds.

Pulls CVE intel from 4 sources and upserts into the `cves` table :
  1. CISA KEV (Known Exploited Vulnerabilities) — ~1300 entries, the
     most actionable signal (CVE confirmed exploited in the wild).
  2. EPSS (Exploit Prediction Scoring System) — ~250k CVE → probability
     of exploitation in the next 30 days.
  3. NVD feeds JSON 1.1 — for selected years (default current + 2 prev).
     Source of CVSS scores, CPEs, descriptions.
  4. Local nuclei-templates scan — `id:` field of YAML files in
     `~/.local/nuclei-templates/http/cves/` → mapping CVE-id → template path.

Only CVEs with at least one signal (KEV listed, nuclei template available,
or NVD entry for a target year) are upserted. EPSS enriches them all when
available.

Run manually for now :
    python3 scripts/cve_pull.py [--years 2024,2025] [--no-nvd] [--dry-run]
"""

from __future__ import annotations

import csv
import glob
import gzip
import io
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import sqlalchemy as sa


# ─── Sources ─────────────────────────────────────────────────────────
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
# NVD JSON feeds 1.1 sont dépréciés depuis 2024 (403 Forbidden). On utilise
# l'API REST 2.0 qui pagine (2000 CVE max par page) et filtre par date.
# Rate limit : 5 req / 30s sans clé, 50 req / 30s avec clé NVD-API-KEY.
# Une clé peut être demandée (gratuite) sur https://nvd.nist.gov/developers/request-an-api-key
# et placée dans config/h4wk3y3.yaml sous `cve_feeds.nvd_api_key`.
NVD_API_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE  = 2000           # API 2.0 max
NVD_MAX_RANGE  = 120            # jours max pour un date range
NVD_SLEEP_NOKEY = 6.5           # 1 req / 6.5s = ~9 req/min < 5/30s limit
NVD_SLEEP_WITH_KEY = 0.7        # ~50 req/30s

DEFAULT_NUCLEI_DIRS = [
    "/home/kali/.local/nuclei-templates/http/cves",
    "./data/nuclei-templates/http/cves",
]

# HTTP client : long timeout for NVD JSON downloads (can be 30–80 MB).
HTTP_TIMEOUT = httpx.Timeout(connect=15.0, read=180.0, write=15.0, pool=15.0)
HTTP_HEADERS = {
    "User-Agent": "argus-cve-feeds/1.0 (Argus CSIRT)",
    "Accept-Encoding": "gzip",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _http_get(url: str) -> bytes:
    """GET with HTTP/2 + gzip, returns body bytes (decompressed if .gz URL)."""
    with httpx.Client(timeout=HTTP_TIMEOUT, headers=HTTP_HEADERS,
                       follow_redirects=True) as client:
        r = client.get(url)
        r.raise_for_status()
        body = r.content
    # NVD feeds are gzipped on the wire; httpx auto-inflates Content-Encoding=gzip.
    # For the .csv.gz EPSS file the server sends application/octet-stream so we
    # need to gunzip manually.
    if url.endswith(".gz"):
        # If httpx already decompressed via Content-Encoding, content starts
        # with the underlying JSON/CSV. Else it's still gzipped.
        if body[:2] == b"\x1f\x8b":
            body = gzip.decompress(body)
    return body


# ────────────────────────────────────────────────────────────────────────
# Source pullers
# ────────────────────────────────────────────────────────────────────────

def pull_kev(log: logging.Logger) -> list[dict]:
    """Returns the KEV catalog as a list of dicts with normalised keys."""
    log.info(f"▶ KEV  : pulling {KEV_URL}")
    t0 = time.time()
    body = _http_get(KEV_URL)
    data = json.loads(body)
    entries = data.get("vulnerabilities", []) or []
    log.info(f"  ✓ KEV  : {len(entries)} entries in {time.time()-t0:.1f}s")
    return entries


def pull_epss(log: logging.Logger) -> dict[str, tuple[float, float]]:
    """Returns dict cve_id → (epss_score, percentile)."""
    log.info(f"▶ EPSS : pulling {EPSS_URL}")
    t0 = time.time()
    body = _http_get(EPSS_URL)
    text = body.decode("utf-8", errors="replace")
    out: dict[str, tuple[float, float]] = {}
    # CSV may have a comment header line ("#model_version:...") before the real header.
    reader = csv.reader(io.StringIO(text))
    header_idx: dict[str, int] = {}
    for row in reader:
        if not row:
            continue
        if row[0].startswith("#"):
            continue
        if not header_idx:
            header_idx = {col.lower(): i for i, col in enumerate(row)}
            continue
        try:
            cve   = row[header_idx["cve"]]
            score = float(row[header_idx["epss"]])
            pct   = float(row[header_idx["percentile"]])
            out[cve] = (score, pct)
        except (KeyError, ValueError, IndexError):
            continue
    log.info(f"  ✓ EPSS : {len(out)} scores in {time.time()-t0:.1f}s")
    return out


def scan_nuclei_templates(dirs: list[str], log: logging.Logger) -> dict[str, str]:
    """Walks nuclei-templates CVE dir, returns dict cve_id → template path."""
    out: dict[str, str] = {}
    for d in dirs:
        if not Path(d).is_dir():
            continue
        log.info(f"▶ Nuclei templates : scanning {d}")
        t0 = time.time()
        # Match files like CVE-2021-41773.yaml ; ignore tracee.yaml
        count_total = 0
        for f in glob.iglob(os.path.join(d, "**", "*.yaml"), recursive=True):
            count_total += 1
            basename = os.path.basename(f)
            m = re.match(r"^(CVE-\d{4}-\d+)\.yaml$", basename, re.IGNORECASE)
            if m:
                cve_id = m.group(1).upper()
                # Store path relative to the nuclei dir for portability
                rel = os.path.relpath(f, d)
                out[cve_id] = f"http/cves/{rel}"
        log.info(f"  ✓ Nuclei: {len(out)} CVE templates ({count_total} yaml scanned) in {time.time()-t0:.1f}s")
        if out:
            return out  # first valid dir wins
    log.warning("  ⚠ Nuclei: no templates directory found")
    return out


def _nvd_iso(dt: datetime) -> str:
    """NVD API 2.0 expects 'YYYY-MM-DDTHH:MM:SS.000' format (no timezone)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _pull_nvd_api(
    log: logging.Logger,
    *,
    start_date: str,
    end_date:   str,
    api_key:    str | None,
    label:      str,
) -> dict[str, dict]:
    """Pull a window of NVD CVEs via API 2.0 (lastModStartDate/lastModEndDate).
    Returns dict cve_id → vulnerability item (the API 2.0 wrap).

    Window MUST be ≤ 120 days. Caller is responsible for chunking longer ranges.
    """
    headers = dict(HTTP_HEADERS)
    sleep_s = NVD_SLEEP_NOKEY
    if api_key:
        headers["apiKey"] = api_key
        sleep_s = NVD_SLEEP_WITH_KEY

    out: dict[str, dict] = {}
    start_index = 0
    total_results = -1
    t0 = time.time()

    with httpx.Client(timeout=HTTP_TIMEOUT, headers=headers,
                       follow_redirects=True) as client:
        while True:
            params = {
                "resultsPerPage":   NVD_PAGE_SIZE,
                "startIndex":       start_index,
                "lastModStartDate": start_date,
                "lastModEndDate":   end_date,
            }
            try:
                r = client.get(NVD_API_URL, params=params)
                r.raise_for_status()
            except httpx.HTTPError as e:
                log.warning(f"  ⚠ NVD API {label} page@{start_index} failed: {e}")
                break
            data = r.json()
            vulns = data.get("vulnerabilities", []) or []
            for v in vulns:
                try:
                    cve_id = v["cve"]["id"]
                    out[cve_id] = v
                except (KeyError, TypeError):
                    continue
            total_results = data.get("totalResults", 0)
            received = len(vulns)
            start_index += received
            if start_index >= total_results or received == 0:
                break
            # Rate limit guard
            time.sleep(sleep_s)

    log.info(f"  ✓ NVD {label}: {len(out)} CVE "
             f"(total reported {total_results}) in {time.time()-t0:.1f}s")
    return out


def pull_nvd_year(year: int, log: logging.Logger,
                  api_key: str | None = None) -> dict[str, dict]:
    """Pull a full year via 4 chunks of ~3 months (NVD 120-day window cap)."""
    log.info(f"▶ NVD  : pulling year {year} via API 2.0 (4×3-month chunks)")
    out: dict[str, dict] = {}
    chunks = [(1, 4), (4, 7), (7, 10), (10, 13)]  # (start_month, next_month)
    for (m1, m2) in chunks:
        end_year = year if m2 <= 12 else year + 1
        end_m    = m2 if m2 <= 12 else 1
        start = f"{year}-{m1:02d}-01T00:00:00.000"
        end   = f"{end_year}-{end_m:02d}-01T00:00:00.000"
        chunk = _pull_nvd_api(log, start_date=start, end_date=end,
                               api_key=api_key, label=f"{year}-Q{(m1+2)//3}")
        out.update(chunk)
    return out


def pull_nvd_recent(log: logging.Logger,
                    api_key: str | None = None) -> dict[str, dict]:
    """Pull last 8 days of CVE modifications via API 2.0.
    Petit (typiquement 1-2k entries), parfait pour le refresh UI button."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=8)
    log.info(f"▶ NVD  : pulling recent ({_nvd_iso(start)} → {_nvd_iso(now)})")
    return _pull_nvd_api(log,
                          start_date=_nvd_iso(start),
                          end_date=_nvd_iso(now),
                          api_key=api_key,
                          label="recent-8d")


# ────────────────────────────────────────────────────────────────────────
# Merge & upsert
# ────────────────────────────────────────────────────────────────────────

_VERSION_OP_MAP = {
    "versionStartIncluding": ">=",
    "versionStartExcluding": ">",
    "versionEndIncluding":   "<=",
    "versionEndExcluding":   "<",
}


def _parse_cpes(nvd_item: dict | None) -> tuple[list[str], list[dict]]:
    """From NVD API 2.0 vulnerability item, extract raw CPE 2.3 strings +
    normalised products: [{vendor, product, version_constraint}].

    Format API 2.0 :
      item["cve"]["configurations"] = [{nodes: [{cpeMatch: [{criteria, ...}]}]}]
    """
    if not nvd_item:
        return [], []
    cpes_raw: list[str] = []
    products: list[dict] = []
    seen: set[str] = set()
    try:
        configs = nvd_item["cve"]["configurations"]
    except (KeyError, TypeError):
        return cpes_raw, products

    def _walk_nodes(nodes_):
        for n in nodes_ or []:
            for m in n.get("cpeMatch", []) or []:
                cpe = m.get("criteria")
                if not cpe:
                    continue
                if cpe not in seen:
                    seen.add(cpe)
                    cpes_raw.append(cpe)
                parts = cpe.split(":")
                # cpe:2.3:a:vendor:product:version:update:edition:lang:sw:tw:tw:tw
                if len(parts) >= 6:
                    vendor  = parts[3]
                    product = parts[4]
                    version = parts[5]
                    constraints: list[str] = []
                    if version not in ("*", "-"):
                        constraints.append(f"= {version}")
                    for k_field, op in _VERSION_OP_MAP.items():
                        if m.get(k_field):
                            constraints.append(f"{op} {m[k_field]}")
                    products.append({
                        "vendor":  vendor,
                        "product": product,
                        "version_constraint": " AND ".join(constraints) if constraints else None,
                    })
            _walk_nodes(n.get("children", []))

    for cfg in configs or []:
        _walk_nodes(cfg.get("nodes", []))
    return cpes_raw, products


def _cvss_from_nvd(nvd_item: dict | None) -> tuple[float | None, str | None, float | None]:
    """Returns (cvss_v3_score, cvss_v3_vector, cvss_v2_score). API 2.0 format."""
    if not nvd_item:
        return None, None, None
    try:
        metrics = nvd_item["cve"].get("metrics", {}) or {}
        v3_score = v3_vector = v2_score = None
        # CVSS v3.1 preferred, fallback v3.0
        for key in ("cvssMetricV31", "cvssMetricV30"):
            arr = metrics.get(key) or []
            if arr:
                d = arr[0].get("cvssData", {}) or {}
                v3_score  = v3_score  or d.get("baseScore")
                v3_vector = v3_vector or d.get("vectorString")
                if v3_score is not None:
                    break
        arr = metrics.get("cvssMetricV2") or []
        if arr:
            v2_score = (arr[0].get("cvssData", {}) or {}).get("baseScore")
        return v3_score, v3_vector, v2_score
    except (KeyError, TypeError, AttributeError):
        return None, None, None


def _description_from_nvd(nvd_item: dict | None) -> str | None:
    if not nvd_item:
        return None
    try:
        for d in nvd_item["cve"].get("descriptions", []) or []:
            if d.get("lang") == "en":
                return d.get("value")
    except (KeyError, TypeError):
        pass
    return None


def _refs_from_nvd(nvd_item: dict | None) -> list[str]:
    if not nvd_item:
        return []
    try:
        return [r.get("url") for r in (nvd_item["cve"].get("references") or [])
                if r.get("url")]
    except (KeyError, TypeError):
        return []


def _published_from_nvd(nvd_item: dict | None) -> str | None:
    if not nvd_item:
        return None
    return (nvd_item.get("cve") or {}).get("published")


def build_cve_row(
    cve_id: str,
    kev:        dict | None,
    epss:       tuple[float, float] | None,
    nuclei_tpl: str | None,
    nvd_item:   dict | None,
) -> dict:
    """Combine all signals into a row ready for upsert."""
    cpes, products = _parse_cpes(nvd_item)
    v3_score, v3_vector, v2_score = _cvss_from_nvd(nvd_item)
    description = _description_from_nvd(nvd_item)
    refs        = _refs_from_nvd(nvd_item)

    # KEV fallbacks (when no NVD enrichment available)
    if not description and kev:
        description = kev.get("shortDescription")
    vendor = None
    if products:
        vendor = products[0]["vendor"]
    elif kev:
        vendor = (kev.get("vendorProject") or "").lower() or None
    if not products and kev:
        # Best-effort from KEV vendor/product fields
        prod_name = kev.get("product")
        if prod_name and vendor:
            products = [{
                "vendor":  vendor,
                "product": prod_name.lower(),
                "version_constraint": None,
            }]

    source_feeds: list[str] = []
    if kev:        source_feeds.append("kev")
    if epss:       source_feeds.append("epss")
    if nvd_item:   source_feeds.append("nvd")
    if nuclei_tpl: source_feeds.append("nuclei")

    return {
        "cve_id":          cve_id,
        "published_at":    _published_from_nvd(nvd_item)
                            or (kev.get("dateAdded") if kev else None),
        "cvss_v3":         v3_score,
        "cvss_v3_vector":  v3_vector,
        "cvss_v2":         v2_score,
        "epss":            epss[0] if epss else None,
        "epss_percentile": epss[1] if epss else None,
        "kev_flag":        1 if kev else 0,
        "kev_added_at":    kev.get("dateAdded") if kev else None,
        "kev_ransomware":  1 if (kev and kev.get("knownRansomwareCampaignUse", "").lower() == "known") else 0,
        "description":     description,
        "vendor":          vendor,
        "cpes":            json.dumps(cpes, ensure_ascii=False) if cpes else None,
        "products":        json.dumps(products, ensure_ascii=False) if products else None,
        "refs":            json.dumps(refs, ensure_ascii=False) if refs else None,
        "nuclei_template": nuclei_tpl,
        "source_feeds":    json.dumps(source_feeds, ensure_ascii=False),
        "updated_at":      _now_iso(),
    }


def upsert_cves(engine, rows: list[dict], log: logging.Logger) -> dict:
    """Bulk upsert via PostgreSQL ON CONFLICT. Returns stats."""
    if not rows:
        return {"upserted": 0, "inserted": 0, "updated": 0}
    log.info(f"▶ Upsert: {len(rows)} CVE rows → table `cves`")
    t0 = time.time()
    now = _now_iso()
    # Set created_at to now if INSERT, otherwise preserve via ON CONFLICT
    insert_stmt = sa.text("""
        INSERT INTO cves (
            cve_id, published_at, cvss_v3, cvss_v3_vector, cvss_v2,
            epss, epss_percentile,
            kev_flag, kev_added_at, kev_ransomware,
            description, vendor, cpes, products, refs,
            nuclei_template, source_feeds, created_at, updated_at
        ) VALUES (
            :cve_id, :published_at, :cvss_v3, :cvss_v3_vector, :cvss_v2,
            :epss, :epss_percentile,
            :kev_flag, :kev_added_at, :kev_ransomware,
            :description, :vendor, :cpes, :products, :refs,
            :nuclei_template, :source_feeds, :created_at, :updated_at
        )
        ON CONFLICT (cve_id) DO UPDATE SET
            published_at    = EXCLUDED.published_at,
            cvss_v3         = EXCLUDED.cvss_v3,
            cvss_v3_vector  = EXCLUDED.cvss_v3_vector,
            cvss_v2         = EXCLUDED.cvss_v2,
            epss            = EXCLUDED.epss,
            epss_percentile = EXCLUDED.epss_percentile,
            kev_flag        = EXCLUDED.kev_flag,
            kev_added_at    = EXCLUDED.kev_added_at,
            kev_ransomware  = EXCLUDED.kev_ransomware,
            description     = EXCLUDED.description,
            vendor          = EXCLUDED.vendor,
            cpes            = EXCLUDED.cpes,
            products        = EXCLUDED.products,
            refs            = EXCLUDED.refs,
            nuclei_template = EXCLUDED.nuclei_template,
            source_feeds    = EXCLUDED.source_feeds,
            updated_at      = EXCLUDED.updated_at
    """)
    inserted = 0
    updated  = 0
    with engine.begin() as c:
        # Pre-check existence to count insert vs update (cheap given the volume)
        existing_ids: set[str] = set()
        ids = [r["cve_id"] for r in rows]
        # SQL IN on long lists is OK in PG up to ~30k items; chunk to be safe
        for i in range(0, len(ids), 1000):
            chunk = ids[i:i+1000]
            res = c.execute(sa.text(
                "SELECT cve_id FROM cves WHERE cve_id = ANY(:ids)"
            ), {"ids": chunk}).fetchall()
            existing_ids.update(r[0] for r in res)
        for r in rows:
            r2 = dict(r)
            r2["created_at"] = r2.get("created_at") or now
            c.execute(insert_stmt, r2)
        inserted = len(rows) - sum(1 for r in rows if r["cve_id"] in existing_ids)
        updated  = len(rows) - inserted
    log.info(f"  ✓ Upsert: {len(rows)} rows ({inserted} new · {updated} updated) in {time.time()-t0:.1f}s")
    return {"upserted": len(rows), "inserted": inserted, "updated": updated}


# ────────────────────────────────────────────────────────────────────────
# Orchestrator
# ────────────────────────────────────────────────────────────────────────

class CVEFeedsModule:
    """Standalone module. Not part of the per-scan Pipeline — runs manually
    (or via cron later)."""

    def __init__(
        self,
        engine,
        years:           list[int] | None = None,
        with_nvd:        bool = True,
        with_recent:     bool = True,
        recent_only:     bool = False,
        nuclei_dirs:     list[str] | None = None,
        nvd_api_key:     str | None = None,
        log:             logging.Logger | None = None,
    ) -> None:
        self.engine      = engine
        cy = datetime.now(timezone.utc).year
        if recent_only:
            # Fast mode : seulement le feed `recent` (~5 MB, 8 derniers jours).
            self.years   = []
            self.with_recent = True
        else:
            self.years   = [cy - 2, cy - 1, cy] if years is None else years
            self.with_recent = with_recent
        self.with_nvd    = with_nvd
        self.nuclei_dirs = nuclei_dirs or DEFAULT_NUCLEI_DIRS
        # NVD API key (optional, 10× rate limit). Fallback env NVD_API_KEY.
        self.nvd_api_key = nvd_api_key or os.environ.get("NVD_API_KEY")
        self.log         = log or logging.getLogger("m15")

    def run(self) -> dict:
        t_start = time.time()
        self.log.info("═" * 64)
        self.log.info("  m15 CVE feeds — Argus")
        self.log.info("═" * 64)

        kev_entries = pull_kev(self.log)
        kev_by_id   = {e["cveID"]: e for e in kev_entries if e.get("cveID")}

        epss_scores = pull_epss(self.log)

        nuclei_map  = scan_nuclei_templates(self.nuclei_dirs, self.log)

        nvd_data: dict[str, dict] = {}
        if self.with_nvd:
            if self.nvd_api_key:
                self.log.info("  🔑 NVD API key present — using 50 req/30s rate limit")
            else:
                self.log.info("  ⚠ no NVD API key — using 5 req/30s rate limit "
                              "(set NVD_API_KEY env or get one at https://nvd.nist.gov/developers/request-an-api-key)")
            for year in self.years:
                nvd_data.update(pull_nvd_year(year, self.log, api_key=self.nvd_api_key))
            if self.with_recent:
                nvd_data.update(pull_nvd_recent(self.log, api_key=self.nvd_api_key))
        else:
            self.log.info("  ⏭  NVD: skipped (--no-nvd)")

        # Sélection : tout CVE avec au moins 1 signal actionable.
        # Trois critères d'inclusion :
        #   1. KEV-listed  (CISA confirmé exploité en prod)
        #   2. nuclei template available (testable activement)
        #   3. présente dans le pull NVD courant (toutes les CVE des années
        #      ciblées + recent feed sont automatiquement incluses — un CVE
        #      qui vient d'être publié AUJOURD'HUI est actionable par
        #      définition même sans KEV / template)
        kev_set    = set(kev_by_id.keys())
        nuclei_set = set(nuclei_map.keys())
        nvd_set    = set(nvd_data.keys()) if self.with_nvd else set()

        target_cves = kev_set | nuclei_set | nvd_set

        self.log.info(
            f"▶ Target CVE set : {len(target_cves)} "
            f"(KEV {len(kev_set)} · nuclei {len(nuclei_set)} · NVD recent/annual {len(nvd_set)})"
        )

        rows = [
            build_cve_row(
                cve_id,
                kev        = kev_by_id.get(cve_id),
                epss       = epss_scores.get(cve_id),
                nuclei_tpl = nuclei_map.get(cve_id),
                nvd_item   = nvd_data.get(cve_id),
            )
            for cve_id in sorted(target_cves)
        ]

        stats = upsert_cves(self.engine, rows, self.log)

        elapsed = time.time() - t_start
        self.log.info("═" * 64)
        self.log.info(f"  ✔ done in {elapsed:.1f}s — {stats}")
        self.log.info("═" * 64)
        stats["elapsed_seconds"] = round(elapsed, 1)
        stats["target_count"] = len(target_cves)
        stats["kev_count"]    = len(kev_by_id)
        stats["epss_count"]   = len(epss_scores)
        stats["nuclei_count"] = len(nuclei_map)
        return stats
