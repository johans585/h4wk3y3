"""
Argus V2 — m17 : CVE correlator (internal).

Matches CVE products from `cves` against technologies observed on
`live_hosts`. Produces candidate `cve_matches` rows with
match_method=product_name_only and confidence=0.4.

Strategy (MVP) :
  - Tokenize cves.vendor + cves.products[*].product (normalised, generic-filtered).
  - Tokenize live_hosts.technologies (normalised).
  - A candidate match exists when at least one CVE token equals one host
    token, both ≥ 3 chars and not in the generic-token blocklist.
  - Inserted with confidence=0.4 ("we know you run X, you might be vulnerable").

This is a low-confidence first pass — meant to surface candidates for
the analyst, NOT to assert "you are vulnerable". The `nuclei_template`
validation step (m18 future) and the `product_version` strategy
(needs NVD CPE pull) raise confidence to 0.85/0.95.

Run manually for now :
    python3 scripts/cve_correlate.py [--limit-cves N] [--dry-run]
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone

import sqlalchemy as sa


# Tokens trop génériques pour fonder un match (sinon "http" → matche tout).
GENERIC_TOKENS = frozenset({
    # Network/protocol
    "http", "https", "tcp", "udp", "tls", "ssl", "smtp", "imap", "pop", "dns",
    # Generic software terms
    "server", "client", "web", "api", "core", "framework", "library",
    "manager", "system", "service", "site", "app", "tool", "platform",
    "engine", "module", "plugin", "extension", "addon", "page", "front",
    "back", "panel", "portal", "console", "dashboard", "main", "user",
    "admin", "login", "config", "default", "setup", "demo", "test", "dev",
    "prod", "stage", "staging", "preview",
})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize(s: str | None) -> str:
    """Lowercase + replace non-alnum runs with spaces. Returns squeezed string."""
    if not s:
        return ""
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def _useful_tokens(s: str | None) -> set[str]:
    """Tokenise + filtre les tokens triviaux."""
    if not s:
        return set()
    out: set[str] = set()
    for tok in _normalize(s).split():
        if len(tok) < 3:        continue
        if tok.isdigit():       continue
        if tok in GENERIC_TOKENS: continue
        out.add(tok)
    return out


def host_tokens(technologies: list[str] | None) -> set[str]:
    """Tokens utiles extraits de la liste technologies d'un live_host."""
    if not technologies:
        return set()
    out: set[str] = set()
    for t in technologies:
        out |= _useful_tokens(t)
    return out


def cve_tokens(vendor: str | None, products: list[dict] | None) -> set[str]:
    """Tokens utiles extraits du vendor + product names d'une CVE (union)."""
    out: set[str] = set()
    out |= _useful_tokens(vendor)
    for p in (products or []):
        out |= _useful_tokens(p.get("product"))
        # Le vendor du CPE peut différer du KEV vendor (ex KEV='joomla!',
        # CPE vendor='joomla') → tokens cumulés.
        out |= _useful_tokens(p.get("vendor"))
    return out


def cve_vendor_and_product_tokens(
    vendor: str | None, products: list[dict] | None,
) -> tuple[set[str], set[str]]:
    """Sépare les tokens du vendor des tokens product-spécifiques.

    Retourne (vendor_tokens, specific_product_tokens) où :
      - vendor_tokens = tokens utiles du champ KEV.vendor + CPE.vendor
      - specific_product_tokens = tokens des CPE.product qui ne sont PAS
        déjà dans vendor_tokens (donc product réel, ex 'solr' / 'tomcat'
        pour vendor 'apache')

    Si specific_product_tokens non vide, le matcher exige qu'au moins un
    de ces tokens apparaisse dans la tech list du host (évite que toute
    CVE Apache:* matche tout host Apache).
    """
    vendor_tokens: set[str] = _useful_tokens(vendor)
    for p in (products or []):
        vendor_tokens |= _useful_tokens(p.get("vendor"))

    product_tokens: set[str] = set()
    for p in (products or []):
        product_tokens |= _useful_tokens(p.get("product"))

    # Specific = product tokens which are NOT already in vendor (ex 'solr'
    # pour vendor 'apache' → specific = {'solr'}). Pour vendor 'drupal'
    # product 'drupal', product_tokens - vendor_tokens = ∅, le matcher
    # tombera sur vendor-only (comportement original).
    specific_tokens = product_tokens - vendor_tokens
    return vendor_tokens, specific_tokens


# ────────────────────────────────────────────────────────────────────────
# Orchestrator
# ────────────────────────────────────────────────────────────────────────

class CVECorrelatorModule:
    """Standalone module. Not part of the per-scan Pipeline."""

    def __init__(
        self,
        engine,
        limit_cves: int | None = None,
        log:        logging.Logger | None = None,
    ) -> None:
        self.engine     = engine
        self.limit_cves = limit_cves
        self.log        = log or logging.getLogger("m17")

    def _load_hosts(self) -> list[dict]:
        with self.engine.connect() as c:
            rows = c.execute(sa.text("""
                SELECT lh.id, lh.domain, lh.url, lh.status_code,
                       lh.technologies, lh.attributed_apex,
                       t.organisation_id
                  FROM live_hosts lh
                  LEFT JOIN targets t ON t.apex = lh.attributed_apex
            """)).fetchall()
        out = []
        for r in rows:
            tech: list[str] = []
            if r[4]:
                try:
                    parsed = json.loads(r[4])
                    if isinstance(parsed, list):
                        tech = [str(x) for x in parsed]
                except Exception:
                    pass
            tokens = host_tokens(tech)
            if not tokens:
                continue  # host sans tech connue = pas de candidat possible
            out.append({
                "id":              r[0],
                "host":            r[1],
                "url":             r[2],
                "status":          r[3],
                "technologies":    tech,
                "attributed_apex": r[5],
                "organisation_id": r[6],
                "tokens":          tokens,
            })
        return out

    def _load_cves(self) -> list[dict]:
        sql = """
            SELECT cve_id, vendor, products, cvss_v3, epss, kev_flag,
                   nuclei_template, kev_added_at
              FROM cves
             WHERE vendor IS NOT NULL OR products IS NOT NULL
             ORDER BY kev_flag DESC, epss DESC NULLS LAST
        """
        if self.limit_cves:
            sql += f" LIMIT {int(self.limit_cves)}"
        with self.engine.connect() as c:
            rows = c.execute(sa.text(sql)).fetchall()
        out = []
        for r in rows:
            products: list[dict] = []
            if r[2]:
                try:
                    parsed = json.loads(r[2])
                    if isinstance(parsed, list):
                        products = parsed
                except Exception:
                    pass
            vendor_tokens, specific_tokens = cve_vendor_and_product_tokens(r[1], products)
            if not vendor_tokens and not specific_tokens:
                continue  # CVE trop générique → skip
            out.append({
                "cve_id":           r[0],
                "vendor":           r[1],
                "products":         products,
                "cvss_v3":          r[3],
                "epss":             r[4],
                "kev_flag":         r[5],
                "nuclei_template":  r[6],
                "kev_added_at":     r[7],
                "vendor_tokens":    vendor_tokens,
                "specific_tokens":  specific_tokens,
            })
        return out

    def _compute_matches(
        self, cves: list[dict], hosts: list[dict],
    ) -> list[dict]:
        """Compute candidate matches with a 2-tier strategy :

          - **Strict**  : CVE has specific product tokens (product != vendor),
                          host tech list must contain at least one. Confidence
                          0.6, match_method='product_name'.
          - **Vendor**  : CVE product equals vendor (drupal/joomla case) OR is
                          entirely generic (Apache http_server). Fallback to
                          vendor-only. Confidence 0.4, 'product_name_only'.

        Removes the noise where CVE-2019-17558 (Apache Solr) used to match
        every Apache host.
        """
        # Inverted index : tech_token → liste de hosts
        token_to_hosts: dict[str, list[dict]] = {}
        for h in hosts:
            for tok in h["tokens"]:
                token_to_hosts.setdefault(tok, []).append(h)

        out: list[dict] = []
        for cve in cves:
            seen_host_ids: set[int] = set()

            # ── Strict tier ─────────────────────────────────────────────
            if cve["specific_tokens"]:
                for spec in cve["specific_tokens"]:
                    for h in token_to_hosts.get(spec, []):
                        if h["id"] in seen_host_ids:
                            continue
                        seen_host_ids.add(h["id"])
                        out.append({
                            "cve_id":           cve["cve_id"],
                            "match_method":     "product_name",   # specific
                            "match_source":     "internal",
                            "asset_host":       h["host"],
                            "asset_ip":         None,
                            "asset_url":        h["url"],
                            "asset_port":       None,
                            "asset_product":    spec,
                            "asset_version":    None,
                            "version_required": None,
                            "attributed_apex":  h["attributed_apex"],
                            "organisation_id":  h["organisation_id"],
                            "pivot_method":     None,
                            "confidence":       0.6,
                            "validation_state": "candidate",
                            "evidence":         json.dumps({
                                "matched_token":     spec,
                                "tier":              "strict_product",
                                "cve_vendor":        cve["vendor"],
                                "host_technologies": h["technologies"],
                            }, ensure_ascii=False),
                        })
                # Specific tier hit → ne fallback PAS sur vendor-only.
                continue

            # ── Vendor fallback ─────────────────────────────────────────
            # CVE product == vendor (drupal/joomla) ou product trop générique
            # (http_server / web_server) → match vendor seul.
            for vt in cve["vendor_tokens"]:
                for h in token_to_hosts.get(vt, []):
                    if h["id"] in seen_host_ids:
                        continue
                    seen_host_ids.add(h["id"])
                    out.append({
                        "cve_id":           cve["cve_id"],
                        "match_method":     "product_name_only",  # vendor-only
                        "match_source":     "internal",
                        "asset_host":       h["host"],
                        "asset_ip":         None,
                        "asset_url":        h["url"],
                        "asset_port":       None,
                        "asset_product":    vt,
                        "asset_version":    None,
                        "version_required": None,
                        "attributed_apex":  h["attributed_apex"],
                        "organisation_id":  h["organisation_id"],
                        "pivot_method":     None,
                        "confidence":       0.4,
                        "validation_state": "candidate",
                        "evidence":         json.dumps({
                            "matched_token":     vt,
                            "tier":              "vendor_fallback",
                            "cve_vendor":        cve["vendor"],
                            "host_technologies": h["technologies"],
                        }, ensure_ascii=False),
                    })
        return out

    def _upsert(self, matches: list[dict]) -> dict:
        if not matches:
            return {"matches_total": 0, "inserted": 0, "refreshed": 0}
        sql = sa.text("""
            INSERT INTO cve_matches (
                cve_id, match_method, match_source, asset_host, asset_ip,
                asset_url, asset_port, asset_product, asset_version,
                version_required, attributed_apex, organisation_id,
                pivot_method, confidence, validation_state,
                evidence, first_seen_at, last_seen_at
            ) VALUES (
                :cve_id, :match_method, :match_source, :asset_host, :asset_ip,
                :asset_url, :asset_port, :asset_product, :asset_version,
                :version_required, :attributed_apex, :organisation_id,
                :pivot_method, :confidence, :validation_state,
                :evidence, :now, :now
            )
            ON CONFLICT (cve_id, asset_url, asset_ip, asset_port, match_method)
            DO UPDATE SET
                last_seen_at    = EXCLUDED.last_seen_at,
                asset_product   = EXCLUDED.asset_product,
                attributed_apex = EXCLUDED.attributed_apex,
                organisation_id = EXCLUDED.organisation_id,
                evidence        = EXCLUDED.evidence
            RETURNING (xmax = 0) AS inserted
        """)
        # `xmax = 0` est `true` quand la row a été INSERT (et pas UPDATE).
        # On compte pour différencier "nouveaux" / "refresh".
        now = _now_iso()
        inserted = refreshed = 0
        with self.engine.begin() as c:
            for m in matches:
                m["now"] = now
                row = c.execute(sql, m).fetchone()
                if row and row[0]:
                    inserted += 1
                else:
                    refreshed += 1
        return {
            "matches_total": len(matches),
            "inserted":      inserted,
            "refreshed":     refreshed,
        }

    def run(self) -> dict:
        t0 = time.time()
        self.log.info("═" * 64)
        self.log.info("  m17 CVE correlator (internal)")
        self.log.info("═" * 64)

        hosts = self._load_hosts()
        self.log.info(f"▶ Loaded {len(hosts)} live_hosts with tech tokens")
        if not hosts:
            self.log.info("  ⏭  no host with tech_versions — nothing to correlate")
            return {"matches_total": 0, "inserted": 0, "refreshed": 0,
                    "elapsed_seconds": round(time.time()-t0, 1)}

        cves = self._load_cves()
        self.log.info(f"▶ Loaded {len(cves)} CVEs with vendor/products tokens"
                      + (f" (limit={self.limit_cves})" if self.limit_cves else ""))

        matches = self._compute_matches(cves, hosts)
        self.log.info(f"▶ Computed {len(matches)} candidate matches")

        # Distribution diagnostique
        if matches:
            by_org: dict[str | None, int] = {}
            for m in matches:
                by_org[m["attributed_apex"]] = by_org.get(m["attributed_apex"], 0) + 1
            top = sorted(by_org.items(), key=lambda kv: -kv[1])[:5]
            self.log.info("  Top apex by candidate count :")
            for apex, n in top:
                self.log.info(f"    {apex or '(orphan)':30s}  {n}")

        stats = self._upsert(matches)
        elapsed = time.time() - t0
        stats["elapsed_seconds"] = round(elapsed, 1)
        stats["cves_evaluated"]  = len(cves)
        stats["hosts_evaluated"] = len(hosts)

        self.log.info("═" * 64)
        self.log.info(f"  ✔ {stats['matches_total']} matches · "
                      f"{stats['inserted']} new · {stats['refreshed']} refreshed "
                      f"in {elapsed:.1f}s")
        self.log.info("═" * 64)
        return stats
