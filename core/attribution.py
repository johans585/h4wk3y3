"""
Argus V2 — Asset attribution (Étape 0003).

Maps any host/URL to the most-specific apex declared in `targets.apex`
via longest-suffix match. Used by:
  - the pipeline post-scan hook (auto-attribution),
  - the backfill script (one-shot retro-attribution),
  - any view that needs to resolve host → org cleanly.

Rule (deterministic) :
  - Match exact      : host == apex                            ✅
  - Match suffix     : host endswith "." + apex                ✅
  - Longest wins     : 'mefb.gouv.bj' beats 'gouv.bj' on 'api.mefb.gouv.bj'
  - NULL             : no apex matches → caller may treat as "orphan / shadow IT"

Designed to be cheap : the caller passes the known apexes list once
(sorted descending by length) and we iterate it per host. For very
large lists (>10k), wrap with a Trie if needed — not the case for
Argus' country-scale inventory.
"""

from __future__ import annotations

import sqlalchemy as sa
from typing import Optional


def resolve_apex(host: Optional[str], apexes_sorted_desc: list[str]) -> Optional[str]:
    """Longest-suffix match. Returns None if no apex matches.

    Args:
        host:               hostname to attribute (case-insensitive).
        apexes_sorted_desc: list of apexes, pre-sorted by length DESC.
                            Caller is responsible for sorting once and
                            reusing the list across many calls.
    """
    if not host:
        return None
    h = host.lower().strip().strip(".")
    if not h:
        return None
    for apex in apexes_sorted_desc:
        if h == apex:
            return apex
        if h.endswith("." + apex):
            return apex
    return None


def load_apexes_sorted(db) -> list[str]:
    """Fetch all known apexes from `targets`, lowercased, sorted DESC by length.

    Use this once per attribution batch — list is small (~200 rows) so the
    Python loop is fast enough.
    """
    with db.engine.connect() as c:
        rows = c.execute(sa.text("SELECT apex FROM targets")).fetchall()
    apexes = [str(r[0]).lower().strip().strip(".") for r in rows if r[0]]
    apexes = [a for a in apexes if a]
    return sorted(set(apexes), key=len, reverse=True)


def extract_host_from_url(url: Optional[str]) -> Optional[str]:
    """Get the hostname from a URL, tolerant to malformed input."""
    if not url:
        return None
    from urllib.parse import urlparse
    try:
        h = urlparse(url).hostname
        return h.lower() if h else None
    except Exception:
        return None
