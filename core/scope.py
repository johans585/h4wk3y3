"""
Argus V2 — Authoritative scope check for a scan.

Constructed once per scan from:
  - the target apex (`example.com`)
  - the global `wildcards` file (extra in-scope parents authorised for the team)
  - an optional out-of-scope list (explicit exclusions — programme-side
    carve-outs like "*.shopify-checkout-uat.com")

Every module that produces URLs/hosts intended for downstream probing
(m04 URL collection, m11 JS endpoints, m12 reflection candidates, m13
nuclei host list, m14 active tests) MUST filter its outputs via
`target.scope.filter_urls(...)` before passing them on. Without this,
gau/katana wayback URLs can drag third-party CDNs into the active
testing surface and produce out-of-scope traffic — a BBP violation.

Matching rules:
  - The apex is always in scope, and so is every subdomain `*.apex`.
  - `extra_in_scope` patterns broaden the in-scope set:
        example.com       → exact match
        *.example.com     → any single-or-multi-level subdomain
        .example.com      → apex + any subdomain (HackerOne shorthand)
        *example.com      → legacy form, treated like *.example.com
  - `out_of_scope` wins over everything. An out-of-scope pattern always
    rejects, even if the host matches the apex or an extra pattern.

This module has no I/O of its own — Pipeline is responsible for reading
the wildcards file and passing the list in.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────

def _normalize_host(s: str) -> str:
    """Extract a lowercase, port-stripped host from a URL or bare host.
    Returns '' if nothing usable can be extracted."""
    if not s:
        return ""
    s = s.strip().lower()
    if "://" in s:
        try:
            host = urlparse(s).hostname or ""
        except ValueError:
            host = ""
    else:
        host = s.split("/", 1)[0]
    # Strip explicit port (host:8080)
    if ":" in host:
        host = host.rsplit(":", 1)[0]
    return host.rstrip(".")


def _match_pattern(host: str, pattern: str) -> bool:
    """Match a bare host against a single scope pattern (no leading scheme)."""
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if not pattern or not host:
        return False
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host == suffix or host.endswith("." + suffix)
    if pattern.startswith("*"):
        # *example.com — H1 legacy form, treat as ".example.com" tail match
        suffix = pattern[1:].lstrip(".")
        return host == suffix or host.endswith("." + suffix)
    if pattern.startswith("."):
        suffix = pattern[1:]
        return host == suffix or host.endswith("." + suffix)
    return host == pattern


# ─────────────────────────────────────────────────────────────────────
# Scope restriction (programme-specific carve-outs beyond simple in/out)
# ─────────────────────────────────────────────────────────────────────

@dataclass
class ScopeRestriction:
    """A programme-side rule applied on top of in/out scope.

    Either `host` or `path` is set (at least one). `disabled=True` makes
    the rule reject matching URLs; `max_rps` is informational (modules
    may read it to throttle themselves — not enforced by Scope itself).
    """
    host:     str | None = None    # glob pattern (fnmatch)
    path:     str | None = None    # glob pattern (fnmatch)
    max_rps:  int | None = None
    disabled: bool       = False
    note:     str | None = None

    def matches(self, url_or_host: str) -> bool:
        """True iff this restriction applies to the given URL/host."""
        if not url_or_host:
            return False
        s = url_or_host.strip()
        # Decompose into host + path. Bare hosts → path "/".
        if "://" in s:
            try:
                u = urlparse(s)
                h = (u.hostname or "").lower().rstrip(".")
                p = u.path or "/"
            except ValueError:
                return False
        else:
            host_part, _, path_part = s.partition("/")
            h = _normalize_host(host_part)
            p = "/" + path_part if path_part else "/"
        if self.host:
            if not fnmatch.fnmatchcase(h, self.host.lower()):
                return False
        if self.path:
            if not fnmatch.fnmatchcase(p, self.path):
                return False
        # If neither host nor path set, restriction is vacuously a no-op.
        return bool(self.host or self.path)


# ─────────────────────────────────────────────────────────────────────
# Scope object — passed via ScanTarget.scope
# ─────────────────────────────────────────────────────────────────────

@dataclass
class Scope:
    apex: str
    extra_in_scope: list[str] = field(default_factory=list)
    out_of_scope:   list[str] = field(default_factory=list)
    restrictions:   list[ScopeRestriction] = field(default_factory=list)
    source:         str = "wildcards"   # "wildcards" | "yaml:<path>" | "inline"
    organisation:   str | None = None    # set when loaded from a YAML org file

    def __post_init__(self) -> None:
        self.apex = (self.apex or "").lower().rstrip(".")
        self.extra_in_scope = [p.lower().rstrip(".") for p in self.extra_in_scope if p and p.strip()]
        self.out_of_scope   = [p.lower().rstrip(".") for p in self.out_of_scope   if p and p.strip()]

    # ── Checks ─────────────────────────────────────────────────

    def is_in_scope(self, url_or_host: str) -> bool:
        """True iff the resolved host is authorised for active probing.

        Back-compat wrapper around `is_in_scope_with_reason` — returns bool only.
        Callers that need to show *why* should use the with_reason variant.
        """
        return self.is_in_scope_with_reason(url_or_host)[0]

    def is_in_scope_with_reason(self, url_or_host: str) -> tuple[bool, str]:
        """Same as is_in_scope but also returns a short reason string for
        introspection / dashboard / `argus scope check`.

        Reasons (stable, lower-case, no trailing punctuation):
          - "empty"                    no usable host extracted
          - "out:<pattern>"            matched out_of_scope pattern
          - "restriction:disabled <pat>"   disabled-restriction matched
          - "apex"                     host == apex or *.apex
          - "extra:<pattern>"          matched an extra in-scope pattern
          - "no match"                 nothing matched (out of scope by default)
        """
        host = _normalize_host(url_or_host)
        if not host:
            return False, "empty"
        # Out-of-scope always wins.
        for pat in self.out_of_scope:
            if _match_pattern(host, pat):
                return False, f"out:{pat}"
        # Disabled restrictions reject like out_of_scope.
        for r in self.restrictions:
            if r.disabled and r.matches(url_or_host):
                marker = r.host or r.path or "*"
                return False, f"restriction:disabled {marker}"
        # Apex + any subdomain of the apex.
        if self.apex and (host == self.apex or host.endswith("." + self.apex)):
            return True, "apex"
        # Extra patterns (from wildcards file or programme-specific config).
        for pat in self.extra_in_scope:
            if _match_pattern(host, pat):
                return True, f"extra:{pat}"
        return False, "no match"

    def get_restrictions(self, url_or_host: str) -> list[ScopeRestriction]:
        """Return every restriction matching the given URL/host (informational
        — already-disabled URLs are rejected by `is_in_scope`, but rate
        limits like `max_rps` are exposed here for modules that wish to
        self-throttle)."""
        return [r for r in self.restrictions if r.matches(url_or_host)]

    def tightest_max_rps(self, hosts: Iterable[str] | None = None) -> int | None:
        """Smallest ``max_rps`` among restrictions that apply, or ``None``.

        Lets request-issuing modules actually honour scope rate limits instead
        of treating ``max_rps`` as informational. When ``hosts`` is given, only
        restrictions matching at least one host count; otherwise every
        max_rps-bearing restriction is considered. The minimum is returned so
        the cap is always the most conservative the scope asks for.
        """
        candidates = list(hosts) if hosts else None
        vals = [
            r.max_rps for r in self.restrictions
            if r.max_rps is not None
            and (candidates is None or any(r.matches(h) for h in candidates))
        ]
        return min(vals) if vals else None

    # ── Filters ────────────────────────────────────────────────

    def filter_urls(self, urls: Iterable[str]) -> tuple[list[str], dict[str, int]]:
        """Return (kept_urls, drop_count_by_host). Order is preserved.

        `urls` may contain bare hostnames; both work. The drop counter
        keys are normalised hosts ('?' when unparseable) so the caller
        can log a top-N breakdown of who got rejected."""
        keep: list[str] = []
        drops: dict[str, int] = {}
        for u in urls:
            if self.is_in_scope(u):
                keep.append(u)
            else:
                h = _normalize_host(u) or "?"
                drops[h] = drops.get(h, 0) + 1
        return keep, drops

    def filter_hosts(self, hosts: Iterable[str]) -> tuple[list[str], dict[str, int]]:
        # Same semantics as filter_urls — host is just a degenerate URL.
        return self.filter_urls(hosts)

    def iter_in_scope(self, items: Iterable[str]) -> Iterator[str]:
        for it in items:
            if self.is_in_scope(it):
                yield it

    # ── Introspection ──────────────────────────────────────────

    def describe(self) -> dict:
        return {
            "organisation":   self.organisation,
            "source":         self.source,
            "apex":           self.apex,
            "extra_in_scope": list(self.extra_in_scope),
            "out_of_scope":   list(self.out_of_scope),
            "restrictions": [
                {
                    "host":     r.host,
                    "path":     r.path,
                    "max_rps":  r.max_rps,
                    "disabled": r.disabled,
                    "note":     r.note,
                }
                for r in self.restrictions
            ],
        }

    def __repr__(self) -> str:  # pragma: no cover — debug aid
        extra = f" +{len(self.extra_in_scope)} extra" if self.extra_in_scope else ""
        out   = f" -{len(self.out_of_scope)} excl"    if self.out_of_scope   else ""
        rest  = f" {len(self.restrictions)} restr"   if self.restrictions   else ""
        return f"Scope({self.apex}{extra}{out}{rest})"


# ─────────────────────────────────────────────────────────────────────
# Loader helpers
# ─────────────────────────────────────────────────────────────────────

def load_wildcards_file(path) -> list[str]:
    """Parse a wildcards file (one pattern per line, '#' comments allowed).
    Returns [] if the file does not exist — silent fallback by design,
    callers should already have warned about missing scope config."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return [
                line.strip()
                for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            ]
    except (FileNotFoundError, OSError):
        return []


def build_scope_for_target(
    apex: str,
    wildcards_path=None,
    out_of_scope: list[str] | None = None,
) -> Scope:
    """Convenience builder used by Pipeline.

    Reads the project-level `wildcards` file (if present) and merges
    entries that are NOT just `apex` itself or its subdomain shorthand —
    those are redundant with the apex check.
    """
    extras: list[str] = []
    if wildcards_path is not None:
        all_wc = load_wildcards_file(wildcards_path)
        apex_l = (apex or "").lower().rstrip(".")
        for pat in all_wc:
            pat_l = pat.lower().rstrip(".")
            # Skip patterns that are exactly the current apex or *.apex —
            # they're already covered by the apex implicit rule and would
            # only inflate `extra_in_scope` for logging.
            if pat_l == apex_l or pat_l == f"*.{apex_l}" or pat_l == f".{apex_l}":
                continue
            extras.append(pat)
    return Scope(
        apex=apex,
        extra_in_scope=extras,
        out_of_scope=list(out_of_scope or []),
        source="wildcards",
    )


# ─────────────────────────────────────────────────────────────────────
# YAML loader — scopes/<org>.yaml (Étape 2.2 — scope-as-code)
# ─────────────────────────────────────────────────────────────────────

class ScopeYamlError(ValueError):
    """Raised when a scope YAML file is malformed (missing keys, wrong types)."""


def _coerce_pattern_list(value: Any, field_name: str) -> list[str]:
    """Accept str | list[str] | None, normalise to list[str]."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        out: list[str] = []
        for i, v in enumerate(value):
            if not isinstance(v, str):
                raise ScopeYamlError(
                    f"{field_name}[{i}] must be a string, got {type(v).__name__}"
                )
            out.append(v)
        return out
    raise ScopeYamlError(
        f"{field_name} must be a string or list of strings, got {type(value).__name__}"
    )


def _parse_restrictions(raw: Any) -> list[ScopeRestriction]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ScopeYamlError(
            f"scope.restrictions must be a list, got {type(raw).__name__}"
        )
    out: list[ScopeRestriction] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ScopeYamlError(
                f"scope.restrictions[{i}] must be a mapping"
            )
        host     = item.get("host")
        path     = item.get("path")
        if host is not None and not isinstance(host, str):
            raise ScopeYamlError(f"scope.restrictions[{i}].host must be a string")
        if path is not None and not isinstance(path, str):
            raise ScopeYamlError(f"scope.restrictions[{i}].path must be a string")
        if not host and not path:
            raise ScopeYamlError(
                f"scope.restrictions[{i}] needs at least one of `host` or `path`"
            )
        max_rps = item.get("max_rps")
        if max_rps is not None and not isinstance(max_rps, int):
            raise ScopeYamlError(
                f"scope.restrictions[{i}].max_rps must be an integer"
            )
        disabled = bool(item.get("disabled", False))
        note     = item.get("note")
        if note is not None and not isinstance(note, str):
            raise ScopeYamlError(f"scope.restrictions[{i}].note must be a string")
        out.append(ScopeRestriction(
            host=host, path=path, max_rps=max_rps, disabled=disabled, note=note,
        ))
    return out


def load_scope_yaml(path, apex_override: str | None = None) -> Scope:
    """Load a `scopes/<org>.yaml` file and return a Scope.

    Schema (minimal):
        organisation: <name>          # required
        apex: <domain>                # optional — falls back to apex_override
        scope:
          in:  [<pattern>, ...]       # optional
          out: [<pattern>, ...]       # optional
          restrictions:               # optional
            - host: "<glob>"
              path: "<glob>"
              max_rps: <int>
              disabled: <bool>
              note: "<str>"

    Raises ScopeYamlError on any malformed input. The caller may catch
    that and fall back to the wildcards file path.
    """
    import yaml  # local import — YAML loader is opt-in

    p = Path(path)
    if not p.exists():
        raise ScopeYamlError(f"scope file not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ScopeYamlError(f"invalid YAML in {p}: {e}") from e
    if not isinstance(data, dict):
        raise ScopeYamlError(f"{p} top-level must be a mapping")

    organisation = data.get("organisation") or data.get("org")
    if not organisation or not isinstance(organisation, str):
        raise ScopeYamlError(f"{p}: `organisation` is required (string)")

    apex = data.get("apex") or apex_override
    if not apex:
        raise ScopeYamlError(
            f"{p}: `apex` missing and no apex_override provided"
        )
    if not isinstance(apex, str):
        raise ScopeYamlError(f"{p}: `apex` must be a string")

    scope_block = data.get("scope") or {}
    if not isinstance(scope_block, dict):
        raise ScopeYamlError(f"{p}: `scope` must be a mapping")

    extras = _coerce_pattern_list(scope_block.get("in"),  "scope.in")
    outs   = _coerce_pattern_list(scope_block.get("out"), "scope.out")
    restr  = _parse_restrictions(scope_block.get("restrictions"))

    return Scope(
        apex=apex,
        extra_in_scope=extras,
        out_of_scope=outs,
        restrictions=restr,
        source=f"yaml:{p}",
        organisation=organisation,
    )


def find_scope_file(apex: str, scopes_dir: Path | str = "scopes") -> Path | None:
    """Locate `scopes/<apex>.yaml` (or .yml). Returns None if absent.

    Used by Pipeline to opt-in to YAML-driven scope without breaking
    targets that have no scope file (they fall back to wildcards).
    """
    d = Path(scopes_dir)
    if not d.is_dir():
        return None
    apex_l = (apex or "").lower().rstrip(".")
    for ext in (".yaml", ".yml"):
        candidate = d / f"{apex_l}{ext}"
        if candidate.exists():
            return candidate
    return None
