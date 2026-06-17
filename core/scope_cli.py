"""
Argus V2 — `argus scope ...` subcommand handler.

Lets ops introspect / debug a scope-as-code file without spinning up
a full scan or the dashboard:

    argus scope list
        List every scopes/*.yaml file detected.

    argus scope show <apex>
        Pretty-print the resolved scope (apex + extras + outs + restrictions).
        Falls back to the wildcards file when no YAML is present.

    argus scope check <apex> <url>
        Run is_in_scope_with_reason(url) and print the verdict.
        Exit code: 0 = in scope, 1 = out of scope (handy for shell pipes).

    argus scope diff <apex> <urls_file>
        Pre-flight: bulk-check a list of URLs (one per line). Prints a
        per-host count of in/out + top-5 drop reasons.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

from core.scope import (
    Scope,
    ScopeYamlError,
    build_scope_for_target,
    find_scope_file,
    load_scope_yaml,
)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_scope(apex: str, config=None) -> Scope:
    """Same precedence as Pipeline: YAML override → scopes/<apex>.yaml → wildcards."""
    root = _project_root()
    cfg_scope = None
    if config is not None:
        cfg_scope = config.get("general", "scope_file", default=None)
    scope_path = None
    if cfg_scope:
        p = Path(cfg_scope)
        scope_path = p if p.is_absolute() else (root / p)
    if scope_path is None:
        scope_path = find_scope_file(apex, root / "scopes")
    if scope_path and scope_path.exists():
        try:
            return load_scope_yaml(scope_path, apex_override=apex)
        except ScopeYamlError as e:
            print(f"⚠ {scope_path}: {e} — falling back to wildcards", file=sys.stderr)
    return build_scope_for_target(apex=apex, wildcards_path=root / "wildcards")


def _cmd_list(args, config) -> int:
    d = _project_root() / "scopes"
    if not d.is_dir():
        print(f"(no scopes/ directory at {d})")
        return 0
    files = sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml")))
    if not files:
        print(f"(no scope files under {d})")
        return 0
    for f in files:
        try:
            sc = load_scope_yaml(f)
            print(
                f"{f.name:30s} org={sc.organisation:<20s} "
                f"apex={sc.apex} "
                f"+{len(sc.extra_in_scope)} -{len(sc.out_of_scope)} "
                f"{len(sc.restrictions)}r"
            )
        except ScopeYamlError as e:
            print(f"{f.name:30s} ⚠ {e}")
    return 0


def _cmd_show(args, config) -> int:
    sc = _resolve_scope(args.apex, config)
    if args.json:
        print(json.dumps(sc.describe(), indent=2))
        return 0
    print(f"organisation : {sc.organisation or '(none)'}")
    print(f"source       : {sc.source}")
    print(f"apex         : {sc.apex}")
    print(f"in-scope     : {len(sc.extra_in_scope)} extra pattern(s)")
    for p in sc.extra_in_scope:
        print(f"    + {p}")
    print(f"out-of-scope : {len(sc.out_of_scope)} pattern(s)")
    for p in sc.out_of_scope:
        print(f"    - {p}")
    print(f"restrictions : {len(sc.restrictions)}")
    for r in sc.restrictions:
        bits = []
        if r.host:     bits.append(f"host={r.host}")
        if r.path:     bits.append(f"path={r.path}")
        if r.max_rps:  bits.append(f"max_rps={r.max_rps}")
        if r.disabled: bits.append("DISABLED")
        if r.note:     bits.append(f"note={r.note!r}")
        print(f"    * {' '.join(bits)}")
    return 0


def _cmd_check(args, config) -> int:
    sc = _resolve_scope(args.apex, config)
    ok, reason = sc.is_in_scope_with_reason(args.url)
    restr = sc.get_restrictions(args.url)
    verdict = "IN  ✓" if ok else "OUT ✗"
    print(f"{verdict}  {args.url}")
    print(f"    apex   : {sc.apex} (source={sc.source})")
    print(f"    reason : {reason}")
    if restr:
        print("    restrictions matching this URL:")
        for r in restr:
            bits = []
            if r.max_rps:  bits.append(f"max_rps={r.max_rps}")
            if r.disabled: bits.append("DISABLED")
            if r.note:     bits.append(f"note={r.note!r}")
            print(f"      - host={r.host} path={r.path} {' '.join(bits)}")
    return 0 if ok else 1


def _cmd_diff(args, config) -> int:
    sc = _resolve_scope(args.apex, config)
    p = Path(args.urls_file)
    if not p.exists():
        print(f"file not found: {p}", file=sys.stderr)
        return 2
    in_hosts: dict[str, int] = {}
    out_reasons: dict[str, int] = {}
    out_hosts: dict[str, int] = {}
    total = 0
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        total += 1
        ok, reason = sc.is_in_scope_with_reason(s)
        # _normalize_host imported lazily to avoid cycle at module import time
        from core.scope import _normalize_host
        host = _normalize_host(s) or "?"
        if ok:
            in_hosts[host] = in_hosts.get(host, 0) + 1
        else:
            out_hosts[host]    = out_hosts.get(host, 0) + 1
            out_reasons[reason] = out_reasons.get(reason, 0) + 1
    print(f"Total candidates : {total}")
    print(f"In scope         : {sum(in_hosts.values())} ({len(in_hosts)} host(s))")
    print(f"Out of scope     : {sum(out_hosts.values())} ({len(out_hosts)} host(s))")
    if out_reasons:
        print("Top drop reasons :")
        for reason, n in sorted(out_reasons.items(), key=lambda x: -x[1])[:5]:
            print(f"    {n:6d}  {reason}")
    if args.verbose and out_hosts:
        print("Top dropped hosts:")
        for h, n in sorted(out_hosts.items(), key=lambda x: -x[1])[:10]:
            print(f"    {n:6d}  {h}")
    return 0


def run_scope_cli(argv: List[str], config) -> int:
    """argv = sys.argv[2:]  (everything after `argus scope`).
    Returns process exit code."""
    p = argparse.ArgumentParser(
        prog="argus scope",
        description="Inspect / debug Argus scope-as-code definitions"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List every scopes/*.yaml file")

    p_show = sub.add_parser("show", help="Show resolved scope for an apex")
    p_show.add_argument("apex", help="Target apex (e.g. shopify.com)")
    p_show.add_argument("--json", action="store_true", help="JSON output")

    p_chk = sub.add_parser("check", help="Check if a URL is in scope")
    p_chk.add_argument("apex", help="Target apex (e.g. shopify.com)")
    p_chk.add_argument("url",  help="URL or bare host to test")

    p_diff = sub.add_parser("diff", help="Bulk-check URLs from a file")
    p_diff.add_argument("apex",      help="Target apex (e.g. shopify.com)")
    p_diff.add_argument("urls_file", help="Path to file with one URL per line")
    p_diff.add_argument("-v", "--verbose", action="store_true",
                        help="Also print top dropped hosts")

    args = p.parse_args(argv)
    dispatch = {
        "list":  _cmd_list,
        "show":  _cmd_show,
        "check": _cmd_check,
        "diff":  _cmd_diff,
    }
    return dispatch[args.cmd](args, config)
