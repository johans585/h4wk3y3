"""
Argus V2 — `argus org ...` subcommand handler.

Inspect / manage organisations and target ↔ org links from the shell:

    argus org list
        List every organisation with target count.

    argus org show <name>
        Show org details + linked targets + aggregate stats.

    argus org add <name> [--h1 HANDLE] [--scope-file PATH] [--notes TEXT]
        Create a new org.

    argus org update <name> [--h1 HANDLE] [--scope-file PATH] [--notes TEXT]
        Update fields (omitted flags leave the field unchanged).

    argus org delete <name> [--force]
        Delete an org. Refuses if it has targets unless --force.

    argus org link <apex> <org>
        Attach an apex to an org (creates target row if needed).

    argus org unlink <apex>
        Detach a target from any org (keeps the target row).

    argus org targets [<org>]
        List targets — for a specific org, or all unlinked targets when
        called without args (--unlinked alias).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from core.database  import ArgusDB
from core.db_engine import build_engine
from core import organisation as O


def _open_db(config) -> ArgusDB:
    return ArgusDB(engine=build_engine(config))


def _print_table(rows: list[dict], cols: list[str]) -> None:
    """Cheap fixed-width table — no extra dep."""
    if not rows:
        print("(no rows)")
        return
    widths = {c: max(len(c), *(len(str(r.get(c, "") or "")) for r in rows)) for c in cols}
    sep = "  "
    print(sep.join(c.ljust(widths[c]) for c in cols))
    print(sep.join("-" * widths[c] for c in cols))
    for r in rows:
        print(sep.join(str(r.get(c, "") or "").ljust(widths[c]) for c in cols))


# ─────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────

def _cmd_list(args, db) -> int:
    orgs = O.list_orgs(db)
    enriched = []
    for org in orgs:
        targets = O.list_targets_for_org(db, org["name"])
        enriched.append({
            **org,
            "targets": len(targets),
        })
    if args.json:
        print(json.dumps(enriched, indent=2))
        return 0
    _print_table(enriched, ["id", "name", "h1_handle", "scope_file", "targets", "created_at"])
    return 0


def _cmd_show(args, db) -> int:
    org = O.get_org(db, args.name)
    if org is None:
        print(f"organisation {args.name!r} not found", file=sys.stderr)
        return 1
    targets = O.list_targets_for_org(db, args.name)
    stats   = O.org_stats(db, args.name)
    if args.json:
        print(json.dumps({
            "organisation": org,
            "targets":      targets,
            "stats":        stats,
        }, indent=2))
        return 0
    print(f"organisation : {org['name']}")
    print(f"id           : {org['id']}")
    print(f"h1_handle    : {org['h1_handle'] or '(none)'}")
    print(f"scope_file   : {org['scope_file'] or '(none)'}")
    print(f"notes        : {org['notes'] or '(none)'}")
    print(f"created_at   : {org['created_at']}")
    print()
    print(f"targets ({len(targets)}):")
    for t in targets:
        flag = "*" if t["scope_file_override"] else " "
        print(f"  {flag} {t['apex']:40s}  override={t['scope_file_override'] or '-'}")
    print()
    print("stats:")
    print(f"  scans      : {stats['scans']}")
    print(f"  live_hosts : {stats['live_hosts']}")
    print(f"  findings   : {stats['findings']}")
    if stats["by_severity"]:
        order = ["critical", "high", "medium", "low", "info"]
        bits  = [f"{s}={stats['by_severity'].get(s, 0)}" for s in order
                 if stats['by_severity'].get(s)]
        print(f"             {' '.join(bits)}")
    return 0


def _cmd_add(args, db) -> int:
    try:
        org = O.create_org(
            db, args.name,
            h1_handle=args.h1,
            scope_file=args.scope_file,
            notes=args.notes,
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"✓ created organisation {org['name']!r} (id={org['id']})")
    return 0


def _cmd_update(args, db) -> int:
    kwargs: dict = {}
    if args.h1         is not None: kwargs["h1_handle"]  = args.h1
    if args.scope_file is not None: kwargs["scope_file"] = args.scope_file
    if args.notes      is not None: kwargs["notes"]      = args.notes
    if args.clear_h1:         kwargs["h1_handle"]  = None
    if args.clear_scope_file: kwargs["scope_file"] = None
    if args.clear_notes:      kwargs["notes"]      = None
    if not kwargs:
        print("nothing to update (pass at least one flag)", file=sys.stderr)
        return 2
    try:
        org = O.update_org(db, args.name, **kwargs)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"✓ updated organisation {org['name']!r}")
    return 0


def _cmd_delete(args, db) -> int:
    try:
        O.delete_org(db, args.name, force=args.force)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"✓ deleted organisation {args.name!r}")
    return 0


def _cmd_link(args, db) -> int:
    try:
        t = O.link_target(
            db, args.apex, args.org,
            scope_file_override=args.override,
            notes=args.notes,
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    org_name = args.org or "(none)"
    print(f"✓ linked {t['apex']} → {org_name}")
    return 0


def _cmd_unlink(args, db) -> int:
    try:
        O.unlink_target(db, args.apex)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"✓ unlinked {args.apex}")
    return 0


def _cmd_targets(args, db) -> int:
    if args.unlinked or args.org is None:
        rows = O.list_unlinked_targets(db)
        label = "unlinked"
    else:
        if O.get_org(db, args.org) is None:
            print(f"organisation {args.org!r} not found", file=sys.stderr)
            return 1
        rows = O.list_targets_for_org(db, args.org)
        label = f"org={args.org}"
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    print(f"targets [{label}]:")
    _print_table(rows, ["apex", "organisation_id", "scope_file_override", "created_at"])
    return 0


# ─────────────────────────────────────────────────────────────────────
# argparse wiring
# ─────────────────────────────────────────────────────────────────────

def run_org_cli(argv: List[str], config) -> int:
    p = argparse.ArgumentParser(
        prog="argus org",
        description="Manage organisations and target ↔ org links",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="List every organisation")
    p_list.add_argument("--json", action="store_true")

    p_show = sub.add_parser("show", help="Show org details + targets + stats")
    p_show.add_argument("name")
    p_show.add_argument("--json", action="store_true")

    p_add = sub.add_parser("add", help="Create a new organisation")
    p_add.add_argument("name")
    p_add.add_argument("--h1",         dest="h1",         help="HackerOne handle")
    p_add.add_argument("--scope-file", dest="scope_file", help="Path to scopes/<x>.yaml")
    p_add.add_argument("--notes",      help="Free-text notes")

    p_upd = sub.add_parser("update", help="Update an organisation")
    p_upd.add_argument("name")
    p_upd.add_argument("--h1",         dest="h1",         default=None)
    p_upd.add_argument("--scope-file", dest="scope_file", default=None)
    p_upd.add_argument("--notes",      default=None)
    p_upd.add_argument("--clear-h1",         action="store_true", help="Clear h1_handle")
    p_upd.add_argument("--clear-scope-file", action="store_true", help="Clear scope_file")
    p_upd.add_argument("--clear-notes",      action="store_true", help="Clear notes")

    p_del = sub.add_parser("delete", help="Delete an organisation")
    p_del.add_argument("name")
    p_del.add_argument("--force", action="store_true",
                       help="Delete even if targets are linked (unlinks them)")

    p_link = sub.add_parser("link", help="Attach an apex to an org")
    p_link.add_argument("apex")
    p_link.add_argument("org",      help="Org name (use 'unlink' for detach)")
    p_link.add_argument("--override", help="Per-target scope file override")
    p_link.add_argument("--notes",    help="Per-target notes")

    p_unl = sub.add_parser("unlink", help="Detach a target from any org")
    p_unl.add_argument("apex")

    p_tgt = sub.add_parser("targets", help="List targets for an org (or unlinked)")
    p_tgt.add_argument("org", nargs="?", help="Org name. Omit to list unlinked targets.")
    p_tgt.add_argument("--unlinked", action="store_true",
                       help="List unlinked targets (also implied when org is omitted)")
    p_tgt.add_argument("--json", action="store_true")

    args = p.parse_args(argv)
    dispatch = {
        "list":    _cmd_list,
        "show":    _cmd_show,
        "add":     _cmd_add,
        "update":  _cmd_update,
        "delete":  _cmd_delete,
        "link":    _cmd_link,
        "unlink":  _cmd_unlink,
        "targets": _cmd_targets,
    }
    db = _open_db(config)
    try:
        return dispatch[args.cmd](args, db)
    finally:
        db.close()
