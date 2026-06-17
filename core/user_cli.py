"""
Argus V2 — `argus user ...` subcommand handler.

Provides admin recovery + user mgmt without going through the dashboard.
Useful when you forgot your super-admin password (use 'reset-admin').

Usage:
    argus user list
    argus user add <name> --role super-admin|admin|user
    argus user chpass <name>
    argus user disable <name>
    argus user enable <name>
    argus user reset-admin    # creates / re-enables a super-admin with random password
"""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import List

from core.database import ArgusDB
from core.auth import (
    list_users, create_user, set_password, set_enabled, get_user,
    ensure_super_admin_bootstrap, _gen_random_password,
    VALID_ROLES,
)


def _prompt_password(label: str = "Password") -> str:
    while True:
        p1 = getpass.getpass(f"{label}: ")
        if len(p1) < 8:
            print("Password must be at least 8 characters.")
            continue
        p2 = getpass.getpass(f"{label} (confirm): ")
        if p1 != p2:
            print("Passwords do not match.")
            continue
        return p1


def run_user_cli(argv: List[str], config) -> int:
    """argv = sys.argv[2:]  (everything after `argus user`).
    `config` is an ArgusConfig instance (used to resolve the Postgres DSN
    via core.db_engine.build_engine). Returns process exit code."""
    p = argparse.ArgumentParser(
        prog="argus user",
        description="User management for Argus dashboard auth"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List all users")

    p_add = sub.add_parser("add", help="Create a new user")
    p_add.add_argument("username")
    p_add.add_argument("--role", choices=VALID_ROLES, default="user")

    p_chp = sub.add_parser("chpass", help="Change a user's password")
    p_chp.add_argument("username")

    p_dis = sub.add_parser("disable", help="Disable a user (audit attribution preserved)")
    p_dis.add_argument("username")

    p_ena = sub.add_parser("enable", help="Re-enable a previously-disabled user")
    p_ena.add_argument("username")

    sub.add_parser("reset-admin",
                   help="Create or re-enable a super-admin with a fresh random password")

    args = p.parse_args(argv)

    from core.db_engine import build_engine
    db = ArgusDB(engine=build_engine(config))

    try:
        if args.cmd == "list":
            users = list_users(db)
            if not users:
                print("(no users)")
                return 0
            print(f"{'USERNAME':<24} {'ROLE':<14} {'ENABLED':<8} {'CREATED':<32} LAST_LOGIN")
            for u in users:
                print(f"{u['username']:<24} {u['role']:<14} "
                      f"{'yes' if u['enabled'] else 'no':<8} "
                      f"{u['created_at']:<32} {u['last_login'] or '-'}")
            return 0

        if args.cmd == "add":
            pwd = _prompt_password("Password")
            create_user(db, args.username, pwd, args.role)
            print(f"[+] user {args.username!r} created (role={args.role})")
            return 0

        if args.cmd == "chpass":
            if get_user(db, args.username) is None:
                print(f"[!] user {args.username!r} not found", file=sys.stderr)
                return 1
            pwd = _prompt_password("New password")
            set_password(db, args.username, pwd)
            print(f"[+] password updated for {args.username!r}")
            return 0

        if args.cmd == "disable":
            if get_user(db, args.username) is None:
                print(f"[!] user {args.username!r} not found", file=sys.stderr)
                return 1
            set_enabled(db, args.username, False)
            print(f"[+] user {args.username!r} disabled")
            return 0

        if args.cmd == "enable":
            if get_user(db, args.username) is None:
                print(f"[!] user {args.username!r} not found", file=sys.stderr)
                return 1
            set_enabled(db, args.username, True)
            print(f"[+] user {args.username!r} enabled")
            return 0

        if args.cmd == "reset-admin":
            # If a super-admin already exists, generate a new password for the
            # first one. Otherwise bootstrap creates a fresh one.
            existing = [u for u in list_users(db) if u['role'] == 'super-admin']
            if existing:
                target = existing[0]['username']
                pwd = _gen_random_password(16)
                set_password(db, target, pwd)
                set_enabled(db, target, True)
                print(f"[+] super-admin {target!r} password reset")
                print(f"    new password: {pwd}")
                return 0
            else:
                creds = ensure_super_admin_bootstrap(db, str(db.db_path))
                if creds:
                    print("[+] bootstrap super-admin created")
                    print(f"    username: {creds['username']}")
                    print(f"    password: {creds['password']}")
                    print(f"    creds file: {creds['creds_file']}")
                else:
                    print("[!] something unexpected: no super-admin found yet bootstrap returned None",
                          file=sys.stderr)
                    return 1
                return 0

    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1
    finally:
        db.close()

    return 0
