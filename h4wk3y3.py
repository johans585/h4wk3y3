#!/usr/bin/env python3
"""
Argus V2 - Advanced Reconnaissance Framework
Usage: python h4wk3y3.py [options]
"""

import argparse
import asyncio
import sys
import os
from pathlib import Path

# Auto re-exec in argus-env venv if available — the Debian apt python3-playwright
# package ships a broken cli.js path; the venv has a working playwright + chromium.
# (Compare sys.prefix because the venv python3 is a symlink to system python.)
_HERE = Path(__file__).resolve().parent
_VENV_DIR = _HERE / 'argus-env'
_VENV_PY  = _VENV_DIR / 'bin' / 'python3'
if _VENV_PY.exists() and Path(sys.prefix).resolve() != _VENV_DIR.resolve():
    os.execv(str(_VENV_PY), [str(_VENV_PY), str(_HERE / 'h4wk3y3.py'), *sys.argv[1:]])

# Ensure all tools are in PATH (Go bins + Python venvs).
# Resolved relative to $HOME so the same Argus checkout works for any user.
# ARGUS_EXTRA_PATH (colon-separated) lets ops add custom tool dirs without
# editing source.
_HOME = Path(os.path.expanduser('~'))
_TOOL_PATHS = [
    str(_HOME / 'go' / 'bin'),                              # gau, gospider, gf, dalfox, anew, chaos, shuffledns, fff
    '/usr/local/go-tools/bin',                              # katana, hakrawler (system-wide install)
    '/usr/local/go/bin',                                    # alt go install location
    str(_HOME / '.local' / 'bin'),                          # pip user installs
    str(_HOME / 'ia' / 'hexstrike-ai' / 'hexstrike-env' / 'bin'),  # uro, waymore, httpx
]
for _p in os.environ.get('ARGUS_EXTRA_PATH', '').split(':'):
    if _p:
        _TOOL_PATHS.append(_p)
for _p in _TOOL_PATHS:
    if _p not in os.environ.get('PATH', '') and Path(_p).exists():
        os.environ['PATH'] = _p + ':' + os.environ['PATH']

# Make sure imports resolve from project root
sys.path.insert(0, str(Path(__file__).parent))

from core.config   import ArgusConfig
from core.database import ArgusDB
from core.logger   import get_logger, banner
from core.models   import ScanTarget
from core.pipeline import Pipeline


def parse_args():
    p = argparse.ArgumentParser(
        description='Argus V2 — Advanced Recon Framework',
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Target
    target_g = p.add_mutually_exclusive_group()
    target_g.add_argument('-t', '--target',  metavar='DOMAIN',
                          help='Single target domain (e.g. example.com)')
    target_g.add_argument('-f', '--file',    metavar='FILE',
                          help='File with one target per line')

    # Scan modes
    mode_g = p.add_mutually_exclusive_group()
    mode_g.add_argument('--full',   action='store_true',
                        help='All modules m01–m14 (+ CVE m15/m17/m18 when enabled) — default')
    mode_g.add_argument('--fast',   action='store_true',
                        help='OSINT + recon + URLs + screenshots + quick checks '
                             '(m01,m02,m03,m10,m04,m05,m09) — no nuclei/active')
    mode_g.add_argument('--passive',action='store_true',
                        help='OSINT + subdomain enum only (m01,m02) — no active requests')
    mode_g.add_argument('--modules', metavar='m02,m03,...',
                        help='Comma-separated list of modules to run')

    # Options
    p.add_argument('--stealth',    action='store_true', help='Rate limiting + random delays')
    p.add_argument('--watch',      action='store_true', help='Continuous mode: re-scan every N minutes')
    p.add_argument('--interval',   type=int, default=60, metavar='MIN',
                   help='Watch interval in minutes (default: 60)')
    p.add_argument('--notify',     metavar='discord|slack',
                   help='Enable notifications (configure webhook in h4wk3y3.yaml)')
    p.add_argument('-c', '--config', metavar='PATH', default=None,
                   help='Path to custom config file')
    p.add_argument('-o', '--output', metavar='DIR',
                   help='Override output directory')
    p.add_argument('--dashboard',  action='store_true', help='Launch web dashboard')
    p.add_argument('-v', '--verbose', action='store_true', help='Debug logging')

    return p.parse_args()


def get_modules(args) -> list:
    if args.modules:
        return [m.strip() for m in args.modules.split(',')]
    if args.fast:
        # OSINT + recon + URL collect + screenshots + quick checks (no nuclei/active)
        return ['m01', 'm02', 'm03', 'm10', 'm04', 'm05', 'm09']
    if args.passive:
        # Pure passive: OSINT (whois/dmarc/hibp) + subdomain enumeration
        return ['m01', 'm02']
    return None  # All modules


def normalize_domain(raw: str) -> str:
    """
    Normalise un domaine depuis n'importe quel format:
      *.example.com       -> example.com
      .example.com        -> example.com
      http://example.com  -> example.com
      https://sub.ex.com/ -> sub.ex.com
      sub.example.com     -> sub.example.com  (inchangé)
    """
    d = raw.strip().lower()
    d = d.removeprefix('http://').removeprefix('https://')
    d = d.rstrip('/')
    # Wildcard: *.foo.com ou *foo.com
    if d.startswith('*.'):
        d = d[2:]
    elif d.startswith('*'):
        d = d[1:]
    # Leading dot: .foo.com
    if d.startswith('.'):
        d = d[1:]
    return d


async def run_scan(config: ArgusConfig, db: ArgusDB, domain: str,
                   modules: list, stealth: bool) -> ScanTarget:
    target   = ScanTarget(domain=domain)
    pipeline = Pipeline(config, db)
    return await pipeline.run(target, modules=modules, stealth=stealth)


async def watch_mode(config: ArgusConfig, db: ArgusDB, domains: list,
                     modules: list, stealth: bool, interval_min: int):
    log = get_logger('watch')
    log.info(f"👁  Watch mode — scanning every {interval_min} minutes")
    while True:
        for domain in domains:
            log.info(f"🔄 Watch scan: {domain}")
            await run_scan(config, db, domain, modules, stealth)
        log.info(f"💤 Next scan in {interval_min} minutes...")
        await asyncio.sleep(interval_min * 60)


def launch_dashboard(config: ArgusConfig, db: ArgusDB):
    """Launch FastAPI dashboard — doit être appelé hors boucle asyncio."""
    try:
        import uvicorn
        from dashboard.backend.app import create_app
        app  = create_app(config, db)
        host = config.get('dashboard', 'host', default='127.0.0.1')
        port = config.get('dashboard', 'port', default=8000)
        print(f"\n🌐 Dashboard running at http://{host}:{port}\n")
        cfg = uvicorn.Config(app, host=host, port=port, log_level='warning', loop='asyncio')
        server = uvicorn.Server(cfg)
        server.run()
    except ImportError as e:
        print(f"Dashboard dependencies missing: {e}")
        print("Run: pip install uvicorn fastapi")


class _DashboardRequest(Exception):
    """Sentinelle pour sortir de asyncio.run() et lancer uvicorn proprement."""
    def __init__(self, config, db):
        self.config = config
        self.db     = db


def _check_api_keys(config, log) -> None:
    """Honest startup audit of API key availability.

    Two paths feed the passive enumeration:
      1. Direct: our Python code calls the `chaos` CLI which reads
         PDCP_API_KEY from the environment. We control this path.
      2. Indirect: subfinder reads ~/.config/subfinder/provider-config.yaml
         on its own. Keys for shodan/virustotal/github/censys/etc. live
         THERE, not in h4wk3y3.yaml. We can't propagate them transparently
         (subfinder doesn't honour env vars for most providers), so we
         only inspect the file and warn if it looks empty.
    """
    import os
    from pathlib import Path
    import yaml as _yaml

    # ── 1. Direct check: chaos (our code calls the CLI) ──────────────
    cfg_keys = config.get('api_keys', default={}) or {}
    if not (cfg_keys.get('chaos') or os.getenv('PDCP_API_KEY')):
        log.warning(
            "⚠ chaos: PDCP_API_KEY missing — chaos source disabled in M01"
        )

    # ── 2. Indirect check: subfinder provider-config.yaml ────────────
    subf_cfg = Path.home() / '.config' / 'subfinder' / 'provider-config.yaml'
    if not subf_cfg.exists():
        log.warning(
            f"⚠ subfinder: no provider config at {subf_cfg} — passive enum "
            "limited to free sources (crt.sh, hackertarget). Run subfinder "
            "once to generate it, then add keys."
        )
        return

    try:
        providers = _yaml.safe_load(subf_cfg.read_text()) or {}
    except Exception:
        return

    # Count providers with any key value vs total providers.
    populated = [p for p, v in providers.items() if v]
    if len(populated) == 0:
        log.warning(
            f"⚠ subfinder: 0/{len(providers)} providers have keys in "
            f"{subf_cfg} — passive enum will only use free sources "
            "(~30% of potential coverage). Edit that file to add keys "
            "(shodan, virustotal, github, securitytrails, censys, etc.)."
        )
    elif len(populated) < 5:
        log.info(
            f"   subfinder: {len(populated)}/{len(providers)} providers configured "
            f"({', '.join(populated[:5])}{'…' if len(populated) > 5 else ''})"
        )


def _preflight_report(config, log) -> None:
    """Consolidated startup preflight: API keys + external tools + coverage.

    Keys are read from the environment (config/h4wk3y3.env is auto-loaded into
    os.environ by ArgusConfig). Each line says what's gained/lost so the
    operator sees coverage at a glance instead of discovering gaps mid-scan.
    """
    import os
    import shutil

    # (env var, capability, impact-if-missing)
    keys = [
        ("PDCP_API_KEY",     "chaos subdomains (m02)",      "less passive enum"),
        ("GITHUB_TOKEN",     "GitHub secret hunt (m01)",    "github scan skipped"),
        ("HIBP_API_KEY",     "breach correlation (m01)",    "HIBP skipped"),
        ("NVD_API_KEY",      "CVE feed pull (m15)",         "NVD rate-limited 5→50 req/30s"),
        ("SHODAN_API_KEY",   "external surface (m16/B5)",   "Shodan cross-ref off"),
        ("CENSYS_API_ID",    "external surface (B6)",       "Censys cross-ref off"),
    ]
    present = [k for k, _, _ in keys if os.getenv(k)]
    missing = [(k, cap, imp) for k, cap, imp in keys if not os.getenv(k)]
    log.info(f"🔑 API keys: {len(present)}/{len(keys)} present"
             + (f" ({', '.join(present)})" if present else ""))
    for k, cap, imp in missing:
        log.info(f"   ○ {k} absent → {cap}: {imp}")

    # External CLI tools per module. Missing → that module degrades/skips.
    tools = [
        ("subfinder", "m02"), ("assetfinder", "m02"), ("findomain", "m02"),
        ("httpx", "m03"), ("dnsx", "m02"), ("katana", "m04"), ("gau", "m04"),
        ("nuclei", "m13"), ("rustscan", "m07"), ("naabu", "m07"), ("nmap", "m07"),
        ("testssl.sh", "m08"), ("jsluice", "m11"), ("dalfox", "m14"),
        ("sqlmap", "m14"), ("wafw00f", "m03"),
    ]
    missing_tools = [(t, m) for t, m in tools if not shutil.which(t)]
    if missing_tools:
        log.warning(
            f"🛠  tools: {len(tools) - len(missing_tools)}/{len(tools)} present — "
            "missing: " + ", ".join(f"{t}({m})" for t, m in missing_tools)
            + " — those modules degrade/skip. Run scripts/install.sh."
        )
    else:
        log.info(f"🛠  tools: {len(tools)}/{len(tools)} present")


async def main():
    banner()
    args = parse_args()

    # ── Config ────────────────────────────────────────────────
    config = ArgusConfig(args.config)
    if args.output:
        config._data['general']['output_dir'] = args.output
    if args.verbose:
        config._data['general']['log_level'] = 'DEBUG'

    # Argus est Postgres-only depuis le switch 2026-05. La DB est résolue
    # via core.db_engine.build_engine(config) qui lit general.db_url.
    from core.db_engine import build_engine
    db  = ArgusDB(engine=build_engine(config))
    log = get_logger('argus', level=config.get('general', 'log_level', default='INFO'))

    # ── Startup preflight ─────────────────────────────────────
    # Consolidated audit: API keys (env / config/h4wk3y3.env) + external tools +
    # subfinder providers. Surfaces coverage gaps up-front instead of mid-scan.
    _preflight_report(config, log)
    _check_api_keys(config, log)

    # Self-heal scans orphaned on 'running' by a previous hard kill (age-gated,
    # so a concurrent legitimate scan is untouched).
    try:
        _fixed = db.abandon_stale_scans()
        if _fixed:
            log.warning(f"🧹 marked {_fixed} stale 'running' scan(s) as abandoned")
    except Exception:
        pass

    # ── Dashboard mode ────────────────────────────────────────
    if args.dashboard:
        # Signale au __main__ block de lancer le dashboard hors asyncio
        raise _DashboardRequest(config, db)

    # ── Collect targets ───────────────────────────────────────
    domains = []
    if args.target:
        domains = [normalize_domain(args.target)]
    elif args.file:
        f = Path(args.file)
        if not f.exists():
            log.error(f"Target file not found: {f}")
            sys.exit(1)
        raw_lines = [l for l in f.read_text().splitlines() if l.strip() and not l.startswith('#')]
        domains = list(dict.fromkeys(normalize_domain(l) for l in raw_lines))  # déduplique
        # Log les wildcards résolus
        for raw, resolved in zip(raw_lines, domains):
            if '*' in raw or raw.strip().lower() != resolved:
                log.info(f"   wildcard/alias: {raw.strip()} → {resolved}")
    else:
        log.error("No target specified. Use -t <domain> or -f <file>")
        print("\nUsage examples:")
        print("  python h4wk3y3.py -t example.com --full")
        print("  python h4wk3y3.py -t example.com --fast --stealth")
        print("  python h4wk3y3.py -f targets.txt --full --notify discord")
        print("  python h4wk3y3.py --dashboard")
        sys.exit(1)

    modules = get_modules(args)
    stealth = args.stealth or config.get('general', 'stealth_mode', default=False)

    log.info(f"🎯 Targets: {len(domains)} domain(s)")
    log.info(f"🔧 Modules: {modules or 'all'} | Stealth: {stealth}")

    # ── Scan ──────────────────────────────────────────────────
    if args.watch:
        await watch_mode(config, db, domains, modules, stealth, args.interval)
    else:
        # Pipeline classique — 1 domaine à la fois (stable, pas de OOM)
        for i, domain in enumerate(domains, 1):
            log.info(f"\n[{i}/{len(domains)}] Scanning {domain}")
            await run_scan(config, db, domain, modules, stealth)

    db.close()
    log.info("🏁 All scans complete.")


if __name__ == '__main__':
    # `argus user ...` subcommand: handle before the regular argparse pipeline
    # to keep the CLI surface clean. No banner, no scan setup.
    if len(sys.argv) > 1 and sys.argv[1] == 'user':
        from core.config import ArgusConfig as _ArgusConfig
        from core.user_cli import run_user_cli as _run_user_cli
        # Argus est Postgres-only depuis le switch 2026-05 — la CLI user
        # passe désormais l'engine SQLAlchemy au sous-module, plus de path.
        _cfg = _ArgusConfig(None)
        sys.exit(_run_user_cli(sys.argv[2:], _cfg))

    # `argus scope ...` subcommand: introspection only, no DB, no banner.
    if len(sys.argv) > 1 and sys.argv[1] == 'scope':
        from core.config   import ArgusConfig as _ArgusConfig
        from core.scope_cli import run_scope_cli as _run_scope_cli
        _cfg = _ArgusConfig(None)
        sys.exit(_run_scope_cli(sys.argv[2:], _cfg))

    # `argus org ...` subcommand: multi-org CRUD (Étape 2.1). No banner.
    if len(sys.argv) > 1 and sys.argv[1] == 'org':
        from core.config import ArgusConfig as _ArgusConfig
        from core.org_cli import run_org_cli as _run_org_cli
        _cfg = _ArgusConfig(None)
        sys.exit(_run_org_cli(sys.argv[2:], _cfg))

    try:
        asyncio.run(main())
    except _DashboardRequest as req:
        # Lance uvicorn ici, hors de toute boucle asyncio
        launch_dashboard(req.config, req.db)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)
