# h4wk3y3 — Advanced Reconnaissance Framework

> Automated, modular web reconnaissance pipeline for bug bounty hunting & penetration testing.

## Architecture

```
h4wk3y3/
├── h4wk3y3.py                  # Main CLI entrypoint
├── core/                     # Core engine
│   ├── pipeline.py           # Pipeline orchestrator (staged + parallel)
│   ├── multi_pipeline.py     # Multi-target wrapper
│   ├── database.py           # Postgres persistence (source of truth) + diff engine
│   ├── config.py             # YAML config loader
│   ├── logger.py             # Unified logging
│   ├── notifier.py           # Discord/Slack alerts
│   ├── auth.py               # bcrypt + signed-session auth
│   ├── audit.py              # Audit log writer
│   ├── user_cli.py           # `h4wk3y3 user ...` subcommand
│   ├── dns_resolver.py       # Shared async DNS helpers
│   ├── utils.py              # strip_ansi, env helpers
│   └── models.py             # Finding / ScanTarget / LiveHost dataclasses
├── modules/                  # 14 recon modules (run via Pipeline)
│   ├── m02_subdomain.py      # Passive multi-source + active brute + alterx
│   ├── m03_http_validator.py # HTTP probing + tech/WAF/CNAME detection
│   ├── m10_fetcher.py       # Full-body fetcher (feeds m11 / m12)
│   ├── m04_url_collector.py  # gau + katana, uro-dedup
│   ├── m05_screenshot.py     # Playwright Chromium captures
│   ├── m11_js_analyzer.py    # jsluice + sourcemapper + secret regex
│   ├── m06_takeover.py       # CNAME → 74 takeover signatures
│   ├── m12_pattern.py        # gf-style patterns + reflection canary + arjun
│   ├── m13_nuclei.py         # Tech-targeted + high-impact info templates
│   ├── m14_active.py         # File exposure / open redirect / dalfox / sqlmap
│   ├── m01_osint.py          # WHOIS + SPF/DMARC/DKIM + GitHub + HIBP
│   ├── m07_ports.py          # naabu + nmap -sV + cdncheck
│   ├── m08_tls.py            # testssl.sh wrapper
│   └── m09_quick_checks.py   # GraphQL / .git / .env / JWT / cloud buckets
├── config/
│   ├── h4wk3y3.yaml            # Main configuration (toggles + caps)
│   ├── patterns.yaml         # Custom regex patterns
│   └── h4wk3y3.env.example     # API keys / env template (copy → h4wk3y3.env)
├── dashboard/
│   ├── backend/              # FastAPI server (auth + audit + scan manager)
│   └── frontend/             # Single-file React 18 SPA (UMD CDN, no bundler)
├── data/
│   ├── wordlists/            # DNS + directory wordlists
│   ├── resolvers/            # DNS resolvers list
│   ├── nuclei-templates/     # Custom Nuclei templates
│   └── .session_secret + .first_admin   # Auth artefacts (Postgres-backed runtime)
├── output/                   # Scan results (one dir per target)
├── scripts/                  # install.sh, quick_scan.sh, run_tests.sh
├── deploy/                   # docker-compose.yml + entrypoint
├── exploit/                  # Manual exploit POCs (not part of pipeline)
├── tests/                    # 40 test files (~720 tests)
├── wildcards                 # Authorised scan targets (when dashboard remote-bound)
└── docs/                     # Pipeline/module reference, QA notes, Postgres + slides
```

## Pipeline Flow

The pipeline is staged with explicit dependencies; modules in the same stage run concurrently.

```
Pre-stage (no live-host deps)
  → M01: OSINT (WHOIS + email auth + GitHub secrets + HIBP)
  → M02: Subdomain Enum (passive multi-source + optional active brute)

Stage 1 (sequential)
  → M03: HTTP Validator + Tech Detection + WAF + CNAME

Stage 2 (parallel — all consume M03 live_hosts)
  → M04: URL Collection (gau + katana)
  → M05: Screenshots (Playwright)
  → M06: Takeover Detection
  → M07: Ports + CDN check
  → M08: TLS audit
  → M09: Quick checks (GraphQL / .git / .env / JWT / cloud buckets)

Stage 3 (sequential, post-M04)
  → M10: Body Fetcher (live_hosts + interesting URLs from M04)

Stage 4 (sequential, post-M10)
  → M11: JS Analyzer (secrets, endpoints, source maps)

Stage 5 (parallel)
  → M12: Pattern Analysis (gf + reflection canary + arjun)
  → M13: Nuclei (tech-targeted + high-impact info)

Stage 6 (sequential, post-M12/M13)
  → M14: Active Validation (file exposure / redirect / XSS / SQLi)
```

## Quick Start

```bash
# Install (Go tools, Python venv, Playwright)
./scripts/install.sh

# Full scan — all 14 modules
python h4wk3y3.py -t example.com --full

# Fast scan — OSINT + recon + URLs + screenshots + quick checks (m01, m02, m03, m10, m04, m05, m09)
python h4wk3y3.py -t example.com --fast

# Passive only — OSINT + subdomain enum (no active requests) (m01, m02)
python h4wk3y3.py -t example.com --passive

# Custom module list
python h4wk3y3.py -t example.com --modules m02,m03,m13

# Stealth mode (rate limited + jitter)
python h4wk3y3.py -t example.com --full --stealth

# Continuous mode (loop every N minutes)
python h4wk3y3.py -t example.com --full --watch --interval 60

# Multi-targets from file
python h4wk3y3.py -f targets.txt --full

# Launch dashboard (FastAPI on 127.0.0.1:8000 by default)
python h4wk3y3.py --dashboard

# User management (CLI subcommand)
python h4wk3y3.py user list
python h4wk3y3.py user create alice --role admin
```

## Modules

| #   | Module             | Tools                                                      | Output                                |
|-----|--------------------|------------------------------------------------------------|---------------------------------------|
| 10  | OSINT              | whois, dnspython, trufflehog, HIBP API                     | osint.json, github_secrets.json       |
| 01  | Subdomain Enum     | subfinder, assetfinder, findomain, crt.sh, certspotter, chaos, alterx, shuffledns, dnsx | subdomains.txt, cnames.json, dns_records.json |
| 02  | HTTP Validator     | aiohttp custom + httpx (probe), mmh3 favicon hash          | live_hosts.json, tech_report.json     |
| 02b | Body Fetcher       | aiohttp                                                    | bodies/, bodies_snippets.json         |
| 03  | URL Collector      | gau, katana, uro                                           | urls_all.txt, urls_live.txt           |
| 04  | Screenshots        | Playwright Chromium                                        | screenshots/, screenshots.json        |
| 05  | JS Analyzer        | jsluice, subjs, sourcemapper, custom regex                 | js_secrets.json, js_endpoints.json    |
| 06  | Takeover Detect    | nuclei takeover templates, dnsx                            | takeovers.json                        |
| 07  | Pattern Analysis   | gf-style regex, arjun, reflection canary                   | patterns.json, params.json            |
| 08  | Nuclei Scan        | nuclei (tech-targeted + always-run profile)                | nuclei_findings.json                  |
| 09  | Active Validation  | dalfox, sqlmap, custom probes                              | active_findings.json                  |
| 11  | Ports + CDN        | naabu, nmap -sV, cdncheck                                  | ports.json, services.json             |
| 12  | TLS Audit          | testssl.sh                                                 | tls_audit.json                        |
| 13  | Quick Checks       | aiohttp custom (5 atomic checks)                           | quick_checks.json                     |

## Output Schema

Every finding follows the unified schema:
```json
{
  "id": "uuid",
  "type": "subdomain_takeover|js_secret|pattern_match|nuclei_finding|...",
  "severity": "info|low|medium|high|critical",
  "confidence": 0.0,
  "target": "sub.example.com",
  "url": "https://sub.example.com/path",
  "module_source": "m06_takeover",
  "title": "Short description",
  "evidence": "Raw evidence string",
  "metadata": {},
  "timestamp": "ISO8601",
  "scan_id": "uuid"
}
```

## Configuration

Edit `config/h4wk3y3.yaml` to set:
- API keys (Chaos via `api_keys.chaos` or `PDCP_API_KEY`; subfinder reads `~/.config/subfinder/provider-config.yaml`)
- Module toggles (`enabled: true/false`)
- Timeouts and caps per module (URLs, hosts, ports)
- Active enum on/off (shuffledns + alterx, off by default)
- Nuclei severity + tag filters
- Notification webhooks (Discord/Slack)
- Dashboard host/port (default 127.0.0.1:8000)

## Multi-org (Étape 2.1)

Organisations group related apexes (one BBP programme → many domains).
Scope resolution at scan time uses the org's `scope_file` by default,
with a per-target override available.

```bash
# Create an org and link targets
h4wk3y3 org add shopify --h1 shopify --scope-file scopes/shopify.com.yaml
h4wk3y3 org link shopify.com shopify
h4wk3y3 org link checkout.shopify.com shopify

# Inspect
h4wk3y3 org list
h4wk3y3 org show shopify              # details + targets + aggregate stats
h4wk3y3 org targets shopify           # just the targets

# Update / delete
h4wk3y3 org update shopify --notes "private programme"
h4wk3y3 org delete shopify --force    # unlinks targets, deletes the org row
```

Scope resolution precedence (used by `h4wk3y3.py -t <apex>` and the dashboard):

1. `targets.scope_file_override` (per-apex override stored in DB)
2. `organisations.scope_file` (org default, via target → org join)
3. `general.scope_file` in `h4wk3y3.yaml` (global override)
4. `scopes/<apex>.yaml` (auto-discovery)
5. Legacy `wildcards` file

Dashboard: the sidebar has an org selector — picking an org filters the
target list, findings, and stats to its members. `/api/findings?org=X`,
`/api/findings/stats?org=X`, `/api/orgs/...` and `/api/targets?org=X`
all support the filter server-side.

## Scope-as-code (`scopes/<apex>.yaml`)

The legacy `wildcards` file (flat list of in-scope apexes) still works,
but per-target YAML scopes are richer and auto-discovered:

```yaml
# scopes/shopify.com.yaml
organisation: shopify
apex: shopify.com
scope:
  in:  ["*.shopify.com", "*.shopifycloud.com"]
  out: ["*.shopify-internal.com"]
  restrictions:
    - host: "checkout.shopify.com"
      max_rps: 5
    - path: "/api/payments/*"
      disabled: true        # filtered out like out_of_scope
```

Precedence at scan time: `scopes/<apex>.yaml` > `general.scope_file` in
`h4wk3y3.yaml` > legacy `wildcards`. `restrictions` with `disabled: true`
reject matching URLs the same way as `out`. `max_rps` is exposed via
`Scope.get_restrictions(url)` so modules can self-throttle (not yet
enforced — wired in 2.3 scheduler).

CLI helpers:

```bash
h4wk3y3 scope list                                    # every scopes/*.yaml
h4wk3y3 scope show shopify.com                        # resolved scope
h4wk3y3 scope show shopify.com --json                 # machine-readable
h4wk3y3 scope check shopify.com https://x.shopify.com # exit 0=in, 1=out
h4wk3y3 scope diff shopify.com /tmp/urls.txt          # bulk pre-flight
```

`scopes/*.yaml` is gitignored by default; commit `scopes/example.com.yaml`
as a template only.

## Dashboard & Auth

- FastAPI backend + React 18 SPA (single file, UMD CDN, no build step).
- bcrypt password hashing (cost 12), signed sessions via itsdangerous (8h sliding window).
- Three roles: `super-admin` (full + user mgmt), `admin` (scan + read), `user` (read-only).
- Bootstrap super-admin auto-created on first boot — credentials in `data/.first_admin` (mode 0600, delete after first login).
- Audit log (`audit_log` table) tracks logins, scan start/stop, config updates, user mgmt, finding deletions.
- Dashboard binds to `127.0.0.1` by default. If bound to `0.0.0.0`, scans are restricted to domains listed in the `wildcards` file (allowlist).

## Testing

```bash
# Run full test suite
./scripts/run_tests.sh
# or directly
pytest tests/
```

40 test files (~720 tests) cover models, config, pipeline, scan_manager,
takeover, the diff engine, the dashboard API, and per-module behaviour
(m02/m03/m04/m11/m12/m14 + CVE).

## Known limitations (as of 2026-06-17)

- **Scope enforcement is per-module, not a hard gate** — m04/m12/m13/m14 each
  call `target.scope.filter_urls()` (defense-in-depth), but enforcement relies
  on every module opting in rather than a single choke point. Recovered targets
  (m11 source-map recovery) are scope-filtered before m13/m14 probe them.
- **`max_rps` scope restriction is honoured only by m13** (nuclei). Other
  modules read it but don't yet self-throttle per-host.
- **CVE scan is opt-in / surface-first** — the default nuclei profile excludes
  `cve`/`intrusive` tags; CVE validation is a separate path (m15 feeds → m17
  correlate → m18 validate the matching template per CVE).

