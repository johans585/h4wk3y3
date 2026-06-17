# h4wk3y3 — Docker deployment

Self-contained container build. **Every recon tool is baked into the image**
— deploy on any host that has Docker, with zero host-side tool install. Lives
inside the repo at `<repo>/deploy/`; the build context is the repo root so the
image bakes the actual source (single source of truth).

Base image: `kalilinux/kali-rolling`. Multi-stage: the Go SDK stays in a
builder stage, only the compiled binaries land in the runtime image.

---

## Topology

```
┌────────────────────────────┐     ┌──────────────────────────┐
│ postgres (postgres:18)     │◄────│ h4wk3y3 (kali-rolling)   │
│  - DB  h4wk3y3             │     │  - FastAPI dashboard     │
│  - volume postgres-data    │     │  - 14-module pipeline    │
│  - healthcheck pg_isready  │     │  - depends_on: healthy   │
└────────────────────────────┘     └──────────────────────────┘
                                            │ entrypoint pre-flight
                                            ▼ 1. wait for postgres
                                              2. alembic upgrade head
                                              3. dashboard host → 0.0.0.0
                                              4. refresh resolvers
```

The dashboard is published on the **host loopback only** (`127.0.0.1:8000`),
so it is never exposed to the internet. Reach it through an SSH tunnel.

---

## Quick start (build-on-host)

```bash
cd deploy
./build.sh                 # creates .env (random DB password) + volumes + builds
                           # first build pulls kali base + bakes tools (~few min)
make up                    # start postgres + dashboard

# From your laptop — tunnel the loopback port, then browse:
ssh -L 8000:127.0.0.1:8000 <user>@<vps>
#   → http://localhost:8000
#   First-boot admin password: volumes/data/.first_admin (mode 0600). Read it,
#   log in, delete the file.

# One-shot scans (run the same migrations + wait for postgres)
make scan      T=example.com    # full
make scan-fast T=example.com    # m01..m05 + m09

make update-templates           # refresh nuclei templates
make logs                       # follow logs
make shell                      # bash inside the container
```

---

## Deploy on another machine

Nothing host-specific is required beyond Docker. From the repo (or a clone):

```bash
git clone <repo-url> h4wk3y3 && cd h4wk3y3/deploy
./build.sh
vi .env                    # set a real POSTGRES_PASSWORD + any API keys
make up
```

Because all tools are in the image, the target host needs **only Docker** —
no nuclei/subfinder/playwright/etc. pre-installed.

---

## Layout

```
deploy/
├── Dockerfile            multi-stage (go-builder + runtime)
├── docker-compose.yml    h4wk3y3 + postgres (+ scan profile)
├── entrypoint.sh         pre-flight (wait DB, alembic, host patch, resolvers)
├── build.sh              idempotent bootstrap + build
├── Makefile              convenience targets
├── .env.example          → copy to .env (build.sh does it)
└── volumes/              runtime data, persisted across rebuilds
    ├── output/             scan results (per domain)
    ├── data/               .session_secret, .first_admin, caches
    ├── config/h4wk3y3.yaml editable; dashboard /api/config writes here
    ├── scopes/             per-org scope-as-code YAML
    ├── wildcards           authorised scan targets (allowlist)
    └── subfinder/          provider-config.yaml (API keys)
```

Named Docker volumes: `h4wk3y3-postgres-data`, `h4wk3y3-nuclei-templates`,
`h4wk3y3-playwright` (Chromium cache, avoids re-download on rebuild).

---

## Raw-socket scanning

`rustscan` (SYN), `naabu` and `nmap -sS` need raw sockets — the compose file
grants `cap_add: [NET_RAW, NET_ADMIN]`. Without them those tools fall back to
slower TCP-connect scans (the pipeline still works, just noisier/slower on m07).

## DNS

The pipeline is DNS-intensive (m02). The compose file forces public DNS
(`1.1.1.1 / 8.8.8.8 / 9.9.9.9`) to bypass Docker's embedded resolver, which
throttles at scale.

## API keys

| Source | Where |
|---|---|
| Chaos (projectdiscovery) | `.env` → `PDCP_API_KEY=` |
| GitHub (subfinder + m01) | `.env` → `GH_TOKEN=` / `GITHUB_TOKEN=` |
| Subfinder providers (shodan/vt/securitytrails/censys…) | `volumes/subfinder/provider-config.yaml` |
| HIBP (m01) | `.env` → `HIBP_API_KEY=` |

## Editing source

Edit files in the repo, then `make rebuild && make up`. For a quick iteration
without a full rebuild:

```bash
docker cp ../modules/m13_nuclei.py h4wk3y3:/home/kali/h4wk3y3/modules/
docker compose restart h4wk3y3
```

---

## Common operations

| Task | Command |
|---|---|
| Start | `make up` |
| Logs | `make logs` |
| Shell | `make shell` |
| psql | `docker compose exec postgres psql -U h4wk3y3 -d h4wk3y3` |
| Backup DB | `docker compose exec postgres pg_dump -U h4wk3y3 h4wk3y3 > backup.sql` |
| Single module | `docker compose run --rm scan raw ./run.sh -t example.com --modules m02,m03 -v` |
| Rebuild (no cache) | `make rebuild` |
| Wipe volumes (DATA LOSS) | `make purge` |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `h4wk3y3` restart-loops | `docker compose logs postgres` — wait for "database system is ready" |
| 500 on `/api/findings` after upgrade | `docker compose restart h4wk3y3` (entrypoint reruns `alembic upgrade head`) |
| Dashboard not reachable | it binds host loopback only — use the SSH tunnel (`make tunnel`) |
| `make scan` "no DSN configured" | `.env` missing POSTGRES_* — the scan service inherits `ARGUS_DB_URL` from them |
| `volumes/` root-owned after sudo build | re-run `sudo ./build.sh` (re-chowns to UID 1000) |
| rustscan/naabu slow or 0 ports | confirm `cap_add: [NET_RAW, NET_ADMIN]` is present (raw sockets) |
