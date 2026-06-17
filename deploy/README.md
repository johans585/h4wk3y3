# Argus — Docker deployment

Container deployment for Argus V2 (Postgres-only runtime since 2026-05).
Lives **inside the repo** at `<repo>/deploy/` so there is a single source of
truth — the orchestration files reference the parent (repo root) as the build
context.

Image base: `kalilinux/kali-rolling` (mirrors the dev environment), all Go
binaries pre-built in a separate stage.

---

## Topology

```
┌──────────────────────────┐    ┌────────────────────────┐
│  postgres (postgres:18)  │◄───│  argus (kalilinux)     │
│  - argus_main DB         │    │  - FastAPI dashboard   │
│  - healthcheck pg_isready│    │  - scan pipeline       │
│  - volume: argus-postgres-data│  - depends_on: postgres healthy
└──────────────────────────┘    └────────────────────────┘
                                          │
                                          ▼ entrypoint pre-flight
                                  1. wait for postgres
                                  2. alembic upgrade head
                                  3. resolvers refresh
                                  4. dashboard host → 0.0.0.0
```

The argus service receives `ARGUS_DB_URL` pointing at the postgres service
on the internal compose network. The same env var is consumed by
`core/db_engine.resolve_db_url` (runtime) and `alembic/env.py` (migrations),
so the URL stays in sync between the app and `alembic upgrade head`.

---

## Layout

```
<repo>/
├── argus.py, core/, modules/, dashboard/, ...    ← code (single source of truth)
├── config/, scopes/, data/, wildcards
├── alembic/, alembic.ini
├── .dockerignore                                  ← excludes argus-env, output, etc.
└── deploy/                                        ← you are here
    ├── Dockerfile
    ├── docker-compose.yml
    ├── entrypoint.sh
    ├── build.sh                                   (idempotent bootstrap + build)
    ├── Makefile                                   (convenience targets)
    ├── README.md (this file)
    ├── .env.example
    ├── .env                                       ← created from .env.example by build.sh
    └── volumes/                                   ← runtime data (persisted across rebuilds)
        ├── output/                                  scan results (per domain)
        ├── data/                                    auth secrets + caches + resolvers
        ├── config/argus.yaml                        editable; dashboard /api/config writes here
        ├── scopes/                                  multi-org scope-as-code YAML (Étape 2.2)
        ├── wildcards                                legacy target whitelist
        └── subfinder/                               provider-config.yaml (API keys)
```

Plus 3 named Docker volumes:

- `argus-postgres-data`     — the Postgres data directory
- `argus-nuclei-templates`  — nuclei templates, refreshable out-of-band
- `argus-playwright`        — Chromium cache (~400 MB), avoids re-DL on rebuild

---

## Quick start

```bash
cd deploy
./build.sh                    # bootstrap volumes + .env + docker compose build
vi .env                       # set POSTGRES_PASSWORD + PDCP_API_KEY (recommended)
make up                       # starts BOTH postgres AND dashboard
# → http://localhost:8000
#   On first boot, the bootstrap super-admin password is written to
#   volumes/data/.first_admin (mode 0600). Read it, log in, delete the file.

# One-shot scan (runs the same migrations + waits for postgres healthy)
make scan T=example.com       # full
make scan-fast T=example.com  # m02..m05 only

# Update nuclei templates
make update-templates
```

### What `make up` does under the hood

1. Compose starts the **postgres** service first, runs `pg_isready` until it goes healthy
2. Then starts the **argus** service. Its entrypoint:
   - waits for `ARGUS_DB_URL` to accept SELECT 1 (defensive)
   - runs `alembic upgrade head` (idempotent)
   - patches `dashboard.host` to `0.0.0.0` in the mounted argus.yaml
   - launches the FastAPI dashboard via `./run.sh --dashboard`
3. Docker's healthcheck pings `/api/health` every 15s and marks the container unhealthy after 5 failed attempts.

---

## Deploying to another machine

The whole repo is portable. From the parent of the repo:

```bash
# Source host
tar czhf argus-deploy.tar.gz \
    --exclude='argus-env' --exclude='output' \
    --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='deploy/volumes' --exclude='deploy/.env' \
    -C ~ argus
scp argus-deploy.tar.gz user@target:/opt/

# Target host (Docker installed, 16 GB RAM recommended)
cd /opt && tar xzf argus-deploy.tar.gz && cd argus/deploy
./build.sh
vi .env                       # CHANGE POSTGRES_PASSWORD before exposing anything
make up
```

---

## Using an external Postgres

To bypass the bundled `postgres` service and target a managed DB (RDS, Cloud
SQL, etc.), set `ARGUS_DB_URL` in `.env`:

```env
ARGUS_DB_URL=postgresql+psycopg://argus:secret@db.internal:5432/argus_main
```

Then comment out or remove the `postgres:` service block from
`docker-compose.yml` AND its `depends_on:` declaration on the argus service.
The entrypoint will still run `alembic upgrade head` against the external DB.

---

## Resource sizing

The compose file caps the argus container at **14 GB RAM** on a 16 GB host
(`mem_limit: 14g`, `memswap_limit: 14g` to avoid swap thrashing). `/dev/shm`
is bumped to **2 GB** — mandatory for Playwright / Chromium (m05); the default
64 MB causes silent crashes.

### Concurrency tuning (16 GB headroom)

The defaults in `config/argus.yaml` were picked for a 4 GB box.
With 16 GB you can safely raise (in `volumes/config/argus.yaml`, hot-editable):

```yaml
fetcher:
  max_extra_urls: 2000        # was 800
  max_body_size: 5_000_000    # was 2_000_000
screenshot:
  concurrent: 6               # was 3
js_analyzer:
  max_js_files: 1500          # was 500
nuclei:
  max_host_error: 500         # was 200
```

---

## DNS

Argus is DNS-intensive (m02 hits 6 passive sources + bulk A/CNAME/MX/TXT). The
compose file forces public DNS (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`) to bypass
Docker's embedded resolver, which throttles at scale.

---

## API keys

| Source | Where to drop key |
|---|---|
| Chaos (projectdiscovery) | `.env` → `PDCP_API_KEY=...` |
| Subfinder providers (shodan, virustotal, securitytrails, censys, github…) | `volumes/subfinder/provider-config.yaml` |
| GitHub (subfinder github source) | `.env` → `GH_TOKEN=...` |

---

## Editing source code (the whole point of this layout)

Just edit the files directly in the repo (above this directory). The Docker
image bakes them on the next build. No `src/` copy, no sync helpers, no
divergence.

To pick up source changes in a running container:

```bash
make rebuild      # full rebuild (~2-3 min thanks to layer cache)
make up
```

Or for a quick iteration without rebuilding, copy the file into the running
container:

```bash
docker cp ../modules/m03_http_validator.py argus:/home/kali/argus/modules/
docker compose restart argus
```

---

## Multi-org / scope-as-code (Étape 2.1 + 2.2)

Organisations and target ↔ org links live in Postgres (tables
`organisations` + `targets`, migration `0002`). Manage them via:

- **UI** : sidebar `ADMIN > Orgs` → modal create/edit/link
- **CLI inside the container** : `docker compose exec argus argus org list`
- **CLI outside** (any psql client) : direct SQL on `argus_main`

The per-org scope YAML files sit under `volumes/scopes/<apex>.yaml` (mounted
into `/home/kali/argus/scopes/`). Edit them on the host, the next scan picks
them up — no container restart needed.

---

## Common operations

| Task | Command |
|---|---|
| Open dashboard | `make up` then http://localhost:8000 |
| Tail logs | `make logs` |
| Get a shell inside | `make shell` |
| Connect to Postgres | `docker compose exec postgres psql -U argus -d argus_main` |
| Run a single module | `docker compose run --rm scan raw ./run.sh -t example.com --modules m02,m03 -v` |
| Inspect output | `ls volumes/output/<domain>/` |
| Refresh nuclei templates | `make update-templates` |
| Manage orgs from CLI | `docker compose exec argus argus org list` |
| Force full rebuild | `make rebuild` |
| Backup the DB | `docker compose exec postgres pg_dump -U argus argus_main > backup.sql` |
| Wipe volumes (data loss!) | `make purge` |

---

## Troubleshooting

| Symptom | Diagnosis | Fix |
|---|---|---|
| `dashboard` container restart-loops | postgres not healthy yet | `docker compose logs postgres` — should say "database system is ready" |
| 500 on /api/findings after upgrade | new migration not applied | `docker compose restart argus` (entrypoint reruns `alembic upgrade head`) |
| `dashboard.host: 127.0.0.1` persists | sed in entrypoint failed on bind-mount | rewrite `volumes/config/argus.yaml:dashboard.host` to `"0.0.0.0"` manually |
| `make scan` errors "no DSN configured" | env var not propagated to scan service | scan extends argus, so `ARGUS_DB_URL` is inherited — check `.env` actually has POSTGRES_* set |
| `volumes/` owned by root after `sudo` build | normal | re-run `sudo ./build.sh` (the script re-chowns to UID 1000) |
