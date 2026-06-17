#!/bin/bash
# ============================================================
#  Argus container entrypoint
#
#  Pre-flight on every start:
#    1. wait for the Postgres backend to accept connections
#    2. run `alembic upgrade head` so the schema is current
#    3. refresh resolvers list if missing/stale
#    4. patch dashboard host to 0.0.0.0 inside the container
#
#  Modes:
#    dashboard          → start FastAPI dashboard (default)
#    scan <domain>      → one-shot scan via run.sh
#    scan-file <path>   → multiple targets from file
#    update-templates   → refresh nuclei templates
#    shell              → drop into bash
#    raw <cmd...>       → exec arbitrary command
# ============================================================
set -e

ARGUS_HOME=/home/kali/argus
CONFIG=$ARGUS_HOME/config/h4wk3y3.yaml
PYTHON=$ARGUS_HOME/argus-env/bin/python
ALEMBIC=$ARGUS_HOME/argus-env/bin/alembic

# ── 1. Wait for Postgres ────────────────────────────────────
# When ARGUS_DB_URL is set (the compose service injects it), parse the
# host:port out of it and retry until pg_isready (or the equivalent
# Python connect) succeeds. Skipped when no DB URL is configured —
# resolve_db_url() will raise a clear error downstream.
if [ -n "$ARGUS_DB_URL" ]; then
  echo "[entrypoint] waiting for Postgres at ARGUS_DB_URL ..."
  tries=0
  max_tries=60
  until $PYTHON -c "
import os, sys
import sqlalchemy as sa
url = os.environ['ARGUS_DB_URL']
try:
    eng = sa.create_engine(url, connect_args={'connect_timeout': 3})
    with eng.connect() as c:
        c.execute(sa.text('SELECT 1'))
    sys.exit(0)
except Exception as e:
    sys.stderr.write(f'pg not ready: {e}\n')
    sys.exit(1)
" 2>/dev/null; do
    tries=$((tries + 1))
    if [ $tries -ge $max_tries ]; then
      echo "[entrypoint] Postgres never came up after $max_tries attempts — aborting"
      exit 1
    fi
    sleep 2
  done
  echo "[entrypoint] Postgres is up (after ${tries} tries)"
fi

# ── 2. Alembic upgrade head ─────────────────────────────────
# Idempotent — applies any pending migration on every container start.
# Critical: a fresh `docker compose up -d` against an empty DB MUST run
# this, otherwise the app crashes on the first query.
if [ -x "$ALEMBIC" ]; then
  echo "[entrypoint] running alembic upgrade head ..."
  (cd "$ARGUS_HOME" && "$ALEMBIC" upgrade head) || {
    echo "[entrypoint] alembic upgrade head FAILED — DB may be inconsistent"
    exit 1
  }
else
  echo "[entrypoint] alembic binary not found at $ALEMBIC — skipping schema migration"
fi

# ── 3. Dashboard host patch ─────────────────────────────────
# Patch dashboard host inside image so `-p 8000:8000` actually exposes it.
# Done at runtime (not build) so a volume-mounted YAML inherits the fix too.
# Note: `sed -i` would try to rename() the file, which fails on bind-mounted
# single files (kernel rejects rename across bind-mount). We rewrite in place
# via `cat > file` to preserve the inode the bind mount points to.
if [ -f "$CONFIG" ] && grep -qE '^\s*host:\s*"?127\.0\.0\.1"?' "$CONFIG"; then
  tmp=$(mktemp)
  if sed -E 's/^(\s*)host:\s*"?127\.0\.0\.1"?/\1host: "0.0.0.0"/' "$CONFIG" > "$tmp"; then
    cat "$tmp" > "$CONFIG" && echo "[entrypoint] dashboard.host → 0.0.0.0 (container-mode)"
  fi
  rm -f "$tmp"
fi

# ── 4. Trickest resolvers refresh if missing or older than 7 days ──
RESOLVERS=$ARGUS_HOME/data/resolvers/resolvers.txt
if [ ! -f "$RESOLVERS" ] || [ "$(find "$RESOLVERS" -mtime +7 2>/dev/null)" ]; then
  mkdir -p "$(dirname "$RESOLVERS")"
  curl -sSL --max-time 30 \
    https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
    -o "$RESOLVERS" 2>/dev/null || echo "[entrypoint] resolvers refresh skipped"
fi

cd "$ARGUS_HOME"

case "${1:-dashboard}" in
  dashboard)
    exec ./run.sh --dashboard
    ;;
  scan)
    shift
    exec ./run.sh -t "$@"
    ;;
  scan-file)
    shift
    exec ./run.sh -f "$@"
    ;;
  update-templates)
    exec /home/kali/go/bin/nuclei -update-templates
    ;;
  shell)
    exec /bin/bash
    ;;
  raw)
    shift
    exec "$@"
    ;;
  *)
    # If first arg starts with '-' or is unknown, pass through to run.sh
    exec ./run.sh "$@"
    ;;
esac
