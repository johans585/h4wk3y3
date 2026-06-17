#!/bin/bash
# ============================================================
#  h4wk3y3 container entrypoint
#
#  Pre-flight on every start:
#    1. wait for the Postgres backend to accept connections
#    2. run `alembic upgrade head` so the schema is current
#    3. patch dashboard host to 0.0.0.0 INSIDE the container so Docker's
#       port mapping can forward it (the host side maps 127.0.0.1 only)
#    4. refresh resolvers list if missing/stale
#
#  Modes:
#    dashboard          → start FastAPI dashboard (default)
#    scan <domain> ...  → one-shot scan via run.sh
#    scan-file <path>   → multiple targets from file
#    update-templates   → refresh nuclei templates
#    shell              → drop into bash
#    raw <cmd...>       → exec arbitrary command
# ============================================================
set -e

APP_HOME=/home/kali/h4wk3y3
CONFIG=$APP_HOME/config/h4wk3y3.yaml
PYTHON=$APP_HOME/argus-env/bin/python
ALEMBIC=$APP_HOME/argus-env/bin/alembic

# ── 1. Wait for Postgres ────────────────────────────────────
if [ -n "$ARGUS_DB_URL" ]; then
  echo "[entrypoint] waiting for Postgres at ARGUS_DB_URL ..."
  tries=0; max_tries=60
  until $PYTHON -c "
import os, sys
import sqlalchemy as sa
try:
    eng = sa.create_engine(os.environ['ARGUS_DB_URL'], connect_args={'connect_timeout': 3})
    with eng.connect() as c:
        c.execute(sa.text('SELECT 1'))
    sys.exit(0)
except Exception as e:
    sys.stderr.write(f'pg not ready: {e}\n'); sys.exit(1)
" 2>/dev/null; do
    tries=$((tries + 1))
    if [ $tries -ge $max_tries ]; then
      echo "[entrypoint] Postgres never came up after $max_tries attempts — aborting"; exit 1
    fi
    sleep 2
  done
  echo "[entrypoint] Postgres is up (after ${tries} tries)"
fi

# ── 2. Alembic upgrade head (idempotent) ────────────────────
if [ -x "$ALEMBIC" ]; then
  echo "[entrypoint] running alembic upgrade head ..."
  (cd "$APP_HOME" && "$ALEMBIC" upgrade head) || {
    echo "[entrypoint] alembic upgrade head FAILED — DB may be inconsistent"; exit 1; }
else
  echo "[entrypoint] alembic binary not found at $ALEMBIC — skipping migration"
fi

# ── 3. Dashboard host → 0.0.0.0 inside the container ────────
# So Docker's port mapping forwards it. The compose file maps the HOST side
# to 127.0.0.1 only, so the dashboard stays reachable on the host loopback
# (use an SSH tunnel) and is NOT exposed to the internet.
# Rewrite in place (cat >, not sed -i) to preserve a bind-mounted file's inode.
if [ -f "$CONFIG" ] && grep -qE '^\s*host:\s*"?127\.0\.0\.1"?' "$CONFIG"; then
  tmp=$(mktemp)
  if sed -E 's/^(\s*)host:\s*"?127\.0\.0\.1"?/\1host: "0.0.0.0"/' "$CONFIG" > "$tmp"; then
    cat "$tmp" > "$CONFIG" && echo "[entrypoint] dashboard.host → 0.0.0.0 (container-mode)"
  fi
  rm -f "$tmp"
fi

# ── 4. Resolvers refresh if missing or older than 7 days ────
RESOLVERS=$APP_HOME/data/resolvers/resolvers.txt
if [ ! -f "$RESOLVERS" ] || [ "$(find "$RESOLVERS" -mtime +7 2>/dev/null)" ]; then
  mkdir -p "$(dirname "$RESOLVERS")"
  curl -sSL --max-time 30 \
    https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
    -o "$RESOLVERS" 2>/dev/null || echo "[entrypoint] resolvers refresh skipped"
fi

cd "$APP_HOME"

case "${1:-dashboard}" in
  dashboard)        exec ./run.sh --dashboard ;;
  scan)             shift; exec ./run.sh -t "$@" ;;
  scan-file)        shift; exec ./run.sh -f "$@" ;;
  update-templates) exec /home/kali/go/bin/nuclei -update-templates ;;
  shell)            exec /bin/bash ;;
  raw)              shift; exec "$@" ;;
  *)                exec ./run.sh "$@" ;;
esac
