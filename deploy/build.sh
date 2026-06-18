#!/usr/bin/env bash
# ============================================================
#  h4wk3y3 — idempotent bootstrap + build
#  Run from deploy/:  ./build.sh
#    1. create .env from .env.example (generate a random DB password)
#    2. create runtime volume dirs + seed config/wildcards/scopes
#    3. docker compose build
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"
REPO_ROOT="$(cd .. && pwd)"

echo "▶ h4wk3y3 deploy bootstrap"

# ── 1. .env ─────────────────────────────────────────────────
if [ ! -f .env ]; then
  cp .env.example .env
  # Generate a strong random Postgres password in-place.
  PW="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
  sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${PW}/" .env
  echo "  ✓ .env created (random POSTGRES_PASSWORD generated)"
else
  echo "  • .env already exists — left untouched"
  if grep -q '^POSTGRES_PASSWORD=CHANGE_ME$' .env; then
    echo "  ⚠ POSTGRES_PASSWORD is still CHANGE_ME — edit .env before exposing anything"
  fi
fi

# ── 2. Runtime volumes (persist across rebuilds) ────────────
mkdir -p volumes/output volumes/data volumes/config volumes/scopes volumes/subfinder

# Seed an editable config copy (dashboard /api/config writes here).
if [ ! -f volumes/config/h4wk3y3.yaml ]; then
  cp "$REPO_ROOT/config/h4wk3y3.yaml" volumes/config/h4wk3y3.yaml
  echo "  ✓ volumes/config/h4wk3y3.yaml seeded"
fi

# Wildcards allowlist (authorised scan targets). Empty by default.
[ -f volumes/wildcards ] || { touch volumes/wildcards; echo "  ✓ volumes/wildcards created (empty — add authorised apexes)"; }

# Seed the constituents CSV into the data volume (the volume mount shadows the
# image's data/ dir, so the CSV must live in the volume for `make import`).
if [ -f "$REPO_ROOT/data/constituents.csv" ] && [ ! -f volumes/data/constituents.csv ]; then
  cp "$REPO_ROOT/data/constituents.csv" volumes/data/constituents.csv
  echo "  ✓ volumes/data/constituents.csv seeded — run 'make import' to load orgs/targets"
fi

# subfinder provider keys (optional)
[ -f volumes/subfinder/provider-config.yaml ] || touch volumes/subfinder/provider-config.yaml

# Self-signed TLS cert for Caddy (1 year). The name has no public DNS (local
# hosts entry), so Let's Encrypt can't issue — we serve this cert and you
# install volumes/caddy-certs/cert.pem on your machine to trust it.
mkdir -p volumes/caddy-certs
if [ ! -f volumes/caddy-certs/cert.pem ]; then
  SITE="$(grep -E '^H4_SITE_ADDRESS=' .env 2>/dev/null | cut -d= -f2)"; SITE="${SITE:-app.h4wk3y3.io}"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
    -keyout volumes/caddy-certs/key.pem -out volumes/caddy-certs/cert.pem \
    -subj "/CN=${SITE}" -addext "subjectAltName=DNS:${SITE}" >/dev/null 2>&1 \
    && echo "  ✓ self-signed cert generated (1y) for ${SITE} → volumes/caddy-certs/" \
    || echo "  ⚠ openssl failed — generate volumes/caddy-certs/{cert,key}.pem manually"
fi

# The container runs as UID 1000 (Dockerfile useradd -u 1000) and writes to the
# bind-mounted volumes (data/, config/). The host user often has a different UID
# (e.g. 1001), so make the volumes writable by the container: chown to 1000 via
# sudo if available, otherwise fall back to world-writable.
if [ "$(id -u)" = "0" ]; then
  chown -R 1000:1000 volumes
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo chown -R 1000:1000 volumes
elif command -v sudo >/dev/null 2>&1; then
  echo "  • chowning volumes to UID 1000 (container user) — sudo password may be prompted"
  sudo chown -R 1000:1000 volumes || chmod -R a+rwX volumes
else
  chmod -R a+rwX volumes
fi
echo "  ✓ volumes writable by the container (UID 1000)"

# ── 3. Build ────────────────────────────────────────────────
echo "▶ docker compose build (first build pulls kali base + bakes tools — a few minutes)"
DOCKER_BUILDKIT=1 docker compose build

echo ""
echo "✓ Done. Next:"
echo "    make up                      # start postgres + dashboard"
echo "    ssh -L 8000:127.0.0.1:8000 <user>@<this-host>   # then open http://localhost:8000"
echo "    make scan T=example.com      # one-shot full scan"
echo "  First-boot admin password is written to volumes/data/.first_admin (mode 0600)."
