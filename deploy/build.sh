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

# subfinder provider keys (optional)
[ -f volumes/subfinder/provider-config.yaml ] || touch volumes/subfinder/provider-config.yaml

# Fix ownership if build.sh was run with sudo (volumes must be writable by UID 1000).
if [ "$(id -u)" = "0" ]; then
  chown -R 1000:1000 volumes 2>/dev/null || true
fi

# ── 3. Build ────────────────────────────────────────────────
echo "▶ docker compose build (first build pulls kali base + bakes tools — a few minutes)"
DOCKER_BUILDKIT=1 docker compose build

echo ""
echo "✓ Done. Next:"
echo "    make up                      # start postgres + dashboard"
echo "    ssh -L 8000:127.0.0.1:8000 <user>@<this-host>   # then open http://localhost:8000"
echo "    make scan T=example.com      # one-shot full scan"
echo "  First-boot admin password is written to volumes/data/.first_admin (mode 0600)."
