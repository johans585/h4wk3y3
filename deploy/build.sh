#!/bin/bash
# ============================================================
#  Argus — build & bootstrap script
#  Idempotent: safe to re-run. Creates volume dirs, .env, builds image.
# ============================================================
set -e

cd "$(dirname "$0")"

# Bootstrap volume dirs (compose mounts host paths, they must exist)
mkdir -p volumes/output volumes/data volumes/config volumes/subfinder volumes/scopes

# Seed config from repo defaults if not yet present in the volume.
# The repo root is the parent of this deploy/ directory.
if [ ! -f volumes/config/h4wk3y3.yaml ]; then
    echo "[*] Seeding volumes/config/h4wk3y3.yaml from repo defaults"
    cp ../config/h4wk3y3.yaml volumes/config/h4wk3y3.yaml
fi

# Seed wildcards (target whitelist file — kept editable side-by-side)
if [ ! -f volumes/wildcards ]; then
    echo "[*] Seeding volumes/wildcards from repo defaults"
    cp ../wildcards volumes/wildcards
fi

# Seed scopes/ (multi-org scope-as-code YAML, Étape 2.2). Only copies the
# example template so an admin can see the schema; per-org files stay
# user-managed via PageOrgs / `argus org` CLI.
if [ ! -f volumes/scopes/example.com.yaml ] && [ -f ../scopes/example.com.yaml ]; then
    echo "[*] Seeding volumes/scopes/example.com.yaml template"
    cp ../scopes/example.com.yaml volumes/scopes/example.com.yaml
fi

# When build.sh is run via sudo (no docker group), volumes/ AND every file
# inside (yaml, wildcards, etc.) end up owned by root → container UID 1000
# (kali) can't write to bind-mounts. Force ownership AFTER seeding so all
# newly-created files are caught.
if [ "$(id -u)" = "0" ]; then
    chown -R 1000:1000 volumes/
    echo "[*] volumes/ chowned to 1000:1000 (matches in-image kali user)"
fi

# Seed .env if missing
if [ ! -f .env ]; then
    echo "[*] Creating .env from .env.example — edit before use"
    cp .env.example .env
fi

# Subfinder provider config stub
if [ ! -f volumes/subfinder/provider-config.yaml ]; then
    cat > volumes/subfinder/provider-config.yaml <<'EOF'
# Subfinder provider keys — fill in to unlock passive sources.
# Without these, subfinder degrades to ~0 results (other sources still work).
# Doc: https://github.com/projectdiscovery/subfinder#post-install-instructions

# shodan: ["YOUR_KEY"]
# virustotal: ["YOUR_KEY"]
# securitytrails: ["YOUR_KEY"]
# censys: ["YOUR_ID:YOUR_SECRET"]
# github: ["YOUR_PAT"]
EOF
    echo "[*] Created volumes/subfinder/provider-config.yaml stub"
fi

# Build image
echo "[*] Building argus:latest (BuildKit)"
DOCKER_BUILDKIT=1 docker compose build "$@"

echo
echo "[✓] Build complete."
echo
echo "Next steps:"
echo "  1. Edit .env (PDCP_API_KEY etc.)"
echo "  2. Optionally edit volumes/config/h4wk3y3.yaml"
echo "  3. Optionally edit volumes/subfinder/provider-config.yaml"
echo "  4. Start dashboard:        docker compose up -d"
echo "                             open http://localhost:\${ARGUS_DASHBOARD_PORT:-8000}"
echo "  5. Run a scan:             docker compose run --rm scan scan example.com --full"
echo "  6. Update nuclei templates: docker compose run --rm argus update-templates"
