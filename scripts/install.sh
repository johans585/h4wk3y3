#!/bin/bash
# ============================================================
#  Argus V2 — Installation Script
# ============================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "[*] $1"; }

info "Installing Argus V2..."
cd "$(dirname "$0")/.."

# Python dependencies
info "Installing Python dependencies..."
pip install -r requirements.txt --break-system-packages -q && ok "Python deps installed"

# Playwright Chromium
info "Installing Playwright Chromium..."
playwright install chromium && ok "Playwright ready"

# Go tools
if command -v go &>/dev/null; then
    info "Installing Go recon tools..."
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest     2>/dev/null && ok "subfinder"
    go install github.com/tomnomnom/assetfinder@latest                            2>/dev/null && ok "assetfinder"
    go install github.com/lc/gau/v2/cmd/gau@latest                               2>/dev/null && ok "gau"
    go install github.com/projectdiscovery/katana/cmd/katana@latest               2>/dev/null && ok "katana"
    go install github.com/tomnomnom/waybackurls@latest                            2>/dev/null && ok "waybackurls"
    go install github.com/lc/subjs@latest                                         2>/dev/null && ok "subjs"
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest               2>/dev/null && ok "alterx"
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest                   2>/dev/null && ok "dnsx"
    go install github.com/d3mondev/puredns/v2@latest                              2>/dev/null && ok "puredns"
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest            2>/dev/null && ok "nuclei"
    go install github.com/BishopFox/jsluice@latest                                2>/dev/null && ok "jsluice"
else
    warn "Go not found — skipping Go tools (install Go 1.21+ first)"
fi

# sourcemapper
if command -v npm &>/dev/null; then
    npm install -g sourcemapper 2>/dev/null && ok "sourcemapper" || warn "sourcemapper install failed"
else
    warn "npm not found — skipping sourcemapper"
fi

# arjun
pip install arjun --break-system-packages -q 2>/dev/null && ok "arjun" || warn "arjun install failed"

# testssl.sh — TLS audit (m08). Optional: m08 emits an INFO finding with this
# command and skips cleanly if it's absent, but installing it enables the audit.
if command -v testssl.sh &>/dev/null; then
    ok "testssl.sh already present"
elif command -v apt-get &>/dev/null && apt-get install -y testssl.sh 2>/dev/null; then
    ok "testssl.sh (apt)"
else
    TESTSSL_DIR="/opt/testssl.sh"
    if git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$TESTSSL_DIR" 2>/dev/null; then
        ln -sf "$TESTSSL_DIR/testssl.sh" /usr/local/bin/testssl.sh 2>/dev/null \
            && ok "testssl.sh (git → /usr/local/bin)" \
            || warn "testssl.sh cloned to $TESTSSL_DIR but symlink failed (add to PATH manually)"
    else
        warn "testssl.sh install failed — m08 TLS audit will skip (non-fatal)"
    fi
fi

# Download DNS resolvers
info "Downloading DNS resolvers..."
mkdir -p data/resolvers
curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
  -o data/resolvers/resolvers.txt 2>/dev/null && ok "resolvers.txt" || warn "resolvers download failed"

# Download DNS wordlist
info "Downloading DNS wordlist..."
mkdir -p data/wordlists
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
  -o data/wordlists/dns_top10k.txt 2>/dev/null && ok "dns_top10k.txt" || warn "wordlist download failed"

# Nuclei templates update
if command -v nuclei &>/dev/null; then
    info "Updating Nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null && ok "nuclei templates updated" || warn "nuclei templates update failed"
fi

# Create output and data dirs
mkdir -p output data

ok "Argus V2 installation complete!"
echo ""
echo "Quick start:"
echo "  python h4wk3y3.py -t example.com --fast"
echo "  python h4wk3y3.py -t example.com --full"
echo "  python h4wk3y3.py --dashboard"
