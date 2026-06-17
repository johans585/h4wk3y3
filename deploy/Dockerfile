# syntax=docker/dockerfile:1.7
# ============================================================
#  Argus V2 — Container image
#  Base: kalilinux/kali-rolling (cohérent avec l'env dev)
#  Multi-stage: Go-builder isolé pour ne pas baker le toolchain Go (>500 MB)
#  dans l'image finale.
# ============================================================

# ─────────────────────────────────────────────────────────────
#  STAGE 1 — Go binaries builder
# ─────────────────────────────────────────────────────────────
FROM kalilinux/kali-rolling AS go-builder

ENV DEBIAN_FRONTEND=noninteractive \
    GOPATH=/go \
    GOBIN=/go/bin \
    GOFLAGS=-mod=mod \
    GOSUMDB=off \
    GOPROXY=https://proxy.golang.org,direct \
    PATH=/usr/local/go/bin:/go/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git golang-go build-essential unzip \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Tools Argus appelle en subprocess. Versions PINNED pour repro builds.
# Pour mettre à jour: `git ls-remote --tags --refs https://<repo>.git | tail`.
# IMPORTANT: pas de commentaires shell `#` à l'intérieur d'un RUN multi-ligne
# avec `\` continuation — Docker concat les lignes en supprimant le `\<newline>`,
# ce qui fait que le `#` commenterait tout le reste du bloc.
ARG SUBFINDER_VER=v2.14.0
ARG ASSETFINDER_VER=v0.1.1
ARG DNSX_VER=v1.2.3
ARG ALTERX_VER=v0.1.0
ARG CHAOS_VER=v0.5.2
ARG CERTSPOTTER_VER=v0.24.0
ARG HTTPX_VER=v1.9.0
ARG GAU_VER=v2.2.4
ARG WAYBACKURLS_VER=v0.1.0
ARG KATANA_VER=v1.6.1
ARG SUBJS_VER=v1.0.1
ARG ANEW_VER=v0.1.1
ARG QSREPLACE_VER=v0.0.3
ARG NUCLEI_VER=v3.8.0
ARG DALFOX_VER=v2.13.0
ARG GF_REV=dcd4c361f9f5
ARG JSLUICE_REV=0ddfab153e06
ARG SHUFFLEDNS_VER=v1.2.1
ARG GOSPIDER_VER=v1.1.6
ARG NAABU_VER=v2.6.1
ARG CDNCHECK_VER=v1.2.35
ARG TRUFFLEHOG_VER=v3.95.3

RUN set -eux; mkdir -p /go/bin; \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VER}      ; \
    go install github.com/tomnomnom/assetfinder@${ASSETFINDER_VER}                          ; \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VER}                        ; \
    go install github.com/projectdiscovery/alterx/cmd/alterx@${ALTERX_VER}                  ; \
    go install github.com/projectdiscovery/chaos-client/cmd/chaos@${CHAOS_VER}              ; \
    go install software.sslmate.com/src/certspotter/cmd/certspotter@${CERTSPOTTER_VER}      ; \
    go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VER}                     ; \
    cp /go/bin/httpx /go/bin/httpx-toolkit                                                  ; \
    go install github.com/lc/gau/v2/cmd/gau@${GAU_VER}                                      ; \
    go install github.com/tomnomnom/waybackurls@${WAYBACKURLS_VER}                          ; \
    go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VER}                  ; \
    go install github.com/lc/subjs@${SUBJS_VER}                                             ; \
    go install github.com/tomnomnom/gf@${GF_REV}                                            ; \
    go install github.com/tomnomnom/anew@${ANEW_VER}                                        ; \
    go install github.com/tomnomnom/qsreplace@${QSREPLACE_VER}                              ; \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VER}               ; \
    go install github.com/hahwul/dalfox/v2@${DALFOX_VER}

# Non-critiques (m01 active, m05 jsluice, m03 gospider) — `|| true` au cas où un
# pin tomberait. Pas la fin du monde si une de ces deps échoue, le pipeline
# dégrade gracieusement.
RUN set -eu; \
    go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@${SHUFFLEDNS_VER} || true ; \
    go install github.com/jaeles-project/gospider@${GOSPIDER_VER}                      || true ; \
    go install github.com/BishopFox/jsluice/cmd/jsluice@${JSLUICE_REV}                 || true

# Phase 1 tools — naabu/cdncheck for m11, trufflehog for m10.
RUN set -eu; \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VER}                   ; \
    go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@${CDNCHECK_VER}             ; \
    go install github.com/trufflesecurity/trufflehog/v3@${TRUFFLEHOG_VER}                    || true

# Findomain (Rust) — official GitHub release zip
RUN curl -sSL -o /tmp/findomain.zip \
        https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip \
    && cd /tmp && unzip -o findomain.zip && chmod +x findomain \
    && mv findomain /go/bin/findomain && rm -f /tmp/findomain.zip \
    || echo "[warn] findomain release download failed — multi-source m01 will degrade gracefully"


# ─────────────────────────────────────────────────────────────
#  STAGE 2 — Runtime image
# ─────────────────────────────────────────────────────────────
FROM kalilinux/kali-rolling AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    TZ=UTC \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/home/kali/.cache/ms-playwright \
    PATH=/home/kali/argus/argus-env/bin:/home/kali/go/bin:/usr/local/go-tools/bin:/home/kali/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ── 1. System packages ───────────────────────────────────────
# Groups (ne PAS écrire ces commentaires INSIDE le RUN avec `\` continuation,
# bash les interprète comme commentaires shell et coupe la liste de paquets) :
#   Core             : ca-certificates curl wget git unzip jq tzdata
#   Python runtime   : python3 python3-pip python3-venv python3-dev
#   Build (wheels)   : build-essential libxml2-dev libxslt1-dev libffi-dev libssl-dev
#   Active recon     : nmap sqlmap dirsearch ffuf gobuster nikto
#   Wordlists        : seclists
#   Chromium deps    : libnss3 libnspr4 libatk* libcups2 libdrm2 libxkbcommon0 etc.
#   JS runtime       : nodejs npm
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git unzip jq tzdata \
        python3 python3-pip python3-venv python3-dev \
        build-essential libxml2-dev libxslt1-dev libffi-dev libssl-dev \
        nmap sqlmap dirsearch ffuf gobuster nikto \
        whois testssl.sh dnsutils libpcap0.8 \
        seclists \
        libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
        libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
        libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2t64 \
        libatspi2.0-0 libwayland-client0 fonts-liberation fonts-noto-color-emoji \
        nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Non-root user matching le repo (paths /home/kali/... codés en dur) ──
# argus.py:24-29 référence /home/kali/go/bin et autres → on garde cet UID/path
RUN useradd -m -u 1000 -s /bin/bash kali \
    && mkdir -p /home/kali/go/bin /usr/local/go-tools/bin /home/kali/.local/bin \
                /home/kali/.config/subfinder /home/kali/.config/nuclei \
                /home/kali/.cache/ms-playwright \
    && chown -R kali:kali /home/kali

# ── 3. Go binaries (depuis stage 1) ─────────────────────────
COPY --from=go-builder --chown=kali:kali /go/bin/ /home/kali/go/bin/

# ── 4. Argus source code ────────────────────────────────────
# Build context = the repo root (parent of deploy/). The source IS the repo.
# argus-env/, output/, data/argus.db, __pycache__, deploy/volumes/ etc. are
# excluded via .dockerignore at the repo root. The deploy/ subdir itself is
# copied (~30 KB) — harmless and keeps the layout self-describing in-image.
COPY --chown=kali:kali . /home/kali/argus/

# ── 5. Python venv (le code re-execve dans argus-env via argus.py:18-20) ──
USER kali
WORKDIR /home/kali/argus

# All runtime deps (incl. ruamel.yaml, dnspython, arjun, uro, psutil) are now
# declared in requirements.txt — single source of truth, no ad-hoc installs.
RUN python3 -m venv /home/kali/argus/argus-env \
    && /home/kali/argus/argus-env/bin/pip install --upgrade pip wheel setuptools \
    && /home/kali/argus/argus-env/bin/pip install -r /home/kali/argus/requirements.txt \
    && /home/kali/argus/argus-env/bin/playwright install chromium

# ── 6. Nuclei templates (snapshot at build, refreshable via volume) ──────
RUN /home/kali/go/bin/nuclei -update-templates -silent || true

# ── 7. Resolvers & wordlists (fallback si volume non monté) ─────────────
RUN mkdir -p /home/kali/argus/data/resolvers /home/kali/argus/data/wordlists \
    && curl -sL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
         -o /home/kali/argus/data/resolvers/resolvers.txt 2>/dev/null \
    || echo "[warn] resolvers download failed at build — will fallback to in-code list"

# ── 8. gf patterns (pour m07 — modules.m07 lance `gf <pattern>`) ─────────
RUN git clone --depth=1 https://github.com/tomnomnom/gf /tmp/gf-src 2>/dev/null \
    && mkdir -p /home/kali/.gf \
    && cp /tmp/gf-src/examples/*.json /home/kali/.gf/ 2>/dev/null \
    && rm -rf /tmp/gf-src \
    && git clone --depth=1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-extra 2>/dev/null \
    && cp /tmp/gf-extra/*.json /home/kali/.gf/ 2>/dev/null \
    && rm -rf /tmp/gf-extra \
    || echo "[warn] gf pattern repos clone failed"

USER root
# entrypoint.sh lives in deploy/ relative to the build context (= repo root)
COPY --chown=kali:kali deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER kali
WORKDIR /home/kali/argus

EXPOSE 8000
VOLUME ["/home/kali/argus/output", "/home/kali/argus/data", "/home/kali/.config/subfinder", "/home/kali/.config/nuclei", "/home/kali/.cache/ms-playwright"]

# Liveness/readiness. Lives in the Dockerfile (not only docker-compose) so it
# also applies to `docker run`, k8s without an explicit probe, swarm, etc.
# /api/health always returns 200 while serving; a non-200/timeout = unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["dashboard"]
