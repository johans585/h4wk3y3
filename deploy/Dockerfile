# syntax=docker/dockerfile:1.7
# ============================================================
#  h4wk3y3 — container image (self-contained: all recon tools baked in)
#  Base: kalilinux/kali-rolling. Multi-stage: Go toolchain isolated in
#  stage 1 so the ~600 MB Go SDK never lands in the runtime image.
#  Goal: `docker build` reproduces the FULL environment on any host —
#  zero dependency on tools pre-installed on the machine.
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
        ca-certificates curl git golang-go build-essential unzip libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Tools the pipeline shells out to. Pinned for reproducible builds.
# NB: no inline `#` comments inside a `\`-continued RUN — Docker joins the
# lines and the `#` would comment out the rest of the package list.
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
ARG SOURCEMAPPER_REV=latest

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

RUN set -eux; \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VER}                  ; \
    go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@${CDNCHECK_VER}

# Non-critical (pipeline degrades gracefully if a pin breaks): shuffledns,
# gospider, jsluice (m11), sourcemapper (m11 source-map recovery), trufflehog.
RUN set -eu; \
    go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@${SHUFFLEDNS_VER} || true ; \
    go install github.com/jaeles-project/gospider@${GOSPIDER_VER}                      || true ; \
    go install github.com/BishopFox/jsluice/cmd/jsluice@${JSLUICE_REV}                 || true ; \
    go install github.com/denandz/sourcemapper@${SOURCEMAPPER_REV}                     || true ; \
    go install github.com/trufflesecurity/trufflehog/v3@${TRUFFLEHOG_VER}              || true

# Findomain (Rust) — official GitHub release binary.
RUN curl -sSL -o /tmp/findomain.zip \
        https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip \
    && cd /tmp && unzip -o findomain.zip && chmod +x findomain \
    && mv findomain /go/bin/findomain && rm -f /tmp/findomain.zip \
    || echo "[warn] findomain download failed — m02 multi-source degrades gracefully"


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
    PATH=/home/kali/h4wk3y3/argus-env/bin:/home/kali/go/bin:/home/kali/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ── 1. System packages ───────────────────────────────────────
#   Core            : ca-certificates curl wget git unzip jq tzdata
#   Python runtime  : python3 python3-pip python3-venv python3-dev
#   Wheel build deps: build-essential libxml2-dev libxslt1-dev libffi-dev libssl-dev
#   Active recon    : nmap sqlmap ffuf rustscan wafw00f testssl.sh
#   Net / dns       : whois dnsutils libpcap0.8
#   Wordlists       : seclists
#   Chromium deps   : libnss3 ... fonts-liberation (mandatory for Playwright m05)
#   JS runtime      : nodejs npm
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git unzip jq tzdata \
        python3 python3-pip python3-venv python3-dev \
        build-essential libxml2-dev libxslt1-dev libffi-dev libssl-dev \
        nmap sqlmap ffuf rustscan wafw00f \
        whois testssl.sh dnsutils libpcap0.8 \
        seclists \
        libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
        libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
        libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2t64 \
        libatspi2.0-0 libwayland-client0 fonts-liberation fonts-noto-color-emoji \
        nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Non-root user (the code hardcodes /home/kali/... tool paths) ──
RUN useradd -m -u 1000 -s /bin/bash kali \
    && mkdir -p /home/kali/go/bin /home/kali/.local/bin \
                /home/kali/.config/subfinder /home/kali/.config/nuclei \
                /home/kali/.cache/ms-playwright \
    && chown -R kali:kali /home/kali

# ── 3. Go binaries (from stage 1) ───────────────────────────
COPY --from=go-builder --chown=kali:kali /go/bin/ /home/kali/go/bin/

# ── 4. Application source ────────────────────────────────────
# Build context = repo root (parent of deploy/). argus-env/, output/,
# __pycache__/, .git/, deploy/volumes/ excluded via .dockerignore.
COPY --chown=kali:kali . /home/kali/h4wk3y3/

# ── 5. Python venv (h4wk3y3.py re-execs into argus-env) ─────
USER kali
WORKDIR /home/kali/h4wk3y3

RUN python3 -m venv /home/kali/h4wk3y3/argus-env \
    && /home/kali/h4wk3y3/argus-env/bin/pip install --upgrade pip wheel setuptools \
    && /home/kali/h4wk3y3/argus-env/bin/pip install -r /home/kali/h4wk3y3/requirements.txt \
    && /home/kali/h4wk3y3/argus-env/bin/playwright install chromium

# ── 6. Nuclei templates (snapshot at build, refreshable via volume) ──
RUN /home/kali/go/bin/nuclei -update-templates -silent || true

# ── 7. Resolvers (fallback if the volume isn't mounted) ─────
RUN mkdir -p /home/kali/h4wk3y3/data/resolvers \
    && curl -sL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
         -o /home/kali/h4wk3y3/data/resolvers/resolvers.txt 2>/dev/null \
    || echo "[warn] resolvers download failed at build — in-code fallback used"

# ── 8. gf patterns (m12 runs `gf <pattern>`) ────────────────
RUN git clone --depth=1 https://github.com/tomnomnom/gf /tmp/gf-src 2>/dev/null \
    && mkdir -p /home/kali/.gf \
    && cp /tmp/gf-src/examples/*.json /home/kali/.gf/ 2>/dev/null \
    && rm -rf /tmp/gf-src \
    && git clone --depth=1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-extra 2>/dev/null \
    && cp /tmp/gf-extra/*.json /home/kali/.gf/ 2>/dev/null \
    && rm -rf /tmp/gf-extra \
    || echo "[warn] gf pattern repos clone failed"

USER root
COPY --chown=kali:kali deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER kali
WORKDIR /home/kali/h4wk3y3

EXPOSE 8000
VOLUME ["/home/kali/h4wk3y3/output", "/home/kali/h4wk3y3/data", \
        "/home/kali/.config/subfinder", "/home/kali/.config/nuclei", \
        "/home/kali/.cache/ms-playwright"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["dashboard"]
