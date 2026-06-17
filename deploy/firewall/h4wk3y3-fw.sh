#!/bin/bash
# Re-apply h4wk3y3's firewall allowance after Docker (re)starts.
#
# Docker flushes/rebuilds the DOCKER-USER chain on start. This box has a
# local hardening rule there (`DROP ctstate INVALID,NEW`) that blocks all new
# inbound connections to containers. We insert an ACCEPT for tcp/udp 443
# ABOVE that DROP so the HTTPS dashboard (Caddy) stays reachable, while every
# other container port remains blocked. Idempotent (safe to run repeatedly).
set -e

PORT="${H4_FW_PORT:-443}"

# Wait for the DOCKER-USER chain to exist (Docker may still be coming up).
for _ in $(seq 1 30); do
  iptables -L DOCKER-USER -n >/dev/null 2>&1 && break
  sleep 1
done

for proto in tcp udp; do
  if ! iptables -C DOCKER-USER -p "$proto" --dport "$PORT" -j ACCEPT 2>/dev/null; then
    iptables -I DOCKER-USER 1 -p "$proto" --dport "$PORT" -j ACCEPT
    echo "[h4wk3y3-fw] inserted ACCEPT $proto/$PORT into DOCKER-USER"
  fi
done
