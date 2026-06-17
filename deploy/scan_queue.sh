#!/usr/bin/env bash
# ============================================================
#  h4wk3y3 — sequential scan queue (one pass over all targets)
#
#  Scans every apex in the `targets` table ONE AT A TIME (the VPS never runs
#  two scans in parallel), with a RAM/load gate before each, a pause between,
#  and resumable progress. Designed to map the whole estate without overloading
#  a small box.
#
#  Usage (from deploy/):
#    ./scan_queue.sh "--fast --stealth"          # quick cartography
#    ./scan_queue.sh "--modules m01,m02,m03,m10,m04,m05,m06,m07,m09,m11 --stealth"
#    ./scan_queue.sh "--full --stealth"          # complete (slow)
#
#  Tunables (env): H4_QUEUE_GAP (s between targets), H4_QUEUE_MIN_FREE_MB,
#                  H4_QUEUE_MAX_LOAD, H4_SCAN_CPUS (compose CPU cap).
#  State/log: volumes/output/_queue_state.txt (done apexes) + _queue.log
# ============================================================
set -uo pipefail
cd "$(dirname "$0")"

MODE_ARGS="${1:---fast --stealth}"
GAP="${H4_QUEUE_GAP:-90}"
MIN_FREE_MB="${H4_QUEUE_MIN_FREE_MB:-2048}"
MAX_LOAD="${H4_QUEUE_MAX_LOAD:-5.0}"

STATE="volumes/output/_queue_state.txt"
LOG="volumes/output/_queue.log"
mkdir -p volumes/output
touch "$STATE" "$LOG"

# Read DB connection defaults from .env (POSTGRES_USER/DB).
PGUSER="$(grep -E '^POSTGRES_USER=' .env 2>/dev/null | cut -d= -f2)"; PGUSER="${PGUSER:-h4wk3y3}"
PGDB="$(grep -E '^POSTGRES_DB=' .env 2>/dev/null | cut -d= -f2)";   PGDB="${PGDB:-h4wk3y3}"

log(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

gate(){
  while :; do
    free_mb=$(free -m | awk '/^Mem:/{print $7}')
    load=$(awk '{print $1}' /proc/loadavg)
    if [ "${free_mb:-0}" -ge "$MIN_FREE_MB" ] && awk "BEGIN{exit !($load < $MAX_LOAD)}"; then
      break
    fi
    log "throttle: free=${free_mb}MB load=${load} (need free>=${MIN_FREE_MB} load<${MAX_LOAD}) — waiting 30s"
    sleep 30
  done
}

mapfile -t TARGETS < <(docker compose exec -T postgres psql -U "$PGUSER" -d "$PGDB" -tA \
                        -c "SELECT apex FROM targets ORDER BY apex" 2>/dev/null)

total=${#TARGETS[@]}
if [ "$total" -eq 0 ]; then log "no targets in DB — run 'make import' first"; exit 1; fi

i=0; ok=0; fail=0
log "════════ queue start: $total targets · mode='$MODE_ARGS' ════════"
for t in "${TARGETS[@]}"; do
  i=$((i+1))
  [ -z "$t" ] && continue
  if grep -qxF "$t" "$STATE"; then log "[$i/$total] skip (already done): $t"; continue; fi
  gate
  log "[$i/$total] ▶ scanning: $t"
  start=$(date +%s)
  if docker compose run --rm scan scan "$t" $MODE_ARGS >>"$LOG" 2>&1; then
    echo "$t" >> "$STATE"; ok=$((ok+1))
    log "[$i/$total] ✓ done: $t ($(( $(date +%s) - start ))s)"
  else
    fail=$((fail+1))
    log "[$i/$total] ✗ FAILED: $t (continuing)"
  fi
  sleep "$GAP"
done
log "════════ queue finished: $ok ok · $fail failed · $total total ════════"
