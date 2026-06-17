"""
Scan manager. Spawns h4wk3y3.py as a subprocess and tracks state both in
memory (live deque tail of stdout) and on disk via the existing ArgusDB
Postgres (table `dashboard_runs`).

Persistence model:
  - Every state transition is mirrored to dashboard_runs.
  - On dashboard startup, all rows in state ∈ {starting, running} are
    re-checked: if the PID is still alive, the row is kept (read-only —
    we don't reattach to the stdout stream of an existing process); if
    the PID is gone, the row is marked 'abandoned' so the UI doesn't
    display permanent "running" rows.
  - Live stdout tail is in-memory only; previous-run logs survive at
    `argus.log` (set in h4wk3y3.yaml).

Concurrency: one scan per (target, mode) — re-runs on the same target
are refused while one is active. Different targets run in parallel.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Optional


def _iso_to_epoch(value) -> Optional[float]:
    """Parse an ISO-8601 timestamp (as stored in the `scans` ledger) into an
    epoch float, matching ScanRun.started_at. Returns None on any failure."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        from datetime import datetime
        return datetime.fromisoformat(str(value)).timestamp()
    except Exception:
        return None


# Tail of stdout/stderr we keep per run for the UI.
LOG_TAIL_SIZE = 400

# Modes accepted by the API → h4wk3y3.py CLI flags.
# "custom" is special: argv is built from the explicit modules list at start time.
MODES = {
    "full":    ["--full"],
    "fast":    ["--fast"],
    "passive": ["--passive"],
    "stealth": ["--full", "--stealth"],
    "custom":  None,  # placeholder — argv built dynamically
}

# Module catalogue exposed to the front (id → human label + dependency note).
MODULE_CATALOG = [
    ("m01", "OSINT",              "WHOIS + SPF/DMARC/DKIM + trufflehog GitHub + HIBP",        []),
    ("m02", "Subdomain enum",     "Passive (subfinder/crt.sh/chaos) + active brute + alterx", []),
    ("m03", "HTTP + Tech",        "Probe alive hosts, detect tech stack, WAF, CORS",          ["m02"]),
    ("m10","Body fetcher",       "Fetch full bodies + headers (feeds m11/m12)",              ["m03"]),
    ("m04", "URL collection",     "gau (passive) + katana (JS-aware crawl)",                  ["m03"]),
    ("m05", "Screenshots",        "Playwright captures of each live host",                    ["m03"]),
    ("m11", "JS analysis",        "Secrets, endpoints, source maps, validation",              ["m10"]),
    ("m06", "Takeover",           "CNAME → vulnerable services (74 signatures)",              ["m02", "m03"]),
    ("m12", "Pattern analysis",   "gf grep + custom regex + reflection check + arjun",        ["m04", "m10"]),
    ("m13", "Nuclei",             "Tech-targeted templates + high-impact info",               ["m03"]),
    ("m07", "Ports + CDN",        "naabu top-1000 + nmap -sV + cdncheck origin",              ["m03"]),
    ("m08", "TLS audit",          "testssl.sh on HTTPS hosts (ciphers, cert, HSTS)",          ["m03"]),
    ("m09", "Quick checks",       "GraphQL / .git / .env / JWT / cloud bucket exposure",      ["m03"]),
    ("m14", "Active validation",  "File exposure / open redirect / dalfox XSS / sqlmap (slow)",["m12", "m03"]),
]

DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)+$")
LIVE_STATES = ("starting", "running")
TERMINAL_STATES = ("done", "failed", "killed", "abandoned")


def is_valid_domain(d: str) -> bool:
    if not d or len(d) > 253:
        return False
    return DOMAIN_RE.match(d) is not None


def _pid_alive(pid: Optional[int]) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but owned by another user — treat as alive.
        return True
    except Exception:
        return Path(f"/proc/{pid}").exists()


class ScanRun:
    __slots__ = ("id", "target", "mode", "modules", "pid", "state", "log",
                 "started_at", "finished_at", "returncode", "_proc", "_thread")

    def __init__(self, target: str, mode: str, modules: Optional[list] = None,
                 run_id: Optional[str] = None):
        self.id          = run_id or uuid.uuid4().hex[:12]
        self.target      = target
        self.mode        = mode
        self.modules     = modules or []   # used when mode == "custom"
        self.pid: Optional[int] = None
        self.state       = "starting"  # starting | running | done | failed | killed | abandoned
        self.log: deque  = deque(maxlen=LOG_TAIL_SIZE)
        self.started_at  = time.time()
        self.finished_at: Optional[float] = None
        self.returncode: Optional[int] = None
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None

    def to_dict(self, include_log: bool = False) -> dict:
        d = {
            "id":          self.id,
            "target":      self.target,
            "mode":        self.mode,
            "modules":     self.modules,
            "pid":         self.pid,
            "state":       self.state,
            "started_at":  self.started_at,
            "finished_at": self.finished_at,
            "duration":    (self.finished_at or time.time()) - self.started_at,
            "returncode":  self.returncode,
        }
        if include_log:
            d["log_tail"] = list(self.log)
        return d


class ScanManager:
    def __init__(self, project_root: Path, allow_remote: bool, wildcards: list[str],
                 db=None):
        """
        project_root: argus repo path.
        allow_remote: if False (default — dashboard binds 127.0.0.1), any target accepted.
                      If True, target must be in `wildcards`.
        wildcards: parent domains the user is authorised to scan.
        db: ArgusDB instance for persistence. If None, falls back to memory-only.
        """
        self._lock         = threading.Lock()  # protects _runs dict + DB writes
        self._runs: dict[str, ScanRun] = {}
        self._target_lock: dict[str, str] = {}  # target → run_id (active)
        self.project_root  = project_root
        self.allow_remote  = allow_remote
        self.wildcards     = set(w.strip().lower() for w in wildcards if w.strip())
        self.db            = db
        if db is not None:
            self._reclaim_orphans()

    # ── Persistence ──────────────────────────────────────────────────────

    def _persist(self, run: ScanRun) -> None:
        """Mirror a run's current state to dashboard_runs."""
        if self.db is None:
            return
        try:
            import sqlalchemy as sa
            from core import orm
            t = orm.DashboardRun.__table__
            vals = dict(
                target=run.target, mode=run.mode,
                modules=json.dumps(run.modules),
                pid=run.pid, state=run.state, started_at=run.started_at,
                finished_at=run.finished_at, returncode=run.returncode,
                log_tail=json.dumps(list(run.log)),
            )
            with self.db.engine.begin() as c:
                # Portable upsert: delete then insert. Volumes are tiny
                # (one row per dashboard-launched scan, persisted seldom).
                c.execute(sa.delete(t).where(t.c.id == run.id))
                c.execute(sa.insert(t).values(id=run.id, **vals))
        except Exception:
            # Persistence failure must never break a live scan.
            pass

    def _reclaim_orphans(self) -> None:
        """
        On startup, sweep dashboard_runs:
          - Rows in 'done/failed/killed/abandoned': leave them (history).
          - Rows in 'starting/running': if PID alive → keep (UI shows
            read-only; we no longer drain its stdout). If PID dead →
            mark 'abandoned' with finished_at = now.
        """
        try:
            import sqlalchemy as sa
            from core import orm
            t = orm.DashboardRun.__table__
            with self.db.engine.connect() as c:
                rows = [dict(r._mapping) for r in c.execute(sa.select(t))]
        except Exception:
            return

        now = time.time()
        for r in rows:
            run = ScanRun(target=r['target'], mode=r['mode'], run_id=r['id'])
            try:
                run.modules = json.loads(r['modules'] or '[]')
            except Exception:
                run.modules = []
            run.pid          = r['pid']
            run.state        = r['state']
            run.started_at   = r['started_at']
            run.finished_at  = r['finished_at']
            run.returncode   = r['returncode']
            try:
                for line in (json.loads(r['log_tail'] or '[]') or []):
                    run.log.append(line)
            except Exception:
                pass

            if run.state in LIVE_STATES:
                if _pid_alive(run.pid):
                    # Still running but we lost the stdout pipe — track read-only.
                    run.log.append("[mgr] reattached on dashboard restart (read-only)")
                    self._target_lock[run.target] = run.id
                else:
                    run.state = "abandoned"
                    run.finished_at = now
                    run.log.append("[mgr] process gone after dashboard restart")
                    self._persist(run)

            self._runs[run.id] = run

    # ── Validation ────────────────────────────────────────────────────────

    def authorise_target(self, target: str) -> Optional[str]:
        """Return None if OK, else error string.

        Note: the wildcards-file allow-list (previously enforced when the
        dashboard binds to a non-loopback host) has been removed. The
        operator is responsible for limiting network exposure of the
        dashboard themselves (firewall, reverse-proxy auth, VPN-only access).
        """
        target = target.strip().lower()
        if not is_valid_domain(target):
            return "invalid domain syntax"
        return None

    # ── Lifecycle ─────────────────────────────────────────────────────────

    _VALID_MODULE_RE = re.compile(r'^m\d{2}[a-z]?$')

    def start(self, target: str, mode: str = "full",
              modules: Optional[list] = None) -> tuple[Optional[ScanRun], Optional[str]]:
        target = target.strip().lower()
        if mode not in MODES:
            return None, f"unknown mode '{mode}'"

        # Custom mode: validate the module list strictly.
        if mode == "custom":
            if not modules:
                return None, "custom mode requires a non-empty module list"
            cleaned = []
            valid = {m[0] for m in MODULE_CATALOG}
            for m in modules:
                m = str(m).strip().lower()
                if m not in valid or not self._VALID_MODULE_RE.match(m):
                    return None, f"invalid module id: '{m}'"
                if m not in cleaned:
                    cleaned.append(m)
            modules = cleaned

        err = self.authorise_target(target)
        if err:
            return None, err

        with self._lock:
            existing = self._target_lock.get(target)
            if existing:
                run = self._runs.get(existing)
                if run and run.state in LIVE_STATES:
                    return None, f"already scanning {target} (run {existing})"
            run = ScanRun(target=target, mode=mode, modules=modules)
            self._runs[run.id] = run
            self._target_lock[target] = run.id
            self._persist(run)

        thread = threading.Thread(target=self._run, args=(run,), daemon=True, name=f"scan-{run.id}")
        run._thread = thread
        thread.start()
        return run, None

    def _run(self, run: ScanRun) -> None:
        if run.mode == "custom":
            mode_args = ["--modules", ",".join(run.modules)]
        else:
            mode_args = MODES[run.mode] or []
        argv = [
            sys.executable, str(self.project_root / "h4wk3y3.py"),
            "-t", run.target,
            *mode_args,
        ]
        run.log.append(f"[mgr] launching: {' '.join(argv)}")
        try:
            proc = subprocess.Popen(
                argv,
                cwd=str(self.project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,  # line-buffered
                universal_newlines=True,
                text=True,
                # New process group so we can SIGTERM the whole tree.
                start_new_session=True,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
        except Exception as e:
            run.state = "failed"
            run.finished_at = time.time()
            run.log.append(f"[mgr] spawn failed: {e}")
            self._persist(run)
            self._release_target(run)
            return

        run._proc = proc
        run.pid   = proc.pid
        run.state = "running"
        run.log.append(f"[mgr] pid={proc.pid}")
        self._persist(run)

        # Persist log tail periodically while reading stdout — so a UI restart
        # mid-scan still shows recent output. Throttled to ~once per 5s.
        last_persist = time.time()
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                run.log.append(line.rstrip())
                if time.time() - last_persist > 5:
                    self._persist(run)
                    last_persist = time.time()
        except Exception as e:
            run.log.append(f"[mgr] stdout drain error: {e}")

        rc = proc.wait()
        run.returncode  = rc
        run.finished_at = time.time()
        if run.state == "killed":
            pass  # keep state
        elif rc == 0:
            run.state = "done"
            run.log.append("[mgr] exit 0 — scan complete")
        else:
            run.state = "failed"
            run.log.append(f"[mgr] exit {rc}")

        self._persist(run)
        self._release_target(run)

    def _release_target(self, run: ScanRun) -> None:
        with self._lock:
            if self._target_lock.get(run.target) == run.id:
                del self._target_lock[run.target]

    def stop(self, run_id: str) -> Optional[str]:
        run = self._runs.get(run_id)
        if not run:
            return "no such run"
        if run.state not in LIVE_STATES:
            return f"run already {run.state}"
        proc = run._proc
        # Reattached run from a previous dashboard process — we own the PID
        # but not a stdout pipe. We can still try to terminate the group.
        if proc is None and run.pid:
            run.state = "killed"
            run.log.append(f"[mgr] SIGTERM sent to reattached pid {run.pid}")
            try:
                os.killpg(os.getpgid(run.pid), signal.SIGTERM)
            except Exception as e:
                run.log.append(f"[mgr] SIGTERM failed: {e}")
            run.finished_at = time.time()
            self._persist(run)
            self._release_target(run)
            return None
        if proc and proc.poll() is None:
            run.state = "killed"
            run.log.append("[mgr] SIGTERM sent")
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception as e:
                run.log.append(f"[mgr] SIGTERM failed: {e}")
            self._persist(run)
            # Give it 5s, then SIGKILL if still alive.
            def _hard_kill():
                time.sleep(5)
                if proc.poll() is None:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        run.log.append("[mgr] SIGKILL sent")
                        self._persist(run)
                    except Exception:
                        pass
            threading.Thread(target=_hard_kill, daemon=True).start()
        return None

    # ── Read API ──────────────────────────────────────────────────────────

    def get(self, run_id: str) -> Optional[ScanRun]:
        return self._runs.get(run_id)

    def list_runs(self) -> list[dict]:
        # Most recent first. Dashboard-launched runs come from the in-memory
        # registry (mirrored to dashboard_runs).
        runs = sorted(self._runs.values(), key=lambda r: r.started_at, reverse=True)
        out = [{**r.to_dict(), "source": "dashboard"} for r in runs]

        # Surface CLI-launched scans (`h4wk3y3.py -t ...`) too. They never create
        # a dashboard_runs row — they live only in the `scans` ledger — so the
        # Scans page used to hide them entirely. Merge recent ones in, skipping
        # any that line up with a dashboard run (same target, start within 2 min)
        # so UI scans are not double-listed.
        if self.db is not None:
            try:
                windows = [(r.target.lower(), r.started_at) for r in runs]
                for s in self.db.get_scans()[:100]:
                    ts  = _iso_to_epoch(s.get("started_at"))
                    tgt = (s.get("domain") or "").lower()
                    if ts is None:
                        continue
                    if any(t == tgt and abs(ts - st) < 120 for t, st in windows):
                        continue
                    fin = _iso_to_epoch(s.get("finished_at"))
                    out.append({
                        "id":          s.get("scan_id"),
                        "target":      s.get("domain"),
                        "mode":        "cli",
                        "modules":     None,
                        "pid":         None,
                        "state":       s.get("status") or "done",
                        "started_at":  ts,
                        "finished_at": fin,
                        "duration":    (fin - ts) if fin else None,
                        "returncode":  None,
                        "source":      "cli",
                    })
            except Exception:
                pass
            out.sort(key=lambda d: d.get("started_at") or 0, reverse=True)
        return out

    def active_for_target(self, target: str) -> Optional[str]:
        return self._target_lock.get(target.lower())
