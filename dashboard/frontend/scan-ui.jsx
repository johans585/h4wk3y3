// h4wk3y3 — scan launch modal, live indicator, log viewer.
// Globals exported: window.ScanModal, window.ScanIndicator, window.useActiveScans
const { useState: sS, useEffect: sE, useRef: sR, useCallback: sC, useMemo: sM } = React;

// ── Mode descriptors (kept in sync with scan_manager.MODES) ─────────────
const SCAN_MODES = [
  { id: "full",    name: "Full",    desc: "All modules — recon + OSINT + ports + TLS + quick checks + active" },
  { id: "fast",    name: "Fast",    desc: "OSINT + subs + http + urls + screenshots + quick checks" },
  { id: "passive", name: "Passive", desc: "OSINT + subdomain enum — no active probes"   },
  { id: "stealth", name: "Stealth", desc: "Full + rate-limited / random delays"          },
];

// ── Hook: poll active scans every 3s ────────────────────────────────────
function useActiveScans(enabled = true) {
  const [runs, setRuns] = sS([]);
  sE(() => {
    if (!enabled) return;
    let alive = true;
    const tick = async () => {
      try {
        const all = await window.ArgusAPI.scan.runs();
        if (!alive) return;
        setRuns(all);
      } catch (_) {}
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => { alive = false; clearInterval(id); };
  }, [enabled]);
  const active = sM(() => runs.filter(r => r.state === "starting" || r.state === "running"), [runs]);
  return { runs, active };
}

// Default module presets for quick toggles in Custom mode.
const CUSTOM_PRESETS = [
  { name: "OSINT only",   ids: ["m01"] },
  { name: "Recon only",   ids: ["m02", "m03", "m10", "m05"] },
  { name: "Discovery",    ids: ["m01", "m02", "m03", "m10", "m04", "m05", "m11", "m09"] },
  { name: "Surface scan", ids: ["m03", "m07", "m08", "m09"] },  // post-m02 sweep
  { name: "Vuln hunt",    ids: ["m12", "m13", "m14", "m09"] },  // assumes prior recon
  { name: "Quick triage", ids: ["m12", "m14", "m09"] },
];

// ── Scan launch modal ───────────────────────────────────────────────────
function ScanModal({ open, onClose, defaultTarget = "", currentOrg = null, onLaunched, canManageOrgs = false }) {
  const [target, setTarget] = sS(defaultTarget);
  const [tab, setTab]       = sS("quick");           // "quick" | "custom"
  const [mode, setMode]     = sS("full");
  // Default "all" — populated from backend catalog as soon as it lands so we
  // don't hardcode a module list that drifts every time we add an m1X.
  const [picked, setPicked] = sS([]);
  const [catalog, setCatalog] = sS([]);
  const [pickedTouched, setPickedTouched] = sS(false);
  const [error, setError]   = sS(null);
  const [submitting, setSubmitting] = sS(false);
  const inputRef = sR(null);

  // Multi-org (Étape 2.1) : let the user pick an org at scan time. The
  // dropdown is lazy-loaded from /api/orgs the first time the modal opens.
  // Default selection is the org currently active in the sidebar — keeps
  // the "browsing acme → launch new acme target" flow one click instead
  // of a round-trip to PageOrgs.
  // `org` of "" means "do not attach to any organisation".
  const [orgs, setOrgs] = sS([]);
  const [org, setOrg]   = sS(currentOrg || "");

  sE(() => { if (open) setTarget(defaultTarget || ""); }, [open, defaultTarget]);
  sE(() => { if (open) { setError(null); setPickedTouched(false); } }, [open]);
  sE(() => { if (open) setOrg(currentOrg || ""); }, [open, currentOrg]);

  // Lazy-load orgs list (admin+ can attach; everyone can at least see
  // the org their session is filtered to). GET /api/orgs is user-level.
  sE(() => {
    if (!open) return;
    window.ArgusAPI.orgs.list()
      .then(setOrgs)
      .catch(() => setOrgs([]));
  }, [open]);

  // Lazy-load module catalog from backend
  sE(() => {
    if (!open || catalog.length) return;
    window.ArgusAPI.scan.modes()
      .then(d => setCatalog(d.modules || []))
      .catch(() => setCatalog([]));
  }, [open, catalog.length]);

  // First time the catalog arrives (or user hasn't touched the selection
  // yet), prefill `picked` with every module = "all selected by default".
  sE(() => {
    if (!catalog.length) return;
    if (!pickedTouched && picked.length === 0) {
      setPicked(catalog.map(m => m.id));
    }
  }, [catalog, pickedTouched, picked.length]);

  sE(() => {
    if (!open) return;
    const t = setTimeout(() => inputRef.current?.focus(), 50);
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => { clearTimeout(t); window.removeEventListener("keydown", onKey); };
  }, [open, onClose]);

  const togglePicked = (id) => {
    setPickedTouched(true);
    setPicked(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  };

  const applyPreset = (preset) => { setPickedTouched(true); setPicked([...preset.ids]); };
  const selectAll  = () => { setPickedTouched(true); setPicked(catalog.map(m => m.id)); };
  const selectNone = () => { setPickedTouched(true); setPicked([]); };

  // Auto-warn when deps not in selection (best-effort UX hint, not blocking).
  const missingDeps = sM(() => {
    const sel = new Set(picked);
    const miss = new Set();
    catalog.filter(m => sel.has(m.id)).forEach(m =>
      (m.deps || []).forEach(d => { if (!sel.has(d)) miss.add(d); }));
    return Array.from(miss);
  }, [picked, catalog]);

  const submit = async (e) => {
    e?.preventDefault?.();
    const apex = target.trim();
    if (!apex) { setError("target is required"); return; }
    if (tab === "custom" && picked.length === 0) {
      setError("select at least one module"); return;
    }
    setSubmitting(true); setError(null);
    try {
      // Step 1 (optional) — attach the apex to an org BEFORE scanning so
      // the scope resolver in the pipeline picks up the org's scope_file.
      // Skipped silently if (a) user picked "(none)", or (b) user is not
      // admin (mutations require admin+ — the backend would 403). The
      // backend's link_target is idempotent: re-linking the same apex to
      // the same org is a no-op.
      if (org && canManageOrgs) {
        try {
          await window.ArgusAPI.orgs.linkTarget(org, { apex });
          // Refresh sidebar target_count without forcing a full reload.
          if (window.ArgusOrgsReload) window.ArgusOrgsReload();
        } catch (linkErr) {
          // Non-fatal — surface the error so the user knows the link
          // didn't take, but continue with the scan launch.
          console.warn("org link failed:", linkErr);
          setError(`org link failed: ${linkErr.message || linkErr}. Scan will proceed unlinked.`);
        }
      }

      const body = tab === "custom"
        ? await window.ArgusAPI.scan.start(apex, "custom", picked)
        : await window.ArgusAPI.scan.start(apex, mode);
      onLaunched?.(body);
      onClose();
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className={`modal-overlay ${open ? "open" : ""}`} onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{flex:1}}>
            <div className="modal-eyebrow">SCAN · NEW RUN</div>
            <h2>Initiate Scan</h2>
          </div>
          <button className="cmd-btn" onClick={onClose}><Icon name="x" size={12}/></button>
        </div>
        <form onSubmit={submit} className="modal-body">
          <div className="form-row">
            <label htmlFor="scan-target">Target domain</label>
            <input
              id="scan-target" className="form-input" type="text" autoComplete="off"
              spellCheck={false} placeholder="example.com"
              value={target} onChange={e => setTarget(e.target.value)} ref={inputRef}/>
            <div className="form-hint">Bare domain — no scheme, no path. Wildcards forbidden.</div>
          </div>

          {canManageOrgs && (
            <div className="form-row">
              <label htmlFor="scan-org">Organisation <span className="form-hint-inline">(optional)</span></label>
              <select
                id="scan-org" className="form-input"
                value={org} onChange={e => setOrg(e.target.value)}>
                <option value="">— None (scope resolves via wildcards / auto-yaml) —</option>
                {orgs.map(o => (
                  <option key={o.id} value={o.name}>
                    {o.name}
                  </option>
                ))}
              </select>
              <div className="form-hint">
                Linking attaches this apex to the organisation for
                filtering/stats. Re-link or detach later via the Orgs page.
              </div>
            </div>
          )}

          <div className="form-row">
            <label>Scan mode</label>
            <div className="modal-tabs">
              <button type="button"
                className={`modal-tab ${tab === "quick" ? "active" : ""}`}
                onClick={() => setTab("quick")}>Quick</button>
              <button type="button"
                className={`modal-tab ${tab === "custom" ? "active" : ""}`}
                onClick={() => setTab("custom")}>Custom · {picked.length}/{catalog.length || 10}</button>
            </div>

            {tab === "quick" && (
              <div className="mode-grid">
                {SCAN_MODES.map(m => (
                  <div key={m.id}
                    className={`mode-chip ${mode === m.id ? "active" : ""}`}
                    onClick={() => setMode(m.id)}>
                    <span className="mode-name">{m.name}</span>
                    <span className="mode-desc">{m.desc}</span>
                  </div>
                ))}
              </div>
            )}

            {tab === "custom" && (
              <div style={{display:"flex",flexDirection:"column",gap:10}}>
                <div style={{display:"flex",flexWrap:"wrap",gap:6,fontSize:11}}>
                  <span style={{color:"var(--text-faint)",fontFamily:"var(--font-mono)",alignSelf:"center"}}>presets:</span>
                  {CUSTOM_PRESETS.map(p => (
                    <button type="button" key={p.name} className="cmd-btn"
                      onClick={() => applyPreset(p)}
                      style={{padding:"3px 8px",fontSize:10}}>{p.name}</button>
                  ))}
                  <span style={{flex:1}}/>
                  <button type="button" className="cmd-btn" onClick={selectAll} style={{padding:"3px 8px",fontSize:10}}>all</button>
                  <button type="button" className="cmd-btn" onClick={selectNone} style={{padding:"3px 8px",fontSize:10}}>none</button>
                </div>

                <div className="module-list">
                  {(catalog.length ? catalog : []).map(m => {
                    const checked = picked.includes(m.id);
                    return (
                      <label key={m.id} className={`module-row-pick ${checked ? "active" : ""}`}>
                        <input type="checkbox" checked={checked} onChange={() => togglePicked(m.id)}/>
                        <span className="mid">{m.id}</span>
                        <span className="mname">{m.label}</span>
                        <span className="mdesc">{m.desc}</span>
                      </label>
                    );
                  })}
                  {!catalog.length && (
                    <div className="form-hint">loading module catalog…</div>
                  )}
                </div>

                {missingDeps.length > 0 && (
                  <div style={{
                    fontFamily:"var(--font-mono)",fontSize:10.5,
                    color:"var(--candidate)",
                    background:"rgba(255,206,90,0.06)",
                    border:"1px solid rgba(255,206,90,0.3)",
                    padding:"6px 10px",borderRadius:3,
                  }}>
                    ⚠ unmet deps: {missingDeps.join(", ")} — argus will use restored state from previous scans, but a fresh run on this target may fail.
                  </div>
                )}
              </div>
            )}
          </div>

          {error && <div className="form-error">{error}</div>}
        </form>
        <div className="modal-footer">
          <button type="button" className="cmd-btn" onClick={onClose}>Cancel</button>
          <button type="button" className="cmd-btn cmd-btn-primary" onClick={submit} disabled={submitting}>
            <Icon name={submitting ? "refresh" : "play"} size={12}/>
            {submitting ? "launching…" : "Launch scan"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Topbar live indicator: pill that opens a panel listing active runs ──
function ScanIndicator({ active, onOpenRun }) {
  const [open, setOpen] = sS(false);
  const ref = sR(null);
  sE(() => {
    const onClick = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);
  if (!active.length) return null;
  return (
    <div ref={ref} style={{position:"relative"}}>
      <div className="scan-pill" onClick={() => setOpen(!open)}>
        <span className="pulse"/>
        <span className="pulse-text">{active.length} scan{active.length > 1 ? "s" : ""}</span>
      </div>
      {open && (
        <div className="target-dropdown-v2" style={{minWidth:340,padding:8}}>
          <div style={{fontFamily:"var(--font-mono)",fontSize:9.5,color:"var(--text-faint)",
                       textTransform:"uppercase",letterSpacing:"0.14em",padding:"4px 10px"}}>
            Active runs
          </div>
          {active.map(r => (
            <div key={r.id} className="target-option-v2"
              onClick={() => { onOpenRun(r.id); setOpen(false); }}
              style={{flexDirection:"column",alignItems:"stretch",gap:4}}>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <span style={{width:6,height:6,borderRadius:"50%",background:"var(--solid)",
                              boxShadow:"0 0 6px rgba(91,231,169,0.5)"}}/>
                <span style={{flex:1}}>{r.target}</span>
                <span style={{color:"var(--text-faint)",fontSize:10}}>{r.mode}</span>
              </div>
              <div style={{display:"flex",justifyContent:"space-between",fontSize:10,color:"var(--text-faint)"}}>
                <span>{r.state}</span>
                <span>{Math.floor(r.duration)}s</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Live log panel: shown on Dashboard when a scan is active for the
// current target. Polls /api/scan/status/{id} every 1.5s.
function ScanLogPanel({ runId, onClose }) {
  const [run, setRun] = sS(null);
  const [error, setError] = sS(null);
  const logRef = sR(null);

  sE(() => {
    if (!runId) return;
    let alive = true;
    const tick = async () => {
      try {
        const r = await window.ArgusAPI.scan.status(runId);
        if (!alive) return;
        setRun(r);
        // auto-scroll to bottom on new lines
        if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
        if (r.state !== "running" && r.state !== "starting") return false;
      } catch (e) {
        if (alive) setError(String(e));
      }
      return true;
    };
    let id = null;
    const loop = async () => {
      const cont = await tick();
      if (cont && alive) id = setTimeout(loop, 1500);
    };
    loop();
    return () => { alive = false; if (id) clearTimeout(id); };
  }, [runId]);

  if (!runId) return null;

  const stop = async () => {
    if (!confirm("Stop this scan?")) return;
    try { await window.ArgusAPI.scan.stop(runId); } catch (e) { alert(e); }
  };

  const stateColor = {
    starting: "var(--text-muted)",
    running:  "var(--solid)",
    done:     "var(--solid)",
    failed:   "var(--sev-critical)",
    killed:   "var(--sev-medium)",
  }[run?.state] || "var(--text-muted)";

  return (
    <div className="card" style={{marginBottom:14}}>
      <div className="card-header">
        <div style={{flex:1}}>
          <div className="card-title">
            <span style={{display:"inline-block",width:7,height:7,borderRadius:"50%",
                          background:stateColor,marginRight:8,
                          animation: run?.state === "running" ? "pulse2 1.4s infinite" : "none"}}/>
            Scan run · {run?.target || "—"}
          </div>
          <div className="card-subtitle">
            // {run?.id || "…"} · MODE={run?.mode || "—"} · STATE={run?.state || "—"}
            {run?.duration != null && <> · {Math.floor(run.duration)}s</>}
            {run?.returncode != null && <> · EXIT={run.returncode}</>}
          </div>
        </div>
        <div className="card-tools">
          {(run?.state === "running" || run?.state === "starting") && (
            <button className="cmd-btn cmd-btn-danger" onClick={stop}>
              <Icon name="x" size={12}/> Stop
            </button>
          )}
          <button className="cmd-btn" onClick={onClose}><Icon name="x" size={12}/></button>
        </div>
      </div>
      {error && <div className="form-error" style={{margin:"10px 14px"}}>{error}</div>}
      <div ref={logRef} className="scan-log">
        {(run?.log_tail || []).map((ln, i) => {
          // Strip ANSI escape sequences (color codes from rich/colorlog)
          const clean = ln.replace(/\[[0-9;]*m/g, "").replace(/\[[0-9;]+m/g, "");
          const cls = clean.startsWith("[mgr]") ? "ln-mgr"
                    : /error|fail|exception/i.test(clean) ? "ln-err"
                    : "";
          return <div key={i} className={cls}>{clean}</div>;
        })}
        {!run?.log_tail?.length && <div style={{color:"var(--text-faint)"}}>waiting for output…</div>}
      </div>
    </div>
  );
}

window.ScanModal = ScanModal;
window.ScanIndicator = ScanIndicator;
window.useActiveScans = useActiveScans;
window.ScanLogPanel = ScanLogPanel;
window.SCAN_MODES = SCAN_MODES;
