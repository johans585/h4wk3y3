// h4wk3y3 — additional page components (replaces stubs with real data)
// Each component lazy-fetches its endpoint on mount.
const { useState: uxS, useEffect: uxE, useMemo: uxM, useRef: uxR, useCallback: uxC } = React;

// ── shared helpers ──────────────────────────────────────────────────────
function useLazy(domain, fetcher, deps = []) {
  const [state, setState] = uxS({ loading: true, data: null, error: null });
  uxE(() => {
    if (!domain) return;
    let cancel = false;
    setState({ loading: true, data: null, error: null });
    fetcher(domain)
      .then(data => { if (!cancel) setState({ loading: false, data, error: null }); })
      .catch(err  => { if (!cancel) setState({ loading: false, data: null, error: String(err) }); });
    return () => { cancel = true; };
  }, [domain, ...deps]);
  return state;
}

// Expandable cell: long values (JWT, API keys, base64 blobs) are clipped
// to two lines by default; click to expand and read the whole thing inline.
// Always exposes a copy button. Wrapping uses break-all so we never need a
// horizontal scroll inside the cell.
function ExpandableValue({ value }) {
  const [open, setOpen] = uxS(false);
  const v = value == null ? "—" : String(value);
  const long = v.length > 120;
  return (
    <div
      className="expand-cell"
      style={{
        fontFamily:"var(--font-mono)",
        fontSize:10.5,
        color:"var(--slate-light)",
        wordBreak:"break-all",
        whiteSpace:"pre-wrap",
        maxHeight: !open && long ? 36 : "none",
        overflow: !open && long ? "hidden" : "visible",
        position:"relative",
        cursor: long ? (open ? "zoom-out" : "zoom-in") : "default",
        paddingRight: 24,
      }}
      onClick={() => long && setOpen(o => !o)}
      title={long ? (open ? "Click to collapse" : "Click to expand") : ""}
    >
      {v}
      {long && !open && (
        <span style={{
          position:"absolute", right:0, bottom:0,
          background:"linear-gradient(90deg, transparent, var(--card-bg, #14181b) 40%)",
          padding:"0 6px 0 16px",
          fontSize:10, color:"var(--accent)",
        }}>more…</span>
      )}
      <span style={{position:"absolute", right:0, top:0}}>
        <CopyButton text={v}/>
      </span>
    </div>
  );
}

function PageLoading({ label = "Loading…" }) {
  return (
    <div className="empty" style={{padding:"60px 20px"}}>
      <div className="empty-icon" style={{
        width:32,height:32,border:"1.5px solid rgba(255,255,255,0.08)",
        borderTopColor:"var(--accent)",borderRadius:"50%",
        animation:"argus-spin 0.9s linear infinite"
      }}/>
      <div className="empty-title" style={{marginTop:14}}>{label}</div>
    </div>
  );
}

function PageError({ error }) {
  return (
    <div className="empty" style={{padding:"60px 20px"}}>
      <div className="empty-icon"><Icon name="x" size={40}/></div>
      <div className="empty-title">load failed</div>
      <div className="empty-msg" style={{color:"var(--sev-critical)"}}>{error}</div>
    </div>
  );
}

function PageHeader({ eyebrow, title, lede, actions }) {
  return (
    <div className="page-header">
      <div>
        <div className="page-eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        {lede && <div className="lede">// {lede.toUpperCase()}</div>}
      </div>
      {actions && <div className="page-header-actions">{actions}</div>}
    </div>
  );
}

// Virtualized table — windowed rendering for large datasets (URLs, subdomains)
function VirtualTable({ items, rowHeight = 32, headerRow, renderRow, height = 600 }) {
  const [scrollTop, setScrollTop] = uxS(0);
  const containerRef = uxR(null);

  const visibleCount = Math.ceil(height / rowHeight) + 6;
  const startIdx = Math.max(0, Math.floor(scrollTop / rowHeight) - 3);
  const endIdx = Math.min(items.length, startIdx + visibleCount);
  const offsetY = startIdx * rowHeight;

  const onScroll = (e) => setScrollTop(e.target.scrollTop);

  return (
    <div className="table-wrap" style={{maxHeight:height,overflowY:"auto"}} ref={containerRef} onScroll={onScroll}>
      <div style={{height: items.length * rowHeight, position:"relative"}}>
        <table className="data" style={{position:"absolute",top:offsetY,left:0,right:0,width:"100%"}}>
          <thead style={{position:"sticky",top:0,background:"var(--bg-card)",zIndex:2}}>{headerRow}</thead>
          <tbody>
            {items.slice(startIdx, endIdx).map((item, i) => renderRow(item, startIdx + i))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// TECHNOLOGIES
// ──────────────────────────────────────────────────────────────────────
function PageTechnologies({ data }) {
  const { loading, data: tech, error } = useLazy(data.target, window.ArgusAPI.lazy.tech);
  const [selected, setSelected] = uxS(null);

  // Aggregate: tech name → list of hosts
  const aggregate = uxM(() => {
    if (!tech) return [];
    const m = {};
    Object.entries(tech).forEach(([host, list]) => {
      (list || []).forEach(t => {
        if (!m[t]) m[t] = [];
        m[t].push(host);
      });
    });
    return Object.entries(m).map(([name, hosts]) => ({ name, hosts })).sort((a,b) => b.hosts.length - a.hosts.length);
  }, [tech]);

  return (
    <div className="page">
      <PageHeader eyebrow="ASSETS · TECHNOLOGIES" title="Technologies"
        lede={`${aggregate.length} unique stacks across ${tech ? Object.keys(tech).length : 0} hosts`}/>
      {loading && <PageLoading label="scanning fingerprints"/>}
      {error && <PageError error={error}/>}
      {!loading && !error && (
        <div style={{display:"grid",gridTemplateColumns:"minmax(260px,1fr) 2fr",gap:16}}>
          <div className="card" style={{padding:14}}>
            <div className="card-title" style={{marginBottom:10}}>Tech stack</div>
            <div style={{display:"flex",flexWrap:"wrap",gap:6,maxHeight:520,overflowY:"auto"}}>
              {aggregate.map(t => (
                <span key={t.name}
                  className={`tech-chip ${selected === t.name ? "active" : ""}`}
                  style={{
                    cursor:"pointer",
                    background: selected === t.name ? "var(--accent-soft)" : undefined,
                    color: selected === t.name ? "var(--accent)" : undefined,
                  }}
                  onClick={() => setSelected(selected === t.name ? null : t.name)}>
                  {t.name}
                  <span style={{marginLeft:6,opacity:0.6,fontSize:10}}>{t.hosts.length}</span>
                </span>
              ))}
              {aggregate.length === 0 && <div className="empty-msg">No tech detected</div>}
            </div>
          </div>
          <div className="card">
            <div className="card-header">
              <div className="card-title">{selected || "Select a tech to see its hosts"}</div>
              {selected && <div className="card-subtitle">// {aggregate.find(t => t.name === selected)?.hosts.length} hosts</div>}
            </div>
            {selected ? (
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th className="ridx">#</th><th>Host</th></tr></thead>
                  <tbody>
                    {aggregate.find(t => t.name === selected).hosts.map((h, i) => (
                      <tr key={h}>
                        <td className="ridx">{String(i+1).padStart(3,"0")}</td>
                        <td className="url"><a href={h.startsWith("http") ? h : `https://${h}`} target="_blank" rel="noopener">{h}</a><CopyButton text={h}/></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty"><div className="empty-icon"><Icon name="cpu" size={40}/></div><div className="empty-title">Pick a stack</div></div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// SCREENSHOTS
// ──────────────────────────────────────────────────────────────────────
function PageScreenshots({ data }) {
  const { loading, data: shots, error } = useLazy(data.target, window.ArgusAPI.lazy.screenshots);
  const [search, setSearch] = uxS("");
  const [zoom, setZoom] = uxS(null);

  const filtered = uxM(() => {
    if (!shots) return [];
    return shots.filter(s => !search || s.url.toLowerCase().includes(search.toLowerCase()) || (s.title||"").toLowerCase().includes(search.toLowerCase()));
  }, [shots, search]);

  return (
    <div className="page">
      <PageHeader eyebrow="ASSETS · SCREENSHOTS" title="Screenshots"
        lede={`${shots ? shots.length : 0} captures · playwright chromium`}/>
      {loading && <PageLoading label="loading captures"/>}
      {error && <PageError error={error}/>}
      {!loading && !error && (
        <>
          <div className="filter-bar">
            <div className="search-input">
              <span className="prompt">$</span>
              <input placeholder="filter url, title..." value={search} onChange={e => setSearch(e.target.value)}/>
            </div>
            <div className="result-count"><span className="accent">{filtered.length}</span> / {shots.length}</div>
          </div>
          <div style={{
            display:"grid",
            gridTemplateColumns:"repeat(auto-fill,minmax(260px,1fr))",
            gap:14,
          }}>
            {filtered.map((s, i) => (
              <div key={`${s.screenshot || s.url || "shot"}-${i}`} className="card" style={{padding:0,overflow:"hidden",cursor:"zoom-in"}}
                   onClick={() => setZoom(s)}>
                <div style={{aspectRatio:"16/10",background:"var(--bg-elevated)",overflow:"hidden",position:"relative"}}>
                  <img src={window.ArgusAPI.screenshotURL(data.target, s.thumb || s.screenshot)}
                       alt={s.title || s.url}
                       loading="lazy"
                       data-fallback={s.screenshot}
                       style={{width:"100%",height:"100%",objectFit:"cover",objectPosition:"top",display:"block"}}
                       onError={e => {
                         const fb = e.target.dataset.fallback;
                         if (fb && !e.target.dataset.tried) {
                           e.target.dataset.tried = "1";
                           e.target.src = window.ArgusAPI.screenshotURL(data.target, fb);
                         } else {
                           e.target.style.display = "none";
                           const ph = e.target.parentElement;
                           if (ph && !ph.querySelector(".no-shot")) {
                             const d = document.createElement("div");
                             d.className = "no-shot";
                             d.style.cssText = "position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:var(--text-faint);font-family:var(--font-mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase";
                             d.textContent = "no capture";
                             ph.appendChild(d);
                           }
                         }
                       }}/>
                </div>
                <div style={{padding:"10px 12px"}}>
                  <div className="mono" style={{fontSize:11,color:"var(--text-dim)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{s.url}</div>
                  <div style={{fontSize:11.5,color:"var(--text-muted)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",marginTop:2}}>{s.title || "—"}</div>
                </div>
              </div>
            ))}
            {filtered.length === 0 && <div className="empty" style={{gridColumn:"1/-1"}}><div className="empty-title">no captures</div></div>}
          </div>
          {zoom && (
            <div onClick={() => setZoom(null)} style={{
              position:"fixed",inset:0,background:"rgba(0,0,0,0.85)",zIndex:60,
              display:"flex",alignItems:"center",justifyContent:"center",cursor:"zoom-out",padding:24,
            }}>
              <div style={{maxWidth:"95vw",maxHeight:"92vh",display:"flex",flexDirection:"column",gap:10}}>
                <div className="mono" style={{color:"var(--text-dim)",fontSize:11,textAlign:"center"}}>{zoom.url}</div>
                <img src={window.ArgusAPI.screenshotURL(data.target, zoom.screenshot)}
                     alt={zoom.title}
                     style={{maxWidth:"95vw",maxHeight:"82vh",border:"1px solid var(--border)",boxShadow:"0 20px 60px rgba(0,0,0,0.6)"}}/>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// URLS
// ──────────────────────────────────────────────────────────────────────
function PageURLs({ data }) {
  const [showAll, setShowAll] = uxS(false);
  const { loading, data: payload, error } = useLazy(data.target, (d) => window.ArgusAPI.lazy.urls(d, showAll), [showAll]);
  const [search, setSearch] = uxS("");
  const [statusFilter, setStatusFilter] = uxS("all");

  const urls = payload ? payload.urls || [] : [];

  const filtered = uxM(() => {
    if (!search) return urls;
    const q = search.toLowerCase();
    return urls.filter(u => u.toLowerCase().includes(q));
  }, [urls, search]);

  return (
    <div className="page">
      <PageHeader eyebrow="CONTENT · URLs" title="URLs"
        lede={`${payload ? (payload.total_all || payload.count).toLocaleString() : "—"} crawled · ${payload && payload.probed ? "live-probed" : "all"}`}
        actions={<>
          <button className={`cmd-btn ${!showAll ? "cmd-btn-primary" : ""}`} onClick={() => setShowAll(false)}>Live</button>
          <button className={`cmd-btn ${showAll ? "cmd-btn-primary" : ""}`} onClick={() => setShowAll(true)}>All</button>
          <ExportButtons
            rows={filtered.map(u => ({ url: u }))}
            columns={[{ key:"url", label:"url" }]}
            basename={`${data.target || "argus"}-urls`}
          />
        </>}/>
      {loading && <PageLoading label="loading URLs"/>}
      {error && <PageError error={error}/>}
      {!loading && !error && (
        <>
          <div className="filter-bar">
            <div className="search-input">
              <span className="prompt">$</span>
              <input placeholder="grep url..." value={search} onChange={e => setSearch(e.target.value)} autoFocus/>
            </div>
            <div className="result-count"><span className="accent">{filtered.length.toLocaleString()}</span> / {urls.length.toLocaleString()}</div>
          </div>
          <div className="card" style={{borderTopLeftRadius:0,borderTopRightRadius:0,borderTop:"none"}}>
            <VirtualTable
              items={filtered}
              rowHeight={40}
              height={Math.min(720, window.innerHeight - 280)}
              headerRow={<tr><th className="ridx">#</th><th>URL</th><th style={{width:70}}/></tr>}
              renderRow={(u, i) => (
                <tr key={i} style={{height:40}}>
                  <td className="ridx">{String(i+1).padStart(5,"0")}</td>
                  <td className="url" style={{maxWidth:"60vw",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
                    <a href={u} target="_blank" rel="noopener noreferrer" style={{color:"inherit",textDecoration:"none"}} onClick={e => e.stopPropagation()}>{u}</a>
                  </td>
                  <td><CopyButton text={u}/></td>
                </tr>
              )}
            />
          </div>
        </>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// JS ANALYSIS
// ──────────────────────────────────────────────────────────────────────
function PageJSAnalysis({ data }) {
  const [tab, setTab] = uxS("secrets");
  const secrets   = useLazy(data.target, window.ArgusAPI.lazy.jsSecrets);
  const endpoints = useLazy(data.target, window.ArgusAPI.lazy.jsEndpoints);
  const files     = useLazy(data.target, window.ArgusAPI.lazy.jsFiles);

  const tabs = [
    ["secrets",   "Secrets",   secrets.data?.length || 0],
    ["endpoints", "Endpoints", endpoints.data?.length || 0],
    ["files",     "Files",     files.data?.length || 0],
  ];

  return (
    <div className="page">
      <PageHeader eyebrow="CONTENT · JS" title="JS Analysis"
        lede="jsluice + sourcemapper · secrets, endpoints, bundles"/>
      <div className="filter-bar">
        <div className="filter-group">
          {tabs.map(([k, label, n]) => (
            <button key={k} className={`filter-chip ${tab === k ? "active" : ""}`} onClick={() => setTab(k)}>
              {label}<span className="num">{n}</span>
            </button>
          ))}
        </div>
      </div>

      {tab === "secrets" && (
        <div className="card" style={{borderTopLeftRadius:0,borderTopRightRadius:0,borderTop:"none"}}>
          {secrets.loading ? <PageLoading/> : secrets.error ? <PageError error={secrets.error}/> :
            secrets.data?.length === 0 ? <div className="empty"><div className="empty-title">no JS secrets</div></div> :
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th style={{width:60}}>Sev</th><th>Type</th><th>Value</th><th>Source</th></tr></thead>
                <tbody>
                  {(secrets.data || []).map((s, i) => (
                    <tr key={i} style={{verticalAlign:"top"}}>
                      <td><SeverityPill sev={s.severity || "info"}/></td>
                      <td className="dim">{s.type || "—"}</td>
                      <td><ExpandableValue value={s.value || "—"}/></td>
                      <td className="url" style={{maxWidth:340,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{s.filename || s.source || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          }
        </div>
      )}

      {tab === "endpoints" && (
        <div className="card" style={{borderTopLeftRadius:0,borderTopRightRadius:0,borderTop:"none"}}>
          {endpoints.loading ? <PageLoading/> : endpoints.error ? <PageError error={endpoints.error}/> :
            endpoints.data?.length === 0 ? <div className="empty"><div className="empty-title">no endpoints found</div></div> :
            <div className="table-wrap" style={{maxHeight:"calc(100vh - 320px)",overflowY:"auto"}}>
              <table className="data">
                <thead><tr><th style={{width:80}}>Method</th><th>Endpoint</th><th>Source</th></tr></thead>
                <tbody>
                  {(endpoints.data || []).map((e, i) => (
                    <tr key={i}>
                      <td className="mono dim">{e.method || "GET"}</td>
                      <td className="url">{e.value || "—"}<CopyButton text={e.value || ""}/></td>
                      <td className="url" style={{maxWidth:380,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{e.source || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          }
        </div>
      )}

      {tab === "files" && (
        <div className="card" style={{borderTopLeftRadius:0,borderTopRightRadius:0,borderTop:"none"}}>
          {files.loading ? <PageLoading/> : files.error ? <PageError error={files.error}/> :
            files.data?.length === 0 ? <div className="empty"><div className="empty-title">no JS files indexed</div></div> :
            <div className="table-wrap" style={{maxHeight:"calc(100vh - 320px)",overflowY:"auto"}}>
              <table className="data">
                <thead><tr><th className="ridx">#</th><th>URL</th><th style={{width:60}}/></tr></thead>
                <tbody>
                  {(files.data || []).map((f, i) => (
                    <tr key={i}>
                      <td className="ridx">{String(i+1).padStart(4,"0")}</td>
                      <td className="url"><a href={f.url} target="_blank" rel="noopener">{f.url}</a></td>
                      <td><CopyButton text={f.url}/></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          }
        </div>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// ATTACK SURFACE
// ──────────────────────────────────────────────────────────────────────
// PageAttackSurface — grid of per-host identity cards.
// Cross-target view : feeds from /api/attack-surface/hosts (enriched).
// Org scope is driven by the sidebar `currentOrg` selector (prop) — no
// duplicate filter in this page's toolbar. Local search filters the
// currently-loaded host list (host / url / title / apex / tech).
// Scope toggle : All / In-scope / Orphans — surfaces shadow IT detection
// from shared-apex scans (gouv.bj → ministerial subs auto-attributed,
// orphans bubble up here for analyst review).
function PageAttackSurface({ data, currentOrg }) {
  const [search,  setSearch]  = uxS("");
  const [hosts,   setHosts]   = uxS([]);
  const [loading, setLoading] = uxS(false);
  const [error,   setError]   = uxS(null);
  // 'all' = attribués + orphans · 'inscope' = attribués seuls · 'orphans' = sans org
  const [scope, setScope] = uxS(() => {
    try { return localStorage.getItem("argus.surface.scope") || "all"; }
    catch (_) { return "all"; }
  });
  uxE(() => {
    try { localStorage.setItem("argus.surface.scope", scope); } catch (_) {}
  }, [scope]);

  const reload = uxC(() => {
    let alive = true;
    setLoading(true); setError(null);
    // When the user is filtering on a specific org, orphans aren't relevant
    // (an orphan by definition has no org). Otherwise honor the toggle.
    const wantOrphans = !currentOrg && (scope === "all" || scope === "orphans");
    window.ArgusAPI.attackSurface.hosts(currentOrg || null,
                                        { includeOrphans: wantOrphans })
      .then(rows => { if (alive) setHosts(rows || []); })
      .catch(e => { if (alive) setError(String(e.message || e)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [currentOrg, scope]);
  uxE(() => { reload(); }, [reload]);

  const cards = uxM(() => {
    let rows = hosts;
    // 'orphans' mode : restreint à attributed_apex IS NULL côté client
    // (le backend retourne all + orphans en mode "all", on filtre ici).
    if (!currentOrg && scope === "orphans") {
      rows = rows.filter(h => h.is_orphan);
    }
    const q = search.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter(h =>
      (h.host  || "").toLowerCase().includes(q) ||
      (h.url   || "").toLowerCase().includes(q) ||
      (h.title || "").toLowerCase().includes(q) ||
      (h.apex  || "").toLowerCase().includes(q) ||
      (h.tech  || []).some(t => t.toLowerCase().includes(q))
    );
  }, [hosts, search, scope, currentOrg]);

  // Counts for the toggle pill — derived from the full host list
  const counts = uxM(() => ({
    all:     hosts.length,
    inscope: hosts.filter(h => !h.is_orphan).length,
    orphans: hosts.filter(h => h.is_orphan).length,
  }), [hosts]);

  return (
    <div className="page">
      <PageHeader
        eyebrow={`SECURITY · ATTACK SURFACE${currentOrg ? ` · ${currentOrg}` : ""}`}
        title="Attack Surface"
        lede={
          loading
            ? "loading inventory…"
            : `${cards.length} hosts · per-host identity card with findings + tech`
        }/>

      <div className="filter-bar">
        <div className="search-input">
          <span className="prompt">$</span>
          <input placeholder="filter host..." value={search}
                 onChange={e => setSearch(e.target.value)}/>
        </div>

        {/* Scope toggle — disabled when an org is already active in sidebar */}
        {!currentOrg && (
          <div className="surface-scope-toggle">
            <button className={`surface-scope-tab ${scope === "all"     ? "active" : ""}`}
                    onClick={() => setScope("all")}
                    title="Show every host">
              all <span className="surface-scope-count">{counts.all}</span>
            </button>
            <button className={`surface-scope-tab ${scope === "inscope" ? "active" : ""}`}
                    onClick={() => setScope("inscope")}
                    title="Hosts attributed to a declared organisation">
              in-scope <span className="surface-scope-count">{counts.inscope}</span>
            </button>
            <button className={`surface-scope-tab ${scope === "orphans" ? "active" : ""}`}
                    onClick={() => setScope("orphans")}
                    title="Hosts with no matching apex in `targets` — shadow IT signal">
              orphans <span className="surface-scope-count">{counts.orphans}</span>
            </button>
          </div>
        )}

        <button className="cmd-btn" onClick={reload} disabled={loading}
                title="Reload inventory">
          <Icon name="refresh" size={12}/>
        </button>
        <div className="result-count">
          <span className="accent">{cards.length}</span> hosts
        </div>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))",
        gap: 14,
      }}>
        {cards.map((h, i) => {
          const counts = h.findings_by_severity || {};
          const hasFindings = !!(counts.critical || counts.high || counts.medium || counts.low);
          return (
            <div key={`${h.host}::${i}`} className="card"
                 style={{padding: 14, display: "flex", flexDirection: "column", gap: 10}}>
              <div style={{display: "flex", alignItems: "center", gap: 8, minWidth: 0}}>
                <StatusBadge code={h.status}/>
                <div style={{flex: 1, minWidth: 0}}>
                  <div className="mono" style={{
                    fontSize: 12, color: "var(--text)",
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  }}>{h.url || h.host}</div>
                  {h.title && (
                    <div style={{
                      fontSize: 11, color: "var(--text-muted)",
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    }}>{h.title}</div>
                  )}
                </div>
              </div>

              {h.org && !currentOrg && (
                <div className="mono" style={{
                  fontSize: 10, color: "var(--text-faint)",
                  letterSpacing: "0.06em", textTransform: "uppercase",
                }}>
                  {h.org}
                </div>
              )}

              {h.is_orphan && !currentOrg && (
                <div className="surface-orphan-badge"
                     title={`No matching apex in 'targets'. Add to data/constituents.csv and re-run import_data.py to attribute future scans of ${h.host} to an organisation.`}>
                  <Icon name="alert-triangle" size={10}/>
                  <span>unattributed · shadow IT</span>
                </div>
              )}

              <div style={{display: "flex", flexWrap: "wrap", gap: 4}}>
                {(h.tech || []).slice(0, 6).map((t, j) =>
                  <span key={j} className="tech-chip">{t}</span>
                )}
                {h.waf && (
                  <span className="pill pill-sev-low" style={{fontSize: 10}}>
                    <Icon name="shield" size={10}/>{h.waf}
                  </span>
                )}
              </div>

              {hasFindings ? (
                <div style={{display: "flex", gap: 6, flexWrap: "wrap"}}>
                  {SEV_ORDER.map(s => counts[s]
                    ? <SeverityPill key={s} sev={s} count={counts[s]}/>
                    : null)}
                </div>
              ) : (
                <div style={{
                  fontSize: 10, color: "var(--text-faint)",
                  fontFamily: "var(--font-mono)",
                  textTransform: "uppercase", letterSpacing: "0.08em",
                }}>no findings</div>
              )}

              {h.cname && (
                <div className="mono" style={{
                  fontSize: 10, color: "var(--text-faint)",
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>cname: {h.cname}</div>
              )}
            </div>
          );
        })}

        {cards.length === 0 && (
          <div className="empty" style={{gridColumn: "1/-1"}}>
            <div className="empty-title">
              {loading
                ? "loading…"
                : (search || currentOrg
                    ? "no hosts match the current filters"
                    : "no hosts — launch a scan to populate")}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}


// ──────────────────────────────────────────────────────────────────────
// GF PATTERNS
// ──────────────────────────────────────────────────────────────────────
function PageGFPatterns({ data }) {
  const cats = useLazy(data.target, window.ArgusAPI.lazy.gfCats);
  const [selected, setSelected] = uxS(null);
  const results = uxS({ loading: false, data: null, error: null });
  const [resState, setResState] = results;

  uxE(() => {
    if (!selected) return;
    setResState({ loading: true, data: null, error: null });
    window.ArgusAPI.lazy.gfResults(data.target, selected)
      .then(r => setResState({ loading: false, data: r.urls || [], error: null }))
      .catch(e => setResState({ loading: false, data: null, error: String(e) }));
  }, [selected, data.target]);

  return (
    <div className="page">
      <PageHeader eyebrow="SECURITY · PATTERNS" title="GF Patterns"
        lede={`${cats.data?.length || 0} categories · click a tile to inspect URLs`}/>
      {cats.loading && <PageLoading/>}
      {cats.error && <PageError error={cats.error}/>}
      {!cats.loading && !cats.error && (
        <>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(180px,1fr))",gap:10,marginBottom:14}}>
            {(cats.data || []).map(c => (
              <div key={c.category} className="card"
                style={{
                  padding:14,cursor:"pointer",
                  borderColor: selected === c.category ? "var(--accent)" : undefined,
                  background: selected === c.category ? "var(--accent-soft)" : undefined,
                }}
                onClick={() => setSelected(c.category)}>
                <div className="mono" style={{fontSize:10,color:"var(--text-faint)",textTransform:"uppercase",letterSpacing:"0.1em"}}>gf:{c.category}</div>
                <div className="stat-value-v2" style={{fontSize:24,marginTop:4}}>{c.count}</div>
              </div>
            ))}
            {(cats.data || []).length === 0 && <div className="empty" style={{gridColumn:"1/-1"}}><div className="empty-title">no patterns matched</div></div>}
          </div>

          {selected && (() => {
            // Build a [{url, evidence, confidence, severity}] list:
            //   1. Take the URL list from the GF endpoint (gf_*.txt) so we
            //      always show the same set the user expects per category.
            //   2. Enrich each URL with the matching M07 finding (confidence,
            //      evidence, severity) via a (pattern, url) index.
            const findingsIdx = {};
            (data.findings || []).forEach(f => {
              if (f.moduleSource !== "m12") return;
              // m12 stores patterns as `gf:<cat>` in metadata, but `selected`
              // is the bare category from the gf_<cat>.txt filename. Strip
              // the `gf:` prefix before comparing so the index actually fills.
              const pat = (f.metadata && f.metadata.pattern) || "";
              const patStripped = pat.startsWith("gf:") ? pat.slice(3) : pat;
              if (patStripped !== selected) return;
              if (f.url && !findingsIdx[f.url]) findingsIdx[f.url] = f;
            });
            const urls = resState.data || [];
            const rows = urls.length > 0
              ? urls.map(u => ({ url: u, finding: findingsIdx[u] }))
              : Object.values(findingsIdx).map(f => ({ url: f.url, finding: f }));

            return (
              <div className="card">
                <div className="card-header">
                  <div className="card-title">gf:{selected}</div>
                  <div className="card-subtitle">// {rows.length} matches · click row to copy match</div>
                </div>
                {resState.loading ? <PageLoading/> :
                 resState.error ? <PageError error={resState.error}/> :
                 rows.length === 0 ? <div className="empty"><div className="empty-title">no matches</div></div> :
                 <div className="table-wrap" style={{maxHeight:"calc(100vh - 480px)",overflowY:"auto"}}>
                   <table className="data">
                     <thead><tr>
                       <th className="ridx">#</th>
                       <th style={{width:80}}>Sev</th>
                       <th>URL</th>
                       <th>Match</th>
                     </tr></thead>
                     <tbody>
                       {rows.map((r, i) => {
                         const f = r.finding;
                         const sev = f?.severity || "info";
                         return (
                           <tr key={i} style={{verticalAlign:"top"}}>
                             <td className="ridx">{String(i+1).padStart(4,"0")}</td>
                             <td><SeverityPill sev={sev} count={null}/></td>
                             <td className="url" style={{maxWidth:"45vw"}}>
                               <a href={r.url} target="_blank" rel="noopener noreferrer">{r.url}</a>
                               <CopyButton text={r.url}/>
                             </td>
                             <td><ExpandableValue value={f?.evidence || "(no body match recorded)"}/></td>
                           </tr>
                         );
                       })}
                     </tbody>
                   </table>
                 </div>
                }
              </div>
            );
          })()}
        </>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// TAKEOVERS
// ──────────────────────────────────────────────────────────────────────
function PageTakeovers({ data }) {
  const { loading, data: list, error } = useLazy(data.target, window.ArgusAPI.lazy.takeovers);
  return (
    <div className="page">
      <PageHeader eyebrow="SECURITY · TAKEOVER" title="Subdomain Takeovers"
        lede={`${list?.length || 0} candidates · subzy + custom CNAME analysis`}/>
      {loading && <PageLoading/>}
      {error && <PageError error={error}/>}
      {!loading && !error && (
        <div className="card">
          {list?.length === 0 ? (
            <div className="empty" style={{padding:"60px 20px"}}>
              <div className="empty-icon" style={{color:"var(--solid)"}}><Icon name="shield" size={40}/></div>
              <div className="empty-title">all clean</div>
              <div className="empty-msg">No takeover candidates detected on this target.</div>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead><tr>
                  <th className="ridx">#</th>
                  <th>Subdomain</th>
                  <th>Service</th>
                  <th>CNAME</th>
                  <th style={{width:80}}>Conf.</th>
                  <th>Evidence</th>
                </tr></thead>
                <tbody>
                  {(list || []).map((t, i) => (
                    <tr key={i}>
                      <td className="ridx">{String(i+1).padStart(3,"0")}</td>
                      <td className="url">{t.subdomain || t.target || t.url || "—"}<CopyButton text={t.subdomain || t.target || ""}/></td>
                      <td><span className="pill pill-sev-high"><span className="dot"/>{t.service || t.engine || "?"}</span></td>
                      <td className="mono dim">{t.cname || "—"}</td>
                      <td className="mono num">{(t.confidence ?? 0).toFixed(2)}</td>
                      <td className="evidence">{t.evidence || t.match || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// EMAIL SECURITY
// ──────────────────────────────────────────────────────────────────────
function PageEmailSecurity({ data }) {
  const { loading, data: list, error } = useLazy(data.target, window.ArgusAPI.lazy.email);
  return (
    <div className="page">
      <PageHeader eyebrow="SECURITY · EMAIL" title="Email Security"
        lede={`SPF · DKIM · DMARC · ${data.target}`}/>
      {loading && <PageLoading/>}
      {error && <PageError error={error}/>}
      {!loading && !error && (
        <div className="card">
          {list?.length === 0 ? (
            <div className="empty">
              <div className="empty-icon" style={{color:"var(--solid)"}}><Icon name="shield" size={40}/></div>
              <div className="empty-title">configuration nominal</div>
              <div className="empty-msg">No email-security issues detected.</div>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead><tr>
                  <th className="ridx">#</th>
                  <th style={{width:90}}>Severity</th>
                  <th style={{width:140}}>Check</th>
                  <th>Title</th>
                  <th>Evidence</th>
                </tr></thead>
                <tbody>
                  {(list || []).map((e, i) => (
                    <tr key={i}>
                      <td className="ridx">{String(i+1).padStart(2,"0")}</td>
                      <td><SeverityPill sev={e.severity || "info"}/></td>
                      <td className="dim mono">{e.check || "—"}</td>
                      <td>{e.title || "—"}</td>
                      <td className="evidence"><span className="ev-text">{e.evidence || "—"}</span><CopyButton text={e.evidence || ""}/></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// API SPECS
// ──────────────────────────────────────────────────────────────────────
function PageAPISpecs({ data }) {
  const { loading, data: list, error } = useLazy(data.target, window.ArgusAPI.lazy.apiSpecs);
  return (
    <div className="page">
      <PageHeader eyebrow="SECURITY · API SPECS" title="Exposed API Specs"
        lede="OpenAPI · Swagger · GraphQL · introspection"/>
      {loading && <PageLoading/>}
      {error && <PageError error={error}/>}
      {!loading && !error && (
        <div className="card">
          {!list || list.length === 0 ? (
            <div className="empty">
              <div className="empty-icon"><Icon name="plug" size={40}/></div>
              <div className="empty-title">no specs found</div>
              <div className="empty-msg">No OpenAPI / GraphQL endpoints leaked.</div>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead><tr>
                  <th className="ridx">#</th>
                  <th>URL</th>
                  <th style={{width:120}}>Type</th>
                  <th style={{width:80}}>Status</th>
                </tr></thead>
                <tbody>
                  {list.map((s, i) => (
                    <tr key={i}>
                      <td className="ridx">{String(i+1).padStart(2,"0")}</td>
                      <td className="url"><a href={s.url} target="_blank" rel="noopener">{s.url}</a><CopyButton text={s.url}/></td>
                      <td className="dim">{s.type || "—"}</td>
                      <td>{s.status_code ? <StatusBadge code={s.status_code}/> : <span className="dim">—</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// ACTIVE VALIDATION (M09)
// ──────────────────────────────────────────────────────────────────────
function PageActive({ data }) {
  const { loading, data: list, error } = useLazy(data.target, window.ArgusAPI.lazy.active);
  const [sourceFilter, setSourceFilter] = uxS("all");

  // Build a unified row schema from two sources:
  //   - M09 active_findings.json   → confirmed XSS/SQLi/redirect/file exposure
  //   - M08 nuclei_findings.json   → already in data.findings, module_source='m13'
  // Both belong on this page since they're the "active testing" output.
  const rows = uxM(() => {
    const out = [];
    (list || []).forEach(f => {
      let cls, sev, detail;
      if (f.payload || f.type === "XSS")          { cls = "XSS";           sev = "high";     detail = `param=${f.param || "—"}`; }
      else if (f.dbms)                            { cls = "SQLi";          sev = "critical"; detail = f.dbms; }
      else if (f.final_location)                  { cls = "Open Redirect"; sev = "medium";   detail = `param=${f.param}`; }
      else if (f.path)                            { cls = "File Exposure"; sev = (f.severity || "medium"); detail = f.path; }
      else                                        { cls = "Active";        sev = "medium";   detail = "—"; }
      out.push({
        source:    "m14",
        cls,
        sev,
        url:       f.url || "",
        detail,
        title:     f.path || f.param || cls,
        evidence:  (f.payload || f.final_location || f.evidence || "").toString(),
      });
    });
    (data.findings || []).forEach(f => {
      // m13 nuclei + m07 port-scan findings (SERVICE_EXPOSED / ORIGIN_IP_LEAK)
      // both belong on the Active page — they're the outcome of active probes.
      // m14 findings come from the dedicated lazy endpoint above; skip here
      // to avoid double-counting if they ever land in data.findings too.
      const src = f.moduleSource;
      if (src !== "m13" && src !== "m07") return;
      if (src === "m13") {
        const tpl = f.metadata?.template_id || "";
        out.push({
          source:    "m13",
          cls:       "Nuclei",
          sev:       f.severity || "info",
          url:       f.url || f.target || "",
          detail:    tpl || f.rawType,
          title:     f.title,
          evidence:  f.evidence || "",
        });
      } else {
        // m07
        const meta = f.metadata || {};
        const isLeak = (f.rawType || f.type) === "origin_ip_leak";
        out.push({
          source:    "m07",
          cls:       isLeak ? "Origin IP Leak" : "Port/Service",
          sev:       f.severity || "info",
          url:       f.url || f.target || "",
          detail:    meta.port
            ? `${meta.service || "service"}/${meta.port}`
            : (meta.ip || "—"),
          title:     f.title,
          evidence:  f.evidence || "",
        });
      }
    });
    return out;
  }, [list, data.findings]);

  const groups = uxM(() => {
    const g = { all: rows.length, m14: 0, m13: 0, m07: 0,
                xss: 0, sqli: 0, redirect: 0, file: 0, nuclei: 0,
                port: 0, originleak: 0 };
    rows.forEach(r => {
      if (r.source === "m14") g.m14++;
      if (r.source === "m13") g.m13++;
      if (r.source === "m07") g.m07++;
      if (r.cls === "Port/Service")       g.port++;
      else if (r.cls === "Origin IP Leak") g.originleak++;
      if (r.cls === "XSS")           g.xss++;
      else if (r.cls === "SQLi")     g.sqli++;
      else if (r.cls === "Open Redirect") g.redirect++;
      else if (r.cls === "File Exposure") g.file++;
      else if (r.cls === "Nuclei")   g.nuclei++;
    });
    return g;
  }, [rows]);

  const filtered = uxM(() => {
    if (sourceFilter === "all") return rows;
    if (sourceFilter === "m14") return rows.filter(r => r.source === "m14");
    if (sourceFilter === "m13") return rows.filter(r => r.source === "m13");
    if (sourceFilter === "m07") return rows.filter(r => r.source === "m07");
    return rows;
  }, [rows, sourceFilter]);

  const isEmpty = !loading && !error && rows.length === 0;

  return (
    <div className="page">
      <PageHeader eyebrow="SECURITY · ACTIVE" title="Active Validation"
        lede={`${rows.length} signals — ${groups.m14} active confirmations (M09) · ${groups.m13} nuclei (M08) · ${groups.m07} ports/leaks (M11)`}/>
      {loading && <PageLoading label="loading active findings"/>}
      {error && <PageError error={error}/>}
      {isEmpty && (
        <div className="card">
          <div className="empty">
            <div className="empty-icon"><Icon name="lightning" size={40}/></div>
            <div className="empty-title">no active signals yet</div>
            <div className="empty-msg">Run h4wk3y3.py with --full (or include m13/m14) to populate.</div>
          </div>
        </div>
      )}
      {!loading && !error && rows.length > 0 && (
        <>
          <div className="stat-grid" style={{marginBottom:14}}>
            <div className="stat-card-v2">
              <div className="stat-label-v2">File Exposure</div>
              <div className="stat-value-v2">{groups.file}</div>
            </div>
            <div className="stat-card-v2">
              <div className="stat-label-v2">Open Redirect</div>
              <div className="stat-value-v2">{groups.redirect}</div>
            </div>
            <div className="stat-card-v2">
              <div className="stat-label-v2">XSS</div>
              <div className="stat-value-v2" style={{color:"var(--sev-high)"}}>{groups.xss}</div>
            </div>
            <div className="stat-card-v2">
              <div className="stat-label-v2">SQLi</div>
              <div className="stat-value-v2" style={{color:"var(--sev-critical)"}}>{groups.sqli}</div>
            </div>
            <div className="stat-card-v2">
              <div className="stat-label-v2">Nuclei (M08)</div>
              <div className="stat-value-v2">{groups.nuclei}</div>
            </div>
            <div className="stat-card-v2">
              <div className="stat-label-v2">Ports / IP Leak</div>
              <div className="stat-value-v2">{groups.port + groups.originleak}</div>
            </div>
          </div>

          <div className="filter-bar">
            <div className="filter-group">
              {[["all","All"],["m14","M09 Active"],["m13","M08 Nuclei"],["m07","M11 Ports"]].map(([k,l]) => (
                <button key={k} className={`filter-chip ${sourceFilter === k ? "active" : ""}`} onClick={() => setSourceFilter(k)}>
                  {l}<span className="num">{groups[k] ?? 0}</span>
                </button>
              ))}
            </div>
            <div className="result-count"><span className="accent">{filtered.length}</span> / {rows.length}</div>
          </div>

          <div className="card" style={{borderTopLeftRadius:0,borderTopRightRadius:0,borderTop:"none"}}>
            <div className="table-wrap">
              <table className="data">
                <thead><tr>
                  <th className="ridx">#</th>
                  <th style={{width:90}}>Severity</th>
                  <th style={{width:120}}>Class</th>
                  <th>Title / URL</th>
                  <th>Detail</th>
                  <th>Evidence</th>
                </tr></thead>
                <tbody>
                  {filtered.map((r, i) => (
                    <tr key={i} style={{verticalAlign:"top"}}>
                      <td className="ridx">{String(i+1).padStart(3,"0")}</td>
                      <td><SeverityPill sev={r.sev} count={null}/></td>
                      <td className="dim">{r.cls}</td>
                      <td>
                        <div style={{fontWeight:500}}>{r.title}</div>
                        {r.url && (
                          <div className="url" style={{fontSize:11,marginTop:2}}>
                            <a href={r.url} target="_blank" rel="noopener noreferrer">{r.url}</a>
                            <CopyButton text={r.url}/>
                          </div>
                        )}
                      </td>
                      <td className="dim mono" style={{fontSize:10.5}}>{r.detail || "—"}</td>
                      <td><ExpandableValue value={r.evidence || "—"}/></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// DOCS — handbook (pipeline, modules, finding types, CLI, troubleshooting)
// ──────────────────────────────────────────────────────────────────────
const DOCS_SECTIONS = [
  {
    id: "quickstart", title: "Quickstart", body: (
      <>
        <p>Argus is a modular web reconnaissance framework. From the CLI:</p>
        <pre>$ ./run.sh -t example.com{"\n"}$ ./run.sh -t example.com --modules m13{"\n"}$ ./run.sh -t example.com --stealth -v</pre>
        <p>Storage is hybrid: <strong>structured data</strong> (findings, scans, subdomains, live hosts, users, audit) → Postgres (see <code>general.db_url</code>); <strong>blobs &amp; module artefacts</strong> (screenshots, HTML bodies, JS files, raw nuclei stdout) → <code>output/&lt;domain&gt;/</code>. Findings JSON files in <code>output/</code> are an export (projection of the DB), not the source of truth. Toggle via <code>general.export_json_artefacts: false</code> for large scans.</p>
        <p>The dashboard you're looking at lazy-loads each module's artefact files; nothing is recomputed from the UI.</p>
      </>
    ),
  },
  {
    id: "pipeline", title: "Pipeline architecture", body: (
      <>
        <p>14 modules in a staged pipeline with parallelism where dependencies allow:</p>
        <pre>{`( m01 osint ║ m02 subs )                                       ← pre-stage
   ↓
m03 (http validate, tech)
   ↓
( m04 urls ║ m05 shots ║ m06 takeover ║ m07 ports ║ m08 tls ║ m09 quick )  ← parallel
   ↓
m10 (fetch bodies + headers, optionally extra m04 URLs)
   ↓
m11 (JS secrets, sourcemaps)
   ↓
( m12 patterns ║ m13 nuclei )                                   ← parallel
   ↓
m14 (active validation: dalfox, sqlmap, file exposure)`}</pre>
        <p>Each parallel group is bound by an <code>asyncio.gather</code>; the pipeline blocks until the slowest member finishes before moving on.</p>
      </>
    ),
  },
  {
    id: "modules", title: "Modules", body: (
      <>
        {[
          ["m01", "OSINT", "WHOIS / RDAP + SPF/DMARC/DKIM lookup + trufflehog GitHub org (GITHUB_TOKEN required) + HIBP domain breach (HIBP_API_KEY required). Pre-stage, runs in parallel with m02 (target.domain only — no deps).", "osint.json"],
          ["m02", "Subdomain Enumeration", "6 passive sources (subfinder, assetfinder, findomain, crtsh+24h cache, certspotter, chaos) + optional active (shuffledns + alterx, off by default). Scope-filtered: subs that match the apex string but fall outside scopes/<apex>.yaml are dropped before being persisted.", "subdomains.json, dns_records.json, enum_stats.json"],
          ["m03", "HTTP Validator + Tech", "httpx-toolkit probe → live hosts with status, title, server, technologies, WAF, CORS, favicon hash (mmh3), redirect chain. Detects missing security headers / cookie flags (via http.cookies.SimpleCookie) / .well-known endpoints. Defence-in-depth scope filter pre-httpx.", "live_hosts.{txt,json}, tech_report.json, unreachable.json"],
          ["m04", "URL Collector", "Passive (gau: Wayback + CommonCrawl + AlienVault + URLScan) + active (katana JS-aware crawler) running in parallel. URO-deduped, capped 5k/domain. URLs passed through scope filter before being emitted downstream.", "urls_all.txt, urls_live.txt, api_specs.json"],
          ["m05", "Screenshots", "Playwright headless captures of each live host. Used for visual triage. Hardened: ctx initialised before browser.new_context() so an early failure doesn't crash the cleanup path.", "screenshots/*.png + thumbnails/"],
          ["m06", "Subdomain Takeover", "CNAME-based takeover detection (90+ providers) + nuclei takeovers + NS delegation analysis. Light, runs in 15s typically.", "takeovers.json"],
          ["m07", "Ports & CDN", "rustscan top-1000 TCP scan (5-10× faster than naabu, fallback to naabu then TCP-connect probe) → nmap -sV banner on a budget of 100 ports (-T2 default, -T1 under --stealth, never -T4) + cdncheck origin/CDN classification. Strict scope filter on IPs+hosts before any packet leaves. Emits SERVICE_EXPOSED + ORIGIN_IP_LEAK.", "ports.json"],
          ["m08", "TLS Audit", "testssl.sh on HTTPS live hosts (capped to 10 by default — testssl is slow). Skipped under --stealth unless tls.run_under_stealth=true is set. Scope filter pre-testssl. Reports weak ciphers/protocols, cert expiry, HSTS missing.", "tls_summary.json, tls/*.json"],
          ["m09", "Quick Checks", "5 atomic high-signal checks per live host: GraphQL introspection, .git/HEAD + config exposure, .env exposure (KEYS-only evidence, never VALUES, body sha256 for correlation), JWT decode (alg=none / no exp / kid path-inj / jku-x5u — token stored as sha256 + claim NAMES, never the token itself), cloud bucket world-readable list. Scope-filtered including cloud-bucket candidates.", "quick_checks.json"],
          ["m10", "Body & Headers Fetcher", "Re-fetches each live host (and optionally interesting M04 URLs, capped at 800 by default) to capture body + full headers — feeds m11/m12. body_snippet kept full by default (so m11/m12 see deep patterns); set fetcher.snippet_max_kb to cap if bodies_snippets.json grows too large.", "fetch_results.json, bodies_snippets.json, headers.json"],
          ["m11", "JS Analyzer", "Discovers JS files (script src, .js URLs, common bundle paths on JS-using hosts only) → fetches → regex-extracts secrets (JWT, API keys, AWS creds, GitHub tokens), endpoints, sourcemaps. CDN/lib files filtered out. JWT claims marked signature_verified=False (we don't have the signing key) — sensitive-role claims downgraded from CRITICAL to HIGH with confidence 0.65 + tag 'unverified-signature'.", "js_files.txt, js_secrets.json, js_endpoints.json, js_bodies.json"],
          ["m12", "Pattern Analysis", "gf-style regex patterns over URLs, headers, bodies, JS bodies (from m10/m11). 42 patterns: SQLi/XSS/SSRF/RCE candidates, secrets, debug pages, internal IPs, stack traces, etc. Scope-filtered, dedup-aware via fingerprint+evidence.", "patterns.json, gf_*.txt, reflected_params.json"],
          ["m13", "Nuclei", "Surface-only profile: http/misconfiguration + http/exposures only (~2300 templates, down from ~4500). CVE / default-login / intrusive tags excluded by exclude_tags — that's not the role of this stage. Tech-targeted tags (wordpress, apache, …) are intersected with exclude_tags so techs only get their non-CVE templates. Rate-limit auto-capped to 5 r/s under WAF / --stealth. Per-module timeout 1800s (config: nuclei.module_timeout_sec).", "nuclei_findings.json, nuclei_stderr.log"],
          ["m14", "Active Validation", "Confirms candidates via active probes: file exposure (strict fingerprints, soft-404 detection with 3 buckets: clean/soft/errored), open redirect (canary), dalfox XSS, sqlmap (level=1 risk=1, --threads=1 under stealth). XSS/SQLi candidates re-filtered through scope at load. SENSITIVE_PATHS redacts secret content via sha256+keys-only metadata. .env coverage is shared with m09 — atomic dedup collapses dupes (see Dedup section).", "active_findings.json, dalfox_results.json, sqlmap/"],
        ].map(([id, name, desc, files]) => (
          <div key={id} style={{borderTop:"1px dashed var(--border)", padding:"10px 0"}}>
            <div style={{fontFamily:"var(--font-mono)", fontSize:11, color:"var(--accent)", letterSpacing:"0.1em"}}>{id.toUpperCase()} · {name}</div>
            <p style={{margin:"6px 0", lineHeight:1.5}}>{desc}</p>
            <div style={{fontSize:10.5, color:"var(--text-faint)"}}>output: <code>{files}</code></div>
          </div>
        ))}
      </>
    ),
  },
  {
    id: "findings", title: "Finding types", body: (
      <>
        <p>Findings unify signals from all modules. Each has a <code>severity</code>, <code>status</code> (solid/candidate), <code>module_source</code> and free-form <code>tags</code>.</p>
        <table className="data" style={{marginTop:10}}>
          <thead><tr><th>Type</th><th>Source</th><th>Meaning</th></tr></thead>
          <tbody>
            {[
              ["SUBDOMAIN", "m02", "Discovered subdomain (info)"],
              ["DOMAIN_INFO", "m01", "WHOIS metadata (registrar, dates, NS)"],
              ["EMAIL_SPOOFABLE", "m01", "Missing/weak SPF, DMARC, or DKIM record"],
              ["BREACHED_CREDENTIAL", "m01", "HIBP returned emails in known breaches"],
              ["GIT_SECRET", "m01", "trufflehog verified secret in a GitHub org repo"],
              ["LIVE_HOST", "m03", "Reachable HTTP/HTTPS endpoint"],
              ["MISCONFIGURATION", "m03", "Security header missing / cookie flags / staging exposure"],
              ["URL", "m04", "Interesting URL (API spec, secrets ext, sensitive params)"],
              ["JS_SECRET", "m11", "Hardcoded credential found in JS"],
              ["JS_VULNERABILITY", "m11", "Dangerous JS pattern (eval, postmessage *, etc.)"],
              ["JS_ENDPOINT", "m11", "API endpoint extracted from JS"],
              ["SUBDOMAIN_TAKEOVER", "m06", "Takeover candidate (CNAME pointing to claimable cloud resource)"],
              ["SERVICE_EXPOSED", "m07", "Non-web service (mysql/redis/...) exposed on a public IP"],
              ["ORIGIN_IP_LEAK", "m07", "CDN-fronted host whose origin IP is reachable directly"],
              ["TLS_WEAK", "m08", "testssl.sh flagged weak cipher / protocol"],
              ["TLS_CERT_ISSUE", "m08", "Cert expired / self-signed / hostname mismatch"],
              ["GRAPHQL_INTROSPECTION", "m09", "/graphql introspection enabled"],
              ["JWT_WEAKNESS", "m09", "JWT with alg=none / no exp / kid path-inj / jku-x5u"],
              ["CLOUD_BUCKET", "m09", "Public-readable S3/GCS/Azure/Firebase bucket"],
              ["ACTIVE_FILE_EXPOSURE", "m14/m09", "Confirmed file exposure (.git, .env, ...)"],
              ["PATTERN_MATCH", "m12", "Regex pattern matched (e.g. SQLi-suspect param)"],
              ["NUCLEI_FINDING", "m13", "Nuclei template matched"],
              ["ACTIVE_OPEN_REDIRECT", "m14", "Confirmed open-redirect (canary echoed in Location)"],
              ["ACTIVE_XSS", "m14", "Dalfox-confirmed XSS"],
              ["ACTIVE_SQLI", "m14", "sqlmap-confirmed SQLi"],
            ].map(([t, src, m]) => (
              <tr key={t}><td><code>{t}</code></td><td className="dim">{src}</td><td>{m}</td></tr>
            ))}
          </tbody>
        </table>
      </>
    ),
  },
  {
    id: "cli", title: "CLI flags", body: (
      <>
        <pre>{`./run.sh -t <domain>                    full pipeline (m01 → m14)
./run.sh -t <domain> --modules m13      single module
./run.sh -t <domain> --stealth          rate-limited, jitter on
./run.sh -t <domain> -v                 verbose log to stdout
./run.sh -t <domain> --notify           push critical+ to Discord/Slack
./run.sh --dashboard                    start dashboard server only

# Org management
argus org add <name> [--h1 <handle>]
argus org link <apex> <org-name>
argus org show <name>

# Restore a scan from disk (handy after accidental DB wipe — re-imports
# subdomains.txt + live_hosts.json + findings.json into the DB)
python scripts/restore_from_json.py <domain>`}</pre>
        <p>Module IDs accepted by <code>--modules</code> (numeric, execution order): m01..m14.</p>
      </>
    ),
  },
  {
    id: "dedup", title: "Dedup & defense-in-depth", body: (
      <>
        <p>Findings are dedup'd at save time by a fingerprint. Two layers:</p>
        <ol style={{lineHeight:1.7}}>
          <li><strong>Standard fingerprint</strong> = <code>(domain, type, url, sha256(evidence))</code>. Re-running the same scan upserts in place. Two modules that detect the same problem with different wording produce different evidences → different fingerprints → 2 rows (legitimate when they're 2 distinct observations on the same URL).</li>
          <li><strong>ATOMIC fingerprint</strong> — for safety-critical types where <code>(domain, type, url)</code> IS the identity (the evidence is just wording), the evidence component is dropped from the hash. Same URL = same fingerprint regardless of which module wrote it. The first writer's evidence/title/severity is preserved; subsequent modules are recorded in <code>metadata.detected_by</code>.</li>
        </ol>
        <p>Atomic types (defined in <code>core/database.py:ATOMIC_FINDING_TYPES</code>):</p>
        <pre>{`active_file_exposure   ← m09 + m14 both probe .env / .git / ...
cloud_bucket           ← m09 ; future modules
jwt_weakness           ← m09 ; m11 inspects JS tokens
subdomain_takeover     ← m06 ; nuclei templates
service_exposed        ← m07 ports (IP+port identity)
origin_ip_leak         ← m07 cdncheck
email_spoofable        ← m01 osint`}</pre>
        <p><strong>Why keep the redundancy at all?</strong> If m09 fails (network blip, scope-filter, swallowed exception), m14 still emits — the finding survives. Same in reverse. A single point of failure on these checks is worse than a duplicate row. The atomic dedup ensures defence-in-depth without polluting findings.json.</p>
        <p>Test coverage: <code>tests/test_database_advanced.py::TestAtomicDedup</code>.</p>
      </>
    ),
  },
  {
    id: "tooling", title: "External tooling", body: (
      <>
        <p>Argus shells out to a curated set of CLIs. All called via <code>asyncio.create_subprocess_exec</code> with per-call timeouts and per-module overall timeout (see <code>core/pipeline.py:_DEFAULT_TIMEOUTS</code>).</p>
        <table className="data" style={{marginTop:10}}>
          <thead><tr><th>Tool</th><th>Used by</th><th>What for</th></tr></thead>
          <tbody>
            {[
              ["subfinder",     "m02",     "passive subdomain enum (needs ~/.config/subfinder/provider-config.yaml for full coverage)"],
              ["assetfinder",   "m02",     "passive subdomain enum (no key)"],
              ["findomain",     "m02",     "passive subdomain enum (no key)"],
              ["chaos",         "m02",     "ProjectDiscovery (needs PDCP_API_KEY)"],
              ["certspotter",   "m02",     "CT-log API (free tier, no key)"],
              ["alterx",        "m02",     "subdomain permutations (active, off by default)"],
              ["shuffledns",    "m02",     "DNS brute (active, off by default)"],
              ["dnsx",          "m02",     "DNS records (A, CNAME, MX, TXT, SPF, DMARC)"],
              ["httpx-toolkit", "m03",     "HTTP probe + tech detection"],
              ["gau",           "m04",     "URLs from Wayback / CommonCrawl / AlienVault / URLScan"],
              ["katana",        "m04",     "JS-aware web crawler (PD)"],
              ["uro",           "m04",     "smart URL dedup"],
              ["Playwright",    "m05",     "Chromium headless screenshots"],
              ["nuclei",        "m13, m06", "template-based scanner (takeover for m06, surface profile for m13)"],
              ["jsluice",       "m11",     "JS endpoint & secret extraction"],
              ["sourcemapper",  "m11",     "extract TS sources from .map files"],
              ["rustscan",      "m07",     "primary port scanner — 5–10× faster than naabu"],
              ["naabu",         "m07",     "fallback port scanner if rustscan missing"],
              ["nmap -sV",      "m07",     "service version detection on open ports (-T2 / -T1 under stealth)"],
              ["cdncheck",      "m07",     "classify IPs as CDN or origin"],
              ["testssl.sh",    "m08",     "TLS audit (ciphers, cert, HSTS)"],
              ["dalfox",        "m14",     "XSS confirmation"],
              ["sqlmap",        "m14",     "SQLi confirmation (--level=1 --risk=1 --threads=1 under stealth)"],
              ["trufflehog",    "m01",     "GitHub org secret scanning"],
              ["arjun",         "m12",     "hidden parameter discovery"],
            ].map(([tool, mod, desc]) => (
              <tr key={tool}><td><code>{tool}</code></td><td className="dim">{mod}</td><td>{desc}</td></tr>
            ))}
          </tbody>
        </table>
        <p style={{marginTop:14}}>OPSEC defaults (CLAUDE.md): nuclei <code>-rate-limit 10</code> (auto-cap 5 under WAF or --stealth), nmap <code>-T2</code> (<code>-T1</code> under --stealth), sqlmap <code>--threads=1</code> under --stealth.</p>
      </>
    ),
  },
  {
    id: "tests", title: "Tests & DB safety", body: (
      <>
        <p>Tests live in <code>tests/</code> and use a shared <code>db</code> fixture that TRUNCATEs Argus tables between cases. Since dev runs on a single Postgres DB (<code>argus_main</code>), running pytest naively wipes real scan data. <code>tests/conftest.py</code> ships a three-layer guard:</p>
        <ol style={{lineHeight:1.7}}>
          <li><strong>Default</strong>: refuse to TRUNCATE if any scan_id NOT LIKE <code>test-%</code> exists. Print a clear message with restore + force-wipe options.</li>
          <li><strong>Bypass 1</strong>: <code>ARGUS_TEST_USE_PROD_DB=1</code> alone — still refused, the guard now also requires the count echo.</li>
          <li><strong>Bypass 2 (echo gate)</strong>: <code>ARGUS_TEST_USE_PROD_DB=1 ARGUS_TEST_CONFIRM_WIPE=&lt;N&gt;</code> where N is the EXACT current scan count. Proves the operator looked at the state before wiping.</li>
        </ol>
        <p>Restore after a wipe (one minute, no re-scan needed):</p>
        <pre>{`python scripts/restore_from_json.py una.bj
# re-imports subs + live_hosts + findings from output/<domain>/*.json`}</pre>
        <p>To keep tests truly non-destructive long-term, create a dedicated <code>argus_test</code> DB (requires CREATEDB on the argus PG user):</p>
        <pre>{`sudo -u postgres psql -c "CREATE DATABASE argus_test OWNER argus;"
export ARGUS_TEST_POSTGRES_URL="postgresql+psycopg://argus:argus_local_dev@127.0.0.1/argus_test"
pytest tests/         # routes to argus_test, never touches argus_main`}</pre>
      </>
    ),
  },
  {
    id: "troubleshooting", title: "Troubleshooting", body: (
      <>
        <ul style={{lineHeight:1.7}}>
          <li><strong>m02 finds 30% of expected subs</strong> — likely subfinder API keys missing. Edit <code>~/.config/subfinder/provider-config.yaml</code> (shodan, virustotal, github, securitytrails, censys keys).</li>
          <li><strong>m13 nuclei hits the 1800s module timeout</strong> — the target's throttling has slowed nuclei below 15 r/s. The pipeline logs <code>⏱ m13 hit module timeout after 1800s — aborted, scan continues</code> and m14 runs anyway. To extend: set <code>nuclei.module_timeout_sec</code> in argus.yaml. To narrow the template set: shrink <code>nuclei.always_run</code>.</li>
          <li><strong>m13 finishes in &lt; 5 s with 0 findings</strong> — DNS resolver throttled; check <code>output/&lt;domain&gt;/nuclei_stderr.log</code>. Bump <code>max_host_error</code> in config or pass explicit resolvers.</li>
          <li><strong>m14 reports tons of file exposures on one host</strong> — that host is soft-404 (200 + HTML on every path). M14's pre-flight canary classifies hosts in 3 buckets (clean/soft/errored) and skips the latter two; if noise still leaks through, the path's good_fp may be too loose — review <code>SENSITIVE_PATHS</code>.</li>
          <li><strong>Dashboard shows no live hosts</strong> — were they captured in <code>output/&lt;domain&gt;/live_hosts.json</code>? If yes, the DB query is the issue. The dashboard fan-outs <code>domain = apex OR LIKE '%.apex'</code> because <code>live_hosts.domain</code> stores the per-host hostname, not the apex.</li>
          <li><strong>Dashboard shows no data after a scan</strong> — check the scan actually committed. Most likely culprit: a pytest run wiped the DB. Restore via <code>python scripts/restore_from_json.py &lt;domain&gt;</code>.</li>
          <li><strong>"Refusing to run tests" message from pytest</strong> — the conftest guard caught real scan data in argus_main. Either back it up first, or use <code>ARGUS_TEST_USE_PROD_DB=1 ARGUS_TEST_CONFIRM_WIPE=&lt;N&gt;</code> where N is the current scan count (forces you to look). Long-term fix: dedicated <code>argus_test</code> DB (see "Tests & DB safety").</li>
          <li><strong>Duplicate-looking critical findings</strong> — pre-fix, the same <code>.env</code> exposure could surface twice (once from m09 quick_checks, once from m14 active validation) because their evidence wording differed. Now collapsed via atomic dedup; check <code>metadata.detected_by</code> to see all confirming modules.</li>
          <li><strong>Want to re-scan from scratch</strong> — purge: <code>rm -rf output/&lt;domain&gt;</code> + <code>psql -d argus_main -c "DELETE FROM findings WHERE domain='&lt;domain&gt;'"</code> (or click the trash icon on the domain card in the dashboard).</li>
        </ul>
      </>
    ),
  },
];

function PageDocs() {
  const [active, setActive] = uxS(DOCS_SECTIONS[0].id);
  uxE(() => {
    const onScroll = () => {
      // Find the section nearest the top of the viewport.
      let best = DOCS_SECTIONS[0].id;
      for (const s of DOCS_SECTIONS) {
        const el = document.getElementById("doc-" + s.id);
        if (el && el.getBoundingClientRect().top < 120) best = s.id;
      }
      setActive(best);
    };
    const wrap = document.querySelector(".docs-scroll");
    wrap && wrap.addEventListener("scroll", onScroll);
    return () => { wrap && wrap.removeEventListener("scroll", onScroll); };
  }, []);

  return (
    <div className="page">
      <PageHeader eyebrow="SYSTEM · DOCUMENTATION" title="Argus Handbook"
        lede="Pipeline, modules, finding types, CLI, troubleshooting"/>
      <div style={{display:"grid", gridTemplateColumns:"180px 1fr", gap:18, alignItems:"start"}}>
        <div className="card" style={{padding:14, position:"sticky", top:14, alignSelf:"start"}}>
          <div style={{fontFamily:"var(--font-mono)", fontSize:9.5, color:"var(--text-faint)", textTransform:"uppercase", letterSpacing:"0.14em", marginBottom:8}}>Contents</div>
          {DOCS_SECTIONS.map(s => (
            <div
              key={s.id}
              className="mono"
              onClick={() => {
                const el = document.getElementById("doc-" + s.id);
                el && el.scrollIntoView({behavior:"smooth", block:"start"});
              }}
              style={{
                padding:"6px 8px",
                fontSize:11,
                cursor:"pointer",
                borderRadius:3,
                color: active === s.id ? "var(--accent)" : "var(--text-dim)",
                background: active === s.id ? "var(--accent-soft)" : "transparent",
                marginBottom:2,
              }}
            >{s.title}</div>
          ))}
        </div>

        <div className="card docs-scroll" style={{padding:"22px 28px", maxHeight:"calc(100vh - 200px)", overflowY:"auto", lineHeight:1.6}}>
          {DOCS_SECTIONS.map(s => (
            <section key={s.id} id={"doc-" + s.id} style={{marginBottom:36}}>
              <h2 style={{fontSize:18, fontWeight:600, marginBottom:12, paddingBottom:8, borderBottom:"1px solid var(--border)", letterSpacing:"-0.01em"}}>{s.title}</h2>
              <div style={{fontSize:13, color:"var(--text-dim)"}}>{s.body}</div>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// CONFIG — typed forms per YAML section
// ──────────────────────────────────────────────────────────────────────
// Schema is declarative: each section = ordered list of fields with types.
// We don't try to render every YAML key automatically — that produces
// noisy, unlabelled UI. Instead, we curate which knobs the operator
// actually wants surfaced; advanced users keep editing the YAML file.
const CONFIG_SCHEMA = [
  {
    section: "general", title: "General",
    fields: [
      { key: "output_dir",    label: "Output directory",   type: "string", help: "Where per-domain artefacts are written." },
      { key: "db_url",        label: "Database DSN",       type: "string", help: "Postgres SQLAlchemy DSN, e.g. postgresql+psycopg://argus:pw@host/argus_main" },
      { key: "log_level",     label: "Log level",          type: "select", options: ["DEBUG","INFO","WARNING","ERROR"] },
      { key: "log_file",      label: "Log file",           type: "string" },
      { key: "user_agent",    label: "User-Agent",         type: "string" },
    ],
  },
  {
    section: "api_keys", title: "API Keys",
    fields: [
      { key: "chaos",         label: "Chaos / PDCP key",   type: "secret", help: "Or set PDCP_API_KEY env var. Required for chaos source in M02." },
    ],
  },

  // ── Execution order: M01 (osint) || M02 (subs) → M03 → M04..M09 (parallel)
  //    → M10 → M11 → M12 || M13 → M14. Same order in this schema. ──

  {
    section: "osint", title: "M01 — OSINT",
    fields: [
      { key: "enabled",            label: "Module enabled",                    type: "bool" },
      { key: "whois",              label: "WHOIS / RDAP lookup",               type: "bool" },
      { key: "email_auth",         label: "SPF / DMARC / DKIM lookup",         type: "bool" },
      { key: "dkim_selectors",     label: "DKIM selectors probed",             type: "list-string", help: "default, google, k1, mail, selector1..." },
      { key: "dns_nameservers",    label: "DNS resolvers",                     type: "list-string", help: "Public DNS avoids split-horizon hiding DMARC." },
      { key: "github_secrets",     label: "trufflehog GitHub scan",            type: "bool", help: "Skipped if no github_org or GITHUB_TOKEN." },
      { key: "github_org",         label: "GitHub org handle",                 type: "string", help: 'e.g. "loteriebenin"' },
      { key: "github_timeout_sec", label: "GitHub timeout (sec)",              type: "int" },
      { key: "github_token",       label: "GITHUB_TOKEN override",             type: "secret", help: "Or set env var." },
      { key: "hibp",               label: "HIBP domain breach lookup",         type: "bool" },
      { key: "hibp_api_key",       label: "HIBP_API_KEY override",             type: "secret", help: "Or set env var." },
    ],
  },
  {
    section: "subdomain", title: "M02 — Subdomain Enumeration",
    fields: [
      { key: "enabled",                       label: "Module enabled",             type: "bool" },
      { key: "passive.subfinder",             label: "Passive: subfinder",         type: "bool" },
      { key: "passive.assetfinder",           label: "Passive: assetfinder",       type: "bool" },
      { key: "passive.findomain",             label: "Passive: findomain",         type: "bool" },
      { key: "passive.crtsh",                 label: "Passive: crt.sh",            type: "bool", help: "5 retries + 24h disk cache." },
      { key: "passive.certspotter",           label: "Passive: certspotter",       type: "bool" },
      { key: "passive.chaos",                 label: "Passive: chaos",             type: "bool", help: "Needs PDCP_API_KEY." },
      { key: "active.enabled",                label: "Active brute-force",         type: "bool", help: "shuffledns + alterx — adds ~8 min for marginal gain." },
      { key: "active.shuffledns",             label: "  — shuffledns",             type: "bool" },
      { key: "active.alterx",                 label: "  — alterx",                 type: "bool" },
      { key: "active.wordlist",               label: "  — wordlist",               type: "string" },
      { key: "active.resolvers",              label: "  — resolvers file",         type: "string" },
      { key: "dnsx.a",                        label: "DNS query: A",               type: "bool" },
      { key: "dnsx.cname",                    label: "DNS query: CNAME",           type: "bool" },
      { key: "dnsx.mx",                       label: "DNS query: MX",              type: "bool" },
      { key: "dnsx.txt",                      label: "DNS query: TXT",             type: "bool" },
      { key: "dnsx.ptr",                      label: "DNS query: PTR (reverse)",   type: "bool" },
      { key: "dns_nameservers",               label: "Custom DNS resolvers",       type: "list-string", help: "Empty = built-in (8.8.8.8, 9.9.9.9, ...)." },
    ],
  },
  {
    section: "http_validator", title: "M03 — HTTP Validator",
    fields: [
      { key: "enabled",              label: "Module enabled",     type: "bool" },
      { key: "timeout",              label: "Timeout (sec)",      type: "int" },
      { key: "min_confidence",       label: "Min confidence",     type: "float", help: "0.0 – 1.0" },
      { key: "detect_waf",           label: "WAF detection",      type: "bool" },
      { key: "extract_favicon_hash", label: "Favicon hash (mmh3)", type: "bool" },
      { key: "probe_ports",          label: "Ports probed",       type: "string", help: "Comma-separated. Bump for heavy BBP." },
      { key: "dns_nameservers",      label: "DNS resolvers",      type: "list-string" },
    ],
  },
  {
    section: "url_collector", title: "M04 — URL Collector",
    fields: [
      { key: "enabled",                  label: "Module enabled",        type: "bool" },
      { key: "gau.enabled",              label: "gau (passive)",         type: "bool" },
      { key: "katana.enabled",           label: "katana (active crawl)", type: "bool" },
      { key: "gospider.enabled",         label: "gospider",              type: "bool", help: "Redundant with katana — usually off." },
      { key: "waybackurls",              label: "waybackurls",           type: "bool" },
      { key: "uro",                      label: "URO smart dedup",       type: "bool" },
      { key: "max_urls_per_domain",      label: "Max URLs / domain",     type: "int" },
      { key: "probe_live.enabled",       label: "Probe URLs alive",      type: "bool" },
      { key: "probe_live.timeout",       label: "Probe timeout (sec)",   type: "int" },
    ],
  },
  {
    section: "screenshot", title: "M05 — Screenshots",
    fields: [
      { key: "enabled",    label: "Module enabled",     type: "bool" },
      { key: "timeout",    label: "Timeout (sec)",      type: "int" },
      { key: "max_urls",   label: "Max URLs",           type: "int" },
      { key: "width",      label: "Viewport width",     type: "int" },
      { key: "height",     label: "Viewport height",    type: "int" },
      { key: "quality",    label: "JPEG quality",       type: "int" },
      { key: "thumbnails", label: "Generate thumbnails",type: "bool" },
    ],
  },
  {
    section: "takeover", title: "M06 — Subdomain Takeover",
    fields: [{ key: "enabled", label: "Module enabled", type: "bool" }],
  },
  {
    section: "ports", title: "M07 — Ports & Service Discovery",
    fields: [
      { key: "enabled",              label: "Module enabled",        type: "bool" },
      { key: "prefer",               label: "Preferred discovery",   type: "select", options: ["rustscan","naabu"], help: "rustscan is ~5-10× faster; naabu used as fallback if rustscan is missing." },
      { key: "max_ips",              label: "Max IPs scanned",       type: "int",    help: "Skips private IPs automatically." },
      { key: "rustscan.range",       label: "rustscan port range",   type: "string", help: "e.g. 1-1000 (top-1000) or 1-65535." },
      { key: "rustscan.ulimit",      label: "rustscan ulimit",       type: "int" },
      { key: "rustscan.batch",       label: "rustscan batch",        type: "int",    help: "Lower under stealth." },
      { key: "rustscan.timeout_ms",  label: "rustscan timeout (ms)", type: "int" },
      { key: "rustscan.batch_stealth",      label: "rustscan batch (stealth)", type: "int" },
      { key: "rustscan.timeout_ms_stealth", label: "rustscan timeout ms (stealth)", type: "int" },
      { key: "rustscan_timeout_sec", label: "rustscan wall timeout (sec)", type: "int" },
      { key: "top_ports",            label: "naabu top-N ports",     type: "int",    help: "Used only when naabu fallback is hit." },
      { key: "rate",                 label: "naabu packets/sec",     type: "int" },
      { key: "naabu_timeout_sec",    label: "naabu wall timeout",    type: "int" },
      { key: "nmap_service_detect",  label: "nmap -sV service detection", type: "bool" },
      { key: "nmap_port_budget",     label: "nmap (ip,port) budget", type: "int" },
      { key: "nmap_concurrency",     label: "nmap concurrency",      type: "int" },
      { key: "nmap_timing",          label: "nmap timing template",  type: "select", options: ["-T1","-T2","-T3"], help: "OPSEC default -T2 (-T1 forced under --stealth). -T4/T5 banned." },
      { key: "nmap_timeout_sec",     label: "nmap wall timeout",     type: "int" },
      { key: "cdncheck",             label: "cdncheck origin/CDN classify", type: "bool" },
      { key: "emit_info_services",   label: "Emit info-severity service findings", type: "bool", help: "false = hide http/https/ssh banner-only findings." },
    ],
  },
  {
    section: "tls", title: "M08 — TLS Audit",
    fields: [
      { key: "enabled",              label: "Module enabled",          type: "bool" },
      { key: "max_hosts",            label: "Max hosts",               type: "int", help: "testssl is slow (~2 min/host)." },
      { key: "concurrency",          label: "Concurrent testssl runs", type: "int" },
      { key: "per_host_timeout_sec", label: "Per-host timeout (sec)",  type: "int" },
      { key: "run_under_stealth",    label: "Run under --stealth",     type: "bool", help: "Default off — testssl is loud (full cipher enum)." },
    ],
  },
  {
    section: "quick_checks", title: "M09 — Quick Checks",
    fields: [
      { key: "enabled",                label: "Module enabled",                   type: "bool" },
      { key: "max_hosts",              label: "Max hosts",                        type: "int" },
      { key: "concurrency",            label: "TCP connector pool size",          type: "int" },
      { key: "per_check_concurrency",  label: "Semaphore per check",              type: "int" },
      { key: "total_timeout",          label: "Total timeout (sec)",              type: "int" },
      { key: "graphql",                label: "GraphQL introspection probe",      type: "bool" },
      { key: "git",                    label: ".git/HEAD + config exposure",      type: "bool" },
      { key: "env",                    label: ".env exposure (keys-only evidence)", type: "bool" },
      { key: "jwt",                    label: "JWT decode (alg=none / no exp …)", type: "bool", help: "Stored as token sha256 + claim names — never the token value." },
      { key: "cloud_bucket",           label: "Cloud bucket world-readable list", type: "bool", help: "Scope-filtered: only buckets matching scope.in are probed." },
    ],
  },
  {
    section: "fetcher", title: "M10 — Body / Headers Fetcher",
    fields: [
      { key: "enabled",          label: "Module enabled",          type: "bool" },
      { key: "timeout",          label: "Timeout (sec)",           type: "int" },
      { key: "save_bodies",      label: "Persist bodies on disk",  type: "bool" },
      { key: "fetch_extra_urls", label: "Fetch M04 extras",        type: "bool" },
      { key: "max_extra_urls",   label: "Max extras",              type: "int", help: "Cap m04 URLs fetched in addition to live hosts." },
      { key: "max_body_size",    label: "Max body bytes",          type: "int" },
      { key: "snippet_max_kb",   label: "Snippet cap (KB)",        type: "int", help: "0 = no cap (full body in bodies_snippets.json → richer m11/m12 analysis). 64–256 caps disk." },
    ],
  },
  {
    section: "js_analyzer", title: "M11 — JS Analyzer",
    fields: [
      { key: "enabled",        label: "Module enabled",          type: "bool" },
      { key: "timeout",        label: "Timeout (sec)",           type: "int" },
      { key: "max_js_files",   label: "Max JS files fetched",    type: "int" },
      { key: "jsluice",        label: "Use jsluice (external)",  type: "bool" },
      { key: "sourcemapper",   label: "Source-map detection",    type: "bool" },
      { key: "min_confidence", label: "Min confidence",          type: "float" },
      { key: "keywords",       label: "Extra secret keywords",   type: "list-string" },
    ],
  },
  {
    section: "pattern_analysis", title: "M12 — Pattern Analysis",
    fields: [
      { key: "gf_enabled",                  label: "gf-style patterns",            type: "bool" },
      { key: "analyze_urls",                label: "Analyze URLs",                  type: "bool" },
      { key: "analyze_bodies",              label: "Analyze bodies",                type: "bool" },
      { key: "analyze_js",                  label: "Analyze JS bodies (from m11)", type: "bool" },
      { key: "reflection_check",            label: "Reflection canary check",      type: "bool" },
      { key: "parameter_discovery.enabled", label: "Parameter discovery (arjun)",  type: "bool" },
    ],
  },
  {
    section: "nuclei", title: "M13 — Nuclei",
    fields: [
      { key: "enabled",              label: "Module enabled",              type: "bool" },
      { key: "severity",             label: "Severities to keep",          type: "list-string", help: "e.g. medium, high, critical" },
      { key: "targeted_scanning",    label: "Tech-targeted templates",     type: "bool", help: "Tag intersect with exclude_tags." },
      { key: "high_impact_info",     label: "High-impact info templates",  type: "bool", help: "config-leak, env, git, sourcemap, secrets..." },
      { key: "rate_limit",           label: "Rate limit (req/s)",          type: "int", help: "Auto-capped to 5 under WAF or --stealth." },
      { key: "concurrency",          label: "Concurrency",                 type: "int" },
      { key: "timeout",              label: "Per-request timeout (sec)",   type: "int" },
      { key: "retries",              label: "Retries on failed request",   type: "int" },
      { key: "max_host_error",       label: "Max errors / host",           type: "int", help: "0 = disabled (-no-mhe)." },
      { key: "always_run",           label: "Template directories",        type: "list-string", help: "Surface-only default: http/misconfiguration/, http/exposures/" },
      { key: "exclude_tags",         label: "Excluded tags",               type: "list-string", help: "Default: dos, fuzz, intrusive, cve, default-login." },
      { key: "custom_templates_dir", label: "Custom templates dir",        type: "string" },
      { key: "module_timeout_sec",   label: "Module wall timeout (sec)",   type: "int", help: "Default 1800. nuclei is killed past this, scan continues." },
    ],
  },
  {
    section: "active_validation", title: "M14 — Active Validation",
    fields: [
      { key: "enabled",            label: "Module enabled",         type: "bool" },
      { key: "total_budget_sec",   label: "Total budget (sec)",     type: "int" },
      { key: "file_exposure",      label: "File-exposure brute",    type: "bool" },
      { key: "open_redirect",      label: "Open-redirect probe",    type: "bool" },
      { key: "open_redirect_cap",  label: "Open-redirect cap",      type: "int" },
      { key: "xss_dalfox",         label: "Dalfox XSS",             type: "bool" },
      { key: "xss_cap",            label: "XSS candidates cap",     type: "int" },
      { key: "sqli_sqlmap",        label: "sqlmap SQLi",            type: "bool" },
      { key: "sqli_cap",           label: "SQLi candidates cap",    type: "int" },
    ],
  },
  {
    section: "notifications", title: "Notifications",
    fields: [
      { key: "discord_webhook", label: "Discord webhook URL", type: "secret" },
      { key: "slack_webhook",   label: "Slack webhook URL",   type: "secret" },
      { key: "notify_on",       label: "Notify on",            type: "list-string", help: "critical, high, new_subdomain, takeover" },
    ],
  },
  {
    section: "dashboard", title: "Dashboard",
    fields: [
      { key: "host", label: "Bind host", type: "string", help: "Restart required for this to take effect." },
      { key: "port", label: "Port",      type: "int",    help: "Restart required for this to take effect." },
    ],
  },
];

// Get/set a value at a dot-path inside a nested dict (matches CONFIG_SCHEMA keys).
function _getPath(obj, path) {
  return path.split(".").reduce((acc, k) => (acc == null ? undefined : acc[k]), obj);
}
function _setPath(obj, path, value) {
  const keys = path.split(".");
  const out = JSON.parse(JSON.stringify(obj || {}));
  let node = out;
  for (let i = 0; i < keys.length - 1; i++) {
    if (typeof node[keys[i]] !== "object" || node[keys[i]] == null) node[keys[i]] = {};
    node = node[keys[i]];
  }
  node[keys[keys.length - 1]] = value;
  return out;
}

function ConfigField({ field, value, onChange }) {
  const set = (v) => onChange(field.key, v);
  switch (field.type) {
    case "bool":
      return (
        <label style={{display:"flex", alignItems:"center", gap:8, cursor:"pointer", userSelect:"none"}}>
          <input type="checkbox" checked={!!value} onChange={e => set(e.target.checked)} />
          <span style={{fontSize:11, color:value ? "var(--solid)" : "var(--text-faint)"}}>{value ? "ON" : "OFF"}</span>
        </label>
      );
    case "int":
      return <input type="number" value={value ?? ""} onChange={e => set(e.target.value === "" ? null : parseInt(e.target.value, 10))} className="cfg-input" />;
    case "float":
      return <input type="number" step="0.01" value={value ?? ""} onChange={e => set(e.target.value === "" ? null : parseFloat(e.target.value))} className="cfg-input" />;
    case "select":
      return (
        <select value={value ?? ""} onChange={e => set(e.target.value)} className="cfg-input">
          {field.options.map(o => <option key={o} value={o}>{o}</option>)}
        </select>
      );
    case "secret":
      return <input type="password" value={value ?? ""} onChange={e => set(e.target.value)} className="cfg-input" placeholder="(empty)" />;
    case "list-string":
      return (
        <input
          type="text"
          value={Array.isArray(value) ? value.join(", ") : ""}
          onChange={e => set(e.target.value.split(",").map(s => s.trim()).filter(Boolean))}
          className="cfg-input"
          placeholder="comma-separated"
        />
      );
    default:
      return <input type="text" value={value ?? ""} onChange={e => set(e.target.value)} className="cfg-input" />;
  }
}

function PageConfig({ me }) {
  const canEdit = me && me.role === "super-admin";
  const canView = me && me.role === "super-admin"; // backend gates GET too
  const [config, setConfig] = uxS(null);
  const [original, setOriginal] = uxS(null);
  const [loading, setLoading] = uxS(true);
  const [error, setError] = uxS(null);
  const [saving, setSaving] = uxS(false);
  const [toast, setToast] = uxS(null);
  const [openSection, setOpenSection] = uxS("general");

  if (!canView) {
    return (
      <div className="page">
        <PageHeader eyebrow="SYSTEM · CONFIGURATION" title="Configuration" lede=""/>
        <div className="card" style={{padding:24}}>
          <div className="empty"><div className="empty-title">access denied</div>
            <div style={{color:"var(--text-dim)",fontSize:12,marginTop:6}}>
              Only super-admin can read or modify the config.
            </div>
          </div>
        </div>
      </div>
    );
  }

  uxE(() => {
    setLoading(true);
    window.ArgusAPI.config.get()
      .then(d => { setConfig(d); setOriginal(JSON.parse(JSON.stringify(d))); setLoading(false); })
      .catch(e => { setError(String(e.message || e)); setLoading(false); });
  }, []);

  const dirty = uxM(() => {
    if (!config || !original) return false;
    return JSON.stringify(config) !== JSON.stringify(original);
  }, [config, original]);

  const updateField = (section, path, value) => {
    setConfig(prev => ({
      ...prev,
      [section]: _setPath(prev[section] || {}, path, value),
    }));
  };

  const onSave = async () => {
    if (!dirty) return;
    setSaving(true); setToast(null);
    try {
      const result = await window.ArgusAPI.config.save(config);
      setOriginal(JSON.parse(JSON.stringify(config)));
      setToast({type:"ok", msg:`Saved. Backup: ${result.backup}. Click Reload to apply to the dashboard process — new scans pick it up automatically.`});
    } catch (e) {
      setToast({type:"err", msg:`Save failed: ${e.message || e}`});
    } finally { setSaving(false); }
  };

  const onReload = async () => {
    setSaving(true); setToast(null);
    try {
      await window.ArgusAPI.config.reload();
      setToast({type:"ok", msg:"Dashboard reloaded the YAML. Refresh the page to see updates that affect the UI itself."});
    } catch (e) {
      setToast({type:"err", msg:`Reload failed: ${e.message || e}`});
    } finally { setSaving(false); }
  };

  const onRevert = () => {
    if (original) setConfig(JSON.parse(JSON.stringify(original)));
    setToast(null);
  };

  if (loading) return <div className="page"><PageHeader eyebrow="SYSTEM · CONFIGURATION" title="Configuration" lede=""/><PageLoading/></div>;
  if (error)   return <div className="page"><PageHeader eyebrow="SYSTEM · CONFIGURATION" title="Configuration" lede=""/><PageError error={error}/></div>;

  return (
    <div className="page">
      <style>{`
        .cfg-input {
          background: var(--panel-bg, #0d1115);
          color: var(--text);
          border: 1px solid var(--border);
          padding: 5px 9px;
          font-family: var(--font-mono);
          font-size: 11.5px;
          border-radius: 3px;
          min-width: 200px;
          max-width: 480px;
        }
        .cfg-input:focus { outline: none; border-color: var(--accent); }
        .cfg-row { display: grid; grid-template-columns: 1fr auto; gap: 14px; padding: 8px 0; border-bottom: 1px dashed var(--border); align-items: center; }
        .cfg-row:last-child { border-bottom: none; }
        .cfg-label { font-size: 12px; color: var(--text); }
        .cfg-help  { font-size: 10.5px; color: var(--text-faint); margin-top: 2px; line-height: 1.4; }
        .cfg-section-toggle { cursor: pointer; user-select: none; padding: 12px 16px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
        .cfg-section-toggle:hover { background: var(--accent-soft); }
      `}</style>

      <PageHeader
        eyebrow="SYSTEM · CONFIGURATION"
        title="Configuration"
        lede={canEdit
          ? `${dirty ? "Unsaved changes" : "In sync with disk"} · YAML at config/argus.yaml · backup auto-created on save`
          : `Read-only — only super-admin can edit. YAML at config/argus.yaml.`}
        actions={canEdit ? <>
          <button className="cmd-btn" onClick={onRevert} disabled={!dirty || saving}>
            <Icon name="refresh" size={12}/> Revert
          </button>
          <button className="cmd-btn" onClick={onReload} disabled={saving}>
            <Icon name="rotate-cw" size={12}/> Reload
          </button>
          <button className="cmd-btn cmd-btn-primary" onClick={onSave} disabled={!dirty || saving}>
            <Icon name="save" size={12}/> {saving ? "Saving…" : "Save"}
          </button>
        </> : null}
      />

      {toast && (
        <div style={{
          padding:"10px 14px",
          marginBottom:14,
          borderLeft: `3px solid ${toast.type === "ok" ? "var(--solid)" : "var(--sev-high)"}`,
          background: toast.type === "ok" ? "rgba(110,255,168,0.05)" : "rgba(255,155,72,0.06)",
          fontFamily:"var(--font-mono)", fontSize:11.5, lineHeight:1.5,
        }}>{toast.msg}</div>
      )}

      <div className="card">
        {CONFIG_SCHEMA.map(s => {
          const sectionData = config[s.section] || {};
          const isOpen = openSection === s.section;
          return (
            <div key={s.section}>
              <div className="cfg-section-toggle" onClick={() => setOpenSection(isOpen ? null : s.section)}>
                <div>
                  <div style={{fontSize:13, fontWeight:500}}>{s.title}</div>
                  <div className="mono" style={{fontSize:10, color:"var(--text-faint)", marginTop:2}}>{s.section}</div>
                </div>
                <Icon name={isOpen ? "chevron-down" : "chevron-right"} size={14}/>
              </div>
              {isOpen && (
                <div style={{padding:"6px 18px 14px"}}>
                  {s.fields.map(f => (
                    <div key={f.key} className="cfg-row">
                      <div>
                        <div className="cfg-label">{f.label}</div>
                        {f.help && <div className="cfg-help">{f.help}</div>}
                        <div className="mono" style={{fontSize:9.5, color:"var(--text-faint)", marginTop:1}}>{s.section}.{f.key}</div>
                      </div>
                      <div>
                        <ConfigField
                          field={f}
                          value={_getPath(sectionData, f.key)}
                          onChange={(path, val) => updateField(s.section, path, val)}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// PageChecks — regroupe les checks transverses (DNS takeover, email auth,
// API specs discovery) dans une seule entrée de nav avec 3 tabs internes.
// Chaque tab réutilise le composant existant — pas de duplication logique.
// La sélection du tab est persistée dans localStorage pour survivre au reload.
function PageChecks({ data }) {
  const TABS = [
    { id: "takeover", label: "Takeover", icon: "shield-alert",
      desc: "DNS / subdomain takeover risk",          Page: PageTakeovers },
    { id: "email",    label: "Email",    icon: "mail",
      desc: "SPF / DMARC / DKIM checks",              Page: PageEmailSecurity },
    { id: "api",      label: "API",      icon: "plug",
      desc: "Swagger / OpenAPI / GraphQL discovered", Page: PageAPISpecs },
  ];
  const [tab, setTab] = uxS(() => {
    try { return localStorage.getItem("argus.checks.tab") || "takeover"; }
    catch (_) { return "takeover"; }
  });
  uxE(() => {
    try { localStorage.setItem("argus.checks.tab", tab); } catch (_) {}
  }, [tab]);
  const ActiveTab = (TABS.find(t => t.id === tab) || TABS[0]).Page;
  return (
    <div className="page page-checks">
      <div className="checks-tabs">
        {TABS.map(t => (
          <button key={t.id}
                  className={`checks-tab ${tab === t.id ? "active" : ""}`}
                  onClick={() => setTab(t.id)}
                  title={t.desc}>
            <Icon name={t.icon} size={12}/>
            <span>{t.label}</span>
          </button>
        ))}
      </div>
      <ActiveTab data={data}/>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
// CVE INTELLIGENCE — list + detail page
// Backend : /api/cves/{list,stats,vendors,{id}}
// Strategy reminder : confidence=0.4 → "candidate" (low signal),
//   bumped to 0.85/0.95 by future product_version / nuclei_template strategies.
// ──────────────────────────────────────────────────────────────────────
function PageCVEs({ currentOrg, onSelectCVE }) {
  // Persisted filters
  const [filters, setFilters] = uxS(() => {
    try { return JSON.parse(localStorage.getItem("argus.cves.filters") || "{}"); }
    catch (_) { return {}; }
  });
  const setFilter = (k, v) => setFilters(f => {
    const next = { ...f };
    if (v === null || v === undefined || v === "" || v === false) delete next[k];
    else next[k] = v;
    try { localStorage.setItem("argus.cves.filters", JSON.stringify(next)); } catch (_) {}
    return next;
  });

  const [sort, setSort] = uxS(() => {
    try { return localStorage.getItem("argus.cves.sort") || "epss"; }
    catch (_) { return "epss"; }
  });
  uxE(() => { try { localStorage.setItem("argus.cves.sort", sort); } catch (_) {} }, [sort]);

  const [offset, setOffset] = uxS(0);
  const LIMIT = 50;

  const [data,    setData]    = uxS({ items: [], total: 0 });
  const [stats,   setStats]   = uxS(null);
  const [vendors, setVendors] = uxS([]);
  const [loading, setLoading] = uxS(false);
  const [error,   setError]   = uxS(null);
  // Feed-pull state (bouton Refresh feeds)
  const [pullState, setPullState] = uxS("idle"); // idle | running | done | error
  const [pullStats, setPullStats] = uxS(null);

  // Reload list when filters/sort/offset change
  uxE(() => {
    let alive = true;
    setLoading(true); setError(null);
    const params = { ...filters, sort, limit: LIMIT, offset };
    window.ArgusAPI.cves.list(params)
      .then(d => { if (alive) setData(d || { items: [], total: 0 }); })
      .catch(e => { if (alive) setError(String(e.message || e)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [filters, sort, offset]);

  // Stats + vendors loaded once
  uxE(() => {
    window.ArgusAPI.cves.stats().then(setStats).catch(() => {});
    window.ArgusAPI.cves.vendors(40).then(setVendors).catch(() => {});
  }, []);

  // Reset offset when filters change
  uxE(() => { setOffset(0); }, [JSON.stringify(filters), sort]);

  // Reload all view data (stats + list)
  const reloadAll = () => {
    window.ArgusAPI.cves.stats().then(setStats).catch(() => {});
    window.ArgusAPI.cves.list({ ...filters, sort, limit: LIMIT, offset })
      .then(setData).catch(() => {});
  };

  // Bouton Refresh feeds — backend pull (+ auto correlate). Sync.
  const refreshFeeds = (full = false) => {
    setPullState("running"); setPullStats(null);
    window.ArgusAPI.cves.pull({ recentOnly: !full, correlate: true })
      .then(result => {
        setPullStats(result);
        setPullState("done");
        reloadAll();
      })
      .catch(e => {
        setPullState("error");
        alert("Pull failed: " + (e.message || e));
      });
  };

  // Bouton Re-correlate (sans pull) — pour quand on a scanné de nouveaux hosts.
  const recorrelate = () => {
    setPullState("running"); setPullStats(null);
    window.ArgusAPI.cves.correlate()
      .then(stats => {
        setPullStats({ correlate: stats });
        setPullState("done");
        reloadAll();
      })
      .catch(e => {
        setPullState("error");
        alert("Correlate failed: " + (e.message || e));
      });
  };

  const SEV = (cvss) => {
    if (cvss == null) return "muted";
    if (cvss >= 9.0) return "critical";
    if (cvss >= 7.0) return "high";
    if (cvss >= 4.0) return "medium";
    return "low";
  };
  const fmt = (v, d = 2) => v == null ? "—" : Number(v).toFixed(d);

  const toggleSort = (col) => setSort(col);
  const sortArrow  = (col) => (sort === col ? " ↓" : "");

  return (
    <div className="page page-cves">
      <div className="page-header">
        <div>
          <div className="page-eyebrow">SECURITY · CVE INTELLIGENCE</div>
          <h1>CVEs</h1>
          <div className="page-lede">
            {stats
              ? `${stats.total_cves} CVEs (${stats.kev_count} KEV) · ${stats.match_count} matches across ${stats.org_count} orgs`
              : "loading CVE catalog…"}
            {pullState === "done" && pullStats && (
              <span className="muted" style={{marginLeft: 12, fontSize: 11}}>
                {pullStats.pull && (
                  <>· pulled +{pullStats.pull.inserted || 0} new, {pullStats.pull.updated || 0} updated ({pullStats.pull.elapsed_seconds}s) </>
                )}
                {pullStats.correlate && !pullStats.correlate.error && (
                  <>· correlate {pullStats.correlate.matches_total || 0} matches ({pullStats.correlate.inserted || 0} new, {pullStats.correlate.refreshed || 0} refreshed)</>
                )}
                {pullStats.correlate?.error && (
                  <span style={{color: "var(--sev-critical)"}}> · correlate failed: {pullStats.correlate.error}</span>
                )}
              </span>
            )}
          </div>
        </div>
        <div className="page-actions">
          <button className="btn-secondary"
                  onClick={() => refreshFeeds(false)}
                  disabled={pullState === "running"}
                  title="Pull KEV + EPSS + nuclei templates + NVD recent (8-day delta) and re-correlate. Fast (~10-15s).">
            <Icon name={pullState === "running" ? "refresh" : "download"}
                  size={12}
                  style={pullState === "running" ? {animation: "argus-spin 0.9s linear infinite"} : {}}/>
            {pullState === "running" ? " working…" : " Refresh feeds"}
          </button>
          <button className="btn-secondary"
                  onClick={recorrelate}
                  disabled={pullState === "running"}
                  title="Re-run correlator only (no feed pull). Use after new scans landed.">
            <Icon name="refresh" size={12}/>
            <span> Re-correlate</span>
          </button>
          <button className="btn-link"
                  onClick={() => {
                    if (confirm("Full pull (NVD years feeds, ~60 MB, ~30s without API key). Continue ?")) {
                      refreshFeeds(true);
                    }
                  }}
                  disabled={pullState === "running"}
                  style={{fontSize: 11}}
                  title="Pull NVD annual feeds (much heavier, full catalog refresh)">
            full
          </button>
        </div>
      </div>

      {/* Filters bar */}
      <div className="cves-filter-bar">
        <input type="search" className="form-input"
               placeholder="Search CVE-ID / description / vendor…"
               value={filters.search || ""}
               onChange={e => setFilter("search", e.target.value)}
               style={{flex: 1, minWidth: 220}}/>

        <label className="cves-filter-toggle" title="Only CVEs in CISA KEV catalog">
          <input type="checkbox"
                 checked={!!filters.kev_only}
                 onChange={e => setFilter("kev_only", e.target.checked)}/>
          <span>KEV only</span>
        </label>
        <label className="cves-filter-toggle" title="Tied to ransomware campaigns">
          <input type="checkbox"
                 checked={!!filters.ransomware}
                 onChange={e => setFilter("ransomware", e.target.checked)}/>
          <span>Ransomware</span>
        </label>
        <label className="cves-filter-toggle" title="With matches on our infra">
          <input type="checkbox"
                 checked={!!filters.has_matches}
                 onChange={e => setFilter("has_matches", e.target.checked)}/>
          <span>Has matches</span>
        </label>
        <label className="cves-filter-toggle" title="With a nuclei template available">
          <input type="checkbox"
                 checked={!!filters.has_template}
                 onChange={e => setFilter("has_template", e.target.checked)}/>
          <span>Has template</span>
        </label>

        <span className="cves-filter-num" title="Minimum CVSS v3 score">
          <span>CVSS≥</span>
          <input type="number" min="0" max="10" step="0.5"
                 value={filters.min_cvss || ""}
                 onChange={e => setFilter("min_cvss", e.target.value)}
                 placeholder="0"/>
        </span>
        <span className="cves-filter-num" title="Minimum EPSS score (0..1)">
          <span>EPSS≥</span>
          <input type="number" min="0" max="1" step="0.05"
                 value={filters.min_epss || ""}
                 onChange={e => setFilter("min_epss", e.target.value)}
                 placeholder="0"/>
        </span>

        <select className="form-input cves-vendor-select"
                value={filters.vendor || ""}
                onChange={e => setFilter("vendor", e.target.value)}
                title="Filter by vendor (top 40 by CVE count)">
          <option value="">— vendor —</option>
          {vendors.map(v => (
            <option key={v.vendor} value={v.vendor}>{v.vendor} ({v.count})</option>
          ))}
        </select>

        {Object.keys(filters).length > 0 && (
          <button className="cmd-btn" onClick={() => {
            setFilters({}); try { localStorage.removeItem("argus.cves.filters"); } catch (_) {}
          }} title="Clear all filters">
            <Icon name="x" size={11}/> clear
          </button>
        )}
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {/* Results table */}
      <div className="users-table-wrap">
        <table className="users-table users-table-compact">
          <thead>
            <tr>
              <th>CVE-ID</th>
              <th>Vendor</th>
              <th className="sortable" onClick={() => toggleSort("cvss")}>CVSS{sortArrow("cvss")}</th>
              <th className="sortable" onClick={() => toggleSort("epss")}>EPSS{sortArrow("epss")}</th>
              <th>Flags</th>
              <th className="sortable" onClick={() => toggleSort("matches")}>Hosts{sortArrow("matches")}</th>
              <th>Orgs</th>
              <th className="sortable" onClick={() => toggleSort("published")}>Published{sortArrow("published")}</th>
            </tr>
          </thead>
          <tbody>
            {data.items.length === 0 ? (
              <tr><td colSpan="8" className="empty">
                {loading
                  ? "Loading…"
                  : (Object.keys(filters).length > 0
                      ? "No CVE matches the current filters."
                      : "No CVEs in catalog yet. Run scripts/cve_pull.py to populate.")}
              </td></tr>
            ) : data.items.map(c => (
              <tr key={c.cve_id}
                  className="row-clickable"
                  onClick={() => onSelectCVE?.(c.cve_id)}
                  title={c.description ? c.description.slice(0, 160) : c.cve_id}>
                <td className="mono"><strong>{c.cve_id}</strong></td>
                <td className="mono">{c.vendor || <span className="muted">—</span>}</td>
                <td>
                  {c.cvss_v3 != null
                    ? <span className={`sev-mini sev-mini-${SEV(c.cvss_v3)}`}>{fmt(c.cvss_v3, 1)}</span>
                    : <span className="muted">—</span>}
                </td>
                <td className="mono">
                  {c.epss != null
                    ? <span style={{
                        color: c.epss >= 0.7 ? "var(--sev-critical, #ff5e62)"
                             : c.epss >= 0.4 ? "var(--sev-medium, #ffcd5a)"
                             : "var(--text-muted)",
                      }}>{fmt(c.epss, 3)}</span>
                    : <span className="muted">—</span>}
                </td>
                <td className="cves-flags">
                  {c.kev_flag      && <span className="cve-badge cve-badge-kev"  title="CISA Known Exploited Vulnerability">KEV</span>}
                  {c.kev_ransomware && <span className="cve-badge cve-badge-ransom" title="Used in known ransomware campaigns">RANSOM</span>}
                  {c.nuclei_template && <span className="cve-badge cve-badge-tpl" title="Nuclei template available">TPL</span>}
                </td>
                <td className="mono">
                  {c.match_count > 0
                    ? <strong style={{color: "var(--sev-critical, #ff5e62)"}}>{c.match_count}</strong>
                    : <span className="muted">—</span>}
                </td>
                <td className="mono">{c.org_count > 0 ? c.org_count : <span className="muted">—</span>}</td>
                <td className="muted mono" style={{fontSize: 10.5}}>
                  {c.published_at ? c.published_at.slice(0, 10) : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data.total > LIMIT && (
        <div className="cves-pagination">
          <button className="cmd-btn" onClick={() => setOffset(Math.max(0, offset - LIMIT))}
                  disabled={offset === 0}>
            ← prev
          </button>
          <span className="muted mono" style={{fontSize: 11}}>
            {offset + 1}–{Math.min(offset + LIMIT, data.total)} of {data.total}
          </span>
          <button className="cmd-btn" onClick={() => setOffset(offset + LIMIT)}
                  disabled={offset + LIMIT >= data.total}>
            next →
          </button>
        </div>
      )}
    </div>
  );
}


function PageCVEDetail({ cveId, onBack }) {
  const [detail,  setDetail]  = uxS(null);
  const [loading, setLoading] = uxS(true);
  const [error,   setError]   = uxS(null);
  const [valState, setValState] = uxS("idle"); // idle | running | done | error
  const [valStats, setValStats] = uxS(null);

  const reload = uxC(() => {
    setLoading(true); setError(null);
    window.ArgusAPI.cves.get(cveId)
      .then(setDetail)
      .catch(e => setError(String(e.message || e)))
      .finally(() => setLoading(false));
  }, [cveId]);
  uxE(() => { reload(); }, [reload]);

  const handleValidate = () => {
    setValState("running"); setValStats(null);
    window.ArgusAPI.cves.validate(cveId)
      .then(stats => {
        setValStats(stats);
        setValState("done");
        reload();   // refresh matches table — validation_state may have changed
      })
      .catch(e => {
        setValState("error");
        alert("Validation failed: " + (e.message || e));
      });
  };

  const SEV = (cvss) => {
    if (cvss == null) return "muted";
    if (cvss >= 9.0) return "critical";
    if (cvss >= 7.0) return "high";
    if (cvss >= 4.0) return "medium";
    return "low";
  };

  const launchScan = (apex) => {
    if (apex && typeof window.openScanModal === "function") {
      window.openScanModal({ target: apex });
    }
  };
  const viewTarget = (apex) => {
    if (apex && typeof window.viewTarget === "function") {
      window.viewTarget(apex);
    }
  };

  if (loading) return <div className="page"><div className="muted">Loading…</div></div>;
  if (error)   return <div className="page"><div className="alert alert-error">{error}</div></div>;
  if (!detail) return <div className="page"><div className="muted">Not found.</div></div>;

  const cve     = detail.cve     || {};
  const matches = detail.matches || [];

  return (
    <div className="page page-cve-detail">
      <div className="org-detail-header">
        <a className="org-detail-back" href="#/cves"
           onClick={e => { e.preventDefault(); onBack?.(); }}>
          ← back to CVEs
        </a>
        <h1 className="mono">{cve.cve_id}</h1>
        {cve.kev_flag       && <span className="cve-badge cve-badge-kev"    title="CISA Known Exploited">KEV</span>}
        {cve.kev_ransomware && <span className="cve-badge cve-badge-ransom" title="Ransomware campaigns">RANSOM</span>}
        {cve.nuclei_template && <span className="cve-badge cve-badge-tpl"   title="Nuclei template available">TPL</span>}
      </div>

      {/* Stats grid */}
      <div className="org-stats-grid">
        <div className="org-stat-card">
          <div className="label">CVSS v3</div>
          <div className={`value`} style={{color:
            cve.cvss_v3 != null ? `var(--sev-${SEV(cve.cvss_v3)}, var(--text))` : "var(--text-faint)"
          }}>{cve.cvss_v3 != null ? cve.cvss_v3.toFixed(1) : "—"}</div>
          {cve.cvss_v3_vector && <div className="sub mono" style={{fontSize: 9.5}}>{cve.cvss_v3_vector}</div>}
        </div>
        <div className="org-stat-card">
          <div className="label">EPSS</div>
          <div className="value" style={{color:
            cve.epss != null
              ? (cve.epss >= 0.7 ? "var(--sev-critical)" : cve.epss >= 0.4 ? "var(--sev-medium)" : "var(--text)")
              : "var(--text-faint)"
          }}>{cve.epss != null ? cve.epss.toFixed(3) : "—"}</div>
          {cve.epss_percentile != null && (
            <div className="sub">percentile {(cve.epss_percentile * 100).toFixed(1)}%</div>
          )}
        </div>
        <div className="org-stat-card">
          <div className="label">Vendor</div>
          <div className="value mono" style={{fontSize: 16}}>{cve.vendor || "—"}</div>
        </div>
        <div className="org-stat-card">
          <div className="label">Affected assets</div>
          <div className="value">{matches.length}</div>
        </div>
      </div>

      {/* Description */}
      {cve.description && (
        <div className="cve-section">
          <h3>Description</h3>
          <p className="cve-description">{cve.description}</p>
        </div>
      )}

      {/* Dates */}
      <div className="cve-meta">
        {cve.published_at && (
          <span><span className="muted">Published</span> <span className="mono">{cve.published_at.slice(0, 10)}</span></span>
        )}
        {cve.kev_added_at && (
          <span><span className="muted">KEV since</span> <span className="mono">{cve.kev_added_at.slice(0, 10)}</span></span>
        )}
        {cve.nuclei_template && (
          <span><span className="muted">Template</span> <span className="mono">{cve.nuclei_template}</span></span>
        )}
      </div>

      {/* Products */}
      {Array.isArray(cve.products) && cve.products.length > 0 && (
        <div className="cve-section">
          <h3>Products affected</h3>
          <div className="cve-products">
            {cve.products.slice(0, 20).map((p, i) => (
              <span key={i} className="tech-chip">
                {p.vendor}:{p.product}{p.version_constraint ? ` ${p.version_constraint}` : ""}
              </span>
            ))}
            {cve.products.length > 20 && (
              <span className="muted">+{cve.products.length - 20} more</span>
            )}
          </div>
        </div>
      )}

      {/* References */}
      {Array.isArray(cve.refs) && cve.refs.length > 0 && (
        <div className="cve-section">
          <h3>References ({cve.refs.length})</h3>
          <ul className="cve-refs">
            {cve.refs.slice(0, 8).map((u, i) => (
              <li key={i}>
                <a href={u} target="_blank" rel="noopener noreferrer" className="mono">{u}</a>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Affected assets table */}
      <div className="cve-section">
        <h3>Affected assets ({matches.length})</h3>
        {matches.length === 0 ? (
          <div className="muted">No matches on our infra (yet).</div>
        ) : (
          <div className="users-table-wrap">
            <table className="users-table users-table-compact">
              <thead>
                <tr>
                  <th>Host / URL</th>
                  <th>Org</th>
                  <th>Method</th>
                  <th>Source</th>
                  <th>Confidence</th>
                  <th>State</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {matches.map(m => (
                  <tr key={m.id}>
                    <td className="mono">
                      <strong>{m.asset_host || m.asset_ip || m.asset_url}</strong>
                      {m.asset_url && m.asset_host && m.asset_url !== m.asset_host && (
                        <div className="muted" style={{fontSize: 10.5}}>{m.asset_url}</div>
                      )}
                    </td>
                    <td className="mono">{m.organisation_name || <span className="muted">—</span>}</td>
                    <td className="muted mono" style={{fontSize: 10.5}}>{m.match_method}</td>
                    <td className="muted mono" style={{fontSize: 10.5}}>{m.match_source}</td>
                    <td className="mono">
                      <span style={{color:
                        m.confidence >= 0.85 ? "var(--sev-critical)" :
                        m.confidence >= 0.5  ? "var(--sev-medium)"   :
                                               "var(--text-muted)"
                      }}>{m.confidence.toFixed(2)}</span>
                    </td>
                    <td>
                      <span className={`cve-state cve-state-${m.validation_state}`}>{m.validation_state}</span>
                    </td>
                    <td className="actions">
                      {m.attributed_apex && (
                        <>
                          <button className="btn-link"
                                  onClick={() => viewTarget(m.attributed_apex)}
                                  title={`View target ${m.attributed_apex}`}>view</button>
                          <button className="btn-link"
                                  onClick={() => launchScan(m.attributed_apex)}
                                  title={`Launch scan on ${m.attributed_apex}`}>scan</button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="cve-actions">
        <button className="btn-secondary" disabled
                title="Phase B5 — needs Shodan API key">
          <Icon name="globe" size={12}/> Query Shodan (BJ)
        </button>
        <button className="btn-secondary"
                onClick={handleValidate}
                disabled={!cve.nuclei_template || valState === "running" || matches.filter(m => m.match_source === "internal" && m.attributed_apex).length === 0}
                title={
                  !cve.nuclei_template
                    ? "No nuclei template available for this CVE"
                    : matches.filter(m => m.match_source === "internal" && m.attributed_apex).length === 0
                      ? "No internal in-scope matches to validate"
                      : "Run nuclei template against internal in-scope matches"
                }>
          <Icon name={valState === "running" ? "refresh" : "play"} size={12}
                style={valState === "running" ? {animation: "argus-spin 0.9s linear infinite"} : {}}/>
          {valState === "running" ? " validating…" : " Validate with nuclei"}
        </button>
        {valState === "done" && valStats && (
          <span className="muted mono" style={{fontSize: 11, alignSelf: "center"}}>
            ✓ {valStats.validated}/{valStats.matches_considered} validated
            · {valStats.findings} nuclei finding(s)
            · {valStats.elapsed_seconds}s
          </span>
        )}
      </div>
    </div>
  );
}


window.PageActive = PageActive;
window.PageTechnologies = PageTechnologies;
window.PageScreenshots = PageScreenshots;
window.PageURLs = PageURLs;
window.PageJSAnalysis = PageJSAnalysis;
window.PageAttackSurface = PageAttackSurface;
window.PageGFPatterns = PageGFPatterns;
window.PageTakeovers = PageTakeovers;
window.PageEmailSecurity = PageEmailSecurity;
window.PageAPISpecs = PageAPISpecs;
window.PageChecks = PageChecks;
window.PageCVEs = PageCVEs;
window.PageCVEDetail = PageCVEDetail;
window.PageDocs = PageDocs;
window.PageConfig = PageConfig;
