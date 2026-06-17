// h4wk3y3 — page components (Ops Center v2)
const { useState: uS, useEffect: uE, useMemo: uM, useRef: uR } = React;

const SEV_COLORS = {
  critical: "#ff5e62", high: "#ff9b48", medium: "#ffce5a", low: "#6da3ff", info: "#6a7384",
};

// ==================== DASHBOARD ====================
function PageDashboard({ data, onNavigate, onSelectFinding, onLaunchScan, onRerun, openRunId, onCloseRun, onFilterFindings, me }) {
  // Hide write actions for read-only users.
  const canScan = me && roleMeets(me.role, "admin");
  const { counts, stats } = data;
  const topFindings = uM(() => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return [...data.findings].sort((a, b) => order[a.severity] - order[b.severity]).slice(0, 7);
  }, [data]);

  const donutData = SEV_ORDER.map(s => ({ value: counts[s], color: SEV_COLORS[s], label: SEV_LABEL[s] }));

  const sevCards = [
    { sev: "critical", value: counts.critical, delta: stats.delta.critical, label: "Critical" },
    { sev: "high", value: counts.high, delta: stats.delta.high, label: "High" },
    { sev: "medium", value: counts.medium, delta: stats.delta.medium, label: "Medium" },
    { sev: "low", value: counts.low, delta: stats.delta.low, label: "Low" },
  ];
  const inventoryCards = [
    { label: "Subdomains", value: stats.subdomains, delta: stats.delta.subdomains, navTo: "subdomains" },
    { label: "Live Hosts", value: stats.liveHosts, delta: stats.delta.liveHosts, navTo: "live-hosts" },
    { label: "URLs", value: stats.urls.toLocaleString(), delta: stats.delta.urls, navTo: "urls" },
    { label: "Findings", value: stats.findings, delta: stats.delta.findings, navTo: "findings" },
  ];

  const sparkSeries = [
    [3,4,3,5,4,6,8,7,9,11,10,12,11,13],
    [2,3,5,4,6,5,7,8,7,9,8,10,11,10],
    [10,12,9,11,13,15,14,16,18,17,19,21,20,22],
    [40,42,45,43,47,49,52,51,55,54,57,60,59,62],
  ];

  // Tech stack: aggregate technologies across live hosts. The shape is
  // h.tech (renamed by reshapeLiveHost in api.js); h.technologies is raw
  // backend data and isn't on this object.
  const techStack = uM(() => {
    const counter = {};
    (data.liveHosts || []).forEach(h => {
      const techs = h.tech || h.technologies || [];
      techs.forEach(t => {
        if (!t) return;
        const norm = String(t).split(":")[0].trim();   // strip "x-powered-by:next.js" prefix
        if (!norm) return;
        counter[norm] = (counter[norm] || 0) + 1;
      });
    });
    return Object.entries(counter)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
  }, [data.liveHosts]);
  const techMax = techStack[0]?.[1] || 1;

  // Top vulnerable hosts: weight findings by severity to rank hosts.
  // Prefer URL hostname over `target` since target is usually the apex
  // domain (set to target.domain in the modules), which would collapse
  // every finding into a single bucket.
  const topVulnHosts = uM(() => {
    const W = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const byHost = {};
    data.findings.forEach(f => {
      let host = "";
      if (f.url) {
        try { host = new URL(f.url).hostname; } catch (_) { /* fall through */ }
      }
      if (!host) host = f.target || "";
      if (!host) return;
      if (!byHost[host]) byHost[host] = { score: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      const sev = (f.severity || "info").toLowerCase();
      byHost[host].score += W[sev] || 0;
      byHost[host][sev] = (byHost[host][sev] || 0) + 1;
    });
    return Object.entries(byHost)
      .filter(([, v]) => v.score > 0)
      .sort((a, b) => b[1].score - a[1].score)
      .slice(0, 6);
  }, [data.findings]);
  const vulnMax = topVulnHosts[0]?.[1].score || 1;

  // Compose the lede from the real summary if available.
  const summary = data._summary || {};
  const scanIdShort = summary.scan_id ? summary.scan_id.slice(0, 8) : "—";
  const lede = summary.finished_at
    ? `SCAN_${scanIdShort.toUpperCase()} // FINISHED ${summary.finished_at.slice(0,19).replace("T"," ")} UTC`
    : "// NO SCAN SUMMARY YET — RUN h4wk3y3.py -t " + data.target;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-eyebrow">OVERVIEW · {data.target.toUpperCase()}</div>
          <h1>Mission Dashboard</h1>
          <div className="lede">{lede}</div>
        </div>
        {canScan && (
          <div className="page-header-actions">
            <button className="cmd-btn" onClick={onRerun} disabled={!data.target || !onRerun}>
              <Icon name="refresh" size={12}/> Re-run
            </button>
          </div>
        )}
      </div>

      {openRunId && <ScanLogPanel runId={openRunId} onClose={onCloseRun}/>}

      <div className="stat-grid">
        {sevCards.map(c => (
          <div
            key={c.sev}
            className="stat-card-v2"
            style={{cursor:"pointer"}}
            title={`Filter findings: ${c.label}`}
            onClick={() => onFilterFindings && onFilterFindings(c.sev)}
          >
            <div className="stat-label-v2">
              <span className="dot-v2" style={{background: SEV_COLORS[c.sev]}}></span>
              {c.label}
            </div>
            <div className={`stat-value-v2 severity-${c.sev}`}>{c.value}</div>
            <Delta value={c.delta}/>
            <Sparkline values={sparkSeries[SEV_ORDER.indexOf(c.sev)]} color={SEV_COLORS[c.sev]} />
          </div>
        ))}
      </div>

      <div className="stat-grid">
        {inventoryCards.map(c => (
          <div
            key={c.label}
            className="stat-card-v2"
            style={{cursor:"pointer"}}
            title={`Open ${c.label}`}
            onClick={() => onNavigate && onNavigate(c.navTo)}
          >
            <div className="stat-label-v2">{c.label}</div>
            <div className="stat-value-v2">{c.value}</div>
            <Delta value={c.delta} invert={true}/>
          </div>
        ))}
      </div>

      <div className="dash-row">
        <div className="card donut-card">
          <Donut data={donutData}/>
          <div className="donut-legend">
            <div style={{fontFamily:"var(--font-mono)",fontSize:9.5,fontWeight:600,textTransform:"uppercase",letterSpacing:"0.14em",color:"var(--text-faint)",marginBottom:8}}>Severity Distribution</div>
            {donutData.map(d => (
              <div key={d.label} className="legend-row">
                <span className="dot" style={{background:d.color}}></span>
                <span className="lbl">{d.label}</span>
                <span className="num">{d.value}</span>
              </div>
            ))}
            <div style={{borderTop:"1px solid var(--border)",marginTop:8,paddingTop:8,display:"flex",justifyContent:"space-between",fontFamily:"var(--font-mono)",fontSize:10,textTransform:"uppercase",letterSpacing:"0.06em"}}>
              <span style={{color:"var(--text-faint)"}}>Solid / Cand</span>
              <span>
                <span style={{color:"var(--solid)"}}>{data.findings.filter(f=>f.status==="solid").length}</span>
                <span style={{color:"var(--text-faint)"}}> / </span>
                <span style={{color:"var(--candidate)"}}>{data.findings.filter(f=>f.status==="candidate").length}</span>
              </span>
            </div>
          </div>
        </div>

        <div className="card module-card">
          <div style={{fontFamily:"var(--font-mono)",fontSize:9.5,fontWeight:600,textTransform:"uppercase",letterSpacing:"0.14em",color:"var(--text-faint)",marginBottom:10,display:"flex",alignItems:"center",gap:6}}>
            <span style={{display:"inline-block",width:5,height:5,background:"var(--accent)",boxShadow:"0 0 6px var(--accent-glow)"}}/>Tech Stack
          </div>
          {techStack.length === 0 ? (
            <div style={{fontFamily:"var(--font-mono)",fontSize:11,color:"var(--text-faint)",padding:"20px 0",textAlign:"center"}}>
              no technologies detected
            </div>
          ) : techStack.map(([name, count]) => (
            <div key={name} className="threat-bar-row" style={{color:"var(--text)"}}>
              <span className="lbl" style={{minWidth:90,maxWidth:120,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{name}</span>
              <div className="threat-bar-track"><div className="threat-bar-fill" style={{width:`${Math.max((count/techMax)*100, 4)}%`,background:"var(--accent)"}}/></div>
              <span className="num">{count}</span>
            </div>
          ))}
          {techStack.length > 0 && (
            <div style={{marginTop:10,paddingTop:8,borderTop:"1px dashed var(--border)",fontFamily:"var(--font-mono)",fontSize:10,color:"var(--text-faint)",cursor:"pointer"}}
                 onClick={() => onNavigate && onNavigate("technologies")}>
              VIEW ALL <Icon name="chevron-right" size={10}/>
            </div>
          )}
        </div>

        <div className="card radar-card">
          <div style={{fontFamily:"var(--font-mono)",fontSize:9.5,fontWeight:600,textTransform:"uppercase",letterSpacing:"0.14em",color:"var(--text-faint)",marginBottom:10,display:"flex",alignItems:"center",gap:6}}>
            <span style={{display:"inline-block",width:5,height:5,background:"var(--accent)",boxShadow:"0 0 6px var(--accent-glow)"}}/>Top Vulnerable Hosts
          </div>
          {topVulnHosts.length === 0 ? (
            <div style={{fontFamily:"var(--font-mono)",fontSize:11,color:"var(--text-faint)",padding:"20px 0",textAlign:"center"}}>
              no findings yet
            </div>
          ) : topVulnHosts.map(([host, info]) => {
            const breakdown = ["critical","high","medium","low"]
              .filter(s => info[s] > 0)
              .map(s => `${info[s]}${s[0].toUpperCase()}`)
              .join(" ");
            const sev = info.critical > 0 ? "critical" : info.high > 0 ? "high" : info.medium > 0 ? "medium" : "low";
            return (
              <div key={host} className="threat-bar-row" style={{color: SEV_COLORS[sev]}}>
                <span className="lbl" style={{minWidth:0,flex:"1 1 auto",maxWidth:160,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={host}>{host}</span>
                <div className="threat-bar-track"><div className="threat-bar-fill" style={{width:`${Math.max((info.score/vulnMax)*100, 4)}%`}}/></div>
                <span className="num" title={breakdown}>{info.score}pts</span>
              </div>
            );
          })}
          {topVulnHosts.length > 0 && (
            <div style={{marginTop:10,paddingTop:8,borderTop:"1px dashed var(--border)",fontFamily:"var(--font-mono)",fontSize:10,color:"var(--text-faint)",cursor:"pointer"}}
                 onClick={() => onNavigate && onNavigate("findings")}>
              VIEW ALL FINDINGS <Icon name="chevron-right" size={10}/>
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">Priority Targets</div>
          <div className="card-subtitle">// SORTED BY SEVERITY · {data.findings.length} TOTAL</div>
          <div className="card-tools">
            <button className="cmd-btn" onClick={() => onNavigate("findings")}>VIEW ALL <Icon name="chevron-right" size={12}/></button>
          </div>
        </div>
        <div className="table-wrap">
          <table className="data">
            <thead><tr>
              <th className="ridx">#</th>
              <th style={{width:90}}>Severity</th>
              <th style={{width:100}}>Status</th>
              <th style={{width:110}}>Type</th>
              <th>Title</th>
              <th>URL</th>
            </tr></thead>
            <tbody>
              {topFindings.map((f, i) => (
                <tr key={f.id} onClick={() => onSelectFinding(f)}>
                  <td className="ridx">{String(i+1).padStart(2,"0")}</td>
                  <td><SeverityPill sev={f.severity}/></td>
                  <td><StatusPill status={f.status}/></td>
                  <td className="dim">{f.type}</td>
                  <td>{f.title}</td>
                  <td className="url">{f.url}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ==================== FINDINGS ====================
function PageFindings({ data, onSelectFinding, initialSevFilter, onConsumeIntent }) {
  const [sevFilter, setSevFilter] = uS(initialSevFilter || "all");
  const [statusFilter, setStatusFilter] = uS("all");
  const [search, setSearch] = uS("");

  // If we arrived from a Dashboard sev card click, apply it once then clear.
  uE(() => {
    if (initialSevFilter) {
      setSevFilter(initialSevFilter);
      onConsumeIntent && onConsumeIntent();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialSevFilter]);

  const filtered = uM(() => {
    return data.findings.filter(f => {
      if (sevFilter !== "all" && f.severity !== sevFilter) return false;
      if (statusFilter !== "all" && f.status !== statusFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        if (!f.title.toLowerCase().includes(q) && !f.url.toLowerCase().includes(q) && !f.evidence.toLowerCase().includes(q)) return false;
      }
      return true;
    }).sort((a,b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  }, [data, sevFilter, statusFilter, search]);

  const sevCounts = uM(() => {
    const c = { all: data.findings.length };
    SEV_ORDER.forEach(s => c[s] = data.findings.filter(f => f.severity === s).length);
    return c;
  }, [data]);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-eyebrow">SECURITY · FINDINGS</div>
          <h1>Findings</h1>
          <div className="lede">// HIERARCHIZED VULNERABILITY SIGNALS · CLICK ROW FOR EVIDENCE</div>
        </div>
        <div className="page-header-actions">
          <ExportButtons
            rows={filtered.map(f => ({
              severity: f.severity, type: f.type, status: f.status,
              title: f.title, url: f.url || "", target: f.target || "",
              evidence: f.evidence || "", module: f.moduleSource || "",
              tags: (f.tags || []).join(" "),
            }))}
            columns={[
              { key:"severity", label:"severity" },
              { key:"type", label:"type" },
              { key:"status", label:"status" },
              { key:"title", label:"title" },
              { key:"url", label:"url" },
              { key:"target", label:"target" },
              { key:"evidence", label:"evidence" },
              { key:"module", label:"module" },
              { key:"tags", label:"tags" },
            ]}
            basename={`${data.target || "argus"}-findings`}
          />
        </div>
      </div>

      <div className="filter-bar">
        <div className="search-input">
          <span className="prompt">$</span>
          <input
            placeholder="grep title, url, evidence..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <kbd>⌘K</kbd>
        </div>

        <div className="filter-divider"/>

        <div className="filter-group">
          {["all", ...SEV_ORDER].map(s => (
            <button key={s} className={`filter-chip ${sevFilter === s ? "active" : ""}`} onClick={() => setSevFilter(s)}>
              {s !== "all" && <span className="dot" style={{background: SEV_COLORS[s]}}></span>}
              {s === "all" ? "All" : SEV_LABEL[s]}
              <span className="num">{sevCounts[s]}</span>
            </button>
          ))}
        </div>

        <div className="filter-group">
          {["all", "solid", "candidate"].map(s => (
            <button key={s} className={`filter-chip ${statusFilter === s ? "active" : ""}`} onClick={() => setStatusFilter(s)}>
              {s !== "all" && <span className="dot" style={{background: s === "solid" ? "var(--solid)" : "var(--candidate)"}}></span>}
              {s === "all" ? "Any" : s}
            </button>
          ))}
        </div>


        <div className="result-count"><span className="accent">{filtered.length}</span> / {data.findings.length}</div>
      </div>

      <div className="card" style={{borderTopLeftRadius:0,borderTopRightRadius:0,borderTop:"none"}}>
        <div className="table-wrap">
          <table className="data">
            <thead><tr>
              <th className="ridx">#</th>
              <th style={{width:90}}>Severity</th>
              <th style={{width:100}}>Status</th>
              <th style={{width:110}}>Type</th>
              <th>Title</th>
              <th>URL</th>
              <th>Evidence</th>
            </tr></thead>
            <tbody>
              {filtered.map((f, i) => (
                <tr key={f.id} onClick={() => onSelectFinding(f)}>
                  <td className="ridx">{String(i+1).padStart(3,"0")}</td>
                  <td><SeverityPill sev={f.severity}/></td>
                  <td><StatusPill status={f.status}/></td>
                  <td className="dim">{f.type}</td>
                  <td>{f.title}</td>
                  <td className="url">{f.url}</td>
                  <td className="evidence"><span className="ev-text">{f.evidence}</span><CopyButton text={f.evidence}/></td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div className="empty">
              <div className="empty-icon"><Icon name="search" size={40}/></div>
              <div className="empty-title">NO MATCHES</div>
              <div className="empty-msg">Adjust filters or clear the search query.</div>
              <button className="cmd-btn" onClick={() => { setSevFilter("all"); setStatusFilter("all"); setSearch(""); }}>Reset</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ==================== LIVE HOSTS ====================
function PageLiveHosts({ data }) {
  const [statusFilter, setStatusFilter] = uS("all");
  const [search, setSearch] = uS("");

  const groups = uM(() => {
    const g = { all: data.liveHosts.length, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0 };
    data.liveHosts.forEach(h => {
      const k = h.status < 300 ? "2xx" : h.status < 400 ? "3xx" : h.status < 500 ? "4xx" : "5xx";
      g[k]++;
    });
    return g;
  }, [data]);

  const filtered = uM(() => {
    return data.liveHosts.filter(h => {
      if (statusFilter !== "all") {
        const k = h.status < 300 ? "2xx" : h.status < 400 ? "3xx" : h.status < 500 ? "4xx" : "5xx";
        if (k !== statusFilter) return false;
      }
      if (search && !h.url.toLowerCase().includes(search.toLowerCase()) && !(h.title || "").toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [data, statusFilter, search]);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-eyebrow">ASSETS · LIVE HOSTS</div>
          <h1>Live Hosts</h1>
          <div className="lede">// {data.liveHosts.length} RESPONSIVE · HTTPX + TECH FINGERPRINT + WAF</div>
        </div>
        <div className="page-header-actions">
          <ExportButtons
            rows={filtered.map(h => ({
              url: h.url, status: h.status, title: h.title || "",
              tech: (h.tech || []).join(", "), waf: h.waf || "", cname: h.cname || "",
            }))}
            columns={[
              { key:"url", label:"url" },
              { key:"status", label:"status" },
              { key:"title", label:"title" },
              { key:"tech", label:"tech" },
              { key:"waf", label:"waf" },
              { key:"cname", label:"cname" },
            ]}
            basename={`${data.target || "argus"}-live-hosts`}
          />
        </div>
      </div>

      <div className="filter-bar">
        <div className="search-input">
          <span className="prompt">$</span>
          <input placeholder="filter url, title..." value={search} onChange={e => setSearch(e.target.value)}/>
        </div>
        <div className="filter-divider"/>
        <div className="filter-group">
          {[["all","All"],["2xx","2xx"],["3xx","3xx"],["4xx","4xx"],["5xx","5xx"]].map(([k,l]) => (
            <button key={k} className={`filter-chip ${statusFilter === k ? "active" : ""}`} onClick={() => setStatusFilter(k)}>
              {l}<span className="num">{groups[k] || 0}</span>
            </button>
          ))}
        </div>
        <div className="result-count"><span className="accent">{filtered.length}</span> hosts</div>
      </div>

      <div className="card" style={{borderTopLeftRadius:0,borderTopRightRadius:0,borderTop:"none"}}>
        <div className="table-wrap">
          <table className="data">
            <thead><tr>
              <th className="ridx">#</th>
              <th>URL</th>
              <th style={{width:80}}>Status</th>
              <th>Title</th>
              <th>Tech Stack</th>
              <th style={{width:120}}>WAF</th>
            </tr></thead>
            <tbody>
              {filtered.map((h, i) => (
                <tr key={i}>
                  <td className="ridx">{String(i+1).padStart(3,"0")}</td>
                  <td className="url">{h.url}<CopyButton text={h.url}/></td>
                  <td><StatusBadge code={h.status}/></td>
                  <td className="dim" style={{maxWidth:200,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{h.title || <span style={{color:"var(--text-faint)"}}>—</span>}</td>
                  <td>
                    <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
                      {h.tech.map((t,j) => <span key={j} className="tech-chip">{t}</span>)}
                    </div>
                  </td>
                  <td>{h.waf ? <span className="pill pill-sev-low"><Icon name="shield" size={10}/>{h.waf}</span> : <span style={{color:"var(--text-faint)"}}>—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ==================== SUBDOMAINS ====================
// 4-state HTTP status pill. http_up = green, http_down = orange,
// resolves = blue (DNS only), nxdomain = grey-faint.
function HttpStatePill({ state, status }) {
  const map = {
    http_up:   { label: "HTTP UP",   tone: "solid",    code: status || 200 },
    http_down: { label: "HTTP DOWN", tone: "warn",     code: status || 0   },
    resolves:  { label: "RESOLVES",  tone: "info",     code: null },
    nxdomain:  { label: "NXDOMAIN",  tone: "faint",    code: null },
  };
  const m = map[state] || map.nxdomain;
  return (
    <span className={`http-state-pill tone-${m.tone}`} title={state}>
      <span className="dot"/>
      <span className="lab">{m.label}</span>
      {m.code != null && <span className="code">{m.code}</span>}
    </span>
  );
}

function PageSubdomains({ data }) {
  const [search, setSearch] = uS("");
  const [stateFilter, setStateFilter] = uS("all"); // all | http_up | http_down | resolves | nxdomain
  const [ipFilter, setIpFilter] = uS(null);        // when set, only rows whose ips include this IP
  const [hideShared, setHideShared] = uS(false);   // hide IPs hosting >= 5 subs (likely CDN/cluster)

  // ip_clusters: Map<ip, [sub,...]> — count of co-located subs per IP.
  const ipClusters = data.ipClusters || {};
  const sharedIps = uM(() => {
    const big = new Set();
    for (const [ip, subs] of Object.entries(ipClusters)) {
      if ((subs || []).length >= 5) big.add(ip);
    }
    return big;
  }, [ipClusters]);

  const counts = uM(() => {
    const c = { all: 0, http_up: 0, http_down: 0, resolves: 0, nxdomain: 0 };
    for (const s of data.subdomains) {
      c.all++;
      if (c[s.httpState] != null) c[s.httpState]++;
    }
    return c;
  }, [data.subdomains]);

  const filtered = uM(() => {
    return data.subdomains.filter(s => {
      if (stateFilter !== "all" && s.httpState !== stateFilter) return false;
      if (ipFilter && !(s.ips || []).includes(ipFilter)) return false;
      if (hideShared && (s.ips || []).every(ip => sharedIps.has(ip)) && (s.ips || []).length) return false;
      if (search) {
        const q = search.toLowerCase();
        const hay = [
          s.sub, s.cname || "", s.ptr || "",
          ...(s.ips || []),
        ].join(" ").toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [data, search, stateFilter, ipFilter, hideShared, sharedIps]);

  const onClickIp = (ip) => setIpFilter(ipFilter === ip ? null : ip);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-eyebrow">ASSETS · SUBDOMAINS</div>
          <h1>Subdomains</h1>
          <div className="lede">
            // {counts.all} DISCOVERED ·{" "}
            <span style={{color:"var(--solid)"}}>{counts.http_up} HTTP UP</span>{" · "}
            <span style={{color:"var(--accent)"}}>{counts.resolves} RESOLVES-ONLY</span>{" · "}
            <span style={{color:"var(--sev-medium)"}}>{counts.http_down} HTTP DOWN</span>
          </div>
        </div>
        <div className="page-header-actions">
          <ExportButtons
            rows={filtered.map(s => ({
              subdomain: s.sub,
              http_state: s.httpState,
              status: s.statusCode || "",
              ips: (s.ips || []).join(" "),
              cname: s.cname || "",
              ptr: s.ptr || "",
              title: s.title || "",
              tech: (s.tech || []).join(", "),
            }))}
            columns={[
              { key:"subdomain", label:"subdomain" },
              { key:"http_state", label:"http_state" },
              { key:"status", label:"status" },
              { key:"ips", label:"ips" },
              { key:"cname", label:"cname" },
              { key:"ptr", label:"ptr" },
              { key:"title", label:"title" },
              { key:"tech", label:"tech" },
            ]}
            basename={`${data.target || "argus"}-subdomains`}
          />
        </div>
      </div>

      <div className="filter-bar">
        <div className="search-input">
          <span className="prompt">$</span>
          <input
            placeholder="grep sub, cname, ip, ptr..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            autoFocus
          />
        </div>
        <div className="filter-divider"/>
        <div className="filter-group">
          {[
            ["all",       "All",       counts.all],
            ["http_up",   "HTTP UP",   counts.http_up],
            ["resolves",  "Resolves",  counts.resolves],
            ["http_down", "HTTP DOWN", counts.http_down],
            ["nxdomain",  "NXDOMAIN",  counts.nxdomain],
          ].map(([key, label, n]) => (
            <button
              key={key}
              className={`filter-chip ${stateFilter === key ? "active" : ""}`}
              onClick={() => setStateFilter(key)}
            >
              {label} <span className="num">{n}</span>
            </button>
          ))}
        </div>
        <div className="filter-divider"/>
        <button
          className={`filter-chip ${hideShared ? "active" : ""}`}
          onClick={() => setHideShared(!hideShared)}
          title="Hide subs whose IPs all host >=5 other subs (likely CDN/shared)"
        >
          {hideShared ? "✓ " : ""}Hide shared <span className="num">{sharedIps.size}</span>
        </button>
        <div className="result-count"><span className="accent">{filtered.length}</span> / {counts.all}</div>
      </div>

      {ipFilter && (
        <div className="ip-filter-chip">
          <span className="prompt">filter:</span>
          <span className="ip-pill">{ipFilter}</span>
          <span className="dim">{(ipClusters[ipFilter] || []).length} subs co-located</span>
          <button onClick={() => setIpFilter(null)} className="cmd-btn" title="Clear filter">
            <Icon name="x" size={12}/>
          </button>
        </div>
      )}

      <div className="card" style={{borderTopLeftRadius:0,borderTopRightRadius:0,borderTop:"none"}}>
        <div className="table-wrap" style={{maxHeight: "calc(100vh - 300px)", overflowY:"auto"}}>
          <table className="data">
            <thead><tr>
              <th className="ridx">#</th>
              <th>Subdomain</th>
              <th>CNAME</th>
              <th>IP</th>
              <th>PTR</th>
              <th style={{width:140}}>Status</th>
            </tr></thead>
            <tbody>
              {filtered.map((s, i) => {
                const ips = s.ips || [];
                return (
                  <tr key={s.sub + ":" + i}>
                    <td className="ridx">{String(i+1).padStart(3,"0")}</td>
                    <td className="url">{s.sub}<CopyButton text={s.sub}/></td>
                    <td className="mono dim">{s.cname || <span style={{color:"var(--text-faint)"}}>—</span>}</td>
                    <td className="mono">
                      {ips.length === 0
                        ? <span style={{color:"var(--text-faint)"}}>—</span>
                        : ips.map((ip, k) => {
                            const cluster = (ipClusters[ip] || []).length;
                            const shared  = cluster >= 5;
                            return (
                              <span
                                key={ip + k}
                                className={`ip-pill clickable ${ipFilter === ip ? "active" : ""} ${shared ? "shared" : ""}`}
                                onClick={() => onClickIp(ip)}
                                title={`${cluster} subdomain${cluster > 1 ? "s" : ""} on this IP — click to filter`}
                              >
                                {ip}
                                {cluster > 1 && <span className="cluster-badge">{cluster}</span>}
                              </span>
                            );
                          })
                      }
                    </td>
                    <td className="mono dim">{s.ptr || <span style={{color:"var(--text-faint)"}}>—</span>}</td>
                    <td><HttpStatePill state={s.httpState} status={s.status}/></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ==================== SOURCE VIEWER ====================
function PageSourceViewer({ data }) {
  const [selectedIdx, setSelectedIdx] = uS(0);
  const [tab, setTab] = uS("response");
  const [search, setSearch] = uS("");
  const [statusFilter, setStatusFilter] = uS("all");
  // Search scope: "meta" (url+title), "body" (full-text in response body),
  // "regex" (regex against body). Body/regex search makes the page useful
  // for hunting strings/secrets across all fetched responses without
  // copy-pasting bodies one by one.
  const [searchMode, setSearchMode] = uS("meta");
  const [regexError, setRegexError] = uS(null);

  const groups = uM(() => {
    const g = { all: data.sourceItems.length, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 };
    data.sourceItems.forEach(it => {
      const s = it.status || 0;
      const k = s >= 200 && s < 300 ? "2xx"
              : s >= 300 && s < 400 ? "3xx"
              : s >= 400 && s < 500 ? "4xx"
              : s >= 500 && s < 600 ? "5xx"
              : "other";
      g[k]++;
    });
    return g;
  }, [data.sourceItems]);

  // Compile a regex matcher when in regex mode; bail loudly on syntax errors.
  const matcher = uM(() => {
    setRegexError(null);
    if (!search) return null;
    if (searchMode === "regex") {
      try {
        return new RegExp(search, "i");
      } catch (e) {
        setRegexError(String(e.message || e));
        return null;
      }
    }
    return null;
  }, [search, searchMode]);

  const items = uM(() => {
    const q = search.toLowerCase();
    return data.sourceItems.filter(it => {
      if (statusFilter !== "all") {
        const s = it.status || 0;
        const k = s >= 200 && s < 300 ? "2xx"
                : s >= 300 && s < 400 ? "3xx"
                : s >= 400 && s < 500 ? "4xx"
                : s >= 500 && s < 600 ? "5xx"
                : "other";
        if (k !== statusFilter) return false;
      }
      if (search) {
        if (searchMode === "regex") {
          if (!matcher) return false;
          return matcher.test(it.body || "") || matcher.test(it.url || "") || matcher.test(it.title || "");
        }
        if (searchMode === "body") {
          if (!(it.body || "").toLowerCase().includes(q) &&
              !(it.url  || "").toLowerCase().includes(q) &&
              !(it.title|| "").toLowerCase().includes(q)) return false;
          return true;
        }
        // meta
        if (!it.url.toLowerCase().includes(q) && !(it.title || "").toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [data.sourceItems, search, statusFilter, searchMode, matcher]);

  // Reset selection when filter changes and selectedIdx falls out of range.
  uE(() => { if (selectedIdx >= items.length) setSelectedIdx(0); }, [items.length]);

  const selected = items[selectedIdx] || items[0] || data.sourceItems[0];

  const renderBody = (body) => {
    if (body.startsWith("{")) {
      return body.split("\n").map((l, i) => (
        <div key={i}>
          {l.split(/("[^"]*":)/).map((part, j) => part.match(/"[^"]*":/)
            ? <span key={j} className="key-json">{part}</span>
            : <span key={j}>{part}</span>)}
        </div>
      ));
    }
    if (body.startsWith("<!DOCTYPE") || body.startsWith("<")) {
      return body.split("\n").map((l, i) => {
        let rest = l;
        rest = rest.replace(/(<)(\/?[a-zA-Z][a-zA-Z0-9]*)/g, (m, lt, tag) => `\u0001TAG\u0002${lt}${tag}\u0001`);
        rest = rest.replace(/("[^"]*")/g, '\u0001STR\u0002$1\u0001');
        const parts = rest.split('\u0001');
        return (
          <div key={i}>
            {parts.map((p, j) => {
              if (p.startsWith("TAG\u0002")) return <span key={j} className="tag">{p.slice(4)}</span>;
              if (p.startsWith("STR\u0002")) return <span key={j} className="str">{p.slice(4)}</span>;
              return <span key={j}>{p}</span>;
            })}
          </div>
        );
      });
    }
    return <pre>{body}</pre>;
  };

  return (
    <div className="page" style={{paddingBottom: 0}}>
      <div className="page-header">
        <div>
          <div className="page-eyebrow">CONTENT · SOURCE</div>
          <h1>Source Viewer</h1>
          <div className="lede">// {data.sourceItems.length} pages · raw headers + body snippets</div>
        </div>
      </div>

      <div className="filter-bar">
        <div className="search-input">
          <span className="prompt">$</span>
          <input
            placeholder={
              searchMode === "regex" ? "regex against body+url+title (e.g. api[_-]?key=)"
              : searchMode === "body" ? "search inside response bodies + url + title"
              : "filter url, title..."
            }
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <div className="filter-group">
          {[["meta","URL"],["body","Body"],["regex","Regex"]].map(([k,l]) => (
            <button key={k} className={`filter-chip ${searchMode === k ? "active" : ""}`} onClick={() => setSearchMode(k)} title={
              k === "meta" ? "Search URL + title only (fast)" :
              k === "body" ? "Full-text search across all fetched bodies" :
              "JavaScript-style regex against body, URL and title"
            }>{l}</button>
          ))}
        </div>
        <div className="filter-divider"/>
        <div className="filter-group">
          {[["all","All"],["2xx","2xx"],["3xx","3xx"],["4xx","4xx"],["5xx","5xx"],["other","other"]].map(([k,l]) => (
            groups[k] > 0 || k === "all" ? (
              <button key={k} className={`filter-chip ${statusFilter === k ? "active" : ""}`} onClick={() => setStatusFilter(k)}>
                {l}<span className="num">{groups[k] || 0}</span>
              </button>
            ) : null
          ))}
        </div>
        <div className="result-count"><span className="accent">{items.length}</span> / {data.sourceItems.length}</div>
      </div>
      {regexError && (
        <div style={{padding:"6px 14px",fontFamily:"var(--font-mono)",fontSize:11,color:"var(--sev-high)",background:"rgba(255,155,72,0.08)",borderLeft:"2px solid var(--sev-high)"}}>
          regex error: {regexError}
        </div>
      )}

      <div className="source-layout">
        <div className="source-list-card">
          <div className="source-list-scroll">
            {items.map((it, i) => (
              <div key={`${it.url || "u"}::${i}`} className={`source-item ${i === selectedIdx ? "selected" : ""}`} onClick={() => setSelectedIdx(i)}>
                <div className="source-item-row1">
                  <StatusBadge code={it.status}/>
                  <span className="source-url">{it.url}</span>
                </div>
                <div className="source-meta">
                  {it.body.length}B · {it.headers.length} headers
                  {it.length > it.body.length && (
                    <span title={`response was ${it.length}B; m10 stored the first ${it.body.length}B (max_body_size cap)`}
                          style={{marginLeft:8,padding:"1px 5px",background:"rgba(255,155,72,0.15)",color:"var(--sev-high)",borderRadius:2,fontSize:9,letterSpacing:"0.05em"}}>
                      truncated
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="source-viewer-card">
          <div className="source-viewer-tabs">
            <div className={`source-tab ${tab === "response" ? "active" : ""}`} onClick={() => setTab("response")}>Response</div>
            <div className={`source-tab ${tab === "headers" ? "active" : ""}`} onClick={() => setTab("headers")}>Headers</div>
            <div className={`source-tab ${tab === "body" ? "active" : ""}`} onClick={() => setTab("body")}>Body</div>
            <div style={{marginLeft:"auto",padding:"6px 12px",display:"flex",gap:6,alignItems:"center"}}>
              <span className="mono" style={{fontSize:10.5,color:"var(--text-dim)"}}>{selected?.url}</span>
              <button className="cmd-btn" style={{padding:"3px 6px"}}><Icon name="external-link" size={11}/></button>
              <button className="cmd-btn" style={{padding:"3px 6px"}}><Icon name="copy" size={11}/></button>
            </div>
          </div>

          <div className="source-viewer-body">
            {(tab === "response" || tab === "headers") && selected?.headers.map((h, i) => {
              const [k, ...rest] = h.split(": ");
              const v = rest.join(": ");
              if (i === 0) return <div key={i} className="header-line status">{h}</div>;
              return <div key={i} className="header-line"><span className="key">{k}:</span> {v}</div>;
            })}
            {tab === "response" && <div style={{height:14}}/>}
            {(tab === "response" || tab === "body") && selected && (
              <div style={{borderTop: tab === "response" ? "1px dashed var(--border)" : "none", paddingTop: tab === "response" ? 14 : 0}}>
                {renderBody(selected.body)}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ==================== STUB ====================
function PageStub({ title, description, icon, eyebrow }) {
  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-eyebrow">{eyebrow || "MODULE"}</div>
          <h1>{title}</h1>
          <div className="lede">// {description.toUpperCase()}</div>
        </div>
      </div>
      <div className="card">
        <div className="empty" style={{padding:"80px 20px"}}>
          <div className="empty-icon"><Icon name={icon || "circle-dot"} size={40}/></div>
          <div className="empty-title">{title} · MODULE READY</div>
          <div className="empty-msg">Pipeline connected · UI mockup pending in this design pass.</div>
        </div>
      </div>
    </div>
  );
}

// ==================== DRAWER ====================
function FindingDrawer({ finding, onClose }) {
  const open = !!finding;
  const [shown, setShown] = uS(finding);
  uE(() => { if (finding) setShown(finding); }, [finding]);

  return (
    <>
      <div className={`drawer-overlay ${open ? "open" : ""}`} onClick={onClose}/>
      <div className={`drawer ${open ? "open" : ""}`}>
        {shown && (
          <>
            <div className="drawer-header">
              <div style={{flex:1, minWidth:0}}>
                <div className="drawer-id">{shown.id} · {shown.scan_id}</div>
                <div style={{display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
                  <SeverityPill sev={shown.severity}/>
                  <StatusPill status={shown.status}/>
                  <span className="pill" style={{background:"rgba(255,255,255,0.04)",color:"var(--text-muted)",border:"1px solid var(--border)"}}>{shown.type}</span>
                </div>
                <div className="drawer-title">{shown.title}</div>
                <div className="mono" style={{fontSize:10.5,color:"var(--text-muted)",wordBreak:"break-all"}}>{shown.url}</div>
              </div>
              <button className="drawer-close" onClick={onClose}><Icon name="x" size={14}/></button>
            </div>
            <div className="drawer-body">
              <div className="drawer-section">
                <div className="drawer-section-title">Evidence</div>
                <div className="evidence-block">{shown.evidence}</div>
              </div>

              <div className="drawer-section">
                <div className="drawer-section-title">Confidence</div>
                <div style={{display:"flex",alignItems:"center",gap:10}}>
                  <div className="mono" style={{fontSize:18,fontWeight:600,color: shown.confidence > 0.85 ? "var(--solid)" : shown.confidence > 0.7 ? "var(--candidate)" : "var(--text-muted)"}}>
                    {shown.confidence.toFixed(2)}
                  </div>
                  <div style={{flex:1}}>
                    <div className="confidence-bar"><div className="confidence-fill" style={{width:`${shown.confidence*100}%`}}/></div>
                  </div>
                </div>
              </div>

              <div className="drawer-section">
                <div className="drawer-section-title">Metadata</div>
                <div className="kv"><div className="k">Finding ID</div><div className="v">{shown.id}</div></div>
                <div className="kv"><div className="k">Scan ID</div><div className="v">{shown.scan_id}</div></div>
                <div className="kv"><div className="k">Type</div><div className="v">{shown.type}</div></div>
                <div className="kv"><div className="k">Severity</div><div className="v">{SEV_LABEL[shown.severity]}</div></div>
                <div className="kv"><div className="k">Status</div><div className="v">{shown.status}</div></div>
                <div className="kv"><div className="k">First seen</div><div className="v">{shown.firstSeen}</div></div>
                <div className="kv"><div className="k">Last seen</div><div className="v">{shown.lastSeen}</div></div>
                <div className="kv"><div className="k">Target URL</div><div className="v">{shown.url}</div></div>
              </div>

            </div>
            <div className="drawer-footer">
              <button className="cmd-btn cmd-btn-primary"
                onClick={() => { if (shown.url) window.open(shown.url, "_blank", "noopener"); }}
                disabled={!shown.url}
                title="Open URL in a new tab">
                <Icon name="external-link" size={12}/> Open
              </button>
              <button className="cmd-btn"
                onClick={() => navigator.clipboard?.writeText(`curl -i '${shown.url || ""}'`)}
                disabled={!shown.url}
                title="Copy curl command">
                <Icon name="copy" size={12}/> Copy curl
              </button>
              <button className="cmd-btn"
                onClick={() => navigator.clipboard?.writeText(shown.url || "")}
                disabled={!shown.url}
                title="Copy URL to clipboard">
                <Icon name="copy" size={12}/> Copy URL
              </button>
              <button className="cmd-btn"
                onClick={() => navigator.clipboard?.writeText(shown.evidence || "")}
                disabled={!shown.evidence}
                title="Copy evidence string"
                style={{marginLeft:"auto"}}>
                <Icon name="copy" size={12}/> Evidence
              </button>
            </div>
          </>
        )}
      </div>
    </>
  );
}

window.PageDashboard = PageDashboard;
window.PageFindings = PageFindings;
window.PageLiveHosts = PageLiveHosts;
window.PageSubdomains = PageSubdomains;
window.PageSourceViewer = PageSourceViewer;
window.PageStub = PageStub;
window.FindingDrawer = FindingDrawer;
