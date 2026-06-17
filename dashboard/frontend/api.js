// h4wk3y3 — API loader (replaces fixture data.js with live backend calls)
// Exposes: window.ArgusAPI.{ listDomains, loadDomain, exportBurp, exportNuclei, deleteDomain }
// loadDomain(domain) returns an object shaped exactly like the mockup's ARGUS_DATA.
(() => {
  const API = "/api";

  // Intercept 401 globally → redirect to login page. Fire once per session
  // (loop guard) so we don't redirect-loop if /api/auth/me itself 401s.
  let _redirected = false;
  const _handle401 = () => {
    if (_redirected) return;
    _redirected = true;
    // Preserve the current location so login can come back here.
    const next = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `/ui/login.html?next=${next}`;
  };

  // ── CSRF (Étape 1.5) ─────────────────────────────────────────────────
  // Token is fetched lazily on first mutating request and cached in-memory.
  // On a 403 "CSRF token missing or invalid" we refresh the token once and
  // retry the original request — covers session-secret rotation and the
  // initial-load race where the SPA dispatches a mutation before boot.
  const MUTATING = new Set(["POST", "PUT", "DELETE", "PATCH"]);
  let _csrfToken = null;
  let _csrfInflight = null;          // promise-coalescing if many calls race

  const _fetchCsrfToken = async () => {
    // Plain fetch (NOT through j) — we don't want recursion.
    const r = await fetch(API + "/auth/csrf-token",
                          { credentials: "same-origin" });
    if (r.status === 401) { _handle401(); throw new Error("auth required"); }
    if (!r.ok) throw new Error(`csrf-token → ${r.status}`);
    const body = await r.json();
    _csrfToken = body.csrf_token || null;
    return _csrfToken;
  };

  const _ensureCsrf = async () => {
    if (_csrfToken) return _csrfToken;
    if (!_csrfInflight) {
      _csrfInflight = _fetchCsrfToken().finally(() => { _csrfInflight = null; });
    }
    return _csrfInflight;
  };

  // Exposed so login.html (which already has a token in the login response)
  // can seed the cache without an extra round-trip.
  const setCsrfToken = (tok) => { _csrfToken = tok || null; };

  const j = async (path, opts) => {
    const o = Object.assign({ credentials: "same-origin" }, opts || {});
    const method = (o.method || "GET").toUpperCase();

    if (MUTATING.has(method)) {
      const tok = await _ensureCsrf();
      const headers = Object.assign({}, o.headers || {});
      headers["X-CSRF-Token"] = tok;
      o.headers = headers;
    }

    let r = await fetch(API + path, o);

    // On CSRF 403, refresh once and retry. Wrong-token can happen after
    // a session_secret rotation or if the SPA loaded before the cookie
    // was set — both are recoverable without bothering the user.
    if (r.status === 403 && MUTATING.has(method)) {
      let detail = "";
      try { detail = (await r.clone().json()).detail || ""; } catch (_) {}
      if (/csrf/i.test(detail)) {
        _csrfToken = null;
        const tok2 = await _ensureCsrf();
        const headers = Object.assign({}, o.headers || {},
                                      { "X-CSRF-Token": tok2 });
        r = await fetch(API + path, Object.assign({}, o, { headers }));
      }
    }

    if (r.status === 401) {
      _handle401();
      throw new Error(`${path} → 401 (auth required)`);
    }
    if (!r.ok) {
      let detail = `${path} → ${r.status}`;
      try {
        const body = await r.json();
        if (body && body.detail) detail = body.detail;
      } catch (_) { /* not JSON — keep status */ }
      throw new Error(detail);
    }
    if (r.status === 204) return null;
    return r.json();
  };

  // POST/PATCH helper — same auth/error handling as j(), JSON-encodes body.
  const jSend = (path, method, body) => j(path, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  // ── Type label mapping (backend type → UI label used by pages) ────────
  const TYPE_LABEL = {
    nuclei_finding:     "Nuclei",
    pattern_match:      "Pattern Match",
    js_secret:          "JS Secret",
    js_endpoint:        "JS Endpoint",
    subdomain_takeover: "Takeover",
    misconfiguration:   "Misconfig",
    live_host:          "Live Host",
    subdomain:          "Subdomain",
    url:                "URL",
    screenshot:         "Screenshot",
    technology:         "Technology",
    secret_validated:   "Secret",
    api_spec:           "API Spec",
  };

  const labelType = (t) => TYPE_LABEL[t] || (t || "Other");

  // Backend status normalisation: candidate iff metadata.requires_validation === true.
  const inferStatus = (f) => {
    const m = f.metadata || {};
    if (m.requires_validation === true) return "candidate";
    return "solid";
  };

  // Short ID for display: first 4 of UUID.
  const shortId = (id) => id ? `F-${String(id).slice(0, 8).toUpperCase()}` : "F-????????";

  const reshapeFinding = (f) => ({
    id:           shortId(f.id),
    severity:     f.severity || "info",
    status:       inferStatus(f),
    type:         labelType(f.type),
    rawType:      f.type || "",
    moduleSource: f.module_source || "",
    title:        f.title || "(untitled)",
    url:          f.url || f.target || "",
    target:       f.target || "",
    evidence:     f.evidence || "",
    confidence:   typeof f.confidence === "number" ? f.confidence : 0.5,
    tags:         Array.isArray(f.tags) ? f.tags : [],
    metadata:     f.metadata || {},
    scan_id:      f.scan_id || "—",
    firstSeen:    (f.timestamp || "").slice(0, 10) || "—",
    lastSeen:     (f.timestamp || "").slice(0, 10) || "—",
  });

  const reshapeLiveHost = (h) => ({
    url:    h.url,
    status: h.status_code || 0,
    title:  h.title || "",
    tech:   Array.isArray(h.technologies) && h.technologies.length
              ? h.technologies
              : (h.server ? [h.server] : []),
    waf:    h.waf || null,
    cname:  h.cname || null,
  });

  const reshapeSubs = (subsResp, liveHosts) => {
    // Backend may return either the legacy `subdomains: [...]` only, or
    // the new `records: [...]` shape. Prefer the rich one.
    const records = (subsResp && subsResp.records) || null;

    // Build a hostname → status lookup from already-reshaped liveHosts so
    // we keep status codes in sync even on legacy payloads.
    const liveByDomain = {};
    for (const h of liveHosts) {
      try {
        const u = new URL(h.url);
        liveByDomain[u.hostname] = h.status;
      } catch (_) {}
    }

    if (records) {
      return records.map(r => ({
        sub:        r.subdomain,
        cname:      r.cname || null,
        ips:        r.ips || [],
        ptr:        r.ptr || null,
        httpState:  r.http_state || (liveByDomain[r.subdomain] != null ? "http_up" : "nxdomain"),
        live:       r.http_state === "http_up",
        status:     (r.live && r.live.status_code) || liveByDomain[r.subdomain] || 0,
      }));
    }

    // Legacy fallback (older backends).
    const subList   = (subsResp && subsResp.subdomains) || [];
    const cnamesMap = (subsResp && subsResp.cnames)     || {};
    return subList.map(sub => {
      const live = liveByDomain[sub] != null;
      return {
        sub,
        cname:     cnamesMap[sub] || null,
        ips:       [],
        ptr:       null,
        httpState: live ? "http_up" : "nxdomain",
        status:    live ? liveByDomain[sub] : 0,
        live,
      };
    });
  };

  const reshapeSourceItems = (fetchResults) => {
    // fetchResults is [{url, status, title, headers:{}, body_snippet, length}]
    return (fetchResults || []).slice(0, 3000).map(it => {
      const headersObj = it.headers || {};
      const headerLines = [
        `HTTP/1.1 ${it.status || 0} ${it.title ? "— " + it.title : ""}`.trim(),
        ...Object.entries(headersObj).map(([k, v]) => `${k.toLowerCase()}: ${v}`),
      ];
      return {
        url:     it.url,
        status:  it.status || 0,
        title:   it.title || "",
        length:  it.length || (it.body_snippet || "").length,
        headers: headerLines,
        body:    it.body_snippet || "",
      };
    });
  };

  // Compute deltas from scan_summary.json + scan_summary.prev.json
  const computeDelta = (cur, prev) => {
    if (!prev) return { critical:0, high:0, medium:0, low:0, info:0,
                        subdomains:0, liveHosts:0, urls:0, findings:0 };
    const cs = cur.by_severity || {}, ps = prev.by_severity || {};
    return {
      critical:   (cs.critical||0) - (ps.critical||0),
      high:       (cs.high||0)     - (ps.high||0),
      medium:     (cs.medium||0)   - (ps.medium||0),
      low:        (cs.low||0)      - (ps.low||0),
      info:       (cs.info||0)     - (ps.info||0),
      subdomains: (cur.subdomains||0) - (prev.subdomains||0),
      liveHosts:  (cur.live_hosts||0) - (prev.live_hosts||0),
      urls:       (cur.urls||0)       - (prev.urls||0),
      findings:   (cur.findings||0)   - (prev.findings||0),
    };
  };

  async function listDomains() {
    const arr = await j("/domains").catch(() => []);
    return arr.map(d => d.domain);
  }

  async function loadDomain(domain) {
    if (!domain) return emptyShape(domain);

    // Parallel fetch — every endpoint is best-effort.
    const safe = (p) => p.catch(() => null);
    const [
      summary,
      findingsRaw,
      liveHostsRaw,
      subsResp,
      fetchResults,
    ] = await Promise.all([
      safe(j(`/summary/${encodeURIComponent(domain)}`)),
      safe(j(`/findings?domain=${encodeURIComponent(domain)}&limit=2000`)),
      safe(j(`/live-hosts/${encodeURIComponent(domain)}`)),
      safe(j(`/subdomains/${encodeURIComponent(domain)}`)),
      safe(j(`/fetch-results/${encodeURIComponent(domain)}`)),
    ]);

    const findings  = (findingsRaw  || []).map(reshapeFinding);
    const liveHosts = (liveHostsRaw || []).map(reshapeLiveHost);
    const subdomains = reshapeSubs(subsResp || {}, liveHosts);
    const ipClusters = (subsResp && subsResp.ip_clusters) || {};
    const sourceItems = reshapeSourceItems(fetchResults);

    const counts = { critical:0, high:0, medium:0, low:0, info:0 };
    findings.forEach(f => { if (counts[f.severity] != null) counts[f.severity]++; });

    const stats = {
      subdomains: subdomains.length,
      liveHosts:  liveHosts.length,
      urls:       (summary && summary.urls) || 0,
      findings:   findings.length,
      delta:      computeDelta(summary || {}, summary && summary.prev_summary),
    };

    return {
      target: domain,
      targets: [], // filled by caller
      counts,
      subdomains,
      ipClusters,
      liveHosts,
      findings,
      sourceItems,
      stats,
      _summary: summary || null,
    };
  }

  function emptyShape(domain) {
    return {
      target: domain || "—",
      targets: [],
      counts: { critical:0, high:0, medium:0, low:0, info:0 },
      subdomains: [], ipClusters: {}, liveHosts: [], findings: [], sourceItems: [],
      stats: { subdomains:0, liveHosts:0, urls:0, findings:0,
               delta: { critical:0, high:0, medium:0, low:0, info:0,
                        subdomains:0, liveHosts:0, urls:0, findings:0 } },
      _summary: null,
    };
  }

  async function deleteDomain(domain) {
    return j(`/domains/${encodeURIComponent(domain)}`, { method: "DELETE" });
  }

  function exportBurp(domain) {
    window.location.href = `${API}/export/${encodeURIComponent(domain)}/burp-scope`;
  }

  function exportNuclei(domain) {
    window.location.href = `${API}/export/${encodeURIComponent(domain)}/nuclei-targets`;
  }

  // ── Generic per-page exports (CSV / TXT) ─────────────────────────────
  // Used by PageSubdomains, PageLiveHosts, PageFindings, PageURLs,
  // PageAuditLog. Produces an offline download from in-memory rows; no
  // backend roundtrip needed.
  function _csvCell(v) {
    if (v == null) return "";
    let s = typeof v === "string" ? v : (typeof v === "object" ? JSON.stringify(v) : String(v));
    // Quote if contains comma, quote, newline, or leading/trailing space
    const needs = /[",\n\r]/.test(s) || /^\s|\s$/.test(s);
    s = s.replace(/"/g, '""');
    return needs ? `"${s}"` : s;
  }
  function rowsToCSV(rows, columns) {
    // columns = [{ key, label }] OR [string,...]
    const cols = columns.map(c => typeof c === "string" ? { key: c, label: c } : c);
    const head = cols.map(c => _csvCell(c.label)).join(",");
    const body = (rows || []).map(r =>
      cols.map(c => _csvCell(r[c.key])).join(",")
    ).join("\n");
    return head + "\n" + body + "\n";
  }
  function rowsToTXT(rows, formatter) {
    // formatter = (row) => string, OR if undefined: pretty-print "key: value"
    const fn = formatter || ((r) => Object.entries(r).map(([k, v]) =>
      `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`
    ).join("\n"));
    return (rows || []).map(fn).join("\n" + "─".repeat(60) + "\n") + "\n";
  }
  function downloadFile(filename, content, mime) {
    const blob = new Blob([content], { type: mime || "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
  function exportRows(basename, rows, columns, format) {
    // basename: filename without extension. format: 'csv' | 'txt'
    const fmt = (format || "csv").toLowerCase();
    if (fmt === "csv") {
      downloadFile(`${basename}.csv`, rowsToCSV(rows, columns), "text/csv;charset=utf-8");
    } else {
      // For TXT, build a column-aware formatter so the output stays readable
      const cols = (columns || []).map(c => typeof c === "string" ? { key: c, label: c } : c);
      const fmtRow = (r) => cols.map(c => `${c.label}: ${r[c.key] == null ? "" : (typeof r[c.key] === "object" ? JSON.stringify(r[c.key]) : r[c.key])}`).join("\n");
      downloadFile(`${basename}.txt`, rowsToTXT(rows, fmtRow), "text/plain;charset=utf-8");
    }
  }

  // ── Lazy per-page fetchers (called on demand by individual page components) ──
  const enc = encodeURIComponent;
  const lazy = {
    tech:        (d) => j(`/tech/${enc(d)}`),
    screenshots: (d) => j(`/screenshots/${enc(d)}`),
    urls:        (d, all=false) => j(`/urls/${enc(d)}?limit=20000${all ? "&all=true" : ""}`),
    jsSecrets:   (d) => j(`/js-secrets/${enc(d)}`),
    jsEndpoints: (d) => j(`/js-endpoints/${enc(d)}`),
    jsFiles:     (d) => j(`/js-files/${enc(d)}`),
    takeovers:   (d) => j(`/takeovers/${enc(d)}`),
    email:       (d) => j(`/email-security/${enc(d)}`),
    apiSpecs:    (d) => j(`/api-specs/${enc(d)}`),
    patterns:    (d) => j(`/patterns/${enc(d)}`),
    secrets:     (d) => j(`/secrets-validated/${enc(d)}`),
    gfCats:      (d) => j(`/gf/${enc(d)}`),
    gfResults:   (d, cat) => j(`/gf/${enc(d)}/${enc(cat)}`),
    active:      (d) => j(`/active/${enc(d)}`),
  };

  // Screenshot image URL (relative — backend serves binary)
  const screenshotURL = (d, file) => `${API}/screenshots/${enc(d)}/${enc(file)}`;

  // ── Scan control ──────────────────────────────────────────────────────
  const scan = {
    modes:    () => j(`/scan/modes`),
    runs:     () => j(`/scan/runs`),
    status:   (id) => j(`/scan/status/${enc(id)}`),
    active:   (target) => j(`/scan/active/${enc(target)}`),
    start:    (target, mode, modules) => jSend(`/scan/start`, "POST",
                modules ? { target, mode, modules } : { target, mode }),
    stop:     (id)                    => jSend(`/scan/stop/${enc(id)}`, "POST"),
  };

  // ── Auth ──────────────────────────────────────────────────────────────
  const auth = {
    me:       () => j(`/auth/me`),
    logout:   async () => {
      // Best-effort logout; we redirect regardless because the user clicked
      // "log out" and expects to land on the login page.
      try {
        await fetch(`${API}/auth/logout`, { method: "POST", credentials: "same-origin" });
      } catch (_) { /* ignore network error */ }
      window.location.href = "/ui/login.html";
    },
    changePassword: (oldPw, newPw) =>
      jSend(`/auth/change-password`, "POST", { old_password: oldPw, new_password: newPw }),
  };

  // ── Users management (super-admin only — gated by backend) ───────────
  const users = {
    list:          () => j(`/users`),
    create:        (username, password, role) => jSend(`/users`, "POST", { username, password, role }),
    setRole:       (username, role) => jSend(`/users/${enc(username)}/role`, "PATCH", { role }),
    disable:       (username) => jSend(`/users/${enc(username)}/disable`, "PATCH"),
    enable:        (username) => jSend(`/users/${enc(username)}/enable`, "PATCH"),
    resetPassword: (username, newPw) => jSend(`/users/${enc(username)}/reset-password`, "POST", { new_password: newPw }),
  };

  // ── Audit log ─────────────────────────────────────────────────────────
  const audit = {
    list: (params = {}) => {
      const q = new URLSearchParams(params).toString();
      return j(`/audit${q ? `?${q}` : ""}`);
    },
  };

  // ── Config (super-admin only) ─────────────────────────────────────────
  const config = {
    get:    ()       => j(`/config`),
    save:   (data)   => jSend(`/config`, "PUT", data),
    reload: ()       => jSend(`/config/reload`, "POST"),
  };

  // ── Multi-org (Étape 2.1) ─────────────────────────────────────────────
  // GETs are open to any authenticated user; mutations require admin+.
  const orgs = {
    list:    ()                    => j(`/orgs`),
    get:     (name)                => j(`/orgs/${encodeURIComponent(name)}`),
    stats:   (name)                => j(`/orgs/${encodeURIComponent(name)}/stats`),
    create:  (data)                => jSend(`/orgs`, "POST", data),
    update:  (name, patch)         => jSend(`/orgs/${encodeURIComponent(name)}`, "PATCH", patch),
    remove:  (name, force = false) =>
      jSend(`/orgs/${encodeURIComponent(name)}?force=${force ? "true" : "false"}`, "DELETE"),
    linkTarget:   (name, payload)  =>
      jSend(`/orgs/${encodeURIComponent(name)}/targets`, "POST", payload),
    unlinkTarget: (name, apex)     =>
      jSend(`/orgs/${encodeURIComponent(name)}/targets/${encodeURIComponent(apex)}`, "DELETE"),
    listTargets:  (org)            =>
      j(`/targets${org ? `?org=${encodeURIComponent(org)}` : ""}`),
    listUnlinkedTargets: ()        => j(`/targets?unlinked=true`),
    // Enriched view used by PageOrgDetail: per-target last_scan, sub/host/findings counts.
    targetsEnriched: (name)        =>
      j(`/orgs/${encodeURIComponent(name)}/targets/enriched`),
  };

  // ── CVE intelligence ────────────────────────────────────────────────
  const cves = {
    // List with filters. `params` = {kev_only, ransomware, min_cvss, min_epss,
    //   vendor, search, has_template, has_matches, sort, limit, offset}.
    list: (params = {}) => {
      const qs = Object.entries(params)
        .filter(([_, v]) => v !== null && v !== undefined && v !== "")
        .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
        .join("&");
      return j(`/cves${qs ? `?${qs}` : ""}`);
    },
    stats:   () => j(`/cves/stats`),
    vendors: (limit = 50) => j(`/cves/vendors?limit=${limit}`),
    get:     (cveId) => j(`/cves/${encodeURIComponent(cveId)}`),
    // Trigger m15 pull (+ auto m17 correlator). Returns {pull, correlate}.
    pull:    ({ recentOnly = true, years = null, correlate = true } = {}) => {
      const qs = [
        `recent_only=${recentOnly ? "true" : "false"}`,
        `correlate=${correlate ? "true" : "false"}`,
      ];
      if (years) qs.push(`years=${encodeURIComponent(years)}`);
      return jSend(`/cves/pull?${qs.join("&")}`, "POST");
    },
    // Re-run correlator only (no feed pull). Useful when new scans landed.
    correlate: () => jSend(`/cves/correlate`, "POST"),
    // Validate a CVE with nuclei : runs the template against internal
    // in-scope matches, upgrades hits to validated/0.95 confidence.
    validate: (cveId) =>
      jSend(`/cves/${encodeURIComponent(cveId)}/validate`, "POST"),
  };

  // ── Attack Surface — flat inventory (cross-target host cards) ───────
  const attackSurface = {
    // Flat list of hosts enriched with status, tech[], waf, findings_by_sev,
    // is_orphan (attributed_apex IS NULL).
    // - org: restrict to a constituent (null = all orgs)
    // - includeOrphans: include hosts without attributed_apex (shadow IT)
    hosts: (org, { includeOrphans = true } = {}) => {
      const params = [];
      if (org) params.push(`org=${encodeURIComponent(org)}`);
      if (!includeOrphans) params.push("include_orphans=false");
      const qs = params.length ? `?${params.join("&")}` : "";
      return j(`/attack-surface/hosts${qs}`);
    },
  };

  window.ArgusAPI = {
    listDomains, loadDomain, deleteDomain, exportBurp, exportNuclei, emptyShape,
    lazy, screenshotURL, scan,
    auth, users, audit, config, orgs, attackSurface, cves,
    // Generic per-page export helpers
    exportRows, rowsToCSV, rowsToTXT, downloadFile,
    // CSRF token cache — login page seeds this with the token returned
    // alongside the session cookie so the SPA doesn't have to re-fetch.
    setCsrfToken,
  };
})();
