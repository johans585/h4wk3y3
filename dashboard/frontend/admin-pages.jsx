// h4wk3y3 — Admin pages (Users management + Audit Log)
// PageUsers   : super-admin only — list / add / disable / role / reset password
// PageAuditLog: admin sees own, super-admin sees all (backend enforces)

// ROLE_RANK / roleMeets are defined on `window` by index.html's bootstrap script.
// Locally re-bind for readability; safe because babel-standalone gives each
// script its own const-scope.
const ROLE_RANK = window.ROLE_RANK;
const roleMeets = window.roleMeets;

// ──────────────────────────────────────────────────────────
// PageUsers — super-admin only
// ──────────────────────────────────────────────────────────
function PageUsers({ me }) {
  const [users, setUsers] = React.useState([]);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState(null);
  const [showAdd, setShowAdd] = React.useState(false);

  const reload = React.useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const u = await window.ArgusAPI.users.list();
      setUsers(u);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }, []);

  React.useEffect(() => { reload(); }, [reload]);

  if (me.role !== "super-admin") {
    return (
      <div className="card" style={{padding:24}}>
        <div className="empty"><div className="empty-title">access denied</div>
          <div style={{color:"var(--text-dim)",fontSize:12,marginTop:6}}>
            Only super-admin can manage users.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <PageHeader title="USERS" lede={`${users.length} account(s) · super-admin can create / disable / change roles`}/>
      <div style={{marginBottom:14,display:"flex",gap:10}}>
        <button className="cmd-btn cmd-btn-primary" onClick={() => setShowAdd(true)}>
          <Icon name="plus" size={12}/><span>Add user</span>
        </button>
        <button className="cmd-btn" onClick={reload} disabled={loading}>
          <span style={{display:"inline-flex",animation: loading ? "argus-spin 0.9s linear infinite" : "none"}}>
            <Icon name="refresh" size={12}/>
          </span>
          <span>Reload</span>
        </button>
      </div>

      {error && <div className="card" style={{padding:14,color:"var(--sev-critical)",marginBottom:12}}>{error}</div>}

      {showAdd && <AddUserModal onClose={() => { setShowAdd(false); reload(); }}/>}

      <div className="card">
        <table className="data">
          <thead><tr>
            <th>Username</th><th>Role</th><th>Enabled</th>
            <th>Created</th><th>Last login</th><th style={{width:300}}>Actions</th>
          </tr></thead>
          <tbody>
            {users.map(u => (
              <UserRow key={u.username} user={u} me={me} onChange={reload}/>
            ))}
            {users.length === 0 && !loading && (
              <tr><td colSpan="6" style={{textAlign:"center",color:"var(--text-dim)",padding:24}}>no users</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function UserRow({ user, me, onChange }) {
  const [busy, setBusy] = React.useState(false);
  const isSelf = user.username === me.username;

  const action = async (fn, label) => {
    if (busy) return;
    if (!confirm(`${label} ${user.username}?`)) return;
    setBusy(true);
    try { await fn(); onChange(); }
    catch (e) { alert(String(e)); }
    finally { setBusy(false); }
  };

  const setRole = async () => {
    const r = prompt(`New role for ${user.username} (super-admin / admin / user):`, user.role);
    if (!r || !["super-admin","admin","user"].includes(r)) return;
    setBusy(true);
    try { await window.ArgusAPI.users.setRole(user.username, r); onChange(); }
    catch (e) { alert(String(e)); }
    finally { setBusy(false); }
  };

  const resetPwd = async () => {
    const p = prompt(`New password for ${user.username} (min 8 chars):`);
    if (!p || p.length < 8) return;
    setBusy(true);
    try { await window.ArgusAPI.users.resetPassword(user.username, p); alert("password updated"); }
    catch (e) { alert(String(e)); }
    finally { setBusy(false); }
  };

  const roleColor = {
    "super-admin": "var(--sev-critical, #ff5e62)",
    "admin":       "var(--accent, #5be7a9)",
    "user":        "var(--text-dim, #7a8597)",
  }[user.role] || "var(--text-dim)";

  return (
    <tr style={{opacity: user.enabled ? 1 : 0.5}}>
      <td className="mono">{user.username}{isSelf && <span style={{marginLeft:6,fontSize:10,color:"var(--text-dim)"}}>(you)</span>}</td>
      <td><span className="mono" style={{fontSize:10,letterSpacing:"0.05em",color:roleColor,textTransform:"uppercase"}}>{user.role}</span></td>
      <td>{user.enabled ? <span style={{color:"var(--accent)"}}>✓</span> : <span style={{color:"var(--sev-critical)"}}>✗</span>}</td>
      <td className="mono" style={{fontSize:11}}>{(user.created_at || "").slice(0,16).replace("T"," ")}</td>
      <td className="mono" style={{fontSize:11}}>{(user.last_login || "—").slice(0,16).replace("T"," ")}</td>
      <td>
        <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
          <button className="cmd-btn" disabled={busy} onClick={setRole} title="Change role">role</button>
          <button className="cmd-btn" disabled={busy} onClick={resetPwd} title="Reset password">pwd</button>
          {user.enabled
            ? <button className="cmd-btn cmd-btn-danger" disabled={busy || isSelf}
                      onClick={() => action(() => window.ArgusAPI.users.disable(user.username), "Disable")}
                      title={isSelf ? "Cannot disable yourself" : "Disable user"}>disable</button>
            : <button className="cmd-btn" disabled={busy}
                      onClick={() => action(() => window.ArgusAPI.users.enable(user.username), "Enable")}>enable</button>
          }
        </div>
      </td>
    </tr>
  );
}

function AddUserModal({ onClose }) {
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [role, setRole] = React.useState("user");
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setErr(null); setBusy(true);
    try {
      await window.ArgusAPI.users.create(username, password, role);
      onClose();
    } catch (e) { setErr(String(e)); setBusy(false); }
  };

  return (
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.6)",display:"flex",
                 alignItems:"center",justifyContent:"center",zIndex:1000}}
         onClick={onClose}>
      <div className="card" style={{padding:24,width:400}} onClick={e => e.stopPropagation()}>
        <h3 style={{margin:"0 0 18px"}}>Add user</h3>
        <form onSubmit={submit}>
          <label style={{fontSize:11,color:"var(--text-dim)",letterSpacing:"0.08em",textTransform:"uppercase"}}>Username</label>
          <input type="text" value={username} onChange={e => setUsername(e.target.value)}
                 required autoFocus
                 style={{width:"100%",padding:10,background:"rgba(255,255,255,0.04)",
                         border:"1px solid var(--border)",borderRadius:6,color:"var(--text)",
                         fontFamily:"'JetBrains Mono',monospace",marginTop:6,marginBottom:14}}/>
          <label style={{fontSize:11,color:"var(--text-dim)",letterSpacing:"0.08em",textTransform:"uppercase"}}>Password (min 8)</label>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                 required minLength={8}
                 style={{width:"100%",padding:10,background:"rgba(255,255,255,0.04)",
                         border:"1px solid var(--border)",borderRadius:6,color:"var(--text)",
                         fontFamily:"'JetBrains Mono',monospace",marginTop:6,marginBottom:14}}/>
          <label style={{fontSize:11,color:"var(--text-dim)",letterSpacing:"0.08em",textTransform:"uppercase"}}>Role</label>
          <select value={role} onChange={e => setRole(e.target.value)}
                  style={{width:"100%",padding:10,background:"rgba(255,255,255,0.04)",
                          border:"1px solid var(--border)",borderRadius:6,color:"var(--text)",
                          marginTop:6,marginBottom:14}}>
            <option value="user">user (read-only)</option>
            <option value="admin">admin (scan + read)</option>
            <option value="super-admin">super-admin (full)</option>
          </select>
          {err && <div style={{padding:10,background:"rgba(255,94,98,0.1)",border:"1px solid rgba(255,94,98,0.4)",
                              borderRadius:6,color:"var(--sev-critical)",fontSize:13,marginBottom:12}}>{err}</div>}
          <div style={{display:"flex",gap:10,justifyContent:"flex-end",marginTop:12}}>
            <button type="button" className="cmd-btn" onClick={onClose} disabled={busy}>Cancel</button>
            <button type="submit" className="cmd-btn cmd-btn-primary" disabled={busy}>
              {busy ? "Creating..." : "Create"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────
// PageAuditLog — admin sees own, super-admin sees all
// ──────────────────────────────────────────────────────────
function PageAuditLog({ me }) {
  const [entries, setEntries] = React.useState([]);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState(null);
  const [filterUser, setFilterUser] = React.useState("");
  const [filterAction, setFilterAction] = React.useState("");
  const [filterSince, setFilterSince] = React.useState("");

  const reload = React.useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const params = { limit: 500 };
      if (filterUser) params.username = filterUser;
      if (filterAction) params.action = filterAction;
      if (filterSince) params.since = filterSince;
      const list = await window.ArgusAPI.audit.list(params);
      setEntries(list);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }, [filterUser, filterAction, filterSince]);

  React.useEffect(() => { reload(); }, [reload]);

  if (!roleMeets(me.role, "admin")) {
    return (
      <div className="card" style={{padding:24}}>
        <div className="empty"><div className="empty-title">access denied</div>
          <div style={{color:"var(--text-dim)",fontSize:12,marginTop:6}}>
            Audit log requires admin or super-admin role.
          </div>
        </div>
      </div>
    );
  }

  const isSuper = me.role === "super-admin";
  const lede = isSuper
    ? `${entries.length} entry/entries · super-admin sees all`
    : `${entries.length} entry/entries · admin sees own actions only`;

  const actionColor = (action) => {
    if (action.includes("FAILURE")) return "var(--sev-critical)";
    if (action.includes("SUCCESS") || action.includes("LOGIN")) return "var(--accent)";
    if (action.includes("DELETED") || action.includes("DISABLED")) return "var(--sev-high)";
    if (action.includes("CREATED") || action.includes("STARTED")) return "var(--candidate)";
    return "var(--text-dim)";
  };

  return (
    <div className="page">
      <PageHeader title="AUDIT LOG" lede={lede}/>
      <div style={{display:"flex",gap:10,marginBottom:14,flexWrap:"wrap"}}>
        {isSuper && (
          <input placeholder="filter by username" value={filterUser}
                 onChange={e => setFilterUser(e.target.value)}
                 style={{padding:8,background:"rgba(255,255,255,0.04)",
                         border:"1px solid var(--border)",borderRadius:6,
                         color:"var(--text)",fontFamily:"'JetBrains Mono',monospace",
                         fontSize:12,minWidth:180}}/>
        )}
        <input placeholder="filter by action (e.g. SCAN_STARTED)" value={filterAction}
               onChange={e => setFilterAction(e.target.value)}
               style={{padding:8,background:"rgba(255,255,255,0.04)",
                       border:"1px solid var(--border)",borderRadius:6,
                       color:"var(--text)",fontFamily:"'JetBrains Mono',monospace",
                       fontSize:12,minWidth:240}}/>
        <input type="datetime-local" value={filterSince}
               onChange={e => setFilterSince(e.target.value ? e.target.value + ":00Z" : "")}
               style={{padding:8,background:"rgba(255,255,255,0.04)",
                       border:"1px solid var(--border)",borderRadius:6,
                       color:"var(--text)",fontSize:12}}/>
        <button className="cmd-btn" onClick={reload} disabled={loading}>
          <span style={{display:"inline-flex",animation: loading ? "argus-spin 0.9s linear infinite" : "none"}}>
            <Icon name="refresh" size={12}/>
          </span>
          <span>Reload</span>
        </button>
        <ExportButtons
          rows={entries.map(e => ({
            ts: e.ts, username: e.username || "",
            ip: e.ip || "", action: e.action,
            target: e.target || "",
            details: e.details ? JSON.stringify(e.details) : "",
          }))}
          columns={[
            { key:"ts", label:"timestamp" },
            { key:"username", label:"username" },
            { key:"ip", label:"ip" },
            { key:"action", label:"action" },
            { key:"target", label:"target" },
            { key:"details", label:"details" },
          ]}
          basename="argus-audit-log"
        />
      </div>

      {error && <div className="card" style={{padding:14,color:"var(--sev-critical)",marginBottom:12}}>{error}</div>}

      <div className="card" style={{maxHeight:"calc(100vh - 320px)",overflowY:"auto"}}>
        <table className="data">
          <thead><tr>
            <th style={{width:160}}>Timestamp</th>
            <th style={{width:130}}>Username</th>
            <th style={{width:110}}>IP</th>
            <th style={{width:200}}>Action</th>
            <th style={{width:200}}>Target</th>
            <th>Details</th>
          </tr></thead>
          <tbody>
            {entries.map(e => (
              <tr key={e.id}>
                <td className="mono" style={{fontSize:11}}>{e.ts.slice(0,19).replace("T"," ")}</td>
                <td className="mono">{e.username || <span style={{color:"var(--text-faint)"}}>—</span>}</td>
                <td className="mono" style={{fontSize:11}}>{e.ip || "—"}</td>
                <td><span className="mono" style={{fontSize:11,color:actionColor(e.action)}}>{e.action}</span></td>
                <td className="mono" style={{fontSize:11}}>{e.target || "—"}</td>
                <td className="mono" style={{fontSize:11,color:"var(--text-dim)"}}>
                  {e.details ? JSON.stringify(e.details).slice(0,200) : "—"}
                </td>
              </tr>
            ))}
            {entries.length === 0 && !loading && (
              <tr><td colSpan="6" style={{textAlign:"center",color:"var(--text-dim)",padding:24}}>no entries</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}


// ──────────────────────────────────────────────────────────
// PageOrgs — admin+ — Étape 2.1 multi-org management
// ──────────────────────────────────────────────────────────
// `onSelectOrg(name)` : called when a row is clicked / "open" pressed.
// Provided by App to switch to PageOrgDetail. If absent (legacy callers),
// falls back to the in-place OrgDetailModal (preserves backwards compat).
function PageOrgs({ me, onSelectOrg }) {
  const canMutate = me && roleMeets(me.role, "admin");
  const [orgs, setOrgs] = React.useState([]);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState(null);
  const [showAdd, setShowAdd] = React.useState(false);
  const [editing, setEditing] = React.useState(null);    // org dict being edited
  const [detailOrg, setDetailOrg] = React.useState(null); // fallback modal target

  // Persisted UI state — survive reloads, share across tabs.
  const [search, setSearch] = React.useState(() => {
    try { return localStorage.getItem("argus.orgs.search") || ""; }
    catch (_) { return ""; }
  });
  const [sortBy, setSortBy] = React.useState(() => {
    try { return localStorage.getItem("argus.orgs.sortBy") || "name"; }
    catch (_) { return "name"; }
  });
  const [sortDir, setSortDir] = React.useState(() => {
    try { return localStorage.getItem("argus.orgs.sortDir") || "asc"; }
    catch (_) { return "asc"; }
  });
  React.useEffect(() => {
    try { localStorage.setItem("argus.orgs.search", search); } catch (_) {}
  }, [search]);
  React.useEffect(() => {
    try {
      localStorage.setItem("argus.orgs.sortBy", sortBy);
      localStorage.setItem("argus.orgs.sortDir", sortDir);
    } catch (_) {}
  }, [sortBy, sortDir]);

  const reload = React.useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const list = await window.ArgusAPI.orgs.list();
      setOrgs(list);
      if (window.ArgusOrgsReload) window.ArgusOrgsReload();
    } catch (e) { setError(String(e)); }
    finally   { setLoading(false); }
  }, []);
  React.useEffect(() => { reload(); }, [reload]);

  const handleDelete = async (org, e) => {
    e?.stopPropagation?.();
    if (!confirm(`Delete organisation ${org.name}? This unlinks all its targets.`)) return;
    try {
      await window.ArgusAPI.orgs.remove(org.name, true);
      reload();
    } catch (e) { alert("delete failed: " + (e.message || e)); }
  };

  const openOrg = (name) => {
    if (onSelectOrg) onSelectOrg(name);
    else             setDetailOrg(name);
  };

  // Filter + sort (client-side — 86 lignes max, instantané).
  const filteredOrgs = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    let rows = orgs;
    if (q) {
      rows = rows.filter(o =>
        (o.name  || "").toLowerCase().includes(q) ||
        (o.notes || "").toLowerCase().includes(q)
      );
    }
    const dir = sortDir === "desc" ? -1 : 1;
    rows = [...rows].sort((a, b) => {
      let cmp = 0;
      if (sortBy === "name") {
        cmp = String(a.name || "").toLowerCase()
              .localeCompare(String(b.name || "").toLowerCase());
      } else if (sortBy === "targets") {
        cmp = (a.target_count || 0) - (b.target_count || 0);
      } else if (sortBy === "created") {
        cmp = String(a.created_at || "").localeCompare(String(b.created_at || ""));
      }
      return cmp * dir;
    });
    return rows;
  }, [orgs, search, sortBy, sortDir]);

  const totalTargets = orgs.reduce((s, o) => s + (o.target_count || 0), 0);

  const toggleSort = (col) => {
    if (sortBy === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else                { setSortBy(col); setSortDir("asc"); }
  };
  const sortArrow = (col) => (
    sortBy === col ? (sortDir === "asc" ? " ↑" : " ↓") : ""
  );

  return (
    <div className="page page-orgs">
      <div className="page-header">
        <h1>Organisations</h1>
        <div className="page-actions">
          <button className="btn-secondary" onClick={reload} disabled={loading}>
            <Icon name="refresh"/> Reload
          </button>
          {canMutate && (
            <button className="btn-primary" onClick={() => setShowAdd(true)}>
              <Icon name="plus"/> New organisation
            </button>
          )}
        </div>
      </div>

      {/* Compteurs résumés */}
      <div className="orgs-summary">
        <div className="orgs-summary-stat">
          <strong>{orgs.length}</strong>
          <span> organisations</span>
        </div>
        <div className="orgs-summary-stat">
          <strong>{totalTargets}</strong>
          <span> targets</span>
        </div>
      </div>

      {/* Search */}
      <div className="orgs-toolbar">
        <input type="search"
               className="form-input orgs-search"
               placeholder={`Search ${orgs.length} orgs (name, notes)…`}
               value={search}
               onChange={(e) => setSearch(e.target.value)}/>
        {search && (
          <span className="muted orgs-search-count">
            {filteredOrgs.length} / {orgs.length}
          </span>
        )}
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="users-table-wrap">
        <table className="users-table users-table-compact">
          <thead>
            <tr>
              <th className="sortable" onClick={() => toggleSort("name")}>
                Name{sortArrow("name")}
              </th>
              <th className="sortable" onClick={() => toggleSort("targets")}>
                Targets{sortArrow("targets")}
              </th>
              <th>Notes</th>
              <th className="sortable" onClick={() => toggleSort("created")}>
                Created{sortArrow("created")}
              </th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredOrgs.length === 0 ? (
              <tr><td colSpan="5" className="empty">
                {loading
                  ? "Loading…"
                  : (search ? `No match for "${search}".` : "No organisations yet.")}
              </td></tr>
            ) : filteredOrgs.map(o => (
              <tr key={o.id}
                  className="row-clickable"
                  onClick={() => openOrg(o.name)}
                  title={`Open ${o.name}`}>
                <td><strong>{o.name}</strong></td>
                <td>{o.target_count || 0}</td>
                <td className="muted">{o.notes || <span className="muted">—</span>}</td>
                <td className="muted">{o.created_at?.slice(0, 10)}</td>
                <td className="actions" onClick={(e) => e.stopPropagation()}>
                  {canMutate && (
                    <>
                      <button className="btn-link" onClick={() => setEditing(o)}>edit</button>
                      <button className="btn-link danger" onClick={(e) => handleDelete(o, e)}>
                        delete
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showAdd && (
        <OrgEditModal
          mode="create"
          onClose={() => setShowAdd(false)}
          onSaved={() => { setShowAdd(false); reload(); }}
        />
      )}
      {editing && (
        <OrgEditModal
          mode="edit"
          org={editing}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); reload(); }}
        />
      )}
      {detailOrg && (
        <OrgDetailModal
          name={detailOrg}
          canMutate={canMutate}
          onClose={() => setDetailOrg(null)}
          onChanged={reload}
        />
      )}
    </div>
  );
}


function OrgEditModal({ mode, org, onClose, onSaved }) {
  const [name,   setName]   = React.useState(org?.name || "");
  const [notes,  setNotes]  = React.useState(org?.notes || "");
  const [err,    setErr]    = React.useState(null);
  const [saving, setSaving] = React.useState(false);

  const save = async (e) => {
    e.preventDefault();
    setSaving(true); setErr(null);
    try {
      if (mode === "create") {
        await window.ArgusAPI.orgs.create({
          name:  name.trim(),
          notes: notes.trim() || null,
        });
      } else {
        await window.ArgusAPI.orgs.update(org.name, {
          notes: notes.trim() || null,
        });
      }
      onSaved();
    } catch (e) {
      setErr(e.message || String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <header className="modal-header">
          <h2>{mode === "create" ? "Create organisation" : `Edit ${org.name}`}</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </header>
        <form onSubmit={save} className="modal-body">
          {err && <div className="alert alert-error">{err}</div>}
          {mode === "create" && (
            <label>
              <span>Name</span>
              <input type="text" value={name} onChange={(e) => setName(e.target.value)}
                     placeholder="acme" required pattern="[A-Za-z0-9._\-]+" autoFocus />
            </label>
          )}
          <label>
            <span>Notes</span>
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows="3"/>
          </label>
          <div className="modal-actions">
            <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-primary" disabled={saving}>
              {saving ? "Saving…" : "Save"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}


function OrgDetailModal({ name, canMutate, onClose, onChanged }) {
  const [detail,  setDetail]  = React.useState(null);
  const [loading, setLoading] = React.useState(true);
  const [err,     setErr]     = React.useState(null);
  const [newApex, setNewApex] = React.useState("");

  const reload = React.useCallback(async () => {
    setLoading(true); setErr(null);
    try {
      const d = await window.ArgusAPI.orgs.get(name);
      setDetail(d);
    } catch (e) { setErr(String(e)); }
    finally   { setLoading(false); }
  }, [name]);
  React.useEffect(() => { reload(); }, [reload]);

  const link = async (e) => {
    e.preventDefault();
    if (!newApex.trim()) return;
    try {
      await window.ArgusAPI.orgs.linkTarget(name, { apex: newApex.trim() });
      setNewApex("");
      await reload();
      if (onChanged) onChanged();
    } catch (e) { alert("link failed: " + (e.message || e)); }
  };
  const unlink = async (apex) => {
    if (!confirm(`Unlink ${apex} from ${name}?`)) return;
    try {
      await window.ArgusAPI.orgs.unlinkTarget(name, apex);
      await reload();
      if (onChanged) onChanged();
    } catch (e) { alert("unlink failed: " + (e.message || e)); }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
        <header className="modal-header">
          <h2>{name} — targets &amp; stats</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </header>
        <div className="modal-body">
          {err && <div className="alert alert-error">{err}</div>}
          {loading && <div>Loading…</div>}
          {detail && (
            <>
              <div className="org-stats">
                <span><strong>{detail.stats.targets}</strong> targets</span>
                <span><strong>{detail.stats.scans}</strong> scans</span>
                <span><strong>{detail.stats.live_hosts}</strong> live hosts</span>
                <span><strong>{detail.stats.findings}</strong> findings</span>
                {detail.stats.by_severity && Object.entries(detail.stats.by_severity).map(([s, n]) => (
                  <span key={s} className={`sev-pill sev-${s}`}>{s}: {n}</span>
                ))}
              </div>

              <h3>Targets ({detail.targets.length})</h3>
              <table className="users-table">
                <thead>
                  <tr><th>Apex</th><th>Linked</th><th></th></tr>
                </thead>
                <tbody>
                  {detail.targets.length === 0 ? (
                    <tr><td colSpan="3" className="empty">No targets linked.</td></tr>
                  ) : detail.targets.map(t => (
                    <tr key={t.apex}>
                      <td className="mono">{t.apex}</td>
                      <td className="muted">{t.created_at?.slice(0,10)}</td>
                      <td className="actions">
                        {canMutate && (
                          <button className="btn-link danger" onClick={() => unlink(t.apex)}>
                            unlink
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {canMutate && (
                <form onSubmit={link} className="org-link-form">
                  <input type="text" value={newApex} onChange={(e) => setNewApex(e.target.value)}
                         placeholder="apex to link (e.g. acme.com)"/>
                  <button type="submit" className="btn-primary" disabled={!newApex.trim()}>
                    <Icon name="plus"/> Link target
                  </button>
                </form>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}


// PageOrgDetail — dedicated page per organisation (replaces OrgDetailModal
// for the main flow). Loads /api/orgs/{name} + /api/orgs/{name}/targets/enriched,
// renders header + stats grid + searchable targets table.
//
// Row click OR scan button → window.openScanModal({target, org}) (exposed by App).
// ──────────────────────────────────────────────────────────────────────────
function PageOrgDetail({ name, me, onBack, onChanged }) {
  const canMutate = me && roleMeets(me.role, "admin");
  const [org,     setOrg]     = React.useState(null);
  const [stats,   setStats]   = React.useState(null);
  const [targets, setTargets] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [error,   setError]   = React.useState(null);
  const [editing, setEditing] = React.useState(false);
  const [newApex, setNewApex] = React.useState("");
  const [search,  setSearch]  = React.useState("");

  const reload = React.useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [d, enriched] = await Promise.all([
        window.ArgusAPI.orgs.get(name),
        window.ArgusAPI.orgs.targetsEnriched(name),
      ]);
      setOrg(d.organisation);
      setStats(d.stats);
      setTargets(enriched);
    } catch (e) { setError(String(e)); }
    finally   { setLoading(false); }
  }, [name]);
  React.useEffect(() => { reload(); }, [reload]);

  const handleDelete = async () => {
    if (!confirm(`Delete organisation ${name}? Unlinks ${targets.length} target(s).`)) return;
    try {
      await window.ArgusAPI.orgs.remove(name, true);
      onChanged?.();
      onBack?.();
    } catch (e) { alert("delete failed: " + (e.message || e)); }
  };

  const handleLink = async (e) => {
    e.preventDefault();
    const apex = newApex.trim();
    if (!apex) return;
    try {
      await window.ArgusAPI.orgs.linkTarget(name, { apex });
      setNewApex("");
      await reload();
      onChanged?.();
    } catch (err) { alert("link failed: " + (err.message || err)); }
  };

  const handleUnlink = async (apex, e) => {
    e?.stopPropagation?.();
    if (!confirm(`Unlink ${apex} from ${name}?`)) return;
    try {
      await window.ArgusAPI.orgs.unlinkTarget(name, apex);
      await reload();
      onChanged?.();
    } catch (err) { alert("unlink failed: " + (err.message || err)); }
  };

  const launchScan = (apex, e) => {
    e?.stopPropagation?.();
    if (typeof window.openScanModal === "function") {
      window.openScanModal({ target: apex, org: name });
    } else {
      alert("scan modal not ready — try reloading the page.");
    }
  };

  const viewResults = (apex, e) => {
    e?.stopPropagation?.();
    if (typeof window.viewTarget === "function") {
      window.viewTarget(apex);
    }
  };

  // Heuristique du click row : si déjà scanné + findings → on va voir les
  // résultats (path d'analyse). Sinon → on lance un scan (path opérationnel).
  // Les deux boutons restent visibles à droite pour ne jamais cacher l'option.
  const onRowClick = (t) => {
    if ((t.findings_total || 0) > 0) viewResults(t.apex);
    else                              launchScan(t.apex);
  };

  // Client-side search filter on apex
  const filteredTargets = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return targets;
    return targets.filter(t => (t.apex || "").toLowerCase().includes(q));
  }, [targets, search]);

  const fmtDate = (s) => (s ? s.slice(0, 10) : "never");
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

  return (
    <div className="page page-org-detail">
      <div className="org-detail-header">
        <a className="org-detail-back"
           href="#/orgs"
           onClick={(e) => { e.preventDefault(); onBack?.(); }}>
          ← back to orgs
        </a>
        <h1>{name}</h1>
        {org?.h1_handle  && <span className="muted mono">h1: {org.h1_handle}</span>}
        {canMutate && (
          <div className="org-detail-actions">
            <button className="btn-secondary" onClick={() => setEditing(true)}>
              <Icon name="edit"/> Edit
            </button>
            <button className="btn-link danger" onClick={handleDelete}>
              delete
            </button>
          </div>
        )}
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {stats && (
        <div className="org-stats-grid">
          <div className="org-stat-card">
            <div className="label">Targets</div>
            <div className="value">{stats.targets || 0}</div>
          </div>
          <div className="org-stat-card">
            <div className="label">Scans run</div>
            <div className="value">{stats.scans || 0}</div>
          </div>
          <div className="org-stat-card">
            <div className="label">Live hosts</div>
            <div className="value">{stats.live_hosts || 0}</div>
          </div>
          <div className="org-stat-card">
            <div className="label">Findings</div>
            <div className="value">{stats.findings || 0}</div>
            {stats.by_severity && Object.keys(stats.by_severity).length > 0 && (
              <div className="sub">
                {SEV_ORDER.filter(s => stats.by_severity[s])
                          .map(s => (
                  <span key={s} className={`sev-mini sev-mini-${s}`}>
                    {s}: {stats.by_severity[s]}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="org-targets-toolbar">
        <input type="search"
               className="form-input org-targets-search"
               placeholder={`Search ${targets.length} targets…`}
               value={search}
               onChange={(e) => setSearch(e.target.value)}/>
        {search && (
          <span className="muted">{filteredTargets.length} / {targets.length}</span>
        )}
        {canMutate && (
          <form onSubmit={handleLink}
                style={{display:"flex", gap:6, marginLeft:"auto"}}>
            <input type="text"
                   className="form-input"
                   placeholder="new apex (e.g. acme.com)"
                   value={newApex}
                   onChange={(e) => setNewApex(e.target.value)}/>
            <button type="submit" className="btn-primary" disabled={!newApex.trim()}>
              <Icon name="plus"/> Link
            </button>
          </form>
        )}
      </div>

      <div className="users-table-wrap">
        <table className="users-table users-table-compact">
          <thead>
            <tr>
              <th>Apex</th>
              <th>Last scan</th>
              <th>Subs</th>
              <th>Live hosts</th>
              <th>Findings</th>
              <th>Severity</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredTargets.length === 0 ? (
              <tr><td colSpan="7" className="empty">
                {loading
                  ? "Loading…"
                  : (search ? "No match." : "No targets linked.")}
              </td></tr>
            ) : filteredTargets.map(t => {
              const hasFindings = (t.findings_total || 0) > 0;
              const tooltip     = hasFindings
                ? `Click to view results for ${t.apex}`
                : `Click to launch scan on ${t.apex}`;
              return (
                <tr key={t.apex}
                    className="row-clickable"
                    onClick={() => onRowClick(t)}
                    title={tooltip}>
                  <td className="mono"><strong>{t.apex}</strong></td>
                  <td className="muted">{fmtDate(t.last_scan_at)}</td>
                  <td>{t.subdomain_count || 0}</td>
                  <td>{t.live_host_count || 0}</td>
                  <td>{t.findings_total || 0}</td>
                  <td>
                    {t.findings_by_severity && SEV_ORDER
                      .filter(s => t.findings_by_severity[s])
                      .map(s => (
                        <span key={s} className={`sev-mini sev-mini-${s}`}
                              title={`${s}: ${t.findings_by_severity[s]}`}>
                          {t.findings_by_severity[s]}
                        </span>
                      ))}
                  </td>
                  <td className="actions scan-cell" onClick={(e) => e.stopPropagation()}>
                    {hasFindings && (
                      <button className="view-btn"
                              onClick={(e) => viewResults(t.apex, e)}
                              title={`View results for ${t.apex}`}>
                        <Icon name="eye" size={10}/> view
                      </button>
                    )}
                    <button className="scan-btn"
                            onClick={(e) => launchScan(t.apex, e)}
                            title={`Launch scan on ${t.apex}`}>
                      <Icon name="play" size={10}/> scan
                    </button>
                    {canMutate && (
                      <button className="btn-link danger"
                              onClick={(e) => handleUnlink(t.apex, e)}>
                        unlink
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {editing && org && (
        <OrgEditModal mode="edit"
                      org={org}
                      onClose={() => setEditing(false)}
                      onSaved={() => { setEditing(false); reload(); onChanged?.(); }}/>
      )}
    </div>
  );
}
