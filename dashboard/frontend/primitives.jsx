// h4wk3y3 — shared UI primitives
const { useState, useEffect, useRef, useMemo } = React;

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

const SeverityPill = ({ sev, count }) => (
  <span className={`pill pill-sev-${sev}`}>
    <span className="dot"></span>
    {SEV_LABEL[sev] || sev}
    {count != null && <span className="num" style={{marginLeft: 4, opacity: 0.7}}>{count}</span>}
  </span>
);

const StatusPill = ({ status }) => {
  const label = status === "solid" ? "Solid" : "Candidate";
  return (
    <span className={`pill pill-${status}`}>
      <span className="dot"></span>
      {label}
    </span>
  );
};

const StatusBadge = ({ code }) => {
  const cls = code === 403 ? "badge-status-403"
    : code >= 200 && code < 300 ? "badge-status-2xx"
    : code >= 300 && code < 400 ? "badge-status-3xx"
    : code >= 400 && code < 500 ? "badge-status-4xx"
    : "badge-status-5xx";
  return <span className={`badge-status ${cls}`}>{code}</span>;
};

const Delta = ({ value, invert = false }) => {
  if (value == null) return null;
  const positive = value > 0;
  // For most stats (findings, criticals), up is bad.
  const cls = positive ? (invert ? "down" : "up") : (invert ? "up" : "down");
  const finalCls = value === 0 ? "neutral" : cls;
  return (
    <span className={`delta ${finalCls}`}>
      {value > 0 ? "▲" : value < 0 ? "▼" : "•"} {Math.abs(value)}
    </span>
  );
};

const CopyButton = ({ text }) => {
  const [copied, setCopied] = useState(false);
  const click = (e) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };
  return (
    <button className="copy-btn" onClick={click} title={copied ? "Copied" : "Copy"}>
      <Icon name={copied ? "circle-dot" : "copy"} size={12} />
    </button>
  );
};

// Mini sparkline
const Sparkline = ({ values, color = "currentColor" }) => {
  const w = 80, h = 28;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const range = max - min || 1;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - ((v - min) / range) * h;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  return (
    <svg className="sparkline" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" />
    </svg>
  );
};

// Donut
const Donut = ({ data, size = 140, thickness = 22 }) => {
  const total = data.reduce((s, d) => s + d.value, 0);
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  let acc = 0;
  return (
    <svg className="donut-svg" viewBox={`0 0 ${size} ${size}`}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={thickness} />
      {data.map((d, i) => {
        if (d.value === 0) return null;
        const frac = d.value / total;
        const dash = frac * c;
        const offset = -acc * c;
        acc += frac;
        return (
          <circle
            key={i}
            cx={size/2} cy={size/2} r={r}
            fill="none"
            stroke={d.color}
            strokeWidth={thickness}
            strokeDasharray={`${dash} ${c - dash}`}
            strokeDashoffset={offset}
            transform={`rotate(-90 ${size/2} ${size/2})`}
            strokeLinecap="butt"
          />
        );
      })}
      <text x={size/2} y={size/2 - 4} textAnchor="middle" fill="var(--text)" fontSize="22" fontWeight="700" fontFamily="var(--font-ui)" style={{letterSpacing:"-0.02em"}}>{total}</text>
      <text x={size/2} y={size/2 + 14} textAnchor="middle" fill="var(--text-dim)" fontSize="10" fontFamily="var(--font-mono)" style={{textTransform:"uppercase",letterSpacing:"0.08em"}}>findings</text>
    </svg>
  );
};

// Per-page export controls (CSV / TXT). Used by Subdomains, Hosts,
// Findings, URLs, Audit Log views. `rows` is the in-memory row array,
// `columns` is [{ key, label }] (or [string]). `basename` becomes the
// downloaded filename (no extension).
const ExportButtons = ({ rows, columns, basename, disabled }) => {
  const off = disabled || !rows || rows.length === 0;
  const fire = (fmt) => window.ArgusAPI.exportRows(basename, rows, columns, fmt);
  return (
    <div style={{display:"inline-flex",gap:6}}>
      <button className="cmd-btn" disabled={off}
              title={`Export ${rows ? rows.length : 0} rows as CSV`}
              onClick={() => fire("csv")}>
        <Icon name="download" size={12}/><span>CSV</span>
      </button>
      <button className="cmd-btn" disabled={off}
              title={`Export ${rows ? rows.length : 0} rows as TXT`}
              onClick={() => fire("txt")}>
        <Icon name="file-text" size={12}/><span>TXT</span>
      </button>
    </div>
  );
};

window.SEV_ORDER = SEV_ORDER;
window.SEV_LABEL = SEV_LABEL;
window.SeverityPill = SeverityPill;
window.StatusPill = StatusPill;
window.StatusBadge = StatusBadge;
window.Delta = Delta;
window.CopyButton = CopyButton;
window.Sparkline = Sparkline;
window.Donut = Donut;
window.ExportButtons = ExportButtons;
