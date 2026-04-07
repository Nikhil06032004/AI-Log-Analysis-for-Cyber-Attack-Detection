import React, { useState, useEffect, useRef, useCallback } from "react";
import { BORD, T, ACC, M, BG } from "../constants/theme";
import { fetchLiveMetrics } from "../services/api";
import type { LiveMetrics } from "../services/api";

// ── Shared palette ─────────────────────────────────────────────────────────────
const SEV_COLOR: Record<string, string> = {
  critical: ACC.red, high: ACC.orange, medium: ACC.yellow, low: ACC.cyan,
};
const CAT_COLOR: Record<string, string> = {
  BRUTE_FORCE: ACC.red, PORT_SCAN: ACC.orange, DOS_ATTACK: ACC.yellow,
  MALWARE: ACC.purple, LOG_EVASION: ACC.cyan,
};

// ── SIEM Rules data ────────────────────────────────────────────────────────────
interface Rule {
  id: string; name: string; category: string; severity: string;
  condition: string; action: string; enabled: boolean;
}
const DEFAULT_RULES: Rule[] = [
  { id: "R001", name: "SSH Brute Force",          category: "BRUTE_FORCE", severity: "critical", condition: "failed_logon_count > 10 in 60s from same IP",            action: "BLOCK_IP + ALERT_ADMIN", enabled: true  },
  { id: "R002", name: "Port Scan Detection",       category: "PORT_SCAN",   severity: "high",     condition: "unique_ports_probed > 100 from same source in 30s",       action: "ALERT_ADMIN + LOG",      enabled: true  },
  { id: "R003", name: "DOS Traffic Spike",         category: "DOS_ATTACK",  severity: "critical", condition: "connection_rate > 10000/min or serror_rate > 0.9",        action: "BLOCK_IP + ALERT_ADMIN", enabled: true  },
  { id: "R004", name: "Suspicious Process Spawn",  category: "MALWARE",     severity: "high",     condition: "EventID=4688 AND (cmd.exe OR powershell.exe) by svchost", action: "ALERT_ADMIN + LOG",      enabled: true  },
  { id: "R005", name: "Audit Log Cleared",         category: "LOG_EVASION", severity: "critical", condition: "EventID=1102 OR EventID=4719",                           action: "BLOCK_IP + ALERT_ADMIN", enabled: true  },
  { id: "R006", name: "Registry Persistence",      category: "MALWARE",     severity: "high",     condition: "EventID=4657 AND path=HKLM\\Run",                        action: "ALERT_ADMIN + LOG",      enabled: false },
  { id: "R007", name: "Data Exfiltration",         category: "MALWARE",     severity: "critical", condition: "dst_bytes > 1GB to external IP in 5min",                 action: "BLOCK_IP + ALERT_ADMIN", enabled: true  },
  { id: "R008", name: "NTLM Relay Attempt",        category: "BRUTE_FORCE", severity: "high",     condition: "EventID=4776 AND FailureReason=%%2313",                  action: "ALERT_ADMIN + LOG",      enabled: false },
];

// ── Helpers ────────────────────────────────────────────────────────────────────
function fmtBytes(b: number): string {
  if (b >= 1e9) return `${(b / 1e9).toFixed(1)} GB/s`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB/s`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB/s`;
  return `${b} B/s`;
}
function fmtBytesTotal(b: number): string {
  if (b >= 1e9) return `${(b / 1e9).toFixed(2)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  return `${(b / 1e3).toFixed(0)} KB`;
}
function percentColor(p: number): string {
  if (p >= 90) return ACC.red;
  if (p >= 70) return ACC.orange;
  if (p >= 50) return ACC.yellow;
  return ACC.cyan;
}

// ── Mini sparkline ─────────────────────────────────────────────────────────────
const Sparkline: React.FC<{ values: number[]; color: string; height?: number }> = ({ values, color, height = 32 }) => {
  if (values.length < 2) return <div style={{ height }} />;
  const max = Math.max(...values, 1);
  const w = 120; const h = height;
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * w},${h - (v / max) * (h - 4) - 2}`).join(" ");
  return (
    <svg width={w} height={h} style={{ display: "block" }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" />
      <polyline
        points={`0,${h} ${pts} ${w},${h}`}
        fill={`${color}20`} stroke="none"
      />
    </svg>
  );
};

// ── Radial gauge ───────────────────────────────────────────────────────────────
const RadialGauge: React.FC<{ value: number; label: string; color: string; sub?: string }> = ({ value, label, color, sub }) => {
  const r = 34; const circ = 2 * Math.PI * r;
  const dash = (value / 100) * circ;
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
      <div style={{ position: "relative", width: 88, height: 88 }}>
        <svg width={88} height={88} style={{ transform: "rotate(-90deg)" }}>
          <circle cx={44} cy={44} r={r} fill="none" stroke={BORD.mid} strokeWidth={6} />
          <circle cx={44} cy={44} r={r} fill="none" stroke={color} strokeWidth={6}
            strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
            style={{ transition: "stroke-dasharray 0.4s ease" }} />
        </svg>
        <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <span style={{ ...M, fontSize: 15, fontWeight: 700, color }}>{value}%</span>
        </div>
      </div>
      <span style={{ ...M, fontSize: 10, color: T.hi, textAlign: "center" }}>{label}</span>
      {sub && <span style={{ ...M, fontSize: 9, color: T.lo, textAlign: "center" }}>{sub}</span>}
    </div>
  );
};

// ── Horizontal bar ─────────────────────────────────────────────────────────────
const HBar: React.FC<{ label: string; value: number; max: number; color: string; unit?: string }> = ({ label, value, max, color, unit = "%" }) => {
  const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "4px 0" }}>
      <span style={{ ...M, fontSize: 10, color: T.lo, width: 90, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{label}</span>
      <div style={{ flex: 1, height: 6, background: BORD.mid, borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 3, transition: "width 0.4s ease" }} />
      </div>
      <span style={{ ...M, fontSize: 10, color, width: 52, textAlign: "right", flexShrink: 0 }}>
        {unit === "%" ? `${value.toFixed(1)}%` : `${value.toFixed(1)} ${unit}`}
      </span>
    </div>
  );
};

// ── Panel wrapper ──────────────────────────────────────────────────────────────
const Panel: React.FC<{ title: string; children: React.ReactNode; badge?: React.ReactNode }> = ({ title, children, badge }) => (
  <div style={{ background: BG.panel, border: `1px solid ${BORD.dim}`, borderRadius: 14, padding: "14px 16px" }}>
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
      <span style={{ ...M, fontSize: 10, color: T.lo, letterSpacing: ".1em", textTransform: "uppercase" }}>{title}</span>
      {badge}
    </div>
    {children}
  </div>
);

// ── Live dot ───────────────────────────────────────────────────────────────────
const LiveDot: React.FC<{ active: boolean }> = ({ active }) => (
  <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
    <span style={{ width: 7, height: 7, borderRadius: "50%", background: active ? ACC.green : T.dim,
      display: "inline-block", animation: active ? "beat 1.6s ease-in-out infinite" : "none" }} />
    <span style={{ ...M, fontSize: 9, color: active ? ACC.green : T.dim }}>
      {active ? "LIVE" : "—"}
    </span>
  </span>
);

// ═══════════════════════════════════════════════════════════════════════════════
// Resource Utilization Tab
// ═══════════════════════════════════════════════════════════════════════════════
const HISTORY_LEN = 30;

const ResourceUtilization: React.FC = () => {
  const [metrics,   setMetrics]   = useState<LiveMetrics | null>(null);
  const [error,     setError]     = useState("");
  const [live,      setLive]      = useState(false);

  // Rolling history for sparklines
  const [cpuHist,  setCpuHist]  = useState<number[]>([]);
  const [ramHist,  setRamHist]  = useState<number[]>([]);
  const [netInHist, setNetInHist] = useState<number[]>([]);
  const [netOutHist,setNetOutHist]= useState<number[]>([]);

  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const poll = useCallback(async () => {
    try {
      const data = await fetchLiveMetrics();
      setMetrics(data);
      setLive(true);
      setError("");
      setCpuHist(h  => [...h, data.cpu.percent].slice(-HISTORY_LEN));
      setRamHist(h  => [...h, data.ram.percent].slice(-HISTORY_LEN));
      setNetInHist(h  => [...h, data.network.bytes_recv_per_s / 1024].slice(-HISTORY_LEN));
      setNetOutHist(h => [...h, data.network.bytes_sent_per_s / 1024].slice(-HISTORY_LEN));
    } catch (e) {
      setLive(false);
      setError("Cannot reach backend. Is the FastAPI server running?");
    }
  }, []);

  useEffect(() => {
    poll();
    timerRef.current = setInterval(poll, 2500);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [poll]);

  if (error && !metrics) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: 200 }}>
      <span style={{ ...M, fontSize: 12, color: ACC.red }}>{error}</span>
    </div>
  );
  if (!metrics) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: 200 }}>
      <span style={{ ...M, fontSize: 11, color: T.lo }}>Fetching metrics…</span>
    </div>
  );

  const cpuColor  = percentColor(metrics.cpu.percent);
  const ramColor  = percentColor(metrics.ram.percent);
  const diskColor = percentColor(metrics.disk.root_percent);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h2 style={{ ...M, color: T.hi, fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Resource Utilization</h2>
          <p style={{ ...M, fontSize: 11, color: T.lo }}>
            {metrics.hostname} · {metrics.platform} · {metrics.cpu.count_logical} logical CPUs
            {metrics.cpu.freq_mhz_current ? ` · ${(metrics.cpu.freq_mhz_current / 1000).toFixed(2)} GHz` : ""}
          </p>
        </div>
        <LiveDot active={live} />
      </div>

      {/* ROW 1 — 4 radial gauges */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14 }}>
        {/* CPU */}
        <div style={{ background: BG.panel, border: `1px solid ${BORD.dim}`, borderRadius: 14, padding: "18px 14px",
          display: "flex", flexDirection: "column", alignItems: "center", gap: 10 }}>
          <span style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".12em" }}>CPU USAGE</span>
          <RadialGauge value={metrics.cpu.percent} label="Overall" color={cpuColor}
            sub={`U:${metrics.cpu.user_pct}% S:${metrics.cpu.system_pct}%`} />
          <Sparkline values={cpuHist} color={cpuColor} />
        </div>

        {/* RAM */}
        <div style={{ background: BG.panel, border: `1px solid ${BORD.dim}`, borderRadius: 14, padding: "18px 14px",
          display: "flex", flexDirection: "column", alignItems: "center", gap: 10 }}>
          <span style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".12em" }}>MEMORY</span>
          <RadialGauge value={metrics.ram.percent} label="RAM"
            color={ramColor} sub={`${metrics.ram.used_gb.toFixed(1)} / ${metrics.ram.total_gb.toFixed(1)} GB`} />
          <Sparkline values={ramHist} color={ramColor} />
        </div>

        {/* Disk */}
        <div style={{ background: BG.panel, border: `1px solid ${BORD.dim}`, borderRadius: 14, padding: "18px 14px",
          display: "flex", flexDirection: "column", alignItems: "center", gap: 10 }}>
          <span style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".12em" }}>DISK (ROOT)</span>
          <RadialGauge value={metrics.disk.root_percent} label="Used"
            color={diskColor} sub={`${metrics.disk.root_used_gb.toFixed(1)} / ${metrics.disk.root_total_gb.toFixed(1)} GB`} />
          <div style={{ textAlign: "center" }}>
            <span style={{ ...M, fontSize: 9, color: T.dim }}>R:{metrics.disk.read_mb_total} MB  W:{metrics.disk.write_mb_total} MB</span>
          </div>
        </div>

        {/* Network */}
        <div style={{ background: BG.panel, border: `1px solid ${BORD.dim}`, borderRadius: 14, padding: "18px 14px",
          display: "flex", flexDirection: "column", alignItems: "center", gap: 10 }}>
          <span style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".12em" }}>NETWORK I/O</span>
          <div style={{ display: "flex", gap: 16, marginTop: 4 }}>
            <div style={{ textAlign: "center" }}>
              <p style={{ ...M, fontSize: 18, fontWeight: 700, color: ACC.cyan }}>
                {fmtBytes(metrics.network.bytes_recv_per_s)}
              </p>
              <p style={{ ...M, fontSize: 9, color: T.lo }}>↓ RECV</p>
              <p style={{ ...M, fontSize: 9, color: T.dim }}>{fmtBytesTotal(metrics.network.bytes_recv_total)}</p>
            </div>
            <div style={{ width: 1, background: BORD.dim }} />
            <div style={{ textAlign: "center" }}>
              <p style={{ ...M, fontSize: 18, fontWeight: 700, color: ACC.green }}>
                {fmtBytes(metrics.network.bytes_sent_per_s)}
              </p>
              <p style={{ ...M, fontSize: 9, color: T.lo }}>↑ SENT</p>
              <p style={{ ...M, fontSize: 9, color: T.dim }}>{fmtBytesTotal(metrics.network.bytes_sent_total)}</p>
            </div>
          </div>
          <Sparkline values={netInHist} color={ACC.cyan} />
        </div>
      </div>

      {/* ROW 2 — CPU per core + Memory breakdown + Disk partitions */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>

        {/* CPU per core */}
        <Panel title="CPU Per Core">
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {metrics.cpu.per_core.map((pct, i) => (
              <HBar key={i} label={`Core ${i}`} value={pct} max={100} color={percentColor(pct)} />
            ))}
          </div>
        </Panel>

        {/* Memory breakdown */}
        <Panel title="Memory Breakdown">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <HBar label="RAM Used"    value={metrics.ram.used_gb}     max={metrics.ram.total_gb}     color={ramColor}   unit="GB" />
            <HBar label="Available"   value={metrics.ram.available_gb} max={metrics.ram.total_gb}    color={ACC.green}  unit="GB" />
            <HBar label="Cached"      value={metrics.ram.cached_gb}   max={metrics.ram.total_gb}     color={ACC.cyan}   unit="GB" />
            <div style={{ borderTop: `1px solid ${BORD.dim}`, margin: "6px 0" }} />
            <HBar label="Swap Used"   value={metrics.ram.swap_used_gb}  max={Math.max(metrics.ram.swap_total_gb, 0.1)} color={ACC.orange} unit="GB" />
            <HBar label="Swap Total"  value={metrics.ram.swap_total_gb} max={Math.max(metrics.ram.swap_total_gb, 0.1)} color={T.dim}      unit="GB" />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 10, paddingTop: 10, borderTop: `1px solid ${BORD.dim}` }}>
            <span style={{ ...M, fontSize: 9, color: T.dim }}>Total RAM</span>
            <span style={{ ...M, fontSize: 10, fontWeight: 700, color: T.hi }}>{metrics.ram.total_gb.toFixed(2)} GB</span>
          </div>
        </Panel>

        {/* Disk partitions */}
        <Panel title="Disk Partitions">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {metrics.disk.partitions.length === 0 && (
              <span style={{ ...M, fontSize: 10, color: T.lo }}>No accessible partitions</span>
            )}
            {metrics.disk.partitions.map((p, i) => (
              <div key={i} style={{ paddingBottom: 8, borderBottom: i < metrics.disk.partitions.length - 1 ? `1px solid ${BORD.dim}` : "none" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ ...M, fontSize: 10, color: T.hi }}>{p.mountpoint}</span>
                  <span style={{ ...M, fontSize: 9, color: T.dim }}>{p.fstype}</span>
                </div>
                <div style={{ height: 5, background: BORD.mid, borderRadius: 3, overflow: "hidden", marginBottom: 3 }}>
                  <div style={{ width: `${p.percent}%`, height: "100%", background: percentColor(p.percent), borderRadius: 3, transition: "width 0.4s" }} />
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ ...M, fontSize: 9, color: T.lo }}>{p.used_gb} / {p.total_gb} GB</span>
                  <span style={{ ...M, fontSize: 9, fontWeight: 700, color: percentColor(p.percent) }}>{p.percent}%</span>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* ROW 3 — Network sparklines + Top processes */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>

        {/* Network activity */}
        <Panel title="Network Activity (KB/s)">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                <span style={{ ...M, fontSize: 10, color: ACC.cyan }}>↓ Inbound</span>
                <span style={{ ...M, fontSize: 10, fontWeight: 700, color: ACC.cyan }}>
                  {fmtBytes(metrics.network.bytes_recv_per_s)}
                </span>
              </div>
              <Sparkline values={netInHist} color={ACC.cyan} height={40} />
            </div>
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                <span style={{ ...M, fontSize: 10, color: ACC.green }}>↑ Outbound</span>
                <span style={{ ...M, fontSize: 10, fontWeight: 700, color: ACC.green }}>
                  {fmtBytes(metrics.network.bytes_sent_per_s)}
                </span>
              </div>
              <Sparkline values={netOutHist} color={ACC.green} height={40} />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, paddingTop: 8, borderTop: `1px solid ${BORD.dim}` }}>
              <div>
                <p style={{ ...M, fontSize: 9, color: T.lo, marginBottom: 2 }}>PKT/s Recv</p>
                <p style={{ ...M, fontSize: 12, fontWeight: 700, color: ACC.cyan }}>{metrics.network.packets_recv_per_s.toLocaleString()}</p>
              </div>
              <div>
                <p style={{ ...M, fontSize: 9, color: T.lo, marginBottom: 2 }}>PKT/s Sent</p>
                <p style={{ ...M, fontSize: 12, fontWeight: 700, color: ACC.green }}>{metrics.network.packets_sent_per_s.toLocaleString()}</p>
              </div>
            </div>
          </div>
        </Panel>

        {/* Top processes */}
        <Panel title="Top Processes by CPU">
          <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
            <div style={{ display: "grid", gridTemplateColumns: "52px 1fr 56px 56px 52px", gap: 8, paddingBottom: 6, borderBottom: `1px solid ${BORD.dim}`, marginBottom: 4 }}>
              {["PID", "NAME", "CPU%", "MEM%", "STATUS"].map(h => (
                <span key={h} style={{ ...M, fontSize: 8, color: T.lo, letterSpacing: ".08em" }}>{h}</span>
              ))}
            </div>
            {metrics.top_processes.map((p, i) => (
              <div key={p.pid} style={{ display: "grid", gridTemplateColumns: "52px 1fr 56px 56px 52px", gap: 8,
                padding: "7px 0", borderBottom: i < metrics.top_processes.length - 1 ? `1px solid ${BORD.dim}` : "none",
                alignItems: "center" }}>
                <span style={{ ...M, fontSize: 9, color: T.dim }}>{p.pid}</span>
                <span style={{ ...M, fontSize: 10, color: T.hi, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.name}</span>
                <span style={{ ...M, fontSize: 10, fontWeight: 700, color: percentColor(p.cpu * 4) }}>{p.cpu.toFixed(1)}%</span>
                <span style={{ ...M, fontSize: 10, color: ACC.purple }}>{p.mem.toFixed(1)}%</span>
                <span style={{ ...M, fontSize: 9, color: p.status === "running" ? ACC.green : T.lo }}>{p.status}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// SIEM Rules Tab
// ═══════════════════════════════════════════════════════════════════════════════
const SIEMRulesTab: React.FC = () => {
  const [rules, setRules] = useState<Rule[]>(DEFAULT_RULES);
  const toggle = (id: string) =>
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  const enabledCount  = rules.filter(r => r.enabled).length;
  const criticalCount = rules.filter(r => r.severity === "critical" && r.enabled).length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h2 style={{ ...M, color: T.hi, fontSize: 18, fontWeight: 700, marginBottom: 4 }}>SIEM Rules</h2>
          <p style={{ ...M, fontSize: 11, color: T.lo }}>{enabledCount}/{rules.length} rules active · {criticalCount} critical</p>
        </div>
      </div>

      <div style={{ background: BG.panel, border: `1px solid ${BORD.dim}`, borderRadius: 14, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "56px 60px 1fr 110px 100px 1fr 64px", gap: 10,
          padding: "8px 18px", borderBottom: `1px solid ${BORD.dim}`, background: BG.strip }}>
          {["ON/OFF","ID","RULE NAME","CATEGORY","SEV","CONDITION","ACTION"].map(h => (
            <span key={h} style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".1em" }}>{h}</span>
          ))}
        </div>
        {rules.map((rule, i) => (
          <div key={rule.id} style={{ display: "grid", gridTemplateColumns: "56px 60px 1fr 110px 100px 1fr 64px",
            gap: 10, padding: "13px 18px", alignItems: "center",
            borderBottom: i < rules.length - 1 ? `1px solid ${BORD.dim}` : "none",
            opacity: rule.enabled ? 1 : 0.45, transition: "opacity .2s" }}>
            <div onClick={() => toggle(rule.id)} style={{ cursor: "pointer", width: 36, height: 20, borderRadius: 10,
              background: rule.enabled ? "rgba(0,230,118,.25)" : BORD.dim,
              border: `1px solid ${rule.enabled ? ACC.green : BORD.mid}`, position: "relative", transition: "all .2s" }}>
              <div style={{ position: "absolute", top: 2, left: rule.enabled ? 16 : 2, width: 14, height: 14,
                borderRadius: "50%", background: rule.enabled ? ACC.green : T.lo, transition: "left .2s" }} />
            </div>
            <span style={{ ...M, fontSize: 10, color: T.dim }}>{rule.id}</span>
            <span style={{ fontSize: 13, color: T.hi, fontFamily: "'Inter',sans-serif", fontWeight: 500 }}>{rule.name}</span>
            <span style={{ ...M, fontSize: 9, color: CAT_COLOR[rule.category] ?? T.md,
              background: `${CAT_COLOR[rule.category] ?? ACC.cyan}18`, border: `1px solid ${CAT_COLOR[rule.category] ?? BORD.dim}`,
              borderRadius: 5, padding: "3px 7px", textAlign: "center" }}>{rule.category}</span>
            <span style={{ ...M, fontSize: 10, fontWeight: 700, color: SEV_COLOR[rule.severity] ?? T.md, textTransform: "uppercase" }}>
              {rule.severity}
            </span>
            <span style={{ ...M, fontSize: 10, color: T.lo }}>{rule.condition}</span>
            <span style={{ ...M, fontSize: 9, color: ACC.orange }}>{rule.action}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
// Root component — tab switcher
// ═══════════════════════════════════════════════════════════════════════════════
type Tab = "rules" | "resources";

const SIEMRules: React.FC = () => {
  const [tab, setTab] = useState<Tab>("rules");

  const tabs: { id: Tab; label: string; icon: string }[] = [
    { id: "rules",     label: "SIEM Rules",           icon: "⚙" },
    { id: "resources", label: "Resource Utilization", icon: "⊡" },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Tab bar */}
      <div style={{ display: "flex", gap: 4, background: BG.panel, borderRadius: 10,
        padding: 4, border: `1px solid ${BORD.dim}`, alignSelf: "flex-start" }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            ...M, fontSize: 11, fontWeight: tab === t.id ? 700 : 400,
            color: tab === t.id ? T.hi : T.lo,
            background: tab === t.id ? "rgba(0,217,255,.12)" : "transparent",
            border: tab === t.id ? `1px solid rgba(0,217,255,.25)` : "1px solid transparent",
            borderRadius: 7, padding: "7px 18px", cursor: "pointer",
            transition: "all .18s", letterSpacing: ".04em",
          }}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "rules"     && <SIEMRulesTab />}
      {tab === "resources" && <ResourceUtilization />}
    </div>
  );
};

export default SIEMRules;
