import React, { useState, useEffect, useRef, useCallback } from "react";
import { BORD, T, ACC, M, BG } from "../constants/theme";
import { fetchLiveMetrics } from "../services/api";
import type { LiveMetrics } from "../services/api";

// ── Constants ──────────────────────────────────────────────────────────────────
const HISTORY_LEN  = 40;   // sparkline data points to keep
const POLL_MS      = 2500; // 2.5 s refresh

// ── Helpers ────────────────────────────────────────────────────────────────────
function fmtBps(b: number): string {
  if (b >= 1e9) return `${(b / 1e9).toFixed(2)} GB/s`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB/s`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB/s`;
  return `${b} B/s`;
}
function fmtTotal(b: number): string {
  if (b >= 1e9) return `${(b / 1e9).toFixed(2)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  return `${(b / 1e3).toFixed(0)} KB`;
}
function usageColor(p: number): string {
  if (p >= 90) return ACC.red;
  if (p >= 70) return ACC.orange;
  if (p >= 45) return ACC.yellow;
  return ACC.cyan;
}

// ── Sparkline SVG ──────────────────────────────────────────────────────────────
interface SparkProps { values: number[]; color: string; width?: number; height?: number }
const Sparkline: React.FC<SparkProps> = ({ values, color, width = 140, height = 36 }) => {
  if (values.length < 2) return <svg width={width} height={height} />;
  const max = Math.max(...values, 1);
  const pts = values
    .map((v, i) => `${(i / (values.length - 1)) * width},${height - (v / max) * (height - 6) - 3}`)
    .join(" ");
  return (
    <svg width={width} height={height} style={{ display: "block", overflow: "visible" }}>
      <defs>
        <linearGradient id={`sg-${color.replace("#","")}`} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <polygon
        points={`0,${height} ${pts} ${width},${height}`}
        fill={`url(#sg-${color.replace("#","")})`}
      />
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.8} strokeLinejoin="round" strokeLinecap="round" />
      {/* last dot */}
      {(() => {
        const lastPt = pts.split(" ").at(-1)?.split(",");
        if (!lastPt) return null;
        return <circle cx={lastPt[0]} cy={lastPt[1]} r={2.5} fill={color} />;
      })()}
    </svg>
  );
};

// ── Radial gauge ───────────────────────────────────────────────────────────────
const RadialGauge: React.FC<{ value: number; color: string; size?: number }> = ({ value, color, size = 72 }) => {
  const r     = (size / 2) - 8;
  const circ  = 2 * Math.PI * r;
  const fill  = Math.min(value / 100, 1) * circ;
  return (
    <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={BORD.mid} strokeWidth={7} />
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={7}
        strokeDasharray={`${fill} ${circ}`} strokeLinecap="round"
        style={{ transition: "stroke-dasharray 0.45s cubic-bezier(.4,0,.2,1)" }} />
    </svg>
  );
};

// ── Metric stat card ───────────────────────────────────────────────────────────
interface StatProps {
  label: string; value: string; sub: string; color: string;
  percent: number; history: number[];
}
const MetricCard: React.FC<StatProps> = ({ label, value, sub, color, percent, history }) => (
  <div style={{
    background: BG.panel, border: `1px solid ${BORD.dim}`, borderRadius: 14,
    padding: "18px 20px", display: "flex", flexDirection: "column", gap: 10,
    transition: "border-color .2s",
  }}>
    {/* header */}
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
      <span style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".14em", textTransform: "uppercase" }}>{label}</span>
      <div style={{ position: "relative", width: 72, height: 72 }}>
        <RadialGauge value={percent} color={color} size={72} />
        <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", transform: "none" }}>
          <span style={{ ...M, fontSize: 13, fontWeight: 700, color }}>{percent.toFixed(0)}%</span>
        </div>
      </div>
    </div>
    {/* value */}
    <div>
      <p style={{ ...M, fontSize: 22, fontWeight: 700, color, lineHeight: 1.1, marginBottom: 3 }}>{value}</p>
      <p style={{ ...M, fontSize: 10, color: T.lo }}>{sub}</p>
    </div>
    {/* sparkline */}
    <Sparkline values={history} color={color} width={200} height={36} />
  </div>
);

// ── Horizontal fill bar ────────────────────────────────────────────────────────
const FillBar: React.FC<{ label: string; pct: number; color: string; right?: string }> = ({ label, pct, color, right }) => (
  <div>
    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
      <span style={{ ...M, fontSize: 10, color: T.lo, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "65%" }}>{label}</span>
      <span style={{ ...M, fontSize: 10, fontWeight: 700, color }}>{right ?? `${pct.toFixed(1)}%`}</span>
    </div>
    <div style={{ height: 5, background: BORD.mid, borderRadius: 3, overflow: "hidden" }}>
      <div style={{ width: `${Math.min(pct, 100)}%`, height: "100%", background: color, borderRadius: 3, transition: "width .45s ease" }} />
    </div>
  </div>
);

// ── Section panel ──────────────────────────────────────────────────────────────
const Section: React.FC<{ title: string; badge?: React.ReactNode; children: React.ReactNode }> = ({ title, badge, children }) => (
  <div style={{ background: BG.panel, border: `1px solid ${BORD.dim}`, borderRadius: 14, padding: "16px 18px" }}>
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
      <span style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".12em", textTransform: "uppercase" }}>{title}</span>
      {badge}
    </div>
    {children}
  </div>
);

// ── Main page ──────────────────────────────────────────────────────────────────
const SystemMonitor: React.FC = () => {
  const [metrics, setMetrics] = useState<LiveMetrics | null>(null);
  const [error,   setError]   = useState("");
  const [live,    setLive]    = useState(false);

  // Rolling history for sparklines
  const [cpuH,    setCpuH]    = useState<number[]>([]);
  const [ramH,    setRamH]    = useState<number[]>([]);
  const [netRxH,  setNetRxH]  = useState<number[]>([]);
  const [netTxH,  setNetTxH]  = useState<number[]>([]);
  const [diskRH,  setDiskRH]  = useState<number[]>([]);
  const [diskWH,  setDiskWH]  = useState<number[]>([]);

  const prevDiskRef = useRef({ r: 0, w: 0, ts: 0 });
  const timerRef    = useRef<ReturnType<typeof setInterval> | null>(null);

  const push = <T,>(setter: React.Dispatch<React.SetStateAction<T[]>>, v: T) =>
    setter(h => [...h, v].slice(-HISTORY_LEN));

  const poll = useCallback(async () => {
    try {
      const data = await fetchLiveMetrics();
      setMetrics(data);
      setLive(true);
      setError("");

      push(setCpuH,   data.cpu.percent);
      push(setRamH,   data.ram.percent);
      push(setNetRxH, data.network.bytes_recv_per_s / 1024);
      push(setNetTxH, data.network.bytes_sent_per_s / 1024);

      // Disk I/O delta (MB/s)
      const now  = Date.now();
      const prev = prevDiskRef.current;
      const dt   = prev.ts ? (now - prev.ts) / 1000 : 1;
      const rMBs = dt > 0 ? Math.max((data.disk.read_mb_total  - prev.r) / dt, 0) : 0;
      const wMBs = dt > 0 ? Math.max((data.disk.write_mb_total - prev.w) / dt, 0) : 0;
      prevDiskRef.current = { r: data.disk.read_mb_total, w: data.disk.write_mb_total, ts: now };
      push(setDiskRH, rMBs);
      push(setDiskWH, wMBs);
    } catch {
      setLive(false);
      setError("Backend unreachable — is the FastAPI server running on :8000?");
    }
  }, []);

  useEffect(() => {
    poll();
    timerRef.current = setInterval(poll, POLL_MS);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [poll]);

  // ── Loading / error states ─────────────────────────────────────────────────
  if (!metrics && !error) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "60vh" }}>
      <div style={{ textAlign: "center" }}>
        <div style={{ ...M, fontSize: 13, color: T.lo, marginBottom: 8 }}>Connecting to metrics endpoint…</div>
        <div style={{ ...M, fontSize: 10, color: T.dim }}>GET /api/metrics/live</div>
      </div>
    </div>
  );
  if (!metrics && error) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "60vh" }}>
      <div style={{ textAlign: "center" }}>
        <p style={{ ...M, fontSize: 12, color: ACC.red, marginBottom: 8 }}>{error}</p>
        <p style={{ ...M, fontSize: 10, color: T.dim }}>Make sure the backend is running: uvicorn app.main:app --reload</p>
      </div>
    </div>
  );

  const m          = metrics!;
  const cpuColor   = usageColor(m.cpu.percent);
  const ramColor   = usageColor(m.ram.percent);
  const diskColor  = usageColor(m.disk.root_percent);
  const swapColor  = usageColor(m.ram.swap_percent);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* ── Page header ──────────────────────────────────────────────────────── */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h1 style={{ ...M, fontSize: 20, fontWeight: 700, color: T.hi, marginBottom: 4 }}>System Monitor</h1>
          <p style={{ ...M, fontSize: 11, color: T.lo }}>
            {m.hostname} &nbsp;·&nbsp; {m.platform} &nbsp;·&nbsp;
            {m.cpu.count_physical} cores / {m.cpu.count_logical} threads
            {m.cpu.freq_mhz_current ? ` · ${(m.cpu.freq_mhz_current / 1000).toFixed(2)} GHz` : ""}
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", display: "inline-block",
            background: live ? ACC.green : ACC.red,
            animation: live ? "beat 1.6s ease-in-out infinite" : "none" }} />
          <span style={{ ...M, fontSize: 10, color: live ? ACC.green : ACC.red }}>
            {live ? `LIVE · every ${POLL_MS / 1000}s` : "OFFLINE"}
          </span>
        </div>
      </div>

      {/* ── ROW 1 — 4 metric cards ────────────────────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14 }}>
        <MetricCard
          label="CPU Usage"
          value={`${m.cpu.percent.toFixed(1)}%`}
          sub={`User ${m.cpu.user_pct}% · Sys ${m.cpu.system_pct}% · Idle ${m.cpu.idle_pct}%`}
          color={cpuColor}
          percent={m.cpu.percent}
          history={cpuH}
        />
        <MetricCard
          label="RAM Usage"
          value={`${m.ram.used_gb.toFixed(2)} GB`}
          sub={`${m.ram.available_gb.toFixed(2)} GB free of ${m.ram.total_gb.toFixed(2)} GB`}
          color={ramColor}
          percent={m.ram.percent}
          history={ramH}
        />
        <MetricCard
          label="Disk (Root)"
          value={`${m.disk.root_used_gb.toFixed(1)} GB`}
          sub={`${m.disk.root_free_gb.toFixed(1)} GB free of ${m.disk.root_total_gb.toFixed(1)} GB`}
          color={diskColor}
          percent={m.disk.root_percent}
          history={diskRH}
        />
        <MetricCard
          label="Network Speed"
          value={fmtBps(m.network.bytes_recv_per_s)}
          sub={`↑ ${fmtBps(m.network.bytes_sent_per_s)} · Total ↓${fmtTotal(m.network.bytes_recv_total)}`}
          color={ACC.cyan}
          percent={Math.min((m.network.bytes_recv_per_s / 125_000_000) * 100, 100)}
          history={netRxH}
        />
      </div>

      {/* ── ROW 2 — CPU cores · Memory breakdown · Network details ───────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>

        {/* CPU per-core */}
        <Section title="CPU Per Core">
          <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
            {m.cpu.per_core.map((pct, i) => (
              <FillBar key={i} label={`Core ${i}`} pct={pct} color={usageColor(pct)} right={`${pct.toFixed(1)}%`} />
            ))}
          </div>
        </Section>

        {/* Memory breakdown */}
        <Section title="Memory Breakdown"
          badge={<span style={{ ...M, fontSize: 9, color: T.dim }}>{m.ram.total_gb.toFixed(1)} GB total</span>}>
          <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
            <FillBar label="Used"      pct={m.ram.percent}                                        color={ramColor}   right={`${m.ram.used_gb.toFixed(2)} GB`} />
            <FillBar label="Available" pct={(m.ram.available_gb / m.ram.total_gb) * 100}          color={ACC.green}  right={`${m.ram.available_gb.toFixed(2)} GB`} />
            <FillBar label="Cached"    pct={(m.ram.cached_gb / m.ram.total_gb) * 100}             color={ACC.purple} right={`${m.ram.cached_gb.toFixed(2)} GB`} />
            <div style={{ height: 1, background: BORD.dim, margin: "4px 0" }} />
            <FillBar label="Swap Used"
              pct={m.ram.swap_total_gb > 0 ? (m.ram.swap_used_gb / m.ram.swap_total_gb) * 100 : 0}
              color={swapColor} right={`${m.ram.swap_used_gb.toFixed(2)} GB / ${m.ram.swap_total_gb.toFixed(2)} GB`} />
          </div>
        </Section>

        {/* Network breakdown */}
        <Section title="Network Activity">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {/* recv */}
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                <span style={{ ...M, fontSize: 10, color: ACC.cyan }}>↓ Inbound</span>
                <span style={{ ...M, fontSize: 11, fontWeight: 700, color: ACC.cyan }}>{fmtBps(m.network.bytes_recv_per_s)}</span>
              </div>
              <Sparkline values={netRxH} color={ACC.cyan} width={204} height={36} />
            </div>
            {/* send */}
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                <span style={{ ...M, fontSize: 10, color: ACC.green }}>↑ Outbound</span>
                <span style={{ ...M, fontSize: 11, fontWeight: 700, color: ACC.green }}>{fmtBps(m.network.bytes_sent_per_s)}</span>
              </div>
              <Sparkline values={netTxH} color={ACC.green} width={204} height={36} />
            </div>
            {/* totals */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, paddingTop: 8, borderTop: `1px solid ${BORD.dim}` }}>
              <div>
                <p style={{ ...M, fontSize: 9, color: T.lo, marginBottom: 2 }}>Total Received</p>
                <p style={{ ...M, fontSize: 12, fontWeight: 700, color: ACC.cyan }}>{fmtTotal(m.network.bytes_recv_total)}</p>
              </div>
              <div>
                <p style={{ ...M, fontSize: 9, color: T.lo, marginBottom: 2 }}>Total Sent</p>
                <p style={{ ...M, fontSize: 12, fontWeight: 700, color: ACC.green }}>{fmtTotal(m.network.bytes_sent_total)}</p>
              </div>
              <div>
                <p style={{ ...M, fontSize: 9, color: T.lo, marginBottom: 2 }}>PKT/s Recv</p>
                <p style={{ ...M, fontSize: 12, fontWeight: 700, color: T.md }}>{m.network.packets_recv_per_s.toLocaleString()}</p>
              </div>
              <div>
                <p style={{ ...M, fontSize: 9, color: T.lo, marginBottom: 2 }}>PKT/s Sent</p>
                <p style={{ ...M, fontSize: 12, fontWeight: 700, color: T.md }}>{m.network.packets_sent_per_s.toLocaleString()}</p>
              </div>
            </div>
          </div>
        </Section>

      </div>

      {/* ── ROW 3 — Disk I/O sparklines + Disk partitions + Top processes ─────── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>

        {/* Disk I/O */}
        <Section title="Disk I/O Speed">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                <span style={{ ...M, fontSize: 10, color: ACC.orange }}>Read</span>
                <span style={{ ...M, fontSize: 10, fontWeight: 700, color: ACC.orange }}>
                  {(diskRH.at(-1) ?? 0).toFixed(2)} MB/s
                </span>
              </div>
              <Sparkline values={diskRH} color={ACC.orange} width={204} height={36} />
            </div>
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                <span style={{ ...M, fontSize: 10, color: ACC.purple }}>Write</span>
                <span style={{ ...M, fontSize: 10, fontWeight: 700, color: ACC.purple }}>
                  {(diskWH.at(-1) ?? 0).toFixed(2)} MB/s
                </span>
              </div>
              <Sparkline values={diskWH} color={ACC.purple} width={204} height={36} />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, paddingTop: 8, borderTop: `1px solid ${BORD.dim}` }}>
              <div>
                <p style={{ ...M, fontSize: 9, color: T.lo, marginBottom: 2 }}>Total Read</p>
                <p style={{ ...M, fontSize: 12, fontWeight: 700, color: ACC.orange }}>{m.disk.read_mb_total.toFixed(0)} MB</p>
              </div>
              <div>
                <p style={{ ...M, fontSize: 9, color: T.lo, marginBottom: 2 }}>Total Written</p>
                <p style={{ ...M, fontSize: 12, fontWeight: 700, color: ACC.purple }}>{m.disk.write_mb_total.toFixed(0)} MB</p>
              </div>
            </div>
          </div>
        </Section>

        {/* Disk partitions */}
        <Section title="Disk Partitions"
          badge={<span style={{ ...M, fontSize: 9, color: T.dim }}>{m.disk.partitions.length} volumes</span>}>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {m.disk.partitions.length === 0 && (
              <span style={{ ...M, fontSize: 10, color: T.lo }}>No accessible partitions</span>
            )}
            {m.disk.partitions.map((p, i) => (
              <div key={i} style={{ paddingBottom: 10, borderBottom: i < m.disk.partitions.length - 1 ? `1px solid ${BORD.dim}` : "none" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                  <span style={{ ...M, fontSize: 11, color: T.hi, fontWeight: 600 }}>{p.mountpoint}</span>
                  <span style={{ ...M, fontSize: 9, color: T.dim, background: BG.card, borderRadius: 4, padding: "1px 6px" }}>{p.fstype}</span>
                </div>
                <div style={{ height: 5, background: BORD.mid, borderRadius: 3, overflow: "hidden", marginBottom: 4 }}>
                  <div style={{ width: `${p.percent}%`, height: "100%", background: usageColor(p.percent), borderRadius: 3, transition: "width .45s" }} />
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ ...M, fontSize: 9, color: T.lo }}>{p.used_gb} / {p.total_gb} GB used</span>
                  <span style={{ ...M, fontSize: 9, fontWeight: 700, color: usageColor(p.percent) }}>{p.percent}%</span>
                </div>
              </div>
            ))}
          </div>
        </Section>

        {/* Top processes */}
        <Section title="Top Processes"
          badge={<span style={{ ...M, fontSize: 9, color: T.dim }}>by CPU usage</span>}>
          {/* column headers */}
          <div style={{ display: "grid", gridTemplateColumns: "44px 1fr 48px 48px 56px", gap: 8, marginBottom: 6, paddingBottom: 6, borderBottom: `1px solid ${BORD.dim}` }}>
            {["PID", "NAME", "CPU%", "MEM%", "STATUS"].map(h => (
              <span key={h} style={{ ...M, fontSize: 8, color: T.dim, letterSpacing: ".08em" }}>{h}</span>
            ))}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
            {m.top_processes.map((p, i) => {
              const cpuCol = usageColor(p.cpu * 5);   // scale 0-20 cpu% → full color range
              const memCol = usageColor(p.mem * 8);
              return (
                <div key={p.pid} style={{
                  display: "grid", gridTemplateColumns: "44px 1fr 48px 48px 56px",
                  gap: 8, padding: "8px 0", alignItems: "center",
                  borderBottom: i < m.top_processes.length - 1 ? `1px solid ${BORD.dim}` : "none",
                }}>
                  <span style={{ ...M, fontSize: 9, color: T.dim }}>{p.pid}</span>

                  <div style={{ minWidth: 0 }}>
                    <p style={{ ...M, fontSize: 11, color: T.hi, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginBottom: 2 }}>{p.name}</p>
                    {/* cpu mini-bar */}
                    <div style={{ height: 3, background: BORD.mid, borderRadius: 2, overflow: "hidden" }}>
                      <div style={{ width: `${Math.min(p.cpu * 5, 100)}%`, height: "100%", background: cpuCol, borderRadius: 2, transition: "width .4s" }} />
                    </div>
                  </div>

                  <span style={{ ...M, fontSize: 10, fontWeight: 700, color: cpuCol }}>{p.cpu.toFixed(1)}%</span>
                  <span style={{ ...M, fontSize: 10, color: memCol }}>{p.mem.toFixed(1)}%</span>
                  <span style={{ ...M, fontSize: 9,
                    color: p.status === "running" ? ACC.green : p.status === "sleeping" ? T.lo : ACC.orange,
                    background: p.status === "running" ? "rgba(0,230,118,.1)" : "transparent",
                    borderRadius: 4, padding: "1px 4px" }}>
                    {p.status}
                  </span>
                </div>
              );
            })}
          </div>
        </Section>

      </div>
    </div>
  );
};

export default SystemMonitor;
