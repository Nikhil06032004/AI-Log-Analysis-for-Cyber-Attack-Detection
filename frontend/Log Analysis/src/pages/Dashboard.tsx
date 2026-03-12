import React, { useState, useEffect, useRef, useCallback } from "react";
import * as echarts from "echarts";
import ThreatCard, { Severity, ThreatStatus } from "../component/ThreatCard";

// ─── Types ────────────────────────────────────────────────────────────────────
interface Threat {
  id: string;
  threatType: string;
  sourceIP: string;
  destinationIP: string;
  severity: Severity;
  status: ThreatStatus;
  timestamp: string;
  description: string;
  protocol: string;
  eventCount: number;
  confidence: number;
}

interface LogEntry {
  id: string;
  time: string;
  level: "INFO" | "WARN" | "ERROR" | "CRITICAL";
  source: string;
  message: string;
}

// ─── Mock Data ────────────────────────────────────────────────────────────────
const MOCK_THREATS: Threat[] = [
  {
    id: "THR-0041",
    threatType: "Brute Force",
    sourceIP: "192.168.4.21",
    destinationIP: "10.0.0.5",
    severity: "critical",
    status: "active",
    timestamp: "14:32:07",
    description: "429 failed SSH login attempts detected from single source over 4 minutes. Lockout threshold exceeded.",
    protocol: "SSH",
    eventCount: 429,
    confidence: 97,
  },
  {
    id: "THR-0040",
    threatType: "Port Scan",
    sourceIP: "203.0.113.88",
    destinationIP: "10.0.0.1",
    severity: "high",
    status: "investigating",
    timestamp: "14:28:55",
    description: "Systematic TCP SYN scan detected on 1,024 ports. Likely network reconnaissance phase.",
    protocol: "TCP",
    eventCount: 1024,
    confidence: 91,
  },
  {
    id: "THR-0039",
    threatType: "Data Exfiltration",
    sourceIP: "10.0.0.45",
    destinationIP: "185.220.101.5",
    severity: "critical",
    status: "active",
    timestamp: "14:15:30",
    description: "Unusual outbound traffic spike: 2.3GB transferred to unknown external host over encrypted channel.",
    protocol: "HTTPS",
    eventCount: 156,
    confidence: 88,
  },
  {
    id: "THR-0038",
    threatType: "SQL Injection",
    sourceIP: "198.51.100.23",
    destinationIP: "10.0.0.12",
    severity: "high",
    status: "resolved",
    timestamp: "13:52:11",
    description: "Malicious SQL payload detected in POST request. Classic UNION-based injection attempt on /api/login.",
    protocol: "HTTP",
    eventCount: 7,
    confidence: 99,
  },
  {
    id: "THR-0037",
    threatType: "Privilege Escalation",
    sourceIP: "10.0.0.78",
    destinationIP: "10.0.0.1",
    severity: "medium",
    status: "investigating",
    timestamp: "13:40:02",
    description: "Internal user attempted to access root-level resources without authorization. SUDO abuse pattern detected.",
    protocol: "Internal",
    eventCount: 12,
    confidence: 76,
  },
  {
    id: "THR-0036",
    threatType: "Phishing",
    sourceIP: "mail.evil-domain.ru",
    destinationIP: "10.0.0.55",
    severity: "medium",
    status: "pending",
    timestamp: "13:25:44",
    description: "Email with malicious URL detected. Domain registered 2 days ago. Spoofed sender identity.",
    protocol: "SMTP",
    eventCount: 3,
    confidence: 82,
  },
];

const MOCK_LOGS: LogEntry[] = [
  { id: "L001", time: "14:32:07", level: "CRITICAL", source: "auth-service", message: "Multiple failed login attempts — IP 192.168.4.21 blocked" },
  { id: "L002", time: "14:31:55", level: "ERROR", source: "firewall", message: "Outbound connection to blacklisted IP 185.220.101.5 blocked" },
  { id: "L003", time: "14:30:12", level: "WARN", source: "ids-engine", message: "Port scan detected from 203.0.113.88 — 1024 ports probed" },
  { id: "L004", time: "14:28:40", level: "INFO", source: "siem-core", message: "DNN model retrain completed — accuracy: 96.4%" },
  { id: "L005", time: "14:27:03", level: "WARN", source: "network-monitor", message: "Unusual bandwidth spike: 2.3GB outbound in 8 min" },
  { id: "L006", time: "14:25:19", level: "ERROR", source: "web-server", message: "SQL injection attempt blocked on endpoint /api/login" },
  { id: "L007", time: "14:22:55", level: "INFO", source: "ansible-agent", message: "Log collection completed from 4 VMs (Ubuntu/Windows)" },
  { id: "L008", time: "14:20:10", level: "INFO", source: "elasticsearch", message: "Index optimized — 1.2M documents indexed successfully" },
  { id: "L009", time: "14:18:34", level: "WARN", source: "auth-service", message: "SUDO privilege escalation attempt by user [jdoe]" },
  { id: "L010", time: "14:15:02", level: "INFO", source: "siem-core", message: "Ruleset update applied — 342 new signatures loaded" },
];

// ─── EChart Hook ──────────────────────────────────────────────────────────────
function useChart(ref: React.RefObject<HTMLDivElement>, option: echarts.EChartsOption, deps: unknown[]) {
  const chartRef = useRef<echarts.ECharts | null>(null);
  useEffect(() => {
    if (!ref.current) return;
    if (!chartRef.current) {
      chartRef.current = echarts.init(ref.current, "dark");
    }
    chartRef.current.setOption(option, true);
    const handler = () => chartRef.current?.resize();
    window.addEventListener("resize", handler);
    return () => window.removeEventListener("resize", handler);
  }, deps);
}

// ─── Stat Card ────────────────────────────────────────────────────────────────
const StatCard: React.FC<{
  label: string; value: string | number; sub?: string; color: string; icon: string; blink?: boolean;
}> = ({ label, value, sub, color, icon, blink }) => (
  <div
    style={{ borderLeft: `3px solid ${color}`, background: "linear-gradient(135deg,#0f172a,#1e293b)" }}
    className="rounded-xl p-4 border border-slate-800/60 relative overflow-hidden"
  >
    <div className="absolute top-0 right-0 w-20 h-20 opacity-5 text-6xl flex items-center justify-center pointer-events-none">
      {icon}
    </div>
    <p className="text-slate-500 text-[10px] uppercase tracking-widest mb-1">{label}</p>
    <div className="flex items-end gap-2">
      <p
        style={{ color, fontFamily: "'JetBrains Mono', monospace" }}
        className="text-3xl font-bold leading-none"
      >
        {blink && <span className="inline-block w-2 h-2 rounded-full mr-2 animate-pulse" style={{ background: color }} />}
        {value}
      </p>
    </div>
    {sub && <p className="text-slate-500 text-xs mt-1">{sub}</p>}
  </div>
);

// ─── Main Dashboard ───────────────────────────────────────────────────────────
const Dashboard: React.FC = () => {
  const [threats, setThreats] = useState<Threat[]>(MOCK_THREATS);
  const [activeTab, setActiveTab] = useState<"all" | Severity | ThreatStatus>("all");
  const [logFilter, setLogFilter] = useState<"ALL" | "CRITICAL" | "ERROR" | "WARN" | "INFO">("ALL");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [liveCount, setLiveCount] = useState(0);

  // Chart refs
  const threatTrendRef = useRef<HTMLDivElement>(null);
  const attackTypesRef = useRef<HTMLDivElement>(null);
  const geoRef = useRef<HTMLDivElement>(null);
  const modelAccRef = useRef<HTMLDivElement>(null);
  const severityRef = useRef<HTMLDivElement>(null);
  const logVolumeRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const t = setInterval(() => setCurrentTime(new Date()), 1000);
    const l = setInterval(() => setLiveCount(Math.floor(Math.random() * 50) + 900), 3000);
    return () => { clearInterval(t); clearInterval(l); };
  }, []);

  // ── Chart Options ──────────────────────────────────────────────────────────

  const threatTrendOption: echarts.EChartsOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "axis", backgroundColor: "#1e293b", borderColor: "#334155", textStyle: { color: "#e2e8f0", fontFamily: "JetBrains Mono" } },
    legend: { data: ["Critical", "High", "Medium", "Low"], textStyle: { color: "#64748b", fontFamily: "JetBrains Mono", fontSize: 11 }, bottom: 0 },
    grid: { top: 10, right: 10, bottom: 40, left: 40, containLabel: true },
    xAxis: {
      type: "category",
      data: ["08:00","09:00","10:00","11:00","12:00","13:00","14:00"],
      axisLine: { lineStyle: { color: "#1e293b" } },
      axisLabel: { color: "#475569", fontFamily: "JetBrains Mono", fontSize: 10 },
    },
    yAxis: { type: "value", splitLine: { lineStyle: { color: "#1e293b" } }, axisLabel: { color: "#475569", fontFamily: "JetBrains Mono", fontSize: 10 } },
    series: [
      { name: "Critical", type: "line", smooth: true, data: [2,3,1,4,5,3,6], lineStyle: { color: "#ef4444", width: 2 }, itemStyle: { color: "#ef4444" }, areaStyle: { color: "rgba(239,68,68,0.1)" } },
      { name: "High", type: "line", smooth: true, data: [5,4,6,3,7,8,5], lineStyle: { color: "#f97316", width: 2 }, itemStyle: { color: "#f97316" }, areaStyle: { color: "rgba(249,115,22,0.08)" } },
      { name: "Medium", type: "line", smooth: true, data: [8,10,7,12,9,11,8], lineStyle: { color: "#eab308", width: 2 }, itemStyle: { color: "#eab308" }, areaStyle: { color: "rgba(234,179,8,0.06)" } },
      { name: "Low", type: "line", smooth: true, data: [15,12,18,14,16,13,17], lineStyle: { color: "#22c55e", width: 2 }, itemStyle: { color: "#22c55e" }, areaStyle: { color: "rgba(34,197,94,0.05)" } },
    ],
  };

  const attackTypesOption: echarts.EChartsOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "item", backgroundColor: "#1e293b", borderColor: "#334155", textStyle: { color: "#e2e8f0", fontFamily: "JetBrains Mono" } },
    series: [{
      type: "pie",
      radius: ["45%", "75%"],
      center: ["50%", "50%"],
      data: [
        { value: 35, name: "Brute Force", itemStyle: { color: "#ef4444" } },
        { value: 22, name: "Port Scan", itemStyle: { color: "#f97316" } },
        { value: 18, name: "SQL Injection", itemStyle: { color: "#eab308" } },
        { value: 12, name: "Phishing", itemStyle: { color: "#8b5cf6" } },
        { value: 8, name: "Malware", itemStyle: { color: "#06b6d4" } },
        { value: 5, name: "Exfiltration", itemStyle: { color: "#22c55e" } },
      ],
      label: { color: "#64748b", fontFamily: "JetBrains Mono", fontSize: 10 },
      labelLine: { lineStyle: { color: "#334155" } },
    }],
  };

  const modelAccOption: echarts.EChartsOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "axis", backgroundColor: "#1e293b", borderColor: "#334155", textStyle: { color: "#e2e8f0", fontFamily: "JetBrains Mono" } },
    grid: { top: 10, right: 10, bottom: 30, left: 10, containLabel: true },
    xAxis: { type: "category", data: ["Epoch 1","Epoch 2","Epoch 3","Epoch 4","Epoch 5","Epoch 6","Epoch 7","Epoch 8"], axisLabel: { color: "#475569", fontFamily: "JetBrains Mono", fontSize: 9 }, axisLine: { lineStyle: { color: "#1e293b" } } },
    yAxis: { type: "value", min: 80, max: 100, axisLabel: { color: "#475569", fontFamily: "JetBrains Mono", fontSize: 9, formatter: "{value}%" }, splitLine: { lineStyle: { color: "#1e293b" } } },
    series: [
      { name: "Accuracy", type: "bar", data: [84, 87, 90, 92, 94, 95, 96, 96.4], itemStyle: { color: { type: "linear", x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: "#06b6d4" }, { offset: 1, color: "#0891b2" }] }, borderRadius: [4,4,0,0] } },
      { name: "F1 Score", type: "line", data: [82, 85, 88, 91, 93, 94, 95.2, 95.8], lineStyle: { color: "#8b5cf6", width: 2 }, itemStyle: { color: "#8b5cf6" } },
    ],
  };

  const severityGaugeOption: echarts.EChartsOption = {
    backgroundColor: "transparent",
    series: [{
      type: "gauge",
      radius: "90%",
      startAngle: 200,
      endAngle: -20,
      min: 0,
      max: 100,
      splitNumber: 4,
      pointer: { length: "60%", width: 4, itemStyle: { color: "#ef4444" } },
      axisLine: { lineStyle: { width: 15, color: [[0.25,"#22c55e"],[0.5,"#eab308"],[0.75,"#f97316"],[1,"#ef4444"]] } },
      axisTick: { show: false },
      splitLine: { show: false },
      axisLabel: { color: "#475569", fontFamily: "JetBrains Mono", fontSize: 9 },
      detail: { valueAnimation: true, formatter: "{value}", color: "#ef4444", fontFamily: "JetBrains Mono", fontSize: 22, fontWeight: "bold", offsetCenter: [0, "35%"] },
      data: [{ value: 73, name: "Risk Score" }],
      title: { color: "#64748b", fontFamily: "JetBrains Mono", fontSize: 10, offsetCenter: [0, "58%"] },
    }],
  };

  const logVolumeOption: echarts.EChartsOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "axis", backgroundColor: "#1e293b", borderColor: "#334155", textStyle: { color: "#e2e8f0", fontFamily: "JetBrains Mono" } },
    grid: { top: 10, right: 10, bottom: 25, left: 40, containLabel: true },
    xAxis: { type: "category", data: Array.from({ length: 12 }, (_, i) => `${(8 + i).toString().padStart(2, "0")}:00`), axisLabel: { color: "#475569", fontFamily: "JetBrains Mono", fontSize: 9 }, axisLine: { lineStyle: { color: "#1e293b" } } },
    yAxis: { type: "value", axisLabel: { color: "#475569", fontFamily: "JetBrains Mono", fontSize: 9 }, splitLine: { lineStyle: { color: "#1e293b" } } },
    series: [{
      type: "bar",
      data: [450,820,1200,980,1450,1100,890,1350,920,1600,1400,1250],
      itemStyle: { color: { type: "linear", x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: "#06b6d4" }, { offset: 1, color: "rgba(6,182,212,0.2)" }] }, borderRadius: [3,3,0,0] },
      barMaxWidth: 20,
    }],
  };

  const geoOption: echarts.EChartsOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "item", backgroundColor: "#1e293b", borderColor: "#334155", textStyle: { color: "#e2e8f0", fontFamily: "JetBrains Mono" } },
    series: [{
      type: "pie",
      radius: ["30%", "60%"],
      roseType: "radius",
      data: [
        { value: 38, name: "🇷🇺 Russia", itemStyle: { color: "#ef4444" } },
        { value: 27, name: "🇨🇳 China", itemStyle: { color: "#f97316" } },
        { value: 18, name: "🇺🇸 USA", itemStyle: { color: "#eab308" } },
        { value: 10, name: "🇩🇪 Germany", itemStyle: { color: "#8b5cf6" } },
        { value: 7, name: "🌍 Other", itemStyle: { color: "#475569" } },
      ],
      label: { color: "#64748b", fontFamily: "JetBrains Mono", fontSize: 9 },
      labelLine: { lineStyle: { color: "#334155" } },
    }],
  };

  useChart(threatTrendRef, threatTrendOption, []);
  useChart(attackTypesRef, attackTypesOption, []);
  useChart(modelAccRef, modelAccOption, []);
  useChart(severityRef, severityGaugeOption, []);
  useChart(logVolumeRef, logVolumeOption, []);
  useChart(geoRef, geoOption, []);

  // ── Handlers ───────────────────────────────────────────────────────────────
  const handleInvestigate = useCallback((id: string) => {
    setThreats(prev => prev.map(t => t.id === id ? { ...t, status: "investigating" as ThreatStatus } : t));
  }, []);
  const handleResolve = useCallback((id: string) => {
    setThreats(prev => prev.map(t => t.id === id ? { ...t, status: "resolved" as ThreatStatus } : t));
  }, []);
  const handleDismiss = useCallback((id: string) => {
    setThreats(prev => prev.filter(t => t.id !== id));
  }, []);

  const filteredThreats = threats.filter(t => {
    if (activeTab === "all") return true;
    return t.severity === activeTab || t.status === activeTab;
  });

  const filteredLogs = MOCK_LOGS.filter(l => logFilter === "ALL" || l.level === logFilter);

  const stats = {
    total: threats.length,
    active: threats.filter(t => t.status === "active").length,
    critical: threats.filter(t => t.severity === "critical").length,
    resolved: threats.filter(t => t.status === "resolved").length,
  };

  const logLevelStyle: Record<string, string> = {
    CRITICAL: "text-red-400",
    ERROR: "text-orange-400",
    WARN: "text-yellow-400",
    INFO: "text-cyan-400",
  };

  return (
    <div
      className="min-h-screen text-slate-200 flex flex-col"
      style={{ background: "#060b14", fontFamily: "'Inter', sans-serif" }}
    >
      {/* Google Fonts */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@300;400;500;600&family=Orbitron:wght@700;900&display=swap');
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #0f172a; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 2px; }
        .line-clamp-2 { overflow:hidden; display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; }
        @keyframes scan { 0%{top:-2px} 100%{top:100%} }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
        .scan-line { position:absolute; left:0; right:0; height:2px; background:linear-gradient(90deg,transparent,rgba(6,182,212,0.4),transparent); animation:scan 3s linear infinite; }
      `}</style>

      {/* ── Top Nav ─────────────────────────────────────────────────────── */}
      <header
        className="flex items-center justify-between px-6 py-3 border-b border-slate-800/70 relative overflow-hidden flex-shrink-0"
        style={{ background: "#08101c" }}
      >
        <div className="scan-line" />
        <div className="flex items-center gap-4">
          <button onClick={() => setSidebarOpen(s => !s)} className="text-slate-500 hover:text-slate-300 transition-colors text-lg">
            ☰
          </button>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 text-sm font-bold">
              AI
            </div>
            <div>
              <p style={{ fontFamily: "'Orbitron', monospace" }} className="text-cyan-400 text-sm font-bold leading-none">
                SENTINEL<span className="text-slate-500">·AI</span>
              </p>
              <p className="text-slate-600 text-[9px] tracking-widest uppercase leading-none mt-0.5">
                Log Analysis &amp; Threat Detection
              </p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            <span className="text-green-400 text-xs" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
              LIVE
            </span>
          </div>
          <div className="text-slate-500 text-xs" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
            {liveCount.toLocaleString()} logs/min
          </div>
          <div
            className="text-slate-300 text-xs px-3 py-1 rounded-lg border border-slate-700 bg-slate-900"
            style={{ fontFamily: "'JetBrains Mono', monospace" }}
          >
            {currentTime.toTimeString().slice(0, 8)}
          </div>
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-full bg-slate-700 border border-slate-600 flex items-center justify-center text-xs text-slate-300">
              NS
            </div>
            <span className="text-slate-400 text-xs">Nikhil S.</span>
          </div>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* ── Sidebar ───────────────────────────────────────────────────── */}
        {sidebarOpen && (
          <aside
            className="w-52 border-r border-slate-800/70 flex flex-col gap-1 p-3 flex-shrink-0"
            style={{ background: "#07111e" }}
          >
            {[
              { icon: "⬡", label: "Dashboard", active: true },
              { icon: "⚠", label: "Threats", badge: stats.active },
              { icon: "📋", label: "Log Explorer" },
              { icon: "🧠", label: "AI Model" },
              { icon: "📡", label: "Network Map" },
              { icon: "📊", label: "Analytics" },
              { icon: "🔒", label: "SIEM Rules" },
              { icon: "⚙", label: "Settings" },
            ].map(({ icon, label, active, badge }) => (
              <div
                key={label}
                className={`flex items-center justify-between px-3 py-2 rounded-lg cursor-pointer transition-all ${
                  active
                    ? "bg-cyan-500/15 border border-cyan-500/30 text-cyan-400"
                    : "text-slate-500 hover:bg-slate-800/60 hover:text-slate-300"
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-sm">{icon}</span>
                  <span className="text-xs font-medium">{label}</span>
                </div>
                {badge !== undefined && badge > 0 && (
                  <span className="w-5 h-5 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center">
                    {badge}
                  </span>
                )}
              </div>
            ))}
            <div className="mt-auto pt-4 border-t border-slate-800/60">
              <div className="px-3 py-2 rounded-lg bg-slate-900/60 border border-slate-800">
                <p className="text-[9px] text-slate-500 uppercase tracking-widest mb-1">DNN Model</p>
                <p className="text-xs font-bold text-cyan-400" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                  v2.4.1 · Active
                </p>
                <div className="h-1 bg-slate-800 rounded-full mt-1.5 overflow-hidden">
                  <div className="h-full w-[96%] bg-cyan-500 rounded-full" />
                </div>
                <p className="text-[9px] text-slate-500 mt-0.5">Acc: 96.4% · F1: 95.8%</p>
              </div>
            </div>
          </aside>
        )}

        {/* ── Main Content ──────────────────────────────────────────────── */}
        <main className="flex-1 overflow-y-auto p-5 space-y-5">

          {/* Stat Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard label="Total Threats" value={stats.total} sub="Last 24 hours" color="#06b6d4" icon="⚠" />
            <StatCard label="Active Threats" value={stats.active} sub="Requires attention" color="#ef4444" icon="🔴" blink />
            <StatCard label="Critical Alerts" value={stats.critical} sub="Immediate action" color="#f97316" icon="🔥" />
            <StatCard label="Resolved Today" value={stats.resolved} sub="Successfully mitigated" color="#22c55e" icon="✓" />
          </div>

          {/* System Status Strip */}
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: "Elasticsearch", status: "Operational", color: "#22c55e" },
              { label: "Ansible Agents", status: "4/4 Online", color: "#22c55e" },
              { label: "SIEM Core", status: "Operational", color: "#22c55e" },
              { label: "DNN Engine", status: "Training", color: "#eab308" },
            ].map(({ label, status, color }) => (
              <div
                key={label}
                className="flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-800/60 bg-slate-900/40"
              >
                <span className="w-2 h-2 rounded-full flex-shrink-0 animate-pulse" style={{ background: color }} />
                <div>
                  <p className="text-[10px] text-slate-500">{label}</p>
                  <p className="text-xs font-semibold" style={{ color }}>{status}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Charts Row 1 */}
          <div className="grid grid-cols-3 gap-4">
            {/* Threat Trend */}
            <div className="col-span-2 rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
              <div className="flex items-center justify-between mb-3">
                <p className="text-sm font-semibold text-slate-200">Threat Trend (Today)</p>
                <span className="text-[10px] text-slate-500 border border-slate-700 px-2 py-0.5 rounded" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                  Real-time
                </span>
              </div>
              <div ref={threatTrendRef} style={{ height: 200 }} />
            </div>
            {/* Risk Gauge */}
            <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4 flex flex-col">
              <p className="text-sm font-semibold text-slate-200 mb-2">Network Risk Score</p>
              <div ref={severityRef} style={{ height: 180 }} className="flex-1" />
              <p className="text-center text-[10px] text-slate-500 mt-1">73/100 — High Risk</p>
            </div>
          </div>

          {/* Charts Row 2 */}
          <div className="grid grid-cols-3 gap-4">
            {/* Attack Types */}
            <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
              <p className="text-sm font-semibold text-slate-200 mb-3">Attack Distribution</p>
              <div ref={attackTypesRef} style={{ height: 200 }} />
            </div>
            {/* Log Volume */}
            <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
              <p className="text-sm font-semibold text-slate-200 mb-3">Log Volume (Hourly)</p>
              <div ref={logVolumeRef} style={{ height: 200 }} />
            </div>
            {/* Geo Origin */}
            <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
              <p className="text-sm font-semibold text-slate-200 mb-3">Attack Origin</p>
              <div ref={geoRef} style={{ height: 200 }} />
            </div>
          </div>

          {/* DNN Model Performance */}
          <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
            <div className="flex items-center justify-between mb-3">
              <p className="text-sm font-semibold text-slate-200">🧠 DNN Model Training Performance</p>
              <div className="flex gap-3 text-[10px]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                {[["Accuracy","#06b6d4"],["F1 Score","#8b5cf6"],["Precision","#22c55e"],["Recall","#eab308"]].map(([k,c]) => (
                  <span key={k} style={{ color: c }}>{k}</span>
                ))}
              </div>
            </div>
            <div ref={modelAccRef} style={{ height: 180 }} />
          </div>

          {/* Threats + Logs */}
          <div className="grid grid-cols-5 gap-5">
            {/* Threat Feed */}
            <div className="col-span-3 rounded-xl border border-slate-800/60 bg-slate-900/30 flex flex-col">
              <div className="flex items-center justify-between p-4 border-b border-slate-800/60">
                <p className="text-sm font-semibold text-slate-200">Active Threat Feed</p>
                <div className="flex gap-1">
                  {(["all","critical","high","medium","low","active","resolved"] as const).map(tab => (
                    <button
                      key={tab}
                      onClick={() => setActiveTab(tab)}
                      className={`text-[10px] px-2 py-1 rounded capitalize transition-colors ${
                        activeTab === tab
                          ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                          : "text-slate-500 hover:text-slate-300"
                      }`}
                      style={{ fontFamily: "'JetBrains Mono', monospace" }}
                    >
                      {tab}
                    </button>
                  ))}
                </div>
              </div>
              <div className="flex-1 overflow-y-auto p-4 space-y-3" style={{ maxHeight: 500 }}>
                {filteredThreats.length === 0 ? (
                  <div className="flex items-center justify-center h-24 text-slate-600 text-sm">
                    No threats in this category
                  </div>
                ) : (
                  filteredThreats.map(t => (
                    <ThreatCard
                      key={t.id}
                      {...t}
                      onInvestigate={handleInvestigate}
                      onResolve={handleResolve}
                      onDismiss={handleDismiss}
                    />
                  ))
                )}
              </div>
            </div>

            {/* Live Logs */}
            <div className="col-span-2 rounded-xl border border-slate-800/60 bg-slate-900/30 flex flex-col">
              <div className="flex items-center justify-between p-4 border-b border-slate-800/60">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                  <p className="text-sm font-semibold text-slate-200">Live Log Stream</p>
                </div>
                <select
                  value={logFilter}
                  onChange={e => setLogFilter(e.target.value as typeof logFilter)}
                  className="text-[10px] bg-slate-800 border border-slate-700 rounded px-2 py-1 text-slate-400"
                  style={{ fontFamily: "'JetBrains Mono', monospace" }}
                >
                  {["ALL","CRITICAL","ERROR","WARN","INFO"].map(v => (
                    <option key={v} value={v}>{v}</option>
                  ))}
                </select>
              </div>
              <div className="flex-1 overflow-y-auto p-3 space-y-1.5" style={{ maxHeight: 500 }}>
                {filteredLogs.map(log => (
                  <div
                    key={log.id}
                    className="p-2.5 rounded-lg border border-slate-800/40 bg-slate-900/60 hover:bg-slate-800/40 transition-colors"
                  >
                    <div className="flex items-center gap-2 mb-0.5">
                      <span
                        className={`text-[9px] font-bold ${logLevelStyle[log.level]}`}
                        style={{ fontFamily: "'JetBrains Mono', monospace" }}
                      >
                        {log.level}
                      </span>
                      <span className="text-slate-600 text-[9px]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                        {log.time}
                      </span>
                      <span className="text-cyan-700 text-[9px]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                        {log.source}
                      </span>
                    </div>
                    <p className="text-slate-400 text-[10px] leading-relaxed">{log.message}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between text-[10px] text-slate-600 pt-2 border-t border-slate-800/40 pb-2">
            <span style={{ fontFamily: "'JetBrains Mono', monospace" }}>
              SENTINEL·AI v2.4.1 · Log Analysis for Cyber Threat Detection · AY25BECS
            </span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace" }}>
              SLRTCE · Dept. of Computer Engineering · University of Mumbai
            </span>
          </div>
        </main>
      </div>
    </div>
  );
};

export default Dashboard;