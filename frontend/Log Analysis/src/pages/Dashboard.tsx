import React, { useState, useEffect, useCallback } from "react";
import { fetchThreats, fetchLogs } from "../services/api";
import type { Threat, LogEntry, ThreatStatus } from "../types";
import { MOCK_THREATS, MOCK_LOGS } from "../constants/mockData";
import { BG, BORD, T, ACC, M } from "../constants/theme";
import "../styles/layout.css";

import Header from "../components/layout/Header";
import Sidebar from "../components/layout/Sidebar";
import StatCard from "../components/ui/StatCard";
import StatusStrip from "../components/ui/StatusStrip";
import Panel from "../components/ui/Panel";
import ThreatTrendChart from "../components/charts/ThreatTrendChart";
import RiskGaugeChart from "../components/charts/RiskGaugeChart";
import AttackDistributionChart from "../components/charts/AttackDistributionChart";
import LogVolumeChart from "../components/charts/LogVolumeChart";
import AttackOriginChart from "../components/charts/AttackOriginChart";
import ModelPerformanceChart from "../components/charts/ModelPerformanceChart";
import ThreatFeed from "../components/threats/ThreatFeed";
import LogStream from "../components/logs/LogStream";

const Dashboard: React.FC = () => {
  const [threats, setThreats]         = useState<Threat[]>(MOCK_THREATS);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [clock, setClock]             = useState(new Date());
  const [rate, setRate]               = useState(934);
  const [apiLogs, setApiLogs]         = useState<LogEntry[] | null>(null);
  const [chartsReady, setChartsReady] = useState(false);

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    const r = setInterval(() => setRate(Math.floor(Math.random()*60)+900), 3000);
    // let layout settle before initialising charts
    const c = setTimeout(() => setChartsReady(true), 200);
    return () => { clearInterval(t); clearInterval(r); clearTimeout(c); };
  }, []);

  useEffect(() => {
    fetchThreats().then(d => setThreats(d)).catch(()=>{});
    fetchLogs().then(d => setApiLogs(d as unknown as LogEntry[])).catch(()=>{});
  }, []);

  /* ── Handlers ────────────────────────────────────────────────────── */
  const handleInvestigate = useCallback((id: string) =>
    setThreats(p => p.map(t => t.id===id ? {...t, status:"investigating" as ThreatStatus} : t)), []);
  const handleResolve = useCallback((id: string) =>
    setThreats(p => p.map(t => t.id===id ? {...t, status:"resolved" as ThreatStatus} : t)), []);
  const handleDismiss = useCallback((id: string) =>
    setThreats(p => p.filter(t => t.id!==id)), []);

  const logs  = apiLogs ?? MOCK_LOGS;
  const stats = {
    total:    threats.length,
    active:   threats.filter(t => t.status==="active").length,
    critical: threats.filter(t => t.severity==="critical").length,
    resolved: threats.filter(t => t.status==="resolved").length,
  };

  return (
    <div id="dbw" className="dash-shell">

      {/* ══ HEADER ══════════════════════════════════════════════ */}
      <Header
        sidebarOpen={sidebarOpen}
        onToggleSidebar={() => setSidebarOpen(s => !s)}
        clock={clock}
        liveRate={rate}
      />

      {/* ══ BODY ROW — sidebar left, main right ═════════════════ */}
      <div className="dash-body">

        <Sidebar open={sidebarOpen} activeCount={stats.active} />

        <div className="dash-main">

          {/* ─ R1 · Stat cards ────────────────────────────────────── */}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:14 }}>
            <div className="sc" style={{ transition:"transform .18s,box-shadow .18s" }}><StatCard label="Total Threats"   value={stats.total}    sub="Last 24 hours"        color={ACC.cyan}   icon="⚠" /></div>
            <div className="sc" style={{ transition:"transform .18s,box-shadow .18s" }}><StatCard label="Active Threats"  value={stats.active}   sub="Requires attention"   color={ACC.red}    icon="🔴" pulse /></div>
            <div className="sc" style={{ transition:"transform .18s,box-shadow .18s" }}><StatCard label="Critical Alerts" value={stats.critical} sub="Immediate action"     color={ACC.orange} icon="🔥" /></div>
            <div className="sc" style={{ transition:"transform .18s,box-shadow .18s" }}><StatCard label="Resolved Today"  value={stats.resolved} sub="Successfully handled" color={ACC.green}  icon="✓" /></div>
          </div>

          {/* ─ R2 · System status ─────────────────────────────────── */}
          <StatusStrip />

          {/* ─ R3 · Threat trend + Risk gauge ─────────────────────── */}
          <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr", gap:14, minHeight:0 }}>
            <Panel
              title="Threat Trend — Today"
              badge={<span style={{ ...M, fontSize:9, color:T.lo, border:`1px solid ${BORD.dim}`, borderRadius:4, padding:"2px 8px", letterSpacing:".1em" }}>REAL-TIME</span>}
              pad={12}
            >
              <ThreatTrendChart ready={chartsReady} />
            </Panel>

            <Panel title="Network Risk Score" pad={10}>
              <RiskGaugeChart ready={chartsReady} />
              <p style={{ ...M, fontSize:10, color:T.lo, textAlign:"center", marginTop:2 }}>73 / 100 — High Risk</p>
            </Panel>
          </div>

          {/* ─ R4 · Attack dist / Log volume / Attack origin ────────── */}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:14 }}>
            <Panel title="Attack Distribution" pad={12}>
              <AttackDistributionChart ready={chartsReady} />
            </Panel>
            <Panel title="Log Volume (Hourly)" pad={12}>
              <LogVolumeChart ready={chartsReady} />
            </Panel>
            <Panel title="Attack Origin" pad={12}>
              <AttackOriginChart ready={chartsReady} />
            </Panel>
          </div>

          {/* ─ R5 · DNN model performance ─────────────────────────── */}
          <Panel
            title="🧠 DNN Model Training Performance"
            badge={
              <div style={{ display:"flex", gap:16, alignItems:"center" }}>
                {([["Accuracy",ACC.cyan],["F1 Score",ACC.purple],["Precision",ACC.green],["Recall",ACC.yellow]] as [string,string][]).map(([k,c]) => (
                  <div key={k} style={{ display:"flex", alignItems:"center", gap:5 }}>
                    <span style={{ width:7, height:7, borderRadius:"50%", background:c, display:"inline-block" }} />
                    <span style={{ ...M, fontSize:10, color:c }}>{k}</span>
                  </div>
                ))}
              </div>
            }
            pad={12}
          >
            <ModelPerformanceChart ready={chartsReady} />
          </Panel>

          {/* ─ R6 · Threat feed + Live logs ───────────────────────── */}
          <div style={{ display:"grid", gridTemplateColumns:"3fr 2fr", gap:14 }}>
            <ThreatFeed
              threats={threats}
              onInvestigate={handleInvestigate}
              onResolve={handleResolve}
              onDismiss={handleDismiss}
            />
            <LogStream logs={logs} />
          </div>

          {/* ─ Footer ─────────────────────────────────────────────── */}
          <div style={{ display:"flex", justifyContent:"space-between", paddingTop:14, borderTop:`1px solid ${BORD.dim}` }}>
            <span style={{ ...M, fontSize:9, color:T.dim }}>SENTINEL·AI v2.4.1 · Log Analysis for Cyber Threat Detection · AY25BECS</span>
            <span style={{ ...M, fontSize:9, color:T.dim }}>SLRTCE · Dept. of Computer Engineering · University of Mumbai</span>
          </div>

        </div>
      </div>{/* end body container */}
    </div>
  );
};

export default Dashboard;
