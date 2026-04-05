import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import { useAnalysis } from "../context/AnalysisContext";
import { BORD, T, ACC, M } from "../constants/theme";
import AttackDistributionChart from "../components/charts/AttackDistributionChart";
import LogVolumeChart from "../components/charts/LogVolumeChart";
import type { AttackDataItem } from "../components/charts/AttackDistributionChart";
import type { LogVolumeDataItem } from "../components/charts/LogVolumeChart";

const THREAT_PALETTE = [ACC.red, ACC.orange, ACC.yellow, ACC.purple, ACC.cyan, ACC.green];

const Analytics: React.FC = () => {
  const { result, hasData, polling } = useAnalysis();
  const [ready,   setReady]   = useState(false);
  const trendRef  = useRef<HTMLDivElement>(null);
  const trendInst = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    const t = setTimeout(() => setReady(true), 150);
    return () => clearTimeout(t);
  }, []);

  // ── Derived data ────────────────────────────────────────────────────────────
  const distribution: AttackDataItem[] = result
    ? Object.entries(result.summary.by_threat_type).map(([name, value], i) => ({
        name: name.replace(/_/g, " "),
        value,
        color: THREAT_PALETTE[i % THREAT_PALETTE.length],
      }))
    : [];

  const volumeData: LogVolumeDataItem[] = result
    ? Object.entries(result.hourly_volume).map(([label, sources]) => ({
        label,
        windows: (sources["windows_security"] ?? 0)
               + (sources["windows_system"]   ?? 0)
               + (sources["windows_application"] ?? 0),
        network: sources["network"] ?? 0,
        syslog:  Object.entries(sources)
          .filter(([k]) => k.startsWith("syslog_"))
          .reduce((s, [, v]) => s + v, 0),
      }))
    : [];

  // ── Trend chart from hourly_volume ─────────────────────────────────────────
  useEffect(() => {
    if (!ready || !trendRef.current || !result) return;

    if (trendInst.current) trendInst.current.dispose();
    trendInst.current = echarts.init(trendRef.current, "dark");

    const hours  = Object.keys(result.hourly_volume);
    const allSources = new Set<string>();
    Object.values(result.hourly_volume).forEach(s => Object.keys(s).forEach(k => allSources.add(k)));

    // group sources into 3 series: windows, network, syslog
    const winData  = hours.map(h => (result.hourly_volume[h]["windows_security"] ?? 0)
                                  + (result.hourly_volume[h]["windows_system"]   ?? 0)
                                  + (result.hourly_volume[h]["windows_application"] ?? 0));
    const netData  = hours.map(h => result.hourly_volume[h]["network"] ?? 0);
    const sysData  = hours.map(h =>
      Object.entries(result.hourly_volume[h])
        .filter(([k]) => k.startsWith("syslog_"))
        .reduce((s, [, v]) => s + v, 0));

    const mkArea = (color: string, alpha = 0.25) =>
      new echarts.graphic.LinearGradient(0, 0, 0, 1, [
        { offset: 0, color: color.replace(")", `,${alpha})`).replace("rgb", "rgba") },
        { offset: 1, color: color.replace(")", ",0)").replace("rgb", "rgba") },
      ]);

    trendInst.current.setOption({
      backgroundColor: "transparent",
      tooltip: {
        trigger: "axis",
        backgroundColor: "#0e2040",
        borderColor: "#1e4060",
        textStyle: { color: "#eaf4ff", fontFamily: "JetBrains Mono", fontSize: 11 },
      },
      legend: {
        top: 0, right: 0,
        textStyle: { color: T.md, fontSize: 10, fontFamily: "JetBrains Mono" },
        icon: "circle", itemWidth: 8, itemHeight: 8,
      },
      grid: { top: 36, right: 14, bottom: 28, left: 8, containLabel: true },
      xAxis: {
        type: "category", data: hours,
        axisLabel: { color: T.lo, fontSize: 9, fontFamily: "JetBrains Mono", interval: Math.max(0, Math.floor(hours.length / 6) - 1) },
        axisLine: { lineStyle: { color: BORD.dim } },
        axisTick: { show: false },
      },
      yAxis: {
        type: "value",
        axisLabel: { color: T.lo, fontSize: 9, fontFamily: "JetBrains Mono" },
        splitLine: { lineStyle: { color: BORD.dim } },
      },
      series: [
        {
          name: "Windows", type: "line", smooth: true, data: winData,
          lineStyle: { color: ACC.purple, width: 2 }, itemStyle: { color: ACC.purple },
          areaStyle: { color: mkArea(ACC.purple) }, symbol: "none",
        },
        {
          name: "Network", type: "line", smooth: true, data: netData,
          lineStyle: { color: ACC.cyan, width: 2 }, itemStyle: { color: ACC.cyan },
          areaStyle: { color: mkArea(ACC.cyan) }, symbol: "none",
        },
        {
          name: "Syslog", type: "line", smooth: true, data: sysData,
          lineStyle: { color: ACC.green, width: 2 }, itemStyle: { color: ACC.green },
          areaStyle: { color: mkArea(ACC.green) }, symbol: "none",
        },
      ],
    });

    const ro = new ResizeObserver(() => trendInst.current?.resize());
    ro.observe(trendRef.current);
    return () => { ro.disconnect(); trendInst.current?.dispose(); };
  }, [ready, result]);

  // ── No data state ───────────────────────────────────────────────────────────
  if (!hasData || !result) {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "50vh", gap: 14, textAlign: "center" }}>
        <span style={{ fontSize: 32 }}>📊</span>
        <h2 style={{ ...M, color: T.hi, fontSize: 18, fontWeight: 700 }}>No Analytics Data</h2>
        <p style={{ ...M, fontSize: 12, color: T.lo }}>Run an analysis from the Dashboard first.</p>
      </div>
    );
  }

  const uniqueSources = new Set(
    result.results.filter(r => r.is_threat).map(r => r.raw_log.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/)?.[1]).filter(Boolean)
  ).size;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* page header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h2 style={{ ...M, color: T.hi, fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Analytics</h2>
          <p style={{ ...M, fontSize: 11, color: T.lo }}>
            Deep-dive charts · {result.total_collected.toLocaleString()} logs analysed
            {polling && <span style={{ color: ACC.cyan, marginLeft: 8 }}>· syncing…</span>}
          </p>
        </div>
        <span style={{ ...M, fontSize: 9, color: T.dim }}>
          Last updated: {new Date(result.timestamp).toLocaleTimeString()}
        </span>
      </div>

      {/* stat strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14 }}>
        {[
          { label: "Total Logs",      value: result.total_collected.toLocaleString(),                 color: ACC.cyan   },
          { label: "Threats Found",   value: result.total_threats.toLocaleString(),                   color: ACC.red    },
          { label: "Threat Rate",     value: `${(result.threat_rate * 100).toFixed(1)}%`,             color: ACC.orange },
          { label: "Unique Attackers",value: uniqueSources.toString(),                                color: ACC.green  },
        ].map(({ label, value, color }) => (
          <div key={label} style={{
            background: "#0b1a2e", border: `1px solid ${BORD.dim}`,
            borderLeft: `3px solid ${color}`, borderRadius: 14, padding: "18px 20px",
          }}>
            <p style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".14em", textTransform: "uppercase", marginBottom: 8 }}>{label}</p>
            <p style={{ ...M, fontSize: 30, fontWeight: 700, color }}>{value}</p>
          </div>
        ))}
      </div>

      {/* threat trend */}
      <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, overflow: "hidden" }}>
        <div style={{ padding: "13px 18px", borderBottom: `1px solid ${BORD.dim}`, background: "#091628" }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: T.hi, fontFamily: "'Inter',sans-serif" }}>
            Log Volume Trend — by Source
          </span>
        </div>
        <div style={{ padding: 14 }}>
          <div ref={trendRef} style={{ width: "100%", height: 280 }} />
        </div>
      </div>

      {/* pie + volume */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, overflow: "hidden" }}>
          <div style={{ padding: "13px 18px", borderBottom: `1px solid ${BORD.dim}`, background: "#091628" }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: T.hi, fontFamily: "'Inter',sans-serif" }}>Attack Distribution</span>
          </div>
          <div style={{ padding: 12 }}>
            <AttackDistributionChart ready={ready} data={distribution.length > 0 ? distribution : undefined} />
          </div>
        </div>

        <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, overflow: "hidden" }}>
          <div style={{ padding: "13px 18px", borderBottom: `1px solid ${BORD.dim}`, background: "#091628" }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: T.hi, fontFamily: "'Inter',sans-serif" }}>Hourly Log Volume</span>
          </div>
          <div style={{ padding: 12 }}>
            <LogVolumeChart ready={ready} data={volumeData.length > 0 ? volumeData : undefined} />
          </div>
        </div>
      </div>

      {/* severity breakdown table */}
      <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, overflow: "hidden" }}>
        <div style={{ padding: "13px 18px", borderBottom: `1px solid ${BORD.dim}`, background: "#091628" }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: T.hi, fontFamily: "'Inter',sans-serif" }}>Severity Breakdown</span>
        </div>
        <div style={{ padding: "14px 20px", display: "flex", flexDirection: "column", gap: 10 }}>
          {Object.entries(result.summary.by_severity).map(([sev, count]) => {
            const pct = result.total_collected > 0 ? (count / result.total_collected) * 100 : 0;
            const color = ({ critical: ACC.red, high: ACC.orange, medium: ACC.yellow, low: ACC.cyan, none: ACC.green } as Record<string, string>)[sev] ?? T.md;
            return (
              <div key={sev} style={{ display: "flex", alignItems: "center", gap: 14 }}>
                <span style={{ ...M, fontSize: 10, fontWeight: 700, color, textTransform: "uppercase", width: 64, flexShrink: 0 }}>{sev}</span>
                <div style={{ flex: 1, height: 8, background: "#06101e", borderRadius: 4, overflow: "hidden" }}>
                  <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 4, transition: "width .6s ease" }} />
                </div>
                <span style={{ ...M, fontSize: 10, color: T.md, width: 52, textAlign: "right", flexShrink: 0 }}>
                  {count.toLocaleString()} <span style={{ color: T.dim, fontSize: 9 }}>({pct.toFixed(1)}%)</span>
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default Analytics;
