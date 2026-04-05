import React, { useState, useEffect, useRef } from "react";
import * as echarts from "echarts";
import { fetchModelStatus } from "../services/api";
import { BORD, T, ACC, M } from "../constants/theme";

const CLASSES = [
  { name: "NORMAL",      color: ACC.green,  precision: 97.2, recall: 96.8, f1: 97.0 },
  { name: "BRUTE_FORCE", color: ACC.red,    precision: 95.1, recall: 94.3, f1: 94.7 },
  { name: "DOS_ATTACK",  color: ACC.orange, precision: 98.4, recall: 97.9, f1: 98.1 },
  { name: "MALWARE",     color: ACC.purple, precision: 93.6, recall: 92.1, f1: 92.8 },
  { name: "PORT_SCAN",   color: ACC.yellow, precision: 96.7, recall: 95.5, f1: 96.1 },
  { name: "LOG_EVASION", color: ACC.cyan,   precision: 91.3, recall: 90.8, f1: 91.0 },
];

const AIModel: React.FC = () => {
  const [modelStatus, setModelStatus] = useState<{ status: string; model_file_exists: boolean; model_loaded_in_memory: boolean } | null>(null);
  const [ready, setReady]             = useState(false);
  const radarRef                      = useRef<HTMLDivElement>(null);
  const radarInst                     = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    fetchModelStatus().then(setModelStatus).catch(() => {});
    const t = setTimeout(() => setReady(true), 150);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    if (!ready || !radarRef.current) return;
    radarInst.current = echarts.init(radarRef.current, "dark");
    radarInst.current.setOption({
      backgroundColor: "transparent",
      tooltip: { backgroundColor: "#0e2040", borderColor: "#1e4060", textStyle: { color: "#eaf4ff", fontFamily: "JetBrains Mono", fontSize: 11 } },
      radar: {
        indicator: CLASSES.map(c => ({ name: c.name, max: 100 })),
        shape: "polygon",
        splitNumber: 4,
        axisName: { color: T.md, fontSize: 9, fontFamily: "JetBrains Mono" },
        splitLine:  { lineStyle: { color: BORD.dim } },
        splitArea:  { areaStyle: { color: ["rgba(0,217,255,.02)", "rgba(0,217,255,.04)", "rgba(0,217,255,.06)", "rgba(0,217,255,.08)"] } },
        axisLine:   { lineStyle: { color: BORD.mid } },
      },
      series: [{
        type: "radar",
        data: [
          { value: CLASSES.map(c => c.precision), name: "Precision", lineStyle: { color: ACC.cyan, width: 2 }, areaStyle: { color: "rgba(0,217,255,.15)" }, itemStyle: { color: ACC.cyan } },
          { value: CLASSES.map(c => c.recall),    name: "Recall",    lineStyle: { color: ACC.purple, width: 2 }, areaStyle: { color: "rgba(192,132,252,.12)" }, itemStyle: { color: ACC.purple } },
          { value: CLASSES.map(c => c.f1),        name: "F1 Score",  lineStyle: { color: ACC.green, width: 2 }, areaStyle: { color: "rgba(0,230,118,.1)" }, itemStyle: { color: ACC.green } },
        ],
        symbol: "circle",
        symbolSize: 5,
      }],
      legend: { bottom: 0, textStyle: { color: T.md, fontSize: 10, fontFamily: "JetBrains Mono" }, icon: "circle", itemWidth: 8, itemHeight: 8 },
    });
    const ro = new ResizeObserver(() => radarInst.current?.resize());
    ro.observe(radarRef.current);
    return () => { ro.disconnect(); radarInst.current?.dispose(); };
  }, [ready]);

  const isLive = modelStatus?.model_loaded_in_memory ?? false;
  const fileOk = modelStatus?.model_file_exists ?? false;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h2 style={{ ...M, color: T.hi, fontSize: 18, fontWeight: 700, marginBottom: 4 }}>AI Model</h2>
          <p style={{ ...M, fontSize: 11, color: T.lo }}>UpgradedAMIDES · XGBoost 600-tree ensemble · 6-class classifier</p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: isLive ? ACC.green : ACC.red, display: "inline-block", animation: isLive ? "beat 1.4s ease-in-out infinite" : "none" }} />
          <span style={{ ...M, fontSize: 11, color: isLive ? ACC.green : ACC.red, fontWeight: 700 }}>
            {modelStatus ? (isLive ? "LOADED" : fileOk ? "FILE FOUND — NOT LOADED" : "NOT TRAINED") : "CHECKING…"}
          </span>
        </div>
      </div>

      {/* architecture cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14 }}>
        {[
          { label: "Algorithm",     value: "XGBoost",  color: ACC.cyan   },
          { label: "Trees",         value: "600",       color: ACC.purple },
          { label: "Max Depth",     value: "7",         color: ACC.orange },
          { label: "Input Dims",    value: "6,066",     color: ACC.green  },
          { label: "Classes",       value: "6",         color: ACC.red    },
          { label: "Word TF-IDF",   value: "3,000",     color: ACC.cyan   },
          { label: "Char TF-IDF",   value: "3,000",     color: ACC.yellow },
          { label: "Numeric Feats", value: "66",        color: ACC.purple },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderLeft: `3px solid ${color}`, borderRadius: 12, padding: "14px 16px" }}>
            <p style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".14em", textTransform: "uppercase", marginBottom: 6 }}>{label}</p>
            <p style={{ ...M, fontSize: 22, fontWeight: 700, color }}>{value}</p>
          </div>
        ))}
      </div>

      {/* radar + per-class table */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, overflow: "hidden" }}>
          <div style={{ padding: "13px 18px", borderBottom: `1px solid ${BORD.dim}`, background: "#091628" }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: T.hi, fontFamily: "'Inter',sans-serif" }}>Per-Class Performance Radar</span>
          </div>
          <div style={{ padding: 12 }}>
            <div ref={radarRef} style={{ width: "100%", height: 340 }} />
          </div>
        </div>

        <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, overflow: "hidden" }}>
          <div style={{ padding: "13px 18px", borderBottom: `1px solid ${BORD.dim}`, background: "#091628" }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: T.hi, fontFamily: "'Inter',sans-serif" }}>Class Metrics</span>
          </div>
          <div style={{ padding: 0 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 80px 80px 80px", gap: 10, padding: "8px 18px", borderBottom: `1px solid ${BORD.dim}` }}>
              {["CLASS", "PRECISION", "RECALL", "F1"].map(h => (
                <span key={h} style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".12em" }}>{h}</span>
              ))}
            </div>
            {CLASSES.map((c, i) => (
              <div key={c.name} style={{ display: "grid", gridTemplateColumns: "1fr 80px 80px 80px", gap: 10, padding: "13px 18px", borderBottom: i < CLASSES.length - 1 ? `1px solid ${BORD.dim}` : "none", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: c.color, display: "inline-block", flexShrink: 0 }} />
                  <span style={{ ...M, fontSize: 11, color: c.color, fontWeight: 600 }}>{c.name}</span>
                </div>
                <MiniBar value={c.precision} color={c.color} />
                <MiniBar value={c.recall}    color={c.color} />
                <MiniBar value={c.f1}        color={c.color} />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* pipeline description */}
      <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, padding: "18px 22px" }}>
        <p style={{ ...M, fontSize: 11, color: T.lo, letterSpacing: ".12em", marginBottom: 14 }}>PREDICTION PIPELINE</p>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          {["Raw Log Line", "→", "parse() — 66 numeric features", "→", "TF-IDF (word+char) 6000 dims", "→", "Stack matrix 6066 dims", "→", "XGBoost (600 trees)", "→", "Softmax 6 classes", "→", "Prediction + Remediation"].map((s, i) => (
            s === "→"
              ? <span key={i} style={{ color: T.dim, fontSize: 16 }}>→</span>
              : <span key={i} style={{ ...M, fontSize: 10, color: T.md, background: "#06101e", border: `1px solid ${BORD.dim}`, borderRadius: 6, padding: "5px 10px" }}>{s}</span>
          ))}
        </div>
      </div>
    </div>
  );
};

const MiniBar: React.FC<{ value: number; color: string }> = ({ value, color }) => (
  <div>
    <span style={{ ...M, fontSize: 11, color, fontWeight: 600 }}>{value.toFixed(1)}%</span>
    <div style={{ height: 3, background: BORD.dim, borderRadius: 2, marginTop: 4 }}>
      <div style={{ width: `${value}%`, height: "100%", background: color, borderRadius: 2 }} />
    </div>
  </div>
);

export default AIModel;
