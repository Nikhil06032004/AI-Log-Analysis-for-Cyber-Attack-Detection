import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import { useAnalysis } from "../context/AnalysisContext";
import type { SystemPredictionEntry } from "../services/api";
import { BORD, T, ACC, M } from "../constants/theme";

const SEV_COLOR: Record<string, string> = {
  critical: ACC.red, high: ACC.orange, medium: ACC.yellow, low: ACC.cyan, none: ACC.green,
};

const EXPLANATION: Record<string, string> = {
  BRUTE_FORCE:       "Repeated authentication failures from single source — password brute-force attack",
  PORT_SCAN:         "Systematic TCP/UDP probe across multiple ports — network reconnaissance",
  DOS_ATTACK:        "High-frequency packet flood to a target — denial-of-service pattern",
  MALWARE:           "Malicious code execution or C2 callback signature detected",
  LOG_EVASION:       "Log tampering or suppression behaviour — attacker hiding activity",
  NORMAL:            "Traffic classified as normal — no threat indicators",
};

function getExplanation(threatType: string): string {
  return EXPLANATION[threatType] ?? `${threatType.replace(/_/g, " ")} activity detected`;
}

function extractIPs(raw: string): { src: string; dst: string } {
  const matches = [...raw.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)].map(m => m[1]);
  return { src: matches[0] ?? "—", dst: matches[1] ?? matches[0] ?? "—" };
}

function guessProtocol(entry: SystemPredictionEntry): string {
  const l = (entry.raw_log + " " + entry.log_source).toLowerCase();
  if (l.includes("ssh"))   return "SSH";
  if (l.includes("https")) return "HTTPS";
  if (l.includes("http"))  return "HTTP";
  if (l.includes("dns"))   return "DNS";
  if (l.includes("rdp"))   return "RDP";
  if (l.includes("ftp"))   return "FTP";
  if (l.includes("smtp"))  return "SMTP";
  if (l.includes("icmp"))  return "ICMP";
  if (l.includes("udp"))   return "UDP";
  if (l.includes("tcp"))   return "TCP";
  if (l.includes("network")) return "TCP";
  return "—";
}

const NetworkMap: React.FC = () => {
  const { result, hasData, polling } = useAnalysis();
  const graphRef  = useRef<HTMLDivElement>(null);
  const graphInst = useRef<echarts.ECharts | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setReady(true), 150);
    return () => clearTimeout(t);
  }, []);

  // filter to threat entries that have at least one IP
  const connections: Array<SystemPredictionEntry & { src: string; dst: string; protocol: string }> =
    (result?.results ?? [])
      .filter(e => e.is_threat)
      .map(e => ({ ...e, ...extractIPs(e.raw_log), protocol: guessProtocol(e) }))
      .filter(e => e.src !== "—");

  // build graph from connections
  useEffect(() => {
    if (!ready || !graphRef.current) return;

    if (graphInst.current) graphInst.current.dispose();
    graphInst.current = echarts.init(graphRef.current, "dark");

    const nodeMap = new Map<string, { id: string; category: number; symbolSize: number }>();
    const links: { source: string; target: string; lineStyle: { color: string; width: number } }[] = [];

    const addNode = (id: string, category: number, size: number) => {
      if (!nodeMap.has(id)) nodeMap.set(id, { id, category, symbolSize: size });
    };

    connections.forEach(c => {
      addNode(c.src, 1, 18);
      addNode(c.dst, 0, 26);
      links.push({
        source: c.src,
        target: c.dst,
        lineStyle: {
          color: SEV_COLOR[c.severity] ?? ACC.cyan,
          width: c.severity === "critical" ? 2.5 : 1.5,
        },
      });
    });

    const nodes = Array.from(nodeMap.values()).map(n => ({
      ...n,
      name: n.id,
      label: { show: true, color: T.md, fontSize: 9, fontFamily: "JetBrains Mono" },
      itemStyle: { color: n.category === 0 ? ACC.cyan : ACC.orange },
    }));

    graphInst.current.setOption({
      backgroundColor: "transparent",
      tooltip: {
        trigger: "item",
        backgroundColor: "#0e2040",
        borderColor: "#1e4060",
        textStyle: { color: "#eaf4ff", fontFamily: "JetBrains Mono", fontSize: 11 },
      },
      series: [{
        type: "graph",
        layout: "force",
        data: nodes,
        links,
        roam: true,
        force: { repulsion: 200, edgeLength: [80, 220], gravity: 0.08 },
        lineStyle: { curveness: 0.25 },
        emphasis: { focus: "adjacency" },
      }],
    });

    const ro = new ResizeObserver(() => graphInst.current?.resize());
    ro.observe(graphRef.current);
    return () => { ro.disconnect(); graphInst.current?.dispose(); };
  }, [ready, connections.length]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!hasData || !result) {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "50vh", gap: 14, textAlign: "center" }}>
        <span style={{ fontSize: 32 }}>📡</span>
        <h2 style={{ ...M, color: T.hi, fontSize: 18, fontWeight: 700 }}>No Network Data</h2>
        <p style={{ ...M, fontSize: 12, color: T.lo }}>Run an analysis from the Dashboard first.</p>
      </div>
    );
  }

  const uniqueSrc  = new Set(connections.map(c => c.src)).size;
  const uniqueDst  = new Set(connections.map(c => c.dst)).size;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h2 style={{ ...M, color: T.hi, fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Network Map</h2>
          <p style={{ ...M, fontSize: 11, color: T.lo }}>
            Force-directed attacker → target graph
            {polling && <span style={{ color: ACC.cyan, marginLeft: 8 }}>· syncing…</span>}
          </p>
        </div>
        <span style={{ ...M, fontSize: 9, color: T.dim }}>
          {new Date(result.timestamp).toLocaleTimeString()}
        </span>
      </div>

      {/* legend strip */}
      <div style={{ display: "flex", gap: 24, alignItems: "center", flexWrap: "wrap" }}>
        {[
          { label: "Target Host", color: ACC.cyan   },
          { label: "Attacker IP", color: ACC.orange  },
          { label: "Critical",    color: ACC.red     },
          { label: "High",        color: ACC.orange  },
          { label: "Medium",      color: ACC.yellow  },
        ].map(({ label, color }) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block" }} />
            <span style={{ ...M, fontSize: 10, color: T.lo }}>{label}</span>
          </div>
        ))}
        <div style={{ marginLeft: "auto", display: "flex", gap: 24 }}>
          <span style={{ ...M, fontSize: 11, color: T.md }}><b style={{ color: ACC.cyan }}>{uniqueDst}</b> targets</span>
          <span style={{ ...M, fontSize: 11, color: T.md }}><b style={{ color: ACC.orange }}>{uniqueSrc}</b> attackers</span>
          <span style={{ ...M, fontSize: 11, color: T.md }}><b style={{ color: ACC.red }}>{connections.length}</b> connections</span>
        </div>
      </div>

      {/* force graph */}
      <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, padding: 4, height: 500 }}>
        {connections.length === 0 ? (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%" }}>
            <p style={{ ...M, fontSize: 12, color: T.lo }}>No threat connections with extractable IPs detected.</p>
          </div>
        ) : (
          <div ref={graphRef} style={{ width: "100%", height: "100%" }} />
        )}
      </div>

      {/* connection details table */}
      <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, overflow: "hidden" }}>
        <div style={{ padding: "13px 18px", borderBottom: `1px solid ${BORD.dim}`, background: "#091628", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: T.hi, fontFamily: "'Inter',sans-serif" }}>Connection Details</span>
          <span style={{ ...M, fontSize: 9, color: T.dim }}>{connections.length} threat connections</span>
        </div>

        {/* header row */}
        <div style={{ display: "grid", gridTemplateColumns: "120px 120px 80px 140px 80px 1fr", gap: 12, padding: "8px 18px", borderBottom: `1px solid ${BORD.dim}` }}>
          {["SOURCE IP", "DEST IP", "PROTOCOL", "THREAT TYPE", "SEV", "EXPLANATION"].map(h => (
            <span key={h} style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".12em" }}>{h}</span>
          ))}
        </div>

        {connections.length === 0 ? (
          <p style={{ ...M, fontSize: 12, color: T.lo, textAlign: "center", padding: 28 }}>
            No threat entries contain IP addresses.
          </p>
        ) : (
          connections.map((c, i) => (
            <div
              key={i}
              style={{
                display: "grid",
                gridTemplateColumns: "120px 120px 80px 140px 80px 1fr",
                gap: 12, padding: "11px 18px", alignItems: "center",
                borderBottom: i < connections.length - 1 ? `1px solid ${BORD.dim}` : "none",
                transition: "background .15s",
              }}
              onMouseEnter={e => (e.currentTarget.style.background = "rgba(255,255,255,.02)")}
              onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
            >
              <span style={{ ...M, fontSize: 10, color: ACC.orange }}>{c.src}</span>
              <span style={{ ...M, fontSize: 10, color: ACC.cyan }}>{c.dst}</span>
              <span style={{ ...M, fontSize: 10, color: T.md, background: "rgba(0,217,255,.06)", borderRadius: 4, padding: "2px 7px" }}>{c.protocol}</span>
              <span style={{ ...M, fontSize: 10, fontWeight: 600, color: SEV_COLOR[c.severity] ?? T.hi }}>
                {c.threat_type.replace(/_/g, " ")}
              </span>
              <span style={{
                ...M, fontSize: 9, fontWeight: 700,
                color: SEV_COLOR[c.severity] ?? T.md,
                textTransform: "uppercase",
              }}>{c.severity}</span>
              <span style={{ ...M, fontSize: 10, color: T.lo }}>
                {getExplanation(c.threat_type)}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default NetworkMap;
