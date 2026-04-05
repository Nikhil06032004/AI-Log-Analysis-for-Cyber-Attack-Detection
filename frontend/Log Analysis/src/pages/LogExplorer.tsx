import React, { useState, useMemo } from "react";
import { ingestSyslogLines, analyzeLogLine } from "../services/api";
import type { AnalysisResult } from "../services/api";
import { useAnalysis } from "../context/AnalysisContext";
import { BORD, T, ACC, M } from "../constants/theme";

const LEVEL_COLOR: Record<string, string> = {
  CRITICAL: ACC.red, ERROR: ACC.orange, WARN: ACC.yellow, INFO: ACC.cyan,
};

const LEVEL_ORDER: Record<string, number> = { CRITICAL: 0, ERROR: 1, WARN: 2, INFO: 3 };

const LogExplorer: React.FC = () => {
  const { result: analysisResult, polling } = useAnalysis();
  const [input,     setInput]     = useState("");
  const [result,    setResult]    = useState<AnalysisResult | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [search,    setSearch]    = useState("");
  const [levelFilter, setLevelFilter] = useState<string>("all");

  // Build a live log stream from the context results
  const logs = useMemo(() => {
    if (!analysisResult) return [];
    return analysisResult.results.map((e, i) => {
      const level = e.severity === "critical" ? "CRITICAL"
                  : e.severity === "high"     ? "ERROR"
                  : e.severity === "medium"   ? "WARN"
                  : "INFO";
      return {
        id: `L${i}`,
        time: new Date(analysisResult.timestamp).toLocaleTimeString(),
        level: level as "INFO" | "WARN" | "ERROR" | "CRITICAL",
        source: e.log_source,
        message: e.normalized,
      };
    }).sort((a, b) => (LEVEL_ORDER[a.level] ?? 3) - (LEVEL_ORDER[b.level] ?? 3));
  }, [analysisResult]);

  const handleAnalyze = async () => {
    if (!input.trim()) return;
    setAnalyzing(true);
    setResult(null);
    try {
      const r = await analyzeLogLine(input.trim());
      setResult(r);
      // also ingest as syslog
      await ingestSyslogLines([input.trim()]).catch(() => {});
    } catch {
      setResult(null);
    }
    setAnalyzing(false);
  };

  const filtered = logs.filter(l => {
    if (levelFilter !== "all" && l.level !== levelFilter) return false;
    if (search && !l.message.toLowerCase().includes(search.toLowerCase()) &&
        !l.source.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div>
          <h2 style={{ ...M, color: T.hi, fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Log Explorer</h2>
          <p style={{ ...M, fontSize: 11, color: T.lo }}>
            {logs.length} entries · browse real system logs · analyse a line against the model
            {polling && <span style={{ color: ACC.cyan, marginLeft: 8 }}>· syncing…</span>}
          </p>
        </div>
        {/* level filter */}
        <div style={{ display: "flex", gap: 6 }}>
          {["all", "CRITICAL", "ERROR", "WARN", "INFO"].map(lv => (
            <button key={lv} onClick={() => setLevelFilter(lv)} style={{
              ...M, fontSize: 10, fontWeight: 600, cursor: "pointer", borderRadius: 6,
              padding: "5px 12px",
              border: `1px solid ${levelFilter === lv ? (LEVEL_COLOR[lv] ?? ACC.cyan) : BORD.dim}`,
              background: levelFilter === lv ? `${LEVEL_COLOR[lv] ?? ACC.cyan}18` : "transparent",
              color: levelFilter === lv ? (LEVEL_COLOR[lv] ?? ACC.cyan) : T.lo,
            }}>{lv}</button>
          ))}
        </div>
      </div>

      {/* single-line analyser */}
      <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, padding: 18 }}>
        <p style={{ ...M, fontSize: 11, color: T.lo, marginBottom: 10, letterSpacing: ".1em" }}>ANALYSE LOG LINE</p>
        <div style={{ display: "flex", gap: 10 }}>
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleAnalyze()}
            placeholder="Paste any syslog / Windows event / network log line…"
            style={{
              flex: 1, ...M, fontSize: 12, color: T.hi, background: "#06101e",
              border: `1px solid ${BORD.dim}`, borderRadius: 8, padding: "10px 14px", outline: "none",
            }}
          />
          <button onClick={handleAnalyze} disabled={analyzing} style={{
            ...M, fontSize: 11, fontWeight: 700, cursor: analyzing ? "wait" : "pointer",
            background: analyzing ? BORD.dim : `rgba(0,217,255,.12)`,
            color: analyzing ? T.lo : ACC.cyan, border: `1px solid ${analyzing ? BORD.dim : "rgba(0,217,255,.3)"}`,
            borderRadius: 8, padding: "10px 22px",
          }}>
            {analyzing ? "ANALYSING…" : "ANALYSE →"}
          </button>
        </div>

        {result && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginTop: 14 }}>
            {[
              { label: "THREAT TYPE", value: result.threat_type, color: result.is_threat ? ACC.red : ACC.green },
              { label: "SEVERITY",    value: result.severity.toUpperCase(), color: ACC.orange },
              { label: "CONFIDENCE",  value: `${(result.confidence * 100).toFixed(1)}%`, color: ACC.cyan },
              { label: "IS THREAT",   value: result.is_threat ? "YES" : "NO", color: result.is_threat ? ACC.red : ACC.green },
            ].map(({ label, value, color }) => (
              <div key={label} style={{ background: "#06101e", border: `1px solid ${BORD.dim}`, borderRadius: 10, padding: "12px 14px" }}>
                <p style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".12em", marginBottom: 6 }}>{label}</p>
                <p style={{ ...M, fontSize: 16, fontWeight: 700, color }}>{value}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* log stream */}
      <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "13px 18px", borderBottom: `1px solid ${BORD.dim}`, background: "#091628" }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: T.hi, fontFamily: "'Inter',sans-serif" }}>
            Live Log Stream <span style={{ fontSize: 10, color: T.lo, fontFamily: "JetBrains Mono", fontWeight: 400 }}>({filtered.length})</span>
          </span>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search…"
            style={{ ...M, fontSize: 11, color: T.hi, background: "#06101e", border: `1px solid ${BORD.dim}`, borderRadius: 6, padding: "5px 12px", outline: "none", width: 200 }} />
        </div>
        {logs.length === 0 ? (
          <p style={{ ...M, fontSize: 12, color: T.lo, textAlign: "center", padding: 28 }}>
            No data yet — run an analysis from the Dashboard.
          </p>
        ) : filtered.length === 0 ? (
          <p style={{ ...M, fontSize: 12, color: T.lo, textAlign: "center", padding: 28 }}>
            No entries match the current filters.
          </p>
        ) : null}
        {filtered.map((log, i) => (
          <div key={log.id} style={{ display: "flex", gap: 14, alignItems: "flex-start", padding: "10px 18px",
            borderBottom: i < filtered.length - 1 ? `1px solid ${BORD.dim}` : "none" }}>
            <span style={{ ...M, fontSize: 10, color: T.dim, flexShrink: 0, width: 52 }}>{log.time}</span>
            <span style={{ ...M, fontSize: 10, fontWeight: 700, color: LEVEL_COLOR[log.level] ?? T.md, width: 60, flexShrink: 0 }}>{log.level}</span>
            <span style={{ ...M, fontSize: 10, color: ACC.cyan, width: 110, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{log.source}</span>
            <span style={{ fontSize: 12, color: T.md, fontFamily: "'Inter',sans-serif" }}>{log.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default LogExplorer;
