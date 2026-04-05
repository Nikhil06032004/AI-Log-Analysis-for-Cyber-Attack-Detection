import React, { useState, useMemo } from "react";
import { useAnalysis } from "../context/AnalysisContext";
import type { SystemPredictionEntry } from "../services/api";
import { BORD, T, ACC, M } from "../constants/theme";

const SEV_COLOR: Record<string, string> = {
  critical: ACC.red, high: ACC.orange, medium: ACC.yellow, low: ACC.cyan,
};
const SEV_BG: Record<string, string> = {
  critical: "rgba(255,69,105,.12)", high: "rgba(255,142,60,.1)",
  medium:   "rgba(255,210,63,.08)", low:  "rgba(0,217,255,.08)",
};

type SevFilter = "all" | "critical" | "high" | "medium" | "low";

const PAGE_SIZE = 25;

/**
 * Override backend severity using confidence score:
 *  < 50%         → low
 *  50% – < 75%   → medium
 *  75% – < 90%   → high
 *  ≥ 90%         → critical
 */
function confToSev(confidence: number): string {
  if (confidence < 0.50) return "low";
  if (confidence < 0.75) return "medium";
  if (confidence < 0.90) return "high";
  return "critical";
}

function extractIP(raw: string): string {
  const m = raw.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
  return m ? m[1] : "—";
}

const Threats: React.FC = () => {
  const { result, hasData, polling } = useAnalysis();

  const [sevFilter, setSevFilter] = useState<SevFilter>("all");
  const [page,      setPage]      = useState(1);

  // Only threat entries, with confidence-derived severity
  const threats: Array<SystemPredictionEntry & { displaySev: string }> = useMemo(() => {
    if (!result) return [];
    return result.results
      .filter(e => e.is_threat)
      .map(e => ({ ...e, displaySev: confToSev(e.confidence) }))
      .sort((a, b) => {
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        const sd = (order[a.displaySev] ?? 4) - (order[b.displaySev] ?? 4);
        return sd !== 0 ? sd : b.confidence - a.confidence;
      });
  }, [result]);

  const filtered = useMemo(
    () => sevFilter === "all" ? threats : threats.filter(e => e.displaySev === sevFilter),
    [threats, sevFilter]
  );

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage   = Math.min(page, totalPages);
  const pageSlice  = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  // Reset to page 1 when filter changes
  const handleFilter = (f: SevFilter) => { setSevFilter(f); setPage(1); };

  if (!hasData || !result) {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "50vh", gap: 14, textAlign: "center" }}>
        <span style={{ fontSize: 32 }}>⚠</span>
        <h2 style={{ ...M, color: T.hi, fontSize: 18, fontWeight: 700 }}>No Data Available</h2>
        <p style={{ ...M, fontSize: 12, color: T.lo }}>Run an analysis from the Dashboard first.</p>
      </div>
    );
  }

  // Counts per derived severity (for filter badges)
  const counts = threats.reduce<Record<string, number>>((acc, e) => {
    acc[e.displaySev] = (acc[e.displaySev] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div>
          <h2 style={{ ...M, color: T.hi, fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Threats</h2>
          <p style={{ ...M, fontSize: 11, color: T.lo }}>
            {filtered.length} threats · page {safePage} of {totalPages}
            {polling && <span style={{ color: ACC.cyan, marginLeft: 8 }}>· live</span>}
          </p>
        </div>

        {/* severity filter */}
        <div style={{ display: "flex", gap: 7, flexWrap: "wrap" }}>
          {(["all", "critical", "high", "medium", "low"] as SevFilter[]).map(s => {
            const active = sevFilter === s;
            const col    = SEV_COLOR[s] ?? ACC.cyan;
            const bg     = SEV_BG[s]   ?? "rgba(0,217,255,.08)";
            const cnt    = s === "all" ? threats.length : (counts[s] ?? 0);
            return (
              <button key={s} onClick={() => handleFilter(s)} style={{
                ...M, fontSize: 10, fontWeight: 600, cursor: "pointer", borderRadius: 7,
                padding: "5px 14px",
                border:      `1px solid ${active ? col : BORD.dim}`,
                background:  active ? bg : "transparent",
                color:       active ? col : T.lo,
                textTransform: "capitalize",
                display: "flex", alignItems: "center", gap: 6,
              }}>
                {s}
                <span style={{
                  fontSize: 9, fontWeight: 700,
                  background: active ? `${col}30` : "#0b1a2e",
                  color: active ? col : T.dim,
                  borderRadius: 10, padding: "1px 6px",
                  border: `1px solid ${active ? col : BORD.dim}`,
                }}>{cnt}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* table */}
      <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 16, overflow: "hidden" }}>

        {/* column headers */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "72px 130px 1fr 120px 100px",
          gap: 12, padding: "10px 20px",
          borderBottom: `1px solid ${BORD.dim}`,
          background: "#091628",
        }}>
          {["SEV", "TYPE", "LOG EXCERPT", "SOURCE / IP", "CONFIDENCE"].map(h => (
            <span key={h} style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".12em" }}>{h}</span>
          ))}
        </div>

        {pageSlice.length === 0 ? (
          <p style={{ ...M, fontSize: 12, color: T.lo, textAlign: "center", padding: 32 }}>
            No threats match this filter.
          </p>
        ) : (
          pageSlice.map((e, i) => (
            <ThreatRow key={i} entry={e} isLast={i === pageSlice.length - 1} />
          ))
        )}
      </div>

      {/* pagination */}
      {totalPages > 1 && (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
          <PagBtn label="← Prev" disabled={safePage === 1}      onClick={() => setPage(p => Math.max(1, p - 1))} />

          {/* page numbers */}
          {Array.from({ length: totalPages }, (_, i) => i + 1)
            .filter(n => n === 1 || n === totalPages || Math.abs(n - safePage) <= 2)
            .reduce<(number | "…")[]>((acc, n, idx, arr) => {
              if (idx > 0 && n - (arr[idx - 1] as number) > 1) acc.push("…");
              acc.push(n);
              return acc;
            }, [])
            .map((n, i) =>
              n === "…" ? (
                <span key={`e${i}`} style={{ ...M, fontSize: 11, color: T.dim, padding: "0 4px" }}>…</span>
              ) : (
                <PagBtn key={n} label={String(n)} disabled={false} active={n === safePage} onClick={() => setPage(n as number)} />
              )
            )}

          <PagBtn label="Next →" disabled={safePage === totalPages} onClick={() => setPage(p => Math.min(totalPages, p + 1))} />
        </div>
      )}
    </div>
  );
};

// ── Pagination button ─────────────────────────────────────────────────────────
const PagBtn: React.FC<{ label: string; disabled: boolean; active?: boolean; onClick: () => void }> = ({ label, disabled, active, onClick }) => (
  <button
    onClick={onClick}
    disabled={disabled}
    style={{
      ...M, fontSize: 11, fontWeight: active ? 700 : 500,
      cursor: disabled ? "default" : "pointer",
      background: active ? "rgba(0,217,255,.13)" : "transparent",
      color: disabled ? T.dim : active ? ACC.cyan : T.md,
      border: `1px solid ${active ? "rgba(0,217,255,.35)" : BORD.dim}`,
      borderRadius: 7, padding: "5px 12px",
      opacity: disabled ? 0.4 : 1,
      transition: "all .15s",
    }}
  >{label}</button>
);

// ── Threat row ─────────────────────────────────────────────────────────────────
const ThreatRow: React.FC<{ entry: SystemPredictionEntry & { displaySev: string }; isLast: boolean }> = ({ entry, isLast }) => {
  const sev = entry.displaySev;
  const ip  = extractIP(entry.raw_log);
  const confPct = (entry.confidence * 100).toFixed(1);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "72px 130px 1fr 120px 100px",
        gap: 12, padding: "12px 20px", alignItems: "center",
        borderBottom: isLast ? "none" : `1px solid ${BORD.dim}`,
        transition: "background .15s",
      }}
      onMouseEnter={e => (e.currentTarget.style.background = "rgba(255,255,255,.02)")}
      onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
    >
      {/* severity */}
      <span style={{
        ...M, fontSize: 9, fontWeight: 700,
        color: SEV_COLOR[sev] ?? T.md,
        background: SEV_BG[sev] ?? "transparent",
        border: `1px solid ${SEV_COLOR[sev] ?? BORD.dim}`,
        borderRadius: 5, padding: "3px 7px",
        textTransform: "uppercase", letterSpacing: ".06em", whiteSpace: "nowrap",
        display: "inline-block", textAlign: "center",
      }}>{sev}</span>

      {/* threat type */}
      <span style={{ ...M, fontSize: 10, color: SEV_COLOR[sev] ?? T.hi, fontWeight: 600 }}>
        {entry.threat_type.replace(/_/g, " ")}
      </span>

      {/* log excerpt */}
      <div style={{ minWidth: 0 }}>
        <p style={{ ...M, fontSize: 10, color: T.hi, marginBottom: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {entry.normalized}
        </p>
        <p style={{ ...M, fontSize: 9, color: T.dim }}>{entry.log_source}</p>
      </div>

      {/* IP / source */}
      <span style={{ ...M, fontSize: 10, color: T.md }}>{ip}</span>

      {/* confidence */}
      <div>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
          <span style={{ ...M, fontSize: 9, color: T.dim }}>CONF</span>
          <span style={{ ...M, fontSize: 9, fontWeight: 700, color: SEV_COLOR[sev] ?? ACC.cyan }}>{confPct}%</span>
        </div>
        <div style={{ height: 3, background: BORD.dim, borderRadius: 2 }}>
          <div style={{ width: `${entry.confidence * 100}%`, height: "100%", background: SEV_COLOR[sev] ?? ACC.cyan, borderRadius: 2 }} />
        </div>
      </div>
    </div>
  );
};

export default Threats;
