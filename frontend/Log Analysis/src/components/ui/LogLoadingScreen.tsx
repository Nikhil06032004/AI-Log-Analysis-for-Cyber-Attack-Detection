import React, { useEffect, useState } from "react";
import { T, ACC, M, BORD } from "../../constants/theme";

export interface LoadingStage {
  id: string;
  label: string;
  detail: string;
  status: "pending" | "active" | "done" | "error";
}

interface Props {
  stages: LoadingStage[];
  /** Optional: live counter fed from backend response as it progresses */
  logsCollected?: number;
  predictionsRun?: number;
  threatsFound?: number;
  errorMessage?: string;
}

const LogLoadingScreen: React.FC<Props> = ({
  stages,
  logsCollected,
  predictionsRun,
  threatsFound,
  errorMessage,
}) => {
  const [dots, setDots] = useState(".");

  useEffect(() => {
    const t = setInterval(() => setDots(d => d.length >= 3 ? "." : d + "."), 500);
    return () => clearInterval(t);
  }, []);

  const activeStage  = stages.find(s => s.status === "active");
  const doneCount    = stages.filter(s => s.status === "done").length;
  const progress     = stages.length > 0 ? Math.round((doneCount / stages.length) * 100) : 0;

  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
      minHeight: "60vh", gap: 36, padding: "40px 20px",
    }}>

      {/* animated radar ring */}
      <div style={{ position: "relative", width: 110, height: 110 }}>
        {/* outer pulsing ring */}
        <div style={{
          position: "absolute", inset: 0, borderRadius: "50%",
          border: `2px solid rgba(0,217,255,.15)`,
          animation: "radarPulse 2s ease-in-out infinite",
        }} />
        {/* spinning arc */}
        <svg width="110" height="110" style={{ position: "absolute", inset: 0, animation: "spin 1.4s linear infinite" }}>
          <circle cx="55" cy="55" r="50"
            fill="none"
            stroke="url(#arcGrad)"
            strokeWidth="3"
            strokeDasharray="80 235"
            strokeLinecap="round"
          />
          <defs>
            <linearGradient id="arcGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={ACC.cyan} stopOpacity="0" />
              <stop offset="100%" stopColor={ACC.cyan} />
            </linearGradient>
          </defs>
        </svg>
        {/* inner dot */}
        <div style={{
          position: "absolute", inset: 0,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 28,
        }}>
          {errorMessage ? "⚠" : "🧠"}
        </div>
      </div>

      {/* headline */}
      <div style={{ textAlign: "center" }}>
        <p style={{ fontFamily: "'Orbitron',monospace", color: ACC.cyan, fontSize: 17, fontWeight: 700, letterSpacing: ".05em", marginBottom: 8 }}>
          {errorMessage ? "Analysis Failed" : activeStage ? activeStage.label + dots : "Initialising…"}
        </p>
        <p style={{ ...M, fontSize: 11, color: T.lo }}>
          {errorMessage ?? (activeStage?.detail ?? "Preparing system log collection")}
        </p>
      </div>

      {/* progress bar */}
      {!errorMessage && (
        <div style={{ width: "min(460px, 90vw)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
            <span style={{ ...M, fontSize: 10, color: T.lo }}>{doneCount} / {stages.length} stages complete</span>
            <span style={{ ...M, fontSize: 10, color: ACC.cyan, fontWeight: 700 }}>{progress}%</span>
          </div>
          <div style={{ height: 6, background: BORD.dim, borderRadius: 4, overflow: "hidden" }}>
            <div style={{
              height: "100%", borderRadius: 4,
              width: `${progress}%`,
              background: `linear-gradient(90deg, ${ACC.cyan}, ${ACC.purple})`,
              transition: "width .5s ease",
              boxShadow: `0 0 8px ${ACC.cyan}88`,
            }} />
          </div>
        </div>
      )}

      {/* stage list */}
      <div style={{ width: "min(460px, 90vw)", display: "flex", flexDirection: "column", gap: 6 }}>
        {stages.map(stage => <StageRow key={stage.id} stage={stage} dots={dots} />)}
      </div>

      {/* live counters */}
      {!errorMessage && (
        <div style={{ display: "flex", gap: 30 }}>
          {[
            { label: "Logs Collected",   value: logsCollected,  color: ACC.cyan   },
            { label: "Predictions Run",  value: predictionsRun, color: ACC.purple },
            { label: "Threats Found",    value: threatsFound,   color: ACC.red    },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ textAlign: "center" }}>
              <p style={{ ...M, fontSize: 22, fontWeight: 700, color }}>
                {value !== undefined ? value.toLocaleString() : "—"}
              </p>
              <p style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".1em" }}>{label.toUpperCase()}</p>
            </div>
          ))}
        </div>
      )}

      {/* error detail */}
      {errorMessage && (
        <div style={{
          width: "min(460px, 90vw)",
          background: "rgba(255,69,105,.07)", border: `1px solid rgba(255,69,105,.22)`,
          borderRadius: 12, padding: "14px 18px",
        }}>
          <p style={{ ...M, fontSize: 11, color: ACC.red, lineHeight: 1.6 }}>{errorMessage}</p>
        </div>
      )}

      <style>{`
        @keyframes spin        { to { transform: rotate(360deg); } }
        @keyframes radarPulse  { 0%,100% { opacity:.15; transform:scale(1);   }
                                 50%     { opacity:.5;  transform:scale(1.08); } }
        @keyframes fadeSlideIn { from { opacity:0; transform:translateX(-8px); }
                                 to   { opacity:1; transform:translateX(0);    } }
      `}</style>
    </div>
  );
};

/* ── Single stage row ────────────────────────────────────────────────────── */
const StageRow: React.FC<{ stage: LoadingStage; dots: string }> = ({ stage, dots }) => {
  const icon = stage.status === "done"  ? "✓"
             : stage.status === "error" ? "✗"
             : stage.status === "active"? "▶"
             : "○";

  const color = stage.status === "done"   ? ACC.green
              : stage.status === "error"  ? ACC.red
              : stage.status === "active" ? ACC.cyan
              : T.dim;

  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12,
      padding: "9px 14px", borderRadius: 8,
      background: stage.status === "active" ? "rgba(0,217,255,.05)" : "transparent",
      border: `1px solid ${stage.status === "active" ? "rgba(0,217,255,.15)" : "transparent"}`,
      animation: stage.status === "active" ? "fadeSlideIn .2s ease-out" : "none",
      transition: "background .2s, border-color .2s",
    }}>
      {/* icon */}
      <span style={{
        ...M, fontSize: 12, color, width: 16, textAlign: "center", flexShrink: 0,
        animation: stage.status === "active" ? "none" : "none",
      }}>
        {stage.status === "active" ? (
          <SpinnerInline color={color} />
        ) : icon}
      </span>

      {/* label */}
      <span style={{ ...M, fontSize: 11, color: stage.status === "pending" ? T.dim : color, flex: 1 }}>
        {stage.label}{stage.status === "active" ? dots : ""}
      </span>

      {/* detail */}
      {stage.status === "active" && (
        <span style={{ ...M, fontSize: 9, color: T.lo }}>{stage.detail}</span>
      )}
    </div>
  );
};

const SpinnerInline: React.FC<{ color: string }> = ({ color }) => (
  <span style={{
    display: "inline-block", width: 11, height: 11,
    border: "2px solid transparent", borderTopColor: color,
    borderRadius: "50%", animation: "spin .7s linear infinite",
    verticalAlign: "middle",
  }} />
);

export default LogLoadingScreen;
