import React from "react";
import { T, ACC, M, BORD } from "../../constants/theme";

interface Props {
  onRetry: () => void;
}

const AccessDenied: React.FC<Props> = ({ onRetry }) => (
  <div style={{
    display: "flex", flexDirection: "column", alignItems: "center",
    justifyContent: "center", minHeight: "60vh", gap: 28, textAlign: "center",
    padding: "40px 20px",
  }}>

    {/* lock icon */}
    <div style={{
      width: 80, height: 80, borderRadius: "50%",
      background: "rgba(255,69,105,.08)", border: `1px solid rgba(255,69,105,.2)`,
      display: "flex", alignItems: "center", justifyContent: "center", fontSize: 36,
    }}>
      🔒
    </div>

    {/* heading */}
    <div>
      <p style={{ fontFamily: "'Orbitron',monospace", color: ACC.red, fontSize: 17, fontWeight: 700, letterSpacing: ".04em", marginBottom: 10 }}>
        Log Access Denied
      </p>
      <p style={{ fontSize: 14, color: T.md, fontFamily: "'Inter',sans-serif", lineHeight: 1.65, maxWidth: 420 }}>
        SENTINEL·AI cannot analyse your system without access to its logs.
        The dashboard will remain empty until you grant permission.
      </p>
    </div>

    {/* what you're missing */}
    <div style={{ width: "min(420px, 90vw)", display: "flex", flexDirection: "column", gap: 8 }}>
      {[
        { icon: "🔍", text: "Real-time threat detection on your Windows Event Logs" },
        { icon: "📡", text: "Network flow anomaly detection" },
        { icon: "🧠", text: "AI model predictions with confidence scores" },
        { icon: "⚠",  text: "Attack distribution and top-alert ranking" },
      ].map(({ icon, text }) => (
        <div key={text} style={{
          display: "flex", gap: 12, alignItems: "flex-start",
          background: "#0b1a2e", border: `1px solid ${BORD.dim}`,
          borderRadius: 10, padding: "10px 14px",
        }}>
          <span style={{ fontSize: 16, flexShrink: 0 }}>{icon}</span>
          <span style={{ fontSize: 13, color: T.lo, fontFamily: "'Inter',sans-serif", textAlign: "left" }}>{text}</span>
        </div>
      ))}
    </div>

    {/* retry button */}
    <button onClick={onRetry} style={{
      ...M, fontSize: 12, fontWeight: 700, cursor: "pointer",
      background: "rgba(0,217,255,.1)", color: ACC.cyan,
      border: `1px solid rgba(0,217,255,.3)`, borderRadius: 10,
      padding: "12px 32px", letterSpacing: ".06em",
    }}>
      GRANT ACCESS →
    </button>

    <p style={{ ...M, fontSize: 10, color: T.dim }}>
      Clicking "Grant Access" will reopen the permission dialog
    </p>
  </div>
);

export default AccessDenied;
