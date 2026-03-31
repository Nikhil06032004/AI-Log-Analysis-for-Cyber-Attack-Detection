import React from "react";
import type { Severity, ThreatStatus } from "../../types";

export type { Severity, ThreatStatus };

interface Props {
  id: string; threatType: string; sourceIP: string; destinationIP: string;
  severity: Severity; status: ThreatStatus; timestamp: string; description: string;
  protocol: string; eventCount: number; confidence: number;
  onInvestigate: (id: string) => void;
  onResolve:     (id: string) => void;
  onDismiss:     (id: string) => void;
}

const SEV: Record<Severity, string> = {
  critical: "#f43f5e",
  high:     "#f97316",
  medium:   "#fbbf24",
  low:      "#10b981",
};

const STAT: Record<ThreatStatus, { bg: string; text: string; label: string }> = {
  active:        { bg:"rgba(244,63,94,.16)",   text:"#f43f5e",  label:"ACTIVE" },
  investigating: { bg:"rgba(251,191,36,.16)",  text:"#fbbf24",  label:"INVESTIGATING" },
  resolved:      { bg:"rgba(16,185,129,.14)",  text:"#10b981",  label:"RESOLVED" },
  pending:       { bg:"rgba(100,116,139,.14)", text:"#6b7280",  label:"PENDING" },
};

const M: React.CSSProperties = { fontFamily:"'JetBrains Mono',monospace" };

const Btn: React.FC<{ label:string; border:string; color:string; onClick:()=>void }> =
({ label, border, color, onClick }) => (
  <button
    onClick={onClick}
    style={{
      ...M, fontSize:9, padding:"3px 9px", borderRadius:6,
      border:`1px solid ${border}`, color, background:"transparent", cursor:"pointer",
      transition:"opacity .15s",
    }}
  >{label}</button>
);

const ThreatCard: React.FC<Props> = ({
  id, threatType, sourceIP, destinationIP, severity, status,
  timestamp, description, protocol, eventCount, confidence,
  onInvestigate, onResolve, onDismiss,
}) => {
  const sc = SEV[severity];
  const ss = STAT[status];
  return (
    <div style={{
      borderLeft: `3px solid ${sc}`,
      background: "#091828",
      border: "1px solid #112240",
      borderLeftColor: sc,
      borderRadius: 10,
      padding: "11px 14px",
      transition: "background .15s",
    }}>

      {/* Row 1 */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:6, flexWrap:"wrap", gap:4 }}>
        <div style={{ display:"flex", alignItems:"center", gap:6, flexWrap:"wrap" }}>
          <span style={{ ...M, fontSize:9, fontWeight:700, textTransform:"uppercase", padding:"2px 7px", borderRadius:4, background:`${sc}1a`, color:sc }}>
            {severity}
          </span>
          <span style={{ fontSize:12, fontWeight:600, color:"#e2eaf4" }}>{threatType}</span>
          <span style={{ ...M, fontSize:9, fontWeight:700, padding:"2px 7px", borderRadius:4, background:ss.bg, color:ss.text }}>
            {ss.label}
          </span>
        </div>
        <div style={{ display:"flex", gap:8, alignItems:"center" }}>
          <span style={{ ...M, fontSize:9, color:"#3a6080" }}>{timestamp}</span>
          <span style={{ ...M, fontSize:9, color:"#1a3a5c" }}>{id}</span>
        </div>
      </div>

      {/* Row 2: IPs */}
      <div style={{ ...M, display:"flex", alignItems:"center", gap:6, marginBottom:6, fontSize:10, flexWrap:"wrap" }}>
        <span style={{ color:"#00d4ff" }}>{sourceIP}</span>
        <span style={{ color:"#1a3a5c" }}>→</span>
        <span style={{ color:"#7a9bb5" }}>{destinationIP}</span>
        <span style={{ color:"#1a3a5c", margin:"0 2px" }}>·</span>
        <span style={{ color:"#3a6080" }}>{protocol}</span>
      </div>

      {/* Row 3: description */}
      <p style={{ fontSize:11, color:"#4a7a9b", lineHeight:1.5, marginBottom:8, overflow:"hidden", display:"-webkit-box", WebkitLineClamp:2, WebkitBoxOrient:"vertical" }}>
        {description}
      </p>

      {/* Row 4: stats + buttons */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between" }}>
        <div style={{ ...M, display:"flex", gap:14, fontSize:10 }}>
          <span style={{ color:"#3a6080" }}>Events: <span style={{ color:"#7a9bb5" }}>{eventCount.toLocaleString()}</span></span>
          <span style={{ color:"#3a6080" }}>Conf: <span style={{ color:sc }}>{confidence}%</span></span>
        </div>
        {status !== "resolved" && (
          <div style={{ display:"flex", gap:5 }}>
            {status !== "investigating" && (
              <Btn label="Investigate" border="rgba(251,191,36,.4)" color="#fbbf24" onClick={()=>onInvestigate(id)} />
            )}
            <Btn label="Resolve" border="rgba(16,185,129,.4)" color="#10b981" onClick={()=>onResolve(id)} />
            <Btn label="Dismiss" border="#112240"             color="#3a6080"  onClick={()=>onDismiss(id)} />
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatCard;
