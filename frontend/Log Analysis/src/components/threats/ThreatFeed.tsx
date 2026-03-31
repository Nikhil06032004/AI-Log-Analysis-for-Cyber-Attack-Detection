import React, { useState } from "react";
import ThreatCard from "./ThreatCard";
import type { Threat, Severity, ThreatStatus } from "../../types";
import { BG, BORD, T, ACC, M } from "../../constants/theme";

interface Props {
  threats: Threat[];
  onInvestigate: (id: string) => void;
  onResolve:     (id: string) => void;
  onDismiss:     (id: string) => void;
}

const TABS: Array<"all" | Severity | ThreatStatus> = ["all","critical","high","medium","low","active","resolved"];

const ThreatFeed: React.FC<Props> = ({ threats, onInvestigate, onResolve, onDismiss }) => {
  const [tab, setTab] = useState<"all" | Severity | ThreatStatus>("all");

  const shownThreats = threats.filter(t => tab === "all" || t.severity === tab || t.status === tab);

  return (
    <div className="panel-hover" style={{ background:BG.panel, border:`1px solid ${BORD.dim}`, borderRadius:14, display:"flex", flexDirection:"column", overflow:"hidden", transition:"border-color .18s" }}>
      <div style={{ padding:"13px 18px 12px", borderBottom:`1px solid ${BORD.dim}`, flexShrink:0, background:BG.strip }}>
        <p style={{ fontSize:13, fontWeight:600, color:T.hi, marginBottom:12 }}>Active Threat Feed</p>
        <div style={{ display:"flex", flexWrap:"wrap", gap:5 }}>
          {TABS.map(t => (
            <button
              key={t}
              className="tb"
              onClick={() => setTab(t)}
              style={{ ...M, fontSize:9, padding:"4px 10px", borderRadius:6, cursor:"pointer", textTransform:"capitalize", transition:"all .15s", border:`1px solid ${tab===t?`rgba(0,217,255,.45)`:BORD.dim}`, background:tab===t?`rgba(0,217,255,.12)`:"transparent", color:tab===t?ACC.cyan:T.lo }}
            >{t}</button>
          ))}
        </div>
      </div>
      <div style={{ overflowY:"auto", padding:12, display:"flex", flexDirection:"column", gap:8, maxHeight:460 }}>
        {shownThreats.length === 0
          ? <p style={{ color:T.lo, fontSize:13, textAlign:"center", padding:"32px 0" }}>No threats in this category</p>
          : shownThreats.map(t => (
            <ThreatCard key={t.id} {...t} onInvestigate={onInvestigate} onResolve={onResolve} onDismiss={onDismiss} />
          ))
        }
      </div>
    </div>
  );
};

export default ThreatFeed;
