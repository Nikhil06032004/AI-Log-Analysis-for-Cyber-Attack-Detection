import React from "react";
import { BG, BORD, T, ACC, M } from "../../constants/theme";

const STATUS_ITEMS: [string, string, string][] = [
  ["Elasticsearch",  "Operational", ACC.green ],
  ["Ansible Agents", "4/4 Online",  ACC.green ],
  ["SIEM Core",      "Operational", ACC.green ],
  ["DNN Engine",     "Training",    ACC.yellow],
];

const StatusStrip: React.FC = () => (
  <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12 }}>
    {STATUS_ITEMS.map(([label, status, color]) => (
      <div key={label} className="panel-hover" style={{ display:"flex", alignItems:"center", gap:12, padding:"12px 16px", borderRadius:12, background:BG.panel, border:`1px solid ${BORD.dim}`, transition:"border-color .18s" }}>
        <span style={{ width:9, height:9, borderRadius:"50%", background:color, animation:"beat 1.6s ease-in-out infinite", flexShrink:0, display:"inline-block" }} />
        <div>
          <p style={{ fontSize:10, color:T.lo, marginBottom:2 }}>{label}</p>
          <p style={{ ...M, fontSize:11, fontWeight:600, color }}>{status}</p>
        </div>
      </div>
    ))}
  </div>
);

export default StatusStrip;
