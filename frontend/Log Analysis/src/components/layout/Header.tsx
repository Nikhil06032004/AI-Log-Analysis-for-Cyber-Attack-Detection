import React from "react";
import { BG, BORD, T, ACC, M } from "../../constants/theme";

interface Props {
  sidebarOpen: boolean;
  onToggleSidebar: () => void;
  clock: Date;
  liveRate: number;
}

const Header: React.FC<Props> = ({ sidebarOpen: _sidebarOpen, onToggleSidebar, clock, liveRate }) => (
  <div
    style={{
      width:"100%",
      height:58,
      flexShrink:0,
      background:BG.panel,
      borderBottom:`1px solid ${BORD.dim}`,
      display:"flex", alignItems:"center", justifyContent:"space-between",
      padding:"0 24px",
      position:"relative", overflow:"hidden",
      zIndex:10,
    }}
  >
    {/* scan line */}
    <span style={{ position:"absolute", left:0, right:0, height:"1px", background:`linear-gradient(90deg,transparent,${ACC.cyan}55,transparent)`, animation:"scan 5s linear infinite", pointerEvents:"none" }} />

    {/* LEFT — hamburger + brand */}
    <div style={{ display:"flex", alignItems:"center", gap:16 }}>
      <button
        onClick={onToggleSidebar}
        style={{ background:"none", border:`1px solid ${BORD.dim}`, borderRadius:8, cursor:"pointer", color:T.md, width:34, height:34, display:"flex", alignItems:"center", justifyContent:"center", fontSize:16, transition:"all .15s", flexShrink:0 }}
      >☰</button>

      <div style={{ display:"flex", alignItems:"center", gap:10 }}>
        <img src="/favicon.svg" alt="LogSentinel AI" style={{ width:36, height:36, flexShrink:0 }} />
        <div>
          <p style={{ fontFamily:"'Orbitron',monospace", color:ACC.cyan, fontSize:14, fontWeight:700, letterSpacing:".04em", lineHeight:1 }}>
            SENTINEL<span style={{ color:T.dim }}>·AI</span>
          </p>
          <p style={{ ...M, color:T.lo, fontSize:9, letterSpacing:".14em", textTransform:"uppercase", marginTop:3 }}>Log Analysis &amp; Threat Detection</p>
        </div>
      </div>
    </div>

    {/* RIGHT — live / rate / clock / user */}
    <div style={{ display:"flex", alignItems:"center", gap:22 }}>
      <div style={{ display:"flex", alignItems:"center", gap:7 }}>
        <span style={{ width:8, height:8, borderRadius:"50%", background:ACC.green, animation:"beat 1.4s ease-in-out infinite", display:"inline-block" }} />
        <span style={{ ...M, color:ACC.green, fontSize:11, fontWeight:600 }}>LIVE</span>
      </div>
      <span style={{ ...M, color:T.lo, fontSize:11 }}>{liveRate.toLocaleString()} <span style={{ color:T.dim }}>logs/min</span></span>
      <div style={{ ...M, color:T.hi, fontSize:12, background:BG.card, border:`1px solid ${BORD.dim}`, borderRadius:8, padding:"5px 14px" }}>
        {clock.toTimeString().slice(0,8)}
      </div>
      <div style={{ display:"flex", alignItems:"center", gap:9 }}>
        <div style={{ width:32, height:32, borderRadius:"50%", background:BG.card, border:`1px solid ${BORD.mid}`, display:"flex", alignItems:"center", justifyContent:"center", ...M, color:T.md, fontSize:11, fontWeight:600 }}>NS</div>
        <span style={{ fontSize:12, color:T.lo }}>Nikhil S.</span>
      </div>
    </div>
  </div>
);

export default Header;
