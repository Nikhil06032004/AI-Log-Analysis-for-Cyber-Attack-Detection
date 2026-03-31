import React from "react";
import { BG, BORD, T, M } from "../../constants/theme";

interface Props {
  label: string;
  value: number | string;
  sub: string;
  color: string;
  icon: string;
  pulse?: boolean;
}

const StatCard: React.FC<Props> = ({ label, value, sub, color, icon, pulse }) => (
  <div style={{
    background: BG.card,
    border: `1px solid ${BORD.dim}`,
    borderLeft: `3px solid ${color}`,
    borderRadius: 16,
    padding: "22px 22px 16px",
    position: "relative",
    overflow: "hidden",
  }}>
    {/* background icon watermark */}
    <span style={{ position:"absolute", right:16, top:12, fontSize:38, opacity:.06, lineHeight:1 }}>{icon}</span>

    {/* label */}
    <p style={{ ...M, fontSize:10, letterSpacing:"0.16em", textTransform:"uppercase", color:T.lo, marginBottom:10, fontWeight:600 }}>{label}</p>

    {/* value */}
    <p style={{ ...M, fontSize:38, fontWeight:700, color, lineHeight:1, marginBottom:8 }}>
      {pulse && (
        <span style={{ display:"inline-block", width:9, height:9, borderRadius:"50%", background:color, marginRight:9, verticalAlign:"middle", animation:"beat 1.4s ease-in-out infinite" }} />
      )}
      {value}
    </p>

    {/* sub-label */}
    <p style={{ fontSize:12, color:T.lo, fontFamily:"'Inter',sans-serif" }}>{sub}</p>
  </div>
);

export default StatCard;
