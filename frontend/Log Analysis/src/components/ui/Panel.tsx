import React from "react";
import { BG, BORD, T } from "../../constants/theme";

interface Props {
  title?: string;
  badge?: React.ReactNode;
  pad?: number;
  children: React.ReactNode;
  flex?: boolean;
  style?: React.CSSProperties;
}

const Panel: React.FC<Props> = ({ title, badge, pad = 16, children, flex, style }) => (
  <div style={{
    background: BG.panel,
    border: `1px solid ${BORD.dim}`,
    borderRadius: 16,
    overflow: "hidden",
    display: flex ? "flex" : "block",
    flexDirection: "column",
    ...style,
  }}>
    {title && (
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "15px 20px",
        borderBottom: `1px solid ${BORD.dim}`,
        flexShrink: 0,
        background: BG.strip,
      }}>
        <span style={{ fontSize: 14, fontWeight: 600, color: T.hi, fontFamily: "'Inter',sans-serif", letterSpacing:"0.01em" }}>{title}</span>
        {badge}
      </div>
    )}
    <div style={{ padding: pad, flex: flex ? 1 : undefined, overflow: flex ? "hidden" : undefined }}>
      {children}
    </div>
  </div>
);

export default Panel;
