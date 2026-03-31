import React from "react";
import "../../styles/sidebar.css";

export const SIDEBAR_W = 240;

interface Props {
  open: boolean;
  activeCount: number;
}

const NAV_ITEMS: [string, string, boolean][] = [
  ["⬡",  "Dashboard",   true  ],
  ["⚠",  "Threats",     false ],
  ["📋", "Log Explorer", false ],
  ["🧠", "AI Model",     false ],
  ["📡", "Network Map",  false ],
  ["📊", "Analytics",    false ],
  ["🔒", "SIEM Rules",   false ],
  ["⚙",  "Settings",    false ],
];

const Sidebar: React.FC<Props> = ({ open, activeCount }) => (
  <div className={`sidebar${open ? "" : " closed"}`}>
    <div className="sidebar-inner">

      <p className="sidebar-section-label">Navigation</p>

      <div className="sidebar-nav">
        {NAV_ITEMS.map(([icon, label, active]) => {
          const badge = label === "Threats" ? activeCount : undefined;
          return (
            <div key={label} className={`sidebar-nav-item${active ? " active" : ""}`}>
              <div className="sidebar-nav-left">
                <span className="sidebar-nav-icon">{icon}</span>
                <span className={`sidebar-nav-label${active ? " active" : ""}`}>{label}</span>
              </div>
              {badge !== undefined && badge > 0 && (
                <span className="sidebar-badge">{badge}</span>
              )}
            </div>
          );
        })}
      </div>

      <div className="sidebar-divider" />

      <div className="sidebar-dnn">
        <p className="sidebar-dnn-label">DNN Model</p>
        <p className="sidebar-dnn-version">v2.4.1 · Active</p>
        <div className="sidebar-dnn-bar-bg">
          <div className="sidebar-dnn-bar-fill" />
        </div>
        <p className="sidebar-dnn-stats">Acc: 96.4% · F1: 95.8%</p>
      </div>

    </div>
  </div>
);

export default Sidebar;
