import React, { useState, useEffect } from "react";
import { Outlet, useNavigate, useLocation } from "react-router-dom";
import Header from "./Header";
import { useAnalysis } from "../../context/AnalysisContext";
import "../../styles/layout.css";

const NAV = [
  { label: "Dashboard",    path: "/dashboard" },
  { label: "Threats",      path: "/threats"   },
  { label: "Log Explorer", path: "/logs"       },
  { label: "Network Map",  path: "/network"   },
  { label: "Analytics",    path: "/analytics" },
];

const AppLayout: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [clock, setClock]   = useState(new Date());
  const [now,   setNow]     = useState(() => Date.now());
  const [hov,   setHov]     = useState<string | null>(null);
  const { result, polling } = useAnalysis();
  const navigate  = useNavigate();
  const location  = useLocation();

  useEffect(() => {
    const t = setInterval(() => { setClock(new Date()); setNow(Date.now()); }, 1000);
    return () => clearInterval(t);
  }, []);

  const liveRate = React.useMemo(() => {
    if (!result) return 0;
    const ageMin = Math.max((now - new Date(result.timestamp).getTime()) / 60_000, 1);
    return Math.round(result.total_collected / ageMin);
  }, [result, now]);

  const threatCount = result?.total_threats ?? 0;

  return (
    <div className="dash-shell">
      <Header
        sidebarOpen={sidebarOpen}
        onToggleSidebar={() => setSidebarOpen(s => !s)}
        clock={clock}
        liveRate={liveRate}
      />

      <div className="dash-body">

        {/* ── SIDEBAR ── */}
        <div style={{
          width:      sidebarOpen ? "240px" : "0px",
          minWidth:   sidebarOpen ? "240px" : "0px",
          maxWidth:   sidebarOpen ? "240px" : "0px",
          flexShrink: 0,
          overflow:   "hidden",
          transition: "width .25s ease, min-width .25s ease",
          background: "#08152a",
          borderRight: sidebarOpen ? "1px solid #1e3a58" : "none",
          display:    "flex",
          flexDirection: "column",
        }}>

          {/* inner — always 240 px wide so transition clips it */}
          <div style={{ width: "240px", minWidth: "240px", display: "flex", flexDirection: "column", flex: 1, overflowY: "auto" }}>

            {/* label */}
            <div style={{ padding: "20px 18px 8px", fontFamily: "JetBrains Mono,monospace", fontSize: "10px", fontWeight: 700, letterSpacing: "0.18em", textTransform: "uppercase", color: "#7ab0cc" }}>
              Navigation
            </div>

            {/* nav items */}
            <div style={{ padding: "4px 10px 10px", display: "flex", flexDirection: "column", gap: "3px" }}>
              {NAV.map(({ label, path }) => {
                const active = location.pathname === path || (path !== "/" && location.pathname.startsWith(path));
                const isHov  = hov === path;
                return (
                  <div
                    key={path}
                    onClick={() => navigate(path)}
                    onMouseEnter={() => setHov(path)}
                    onMouseLeave={() => setHov(null)}
                    style={{
                      display:        "flex",
                      alignItems:     "center",
                      justifyContent: "space-between",
                      padding:        "11px 14px",
                      borderRadius:   "10px",
                      cursor:         "pointer",
                      border:         active ? "1px solid rgba(0,217,255,.35)" : isHov ? "1px solid rgba(0,217,255,.15)" : "1px solid transparent",
                      background:     active ? "rgba(0,217,255,.13)" : isHov ? "rgba(0,217,255,.08)" : "transparent",
                      transition:     "background .15s, border-color .15s",
                    }}
                  >
                    <span style={{ fontFamily: "Inter,sans-serif", fontSize: "13.5px", fontWeight: active ? 700 : 500, color: active ? "#00d9ff" : isHov ? "#d8f0ff" : "#9ecce8", whiteSpace: "nowrap" }}>
                      {label}
                    </span>
                    {path === "/threats" && threatCount > 0 && (
                      <span style={{ minWidth: "20px", height: "20px", borderRadius: "10px", background: "#ff4569", color: "#fff", fontSize: "10px", fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", padding: "0 5px", fontFamily: "JetBrains Mono,monospace" }}>
                        {threatCount > 99 ? "99+" : threatCount}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>

            {/* divider */}
            <div style={{ height: "1px", background: "#1e3a58", margin: "10px 14px" }} />

            {/* model card */}
            <div style={{ margin: "auto 12px 18px", padding: "16px 18px", borderRadius: "14px", background: "linear-gradient(135deg,#0d1f38,#0a1828)", border: "1px solid #1e3a58" }}>
              <div style={{ fontFamily: "JetBrains Mono,monospace", fontSize: "10px", fontWeight: 700, letterSpacing: "0.16em", textTransform: "uppercase", color: "#7ab0cc", marginBottom: "6px" }}>UpgradedAMIDES</div>
              <div style={{ fontFamily: "JetBrains Mono,monospace", fontSize: "14px", fontWeight: 700, color: "#00d9ff", marginBottom: "12px" }}>
                v1.0 &nbsp;·&nbsp;
                <span style={{ color: polling ? "#00d9ff" : "#00e676", fontSize: "12px" }}>{polling ? "Syncing" : "Active"}</span>
              </div>
              <div style={{ height: "5px", background: "#06101e", borderRadius: "3px", overflow: "hidden", marginBottom: "8px" }}>
                <div style={{ width: "96%", height: "100%", background: "linear-gradient(90deg,#00d9ff,#c084fc)", borderRadius: "3px" }} />
              </div>
              <div style={{ fontFamily: "JetBrains Mono,monospace", fontSize: "10px", color: "#7ab0cc", letterSpacing: "0.04em" }}>XGBoost · 600 trees · 6 classes</div>
            </div>

          </div>
        </div>

        {/* ── MAIN CONTENT ── */}
        <div className="dash-main">
          <Outlet />
        </div>

      </div>
    </div>
  );
};

export default AppLayout;
