import React, { useEffect, useState } from "react";
import { fetchSystemSources } from "../../services/api";
import type { LogSource } from "../../services/api";
import { BORD, T, ACC, M } from "../../constants/theme";

interface Props {
  onAllow:  (selectedSources: string[]) => void;
  onDeny:   () => void;
}

const PermissionDialog: React.FC<Props> = ({ onAllow, onDeny }) => {
  const [sources, setSources]     = useState<LogSource[]>([]);
  const [selected, setSelected]   = useState<Set<string>>(new Set());
  const [loading, setLoading]     = useState(true);
  const [platform, setPlatform]   = useState("");
  const [hostname, setHostname]   = useState("");
  const [error, setError]         = useState("");

  // fetch available sources from the backend as soon as dialog opens
  useEffect(() => {
    fetchSystemSources()
      .then(data => {
        setSources(data.available);
        setPlatform(data.platform);
        setHostname(data.hostname);
        // pre-select all by default
        setSelected(new Set(data.available.map(s => s.id)));
      })
      .catch(() => setError("Cannot reach backend. Make sure the server is running on port 8000."))
      .finally(() => setLoading(false));
  }, []);

  const toggle = (id: string) =>
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const handleAllow = () => {
    if (selected.size === 0) return;
    onAllow(Array.from(selected));
  };

  return (
    /* overlay */
    <div style={{
      position: "fixed", inset: 0,
      background: "rgba(6,16,30,.92)",
      backdropFilter: "blur(6px)",
      display: "flex", alignItems: "center", justifyContent: "center",
      zIndex: 9999,
    }}>
      {/* dialog box */}
      <div style={{
        background: "#0b1a2e",
        border: `1px solid ${BORD.mid}`,
        borderRadius: 20,
        width: "min(560px, 92vw)",
        boxShadow: "0 32px 80px rgba(0,0,0,.6)",
        overflow: "hidden",
        animation: "slideUp .25s ease-out",
      }}>

        {/* header */}
        <div style={{ padding: "24px 28px 18px", borderBottom: `1px solid ${BORD.dim}`, background: "#091628" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 12 }}>
            <div style={{
              width: 44, height: 44, borderRadius: 12,
              background: "rgba(0,217,255,.1)", border: `1px solid rgba(0,217,255,.3)`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 22,
            }}>🔒</div>
            <div>
              <p style={{ fontFamily: "'Orbitron',monospace", color: ACC.cyan, fontSize: 15, fontWeight: 700, letterSpacing: ".04em" }}>
                Log Access Required
              </p>
              <p style={{ ...M, fontSize: 10, color: T.lo, marginTop: 3 }}>
                SENTINEL·AI needs permission to read system logs
              </p>
            </div>
          </div>

          <p style={{ fontSize: 13, color: T.md, fontFamily: "'Inter',sans-serif", lineHeight: 1.55 }}>
            To detect cyber threats, the AI model needs to analyse real logs from your machine.
            Select the sources you want to share, then click <b style={{ color: ACC.cyan }}>Allow Access</b>.
          </p>
        </div>

        {/* source list */}
        <div style={{ padding: "18px 28px" }}>

          {loading && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, color: T.lo, ...M, fontSize: 12 }}>
              <Spinner color={ACC.cyan} size={16} />
              Discovering log sources on this machine…
            </div>
          )}

          {error && (
            <div style={{ background: "rgba(255,69,105,.08)", border: `1px solid rgba(255,69,105,.25)`, borderRadius: 10, padding: "12px 16px", color: ACC.red, ...M, fontSize: 12 }}>
              ⚠ {error}
            </div>
          )}

          {!loading && !error && sources.length === 0 && (
            <div style={{ ...M, fontSize: 12, color: T.lo, textAlign: "center", padding: "16px 0" }}>
              No accessible log sources found on this machine.
            </div>
          )}

          {!loading && !error && sources.length > 0 && (
            <>
              <p style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".14em", marginBottom: 12 }}>
                DETECTED ON {platform.toUpperCase()} · {hostname}
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {sources.map(src => (
                  <SourceRow
                    key={src.id}
                    source={src}
                    checked={selected.has(src.id)}
                    onToggle={() => toggle(src.id)}
                  />
                ))}
              </div>
            </>
          )}
        </div>

        {/* privacy note */}
        <div style={{ padding: "0 28px 18px" }}>
          <div style={{ background: "rgba(0,217,255,.04)", border: `1px solid rgba(0,217,255,.1)`, borderRadius: 10, padding: "10px 14px", display: "flex", gap: 10, alignItems: "flex-start" }}>
            <span style={{ color: ACC.cyan, fontSize: 14, flexShrink: 0 }}>ℹ</span>
            <p style={{ ...M, fontSize: 10, color: T.lo, lineHeight: 1.6 }}>
              Logs are sent only to your local backend server (<b style={{ color: T.md }}>localhost:8000</b>).
              Nothing leaves your machine. Access is one-time — you can revoke it by refreshing the page.
            </p>
          </div>
        </div>

        {/* action buttons */}
        <div style={{ display: "flex", gap: 12, padding: "16px 28px 24px", justifyContent: "flex-end" }}>
          <button onClick={onDeny} style={{
            ...M, fontSize: 12, fontWeight: 600, cursor: "pointer",
            background: "transparent", color: T.lo,
            border: `1px solid ${BORD.dim}`, borderRadius: 10, padding: "11px 24px",
          }}>
            Deny Access
          </button>
          <button
            onClick={handleAllow}
            disabled={selected.size === 0 || loading || !!error}
            style={{
              ...M, fontSize: 12, fontWeight: 700, cursor: selected.size === 0 || loading || !!error ? "not-allowed" : "pointer",
              background: selected.size === 0 || loading || !!error ? "rgba(0,217,255,.05)" : "rgba(0,217,255,.14)",
              color: selected.size === 0 || loading || !!error ? T.lo : ACC.cyan,
              border: `1px solid ${selected.size === 0 || loading || !!error ? BORD.dim : "rgba(0,217,255,.4)"}`,
              borderRadius: 10, padding: "11px 28px",
            }}
          >
            Allow Access {selected.size > 0 ? `(${selected.size} source${selected.size > 1 ? "s" : ""})` : ""}
          </button>
        </div>

      </div>

      <style>{`
        @keyframes slideUp {
          from { transform: translateY(28px); opacity: 0; }
          to   { transform: translateY(0);    opacity: 1; }
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

/* ── Single source row ───────────────────────────────────────────────────────  */
const SourceRow: React.FC<{ source: LogSource; checked: boolean; onToggle: () => void }> = ({ source, checked, onToggle }) => (
  <div
    onClick={onToggle}
    style={{
      display: "flex", alignItems: "center", gap: 14,
      padding: "12px 16px",
      background: checked ? "rgba(0,217,255,.06)" : "rgba(255,255,255,.02)",
      border: `1px solid ${checked ? "rgba(0,217,255,.25)" : BORD.dim}`,
      borderRadius: 10, cursor: "pointer",
      transition: "all .15s",
    }}
  >
    {/* checkbox */}
    <div style={{
      width: 18, height: 18, borderRadius: 5, flexShrink: 0,
      border: `2px solid ${checked ? ACC.cyan : BORD.mid}`,
      background: checked ? "rgba(0,217,255,.2)" : "transparent",
      display: "flex", alignItems: "center", justifyContent: "center",
      transition: "all .15s",
    }}>
      {checked && <span style={{ color: ACC.cyan, fontSize: 11, fontWeight: 900, lineHeight: 1 }}>✓</span>}
    </div>

    {/* icon */}
    <span style={{ fontSize: 18, flexShrink: 0 }}>
      {source.platform === "windows" ? "⊞" : "🐧"}
    </span>

    {/* label + meta */}
    <div style={{ flex: 1, minWidth: 0 }}>
      <p style={{ fontSize: 13, color: T.hi, fontFamily: "'Inter',sans-serif", fontWeight: 500, marginBottom: 2 }}>
        {source.label}
      </p>
      <p style={{ ...M, fontSize: 10, color: T.lo }}>
        {source.id}
        {source.event_count !== undefined && source.event_count > 0 && (
          <span style={{ color: ACC.cyan, marginLeft: 10 }}>{source.event_count.toLocaleString()} events available</span>
        )}
      </p>
    </div>
  </div>
);

/* ── Tiny spinner ─────────────────────────────────────────────────────────── */
const Spinner: React.FC<{ color: string; size: number }> = ({ color, size }) => (
  <span style={{
    width: size, height: size, display: "inline-block", flexShrink: 0,
    border: `2px solid transparent`,
    borderTopColor: color,
    borderRadius: "50%",
    animation: "spin .7s linear infinite",
  }} />
);

export default PermissionDialog;
