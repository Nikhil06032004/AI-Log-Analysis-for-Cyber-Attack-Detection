import React, { useState } from "react";
import { BORD, T, ACC, M } from "../constants/theme";

const Settings: React.FC = () => {
  const [apiUrl, setApiUrl]       = useState("http://localhost:8000");
  const [adminEmail, setAdminEmail] = useState("");
  const [smtpHost, setSmtpHost]   = useState("localhost");
  const [smtpPort, setSmtpPort]   = useState("25");
  const [saved, setSaved]         = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20, maxWidth: 680 }}>
      <div>
        <h2 style={{ ...M, color: T.hi, fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Settings</h2>
        <p style={{ ...M, fontSize: 11, color: T.lo }}>Backend connection · remediation · notification</p>
      </div>

      {/* Backend */}
      <Section title="Backend API">
        <Field label="API Base URL" value={apiUrl} onChange={setApiUrl} placeholder="http://localhost:8000" />
      </Section>

      {/* Remediation */}
      <Section title="Remediation — Email Alerts">
        <Field label="Admin Email"  value={adminEmail} onChange={setAdminEmail} placeholder="admin@example.com" />
        <Field label="SMTP Host"    value={smtpHost}   onChange={setSmtpHost}   placeholder="smtp.example.com" />
        <Field label="SMTP Port"    value={smtpPort}   onChange={setSmtpPort}   placeholder="587" />
      </Section>

      {/* save */}
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        <button onClick={handleSave} style={{
          ...M, fontSize: 12, fontWeight: 700, cursor: "pointer",
          background: "rgba(0,217,255,.12)", color: ACC.cyan,
          border: `1px solid rgba(0,217,255,.3)`, borderRadius: 8, padding: "10px 28px",
        }}>
          SAVE SETTINGS
        </button>
        {saved && <span style={{ ...M, fontSize: 11, color: ACC.green }}>✓ Saved</span>}
      </div>

      {/* how-to */}
      <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, padding: "18px 22px" }}>
        <p style={{ ...M, fontSize: 11, color: T.lo, letterSpacing: ".12em", marginBottom: 14 }}>STARTING THE BACKEND</p>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {[
            "cd backend",
            "uvicorn app.main:app --reload --host 0.0.0.0 --port 8000",
            "# Then open http://localhost:8000/docs for Swagger UI",
          ].map((cmd, i) => (
            <code key={i} style={{ ...M, fontSize: 11, color: cmd.startsWith("#") ? T.lo : ACC.cyan,
              background: "#06101e", border: `1px solid ${BORD.dim}`, borderRadius: 6, padding: "8px 14px", display: "block" }}>
              {cmd}
            </code>
          ))}
        </div>
      </div>
    </div>
  );
};

const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, overflow: "hidden" }}>
    <div style={{ padding: "13px 20px", borderBottom: `1px solid ${BORD.dim}`, background: "#091628" }}>
      <span style={{ fontSize: 13, fontWeight: 600, color: T.hi, fontFamily: "'Inter',sans-serif" }}>{title}</span>
    </div>
    <div style={{ padding: "16px 20px", display: "flex", flexDirection: "column", gap: 14 }}>{children}</div>
  </div>
);

const Field: React.FC<{ label: string; value: string; onChange: (v: string) => void; placeholder?: string }> = ({ label, value, onChange, placeholder }) => (
  <div>
    <label style={{ ...M, fontSize: 10, color: T.lo, letterSpacing: ".12em", display: "block", marginBottom: 6 }}>
      {label.toUpperCase()}
    </label>
    <input
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      style={{ width: "100%", ...M, fontSize: 12, color: T.hi, background: "#06101e",
        border: `1px solid ${BORD.dim}`, borderRadius: 8, padding: "9px 14px", outline: "none", boxSizing: "border-box" }}
    />
  </div>
);

export default Settings;
