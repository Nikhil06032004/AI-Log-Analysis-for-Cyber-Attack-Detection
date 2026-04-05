import React, { useState } from "react";
import { BORD, T, ACC, M } from "../constants/theme";

interface Rule {
  id: string;
  name: string;
  category: string;
  severity: string;
  condition: string;
  action: string;
  enabled: boolean;
}

const DEFAULT_RULES: Rule[] = [
  { id: "R001", name: "SSH Brute Force",         category: "BRUTE_FORCE", severity: "critical", condition: "failed_logon_count > 10 in 60s from same IP",        action: "BLOCK_IP + ALERT_ADMIN",     enabled: true  },
  { id: "R002", name: "Port Scan Detection",      category: "PORT_SCAN",   severity: "high",     condition: "unique_ports_probed > 100 from same source in 30s",   action: "ALERT_ADMIN + LOG",          enabled: true  },
  { id: "R003", name: "DOS Traffic Spike",        category: "DOS_ATTACK",  severity: "critical", condition: "connection_rate > 10000/min or serror_rate > 0.9",    action: "BLOCK_IP + ALERT_ADMIN",     enabled: true  },
  { id: "R004", name: "Suspicious Process Spawn", category: "MALWARE",     severity: "high",     condition: "EventID=4688 AND (cmd.exe OR powershell.exe) by svchost", action: "ALERT_ADMIN + LOG",        enabled: true  },
  { id: "R005", name: "Audit Log Cleared",        category: "LOG_EVASION", severity: "critical", condition: "EventID=1102 OR EventID=4719",                       action: "BLOCK_IP + ALERT_ADMIN",     enabled: true  },
  { id: "R006", name: "Registry Persistence",     category: "MALWARE",     severity: "high",     condition: "EventID=4657 AND path=HKLM\\Run",                    action: "ALERT_ADMIN + LOG",          enabled: false },
  { id: "R007", name: "Data Exfiltration",        category: "MALWARE",     severity: "critical", condition: "dst_bytes > 1GB to external IP in 5min",             action: "BLOCK_IP + ALERT_ADMIN",     enabled: true  },
  { id: "R008", name: "NTLM Relay Attempt",       category: "BRUTE_FORCE", severity: "high",     condition: "EventID=4776 AND FailureReason=%%2313",              action: "ALERT_ADMIN + LOG",          enabled: false },
];

const SEV_COLOR: Record<string, string> = {
  critical: ACC.red, high: ACC.orange, medium: ACC.yellow, low: ACC.cyan,
};

const CAT_COLOR: Record<string, string> = {
  BRUTE_FORCE: ACC.red, PORT_SCAN: ACC.orange, DOS_ATTACK: ACC.yellow,
  MALWARE: ACC.purple, LOG_EVASION: ACC.cyan,
};

const SIEMRules: React.FC = () => {
  const [rules, setRules] = useState<Rule[]>(DEFAULT_RULES);

  const toggle = (id: string) =>
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));

  const enabledCount  = rules.filter(r => r.enabled).length;
  const criticalCount = rules.filter(r => r.severity === "critical" && r.enabled).length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <h2 style={{ ...M, color: T.hi, fontSize: 18, fontWeight: 700, marginBottom: 4 }}>SIEM Rules</h2>
          <p style={{ ...M, fontSize: 11, color: T.lo }}>{enabledCount}/{rules.length} rules active · {criticalCount} critical</p>
        </div>
      </div>

      <div style={{ background: "#0b1a2e", border: `1px solid ${BORD.dim}`, borderRadius: 14, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "56px 60px 1fr 110px 100px 1fr 64px", gap: 10, padding: "8px 18px", borderBottom: `1px solid ${BORD.dim}`, background: "#091628" }}>
          {["ON/OFF", "ID", "RULE NAME", "CATEGORY", "SEV", "CONDITION", "ACTION"].map(h => (
            <span key={h} style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".1em" }}>{h}</span>
          ))}
        </div>
        {rules.map((rule, i) => (
          <div key={rule.id} style={{
            display: "grid", gridTemplateColumns: "56px 60px 1fr 110px 100px 1fr 64px",
            gap: 10, padding: "13px 18px", alignItems: "center",
            borderBottom: i < rules.length - 1 ? `1px solid ${BORD.dim}` : "none",
            opacity: rule.enabled ? 1 : 0.45,
            transition: "opacity .2s",
          }}>
            {/* toggle */}
            <div onClick={() => toggle(rule.id)} style={{ cursor: "pointer", width: 36, height: 20, borderRadius: 10,
              background: rule.enabled ? "rgba(0,230,118,.25)" : BORD.dim,
              border: `1px solid ${rule.enabled ? ACC.green : BORD.mid}`, position: "relative", transition: "all .2s" }}>
              <div style={{ position: "absolute", top: 2, left: rule.enabled ? 16 : 2, width: 14, height: 14, borderRadius: "50%",
                background: rule.enabled ? ACC.green : T.lo, transition: "left .2s" }} />
            </div>

            <span style={{ ...M, fontSize: 10, color: T.dim }}>{rule.id}</span>
            <span style={{ fontSize: 13, color: T.hi, fontFamily: "'Inter',sans-serif", fontWeight: 500 }}>{rule.name}</span>

            <span style={{ ...M, fontSize: 9, color: CAT_COLOR[rule.category] ?? T.md,
              background: `${CAT_COLOR[rule.category] ?? ACC.cyan}18`, border: `1px solid ${CAT_COLOR[rule.category] ?? BORD.dim}`,
              borderRadius: 5, padding: "3px 7px", textAlign: "center" }}>{rule.category}</span>

            <span style={{ ...M, fontSize: 10, fontWeight: 700, color: SEV_COLOR[rule.severity] ?? T.md, textTransform: "uppercase" }}>
              {rule.severity}
            </span>

            <span style={{ ...M, fontSize: 10, color: T.lo }}>{rule.condition}</span>
            <span style={{ ...M, fontSize: 9, color: ACC.orange }}>{rule.action}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SIEMRules;
