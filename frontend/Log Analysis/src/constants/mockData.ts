import type { Threat, LogEntry } from "../types";

export const MOCK_THREATS: Threat[] = [
  { id:"THR-0041", threatType:"Brute Force",        sourceIP:"192.168.4.21",     destinationIP:"10.0.0.5",      severity:"critical", status:"active",        timestamp:"14:32:07", description:"429 failed SSH login attempts from single source over 4 min. Lockout threshold exceeded.",            protocol:"SSH",      eventCount:429,  confidence:97 },
  { id:"THR-0040", threatType:"Port Scan",           sourceIP:"203.0.113.88",     destinationIP:"10.0.0.1",      severity:"high",     status:"investigating", timestamp:"14:28:55", description:"Systematic TCP SYN scan on 1,024 ports. Likely network reconnaissance phase.",                        protocol:"TCP",      eventCount:1024, confidence:91 },
  { id:"THR-0039", threatType:"Data Exfiltration",   sourceIP:"10.0.0.45",        destinationIP:"185.220.101.5", severity:"critical", status:"active",        timestamp:"14:15:30", description:"Unusual outbound spike: 2.3 GB transferred to unknown external host over encrypted channel.",         protocol:"HTTPS",    eventCount:156,  confidence:88 },
  { id:"THR-0038", threatType:"SQL Injection",        sourceIP:"198.51.100.23",    destinationIP:"10.0.0.12",     severity:"high",     status:"resolved",      timestamp:"13:52:11", description:"Malicious SQL payload in POST request. UNION-based injection on /api/login.",                        protocol:"HTTP",     eventCount:7,    confidence:99 },
  { id:"THR-0037", threatType:"Privilege Escalation", sourceIP:"10.0.0.78",        destinationIP:"10.0.0.1",      severity:"medium",   status:"investigating", timestamp:"13:40:02", description:"Internal user attempted root-level resource access without authorization. SUDO abuse detected.",      protocol:"Internal", eventCount:12,   confidence:76 },
  { id:"THR-0036", threatType:"Phishing",             sourceIP:"mail.evil.ru",     destinationIP:"10.0.0.55",     severity:"medium",   status:"pending",       timestamp:"13:25:44", description:"Email with malicious URL. Domain registered 2 days ago. Spoofed sender identity.",                  protocol:"SMTP",     eventCount:3,    confidence:82 },
];

export const MOCK_LOGS: LogEntry[] = [
  { id:"L001", time:"14:32:07", level:"CRITICAL", source:"auth-service",    message:"Multiple failed login attempts — IP 192.168.4.21 blocked" },
  { id:"L002", time:"14:31:55", level:"ERROR",    source:"firewall",        message:"Outbound connection to blacklisted IP 185.220.101.5 blocked" },
  { id:"L003", time:"14:30:12", level:"WARN",     source:"ids-engine",      message:"Port scan detected from 203.0.113.88 — 1024 ports probed" },
  { id:"L004", time:"14:28:40", level:"INFO",     source:"siem-core",       message:"DNN model retrain completed — accuracy: 96.4%" },
  { id:"L005", time:"14:27:03", level:"WARN",     source:"network-monitor", message:"Unusual bandwidth spike: 2.3 GB outbound in 8 min" },
  { id:"L006", time:"14:25:19", level:"ERROR",    source:"web-server",      message:"SQL injection attempt blocked on /api/login" },
  { id:"L007", time:"14:22:55", level:"INFO",     source:"ansible-agent",   message:"Log collection from 4 VMs (Ubuntu/Windows) completed" },
  { id:"L008", time:"14:20:10", level:"INFO",     source:"elasticsearch",   message:"Index optimised — 1.2 M documents indexed" },
  { id:"L009", time:"14:18:34", level:"WARN",     source:"auth-service",    message:"SUDO privilege escalation attempt by user [jdoe]" },
  { id:"L010", time:"14:15:02", level:"INFO",     source:"siem-core",       message:"Ruleset update applied — 342 new signatures loaded" },
];
