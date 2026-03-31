export type Severity     = "critical" | "high" | "medium" | "low";
export type ThreatStatus = "active" | "investigating" | "resolved" | "pending";

export interface Threat {
  id: string;
  threatType: string;
  sourceIP: string;
  destinationIP: string;
  severity: Severity;
  status: ThreatStatus;
  timestamp: string;
  description: string;
  protocol: string;
  eventCount: number;
  confidence: number;
}

export interface LogEntry {
  id: string;
  time: string;
  level: "INFO" | "WARN" | "ERROR" | "CRITICAL";
  source: string;
  message: string;
}
