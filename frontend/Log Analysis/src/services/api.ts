import axios from "axios";

const API = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? "http://localhost:8000",
});

export interface Threat {
  id: string;
  threatType: string;
  sourceIP: string;
  destinationIP: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "active" | "investigating" | "resolved" | "pending";
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

export const fetchThreats = (): Promise<Threat[]> =>
  API.get<{ status: string; data: Threat[] }>("/api/threats").then(r => r.data.data);

export const fetchLogs = (): Promise<LogEntry[]> =>
  API.get<{ status: string; data: LogEntry[] }>("/api/logs").then(r => r.data.data);

export const fetchHealth = (): Promise<{ status: string; timestamp: string }> =>
  API.get<{ status: string; timestamp: string }>("/api/health").then(r => r.data);

export default API;
