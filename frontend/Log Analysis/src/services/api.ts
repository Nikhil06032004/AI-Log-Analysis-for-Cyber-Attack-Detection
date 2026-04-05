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

export interface IngestStats {
  total_logs_processed: number;
  windows_events: number;
  network_flows: number;
  syslog_lines: number;
  total_threats_detected: number;
  threat_rate: number;
}

export interface AnalysisResult {
  threat_type: string;
  severity: string;
  confidence: number;
  is_threat: boolean;
  remediation_actions: string[];
  top_signals: Record<string, number>;
}

export const fetchThreats = (): Promise<Threat[]> =>
  API.get<{ status: string; data: Threat[] }>("/api/threats").then(r => r.data.data);

export const fetchLogs = (): Promise<LogEntry[]> =>
  API.get<{ status: string; data: LogEntry[] }>("/api/logs").then(r => r.data.data);

export const fetchHealth = (): Promise<{ status: string; timestamp: string }> =>
  API.get<{ status: string; timestamp: string }>("/api/health").then(r => r.data);

export const fetchIngestStats = (): Promise<IngestStats> =>
  API.get<{ status: string; stats: IngestStats }>("/api/ingest/stats")
    .then(r => r.data.stats)
    .catch((): IngestStats => ({
      total_logs_processed: 0,
      windows_events: 0,
      network_flows: 0,
      syslog_lines: 0,
      total_threats_detected: 0,
      threat_rate: 0,
    }));

export const fetchModelStatus = (): Promise<{ status: string; model_file_exists: boolean; model_loaded_in_memory: boolean }> =>
  API.get("/api/status").then(r => r.data);

export const analyzeLogLine = (log_line: string): Promise<AnalysisResult> =>
  API.post<{ status: string } & AnalysisResult>("/api/analyze/line", { log_line })
    .then(r => r.data);

export const ingestWindowsLogs = (events: object[]): Promise<unknown> =>
  API.post("/api/ingest/windows", events).then(r => r.data);

export const ingestNetworkFlows = (flows: object[]): Promise<unknown> =>
  API.post("/api/ingest/network", { flows }).then(r => r.data);

export const ingestSyslogLines = (lines: string[]): Promise<unknown> =>
  API.post("/api/ingest/syslog", { lines }).then(r => r.data);

// ── System log collection ─────────────────────────────────────────────────────

export interface LogSource {
  id: string;
  label: string;
  platform: string;
  event_count?: number;
}

export interface SystemPredictionEntry {
  log_source: string;
  raw_log: string;
  normalized: string;
  threat_type: string;
  severity: string;
  confidence: number;
  is_threat: boolean;
  remediation_actions: string[];
  top_signals: Record<string, number>;
}

export interface SystemAnalysisResult {
  status: string;
  platform: string;
  hostname: string;
  total_collected: number;
  total_threats: number;
  total_normal: number;
  threat_rate: number;
  summary: {
    by_threat_type: Record<string, number>;
    by_severity: Record<string, number>;
    by_source: Record<string, number>;
  };
  hourly_volume: Record<string, Record<string, number>>;
  results: SystemPredictionEntry[];
  timestamp: string;
}

export const fetchSystemSources = (): Promise<{ available: LogSource[]; platform: string; hostname: string }> =>
  API.get("/api/system/sources").then(r => r.data);

export const collectAndAnalyze = (
  sources: string[],
  maxEvents: number = 150,
): Promise<SystemAnalysisResult> =>
  API.post("/api/system/collect-analyze", { sources, max_events: maxEvents }).then(r => r.data);

export default API;
