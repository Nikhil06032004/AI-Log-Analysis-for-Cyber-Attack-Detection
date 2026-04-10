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
  event_id: number;
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

/** Human-readable labels for backend source IDs shown in tables and charts. */
export const SOURCE_LABELS: Record<string, string> = {
  windows_security:    "Win Security",
  windows_system:      "Win System",
  windows_application: "Win Application",
  windows_network:     "Win Network",
  windows_firewall:    "Win Firewall",
  network:             "Network",
  syslog_windows:      "Syslog",
  syslog_auth:         "Syslog Auth",
  syslog_kern:         "Syslog Kernel",
  syslog_messages:     "Syslog Messages",
};

/** Returns a display label for a source ID, falling back to the raw id. */
export const sourceLabel = (id: string): string =>
  SOURCE_LABELS[id] ?? id.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());

export const fetchSystemSources = (): Promise<{ available: LogSource[]; platform: string; hostname: string }> =>
  API.get("/api/system/sources").then(r => r.data);

export const collectAndAnalyze = (
  sources: string[],
  maxEvents: number = 0,       // 0 = unlimited
  since?: string,              // ISO-8601 UTC — only events after this timestamp
  hoursBack?: number,          // initial load window (default 24h when no `since`)
): Promise<SystemAnalysisResult> =>
  API.post("/api/system/collect-analyze", {
    sources,
    max_events: maxEvents,
    ...(since     ? { since }          : {}),
    ...(hoursBack ? { hours_back: hoursBack } : {}),
  }).then(r => r.data);

// ── System resource metrics ───────────────────────────────────────────────────

export interface CpuMetrics {
  percent:          number;
  per_core:         number[];
  count_logical:    number;
  count_physical:   number;
  freq_mhz_current: number | null;
  freq_mhz_max:     number | null;
  user_pct:         number;
  system_pct:       number;
  idle_pct:         number;
}

export interface RamMetrics {
  total_gb:      number;
  used_gb:       number;
  available_gb:  number;
  percent:       number;
  cached_gb:     number;
  swap_total_gb: number;
  swap_used_gb:  number;
  swap_percent:  number;
}

export interface DiskMetrics {
  root_total_gb:  number;
  root_used_gb:   number;
  root_free_gb:   number;
  root_percent:   number;
  read_mb_total:  number;
  write_mb_total: number;
  partitions: {
    device: string; mountpoint: string; fstype: string;
    total_gb: number; used_gb: number; free_gb: number; percent: number;
  }[];
}

export interface NetworkMetrics {
  bytes_sent_per_s:   number;
  bytes_recv_per_s:   number;
  packets_sent_per_s: number;
  packets_recv_per_s: number;
  bytes_sent_total:   number;
  bytes_recv_total:   number;
}

export interface ProcessInfo {
  pid: number; name: string; cpu: number; mem: number; status: string;
}

export interface LiveMetrics {
  timestamp:     string;
  platform:      string;
  hostname:      string;
  cpu:           CpuMetrics;
  ram:           RamMetrics;
  disk:          DiskMetrics;
  network:       NetworkMetrics;
  top_processes: ProcessInfo[];
}

export const fetchLiveMetrics = (): Promise<LiveMetrics> =>
  API.get<LiveMetrics>("/api/metrics/live").then(r => r.data);

export default API;
