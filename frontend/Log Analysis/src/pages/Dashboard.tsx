import React, { useState, useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAnalysis } from "../context/AnalysisContext";
import { collectAndAnalyze } from "../services/api";
import type { SystemAnalysisResult, SystemPredictionEntry } from "../services/api";
import { BORD, T, ACC, M } from "../constants/theme";
import StatCard from "../components/ui/StatCard";
import Panel from "../components/ui/Panel";
import PermissionDialog from "../components/ui/PermissionDialog";
import LogLoadingScreen from "../components/ui/LogLoadingScreen";
import AccessDenied from "../components/ui/AccessDenied";
import AttackDistributionChart from "../components/charts/AttackDistributionChart";
import LogVolumeChart from "../components/charts/LogVolumeChart";
import type { LoadingStage } from "../components/ui/LogLoadingScreen";
import type { AttackDataItem } from "../components/charts/AttackDistributionChart";
import type { LogVolumeDataItem } from "../components/charts/LogVolumeChart";

const THREAT_PALETTE = [ACC.red, ACC.orange, ACC.yellow, ACC.purple, ACC.cyan, ACC.green];

const SEV_COLOR: Record<string, string> = {
  critical: ACC.red, high: ACC.orange, medium: ACC.yellow, low: ACC.cyan, none: ACC.green,
};
const SEV_BG: Record<string, string> = {
  critical: "rgba(255,69,105,.12)", high: "rgba(255,142,60,.1)",
  medium: "rgba(255,210,63,.08)",   low: "rgba(0,217,255,.08)",
  none: "rgba(0,230,118,.07)",
};

/** Map confidence score → display severity */
function confToSev(confidence: number): string {
  if (confidence < 0.50) return "low";
  if (confidence < 0.75) return "medium";
  if (confidence < 0.90) return "high";
  return "critical";
}

const STAGE_DEFS: Omit<LoadingStage, "status">[] = [
  { id: "connect",   label: "Connecting to system log sources",  detail: "Reaching backend at localhost:8000" },
  { id: "read",      label: "Reading system event logs",         detail: "Windows Security / System / Application" },
  { id: "normalize", label: "Normalising log entries",           detail: "Mapping events to model input format" },
  { id: "predict",   label: "Running AI model predictions",      detail: "UpgradedAMIDES · XGBoost 600-tree ensemble" },
  { id: "threat",    label: "Classifying threats",               detail: "Mapping predictions to attack categories" },
  { id: "remediate", label: "Triggering remediation checks",     detail: "Evaluating high/critical events" },
  { id: "render",    label: "Building threat dashboard",         detail: "Aggregating results for display" },
];

function makeStages(active: string | null, done: string[]): LoadingStage[] {
  return STAGE_DEFS.map(s => ({
    ...s,
    status: done.includes(s.id) ? "done" : s.id === active ? "active" : "pending",
  }));
}

type PermState = "asking" | "granted" | "denied";

const ViewMoreBtn: React.FC<{ onClick: () => void }> = ({ onClick }) => (
  <button onClick={onClick} style={{
    ...M, fontSize: 10, color: ACC.cyan,
    background: "rgba(0,217,255,.08)", border: "1px solid rgba(0,217,255,.2)",
    borderRadius: 6, padding: "4px 12px", cursor: "pointer", letterSpacing: ".06em", flexShrink: 0,
  }}>VIEW MORE →</button>
);

// ── Inline alerts table for Row 2 ─────────────────────────────────────────────
const RecentAlertsTable: React.FC<{ entries: SystemPredictionEntry[] }> = ({ entries }) => {
  const top5 = [...entries]
    .filter(e => e.is_threat)
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 5);

  if (top5.length === 0) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", minHeight: 120 }}>
        <p style={{ ...M, fontSize: 11, color: T.lo }}>No threats detected ✓</p>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
      {top5.map((e, i) => {
        const sev = confToSev(e.confidence);
        const ipMatch = e.raw_log.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
        const ip = ipMatch ? ipMatch[1] : e.log_source.split("_").slice(-1)[0];
        return (
          <div
            key={i}
            style={{
              display: "grid", gridTemplateColumns: "60px 1fr 54px",
              gap: 8, padding: "10px 0",
              borderBottom: i < top5.length - 1 ? `1px solid ${BORD.dim}` : "none",
              alignItems: "center",
            }}
          >
            {/* severity badge */}
            <span style={{
              ...M, fontSize: 8, fontWeight: 700,
              color: SEV_COLOR[sev] ?? T.md,
              background: SEV_BG[sev] ?? "transparent",
              border: `1px solid ${SEV_COLOR[sev] ?? BORD.dim}`,
              borderRadius: 4, padding: "2px 5px",
              textTransform: "uppercase", letterSpacing: ".05em",
              textAlign: "center", whiteSpace: "nowrap",
            }}>{sev}</span>

            {/* log + source */}
            <div style={{ minWidth: 0 }}>
              <p style={{
                ...M, fontSize: 10, color: T.hi,
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                marginBottom: 2,
              }}>
                {e.threat_type.replace(/_/g, " ")}
              </p>
              <p style={{ ...M, fontSize: 9, color: T.lo, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {ip} · {e.log_source}
              </p>
            </div>

            {/* confidence */}
            <div style={{ textAlign: "right" }}>
              <span style={{ ...M, fontSize: 10, fontWeight: 700, color: SEV_COLOR[sev] ?? ACC.cyan }}>
                {(e.confidence * 100).toFixed(0)}%
              </span>
              <div style={{ height: 3, background: BORD.dim, borderRadius: 2, marginTop: 3 }}>
                <div style={{ width: `${e.confidence * 100}%`, height: "100%", background: SEV_COLOR[sev] ?? ACC.cyan, borderRadius: 2 }} />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

// ── Dashboard ──────────────────────────────────────────────────────────────────
const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { result: ctxResult, hasData, saveAnalysis, polling } = useAnalysis();

  const [permState,   setPermState]   = useState<PermState>(() => hasData ? "granted" : "asking");
  const [isLoading,   setIsLoading]   = useState(false);
  const [activeStage, setActiveStage] = useState<string | null>(null);
  const [doneStages,  setDoneStages]  = useState<string[]>([]);
  const [loadError,   setLoadError]   = useState("");
  const [localResult, setLocalResult] = useState<SystemAnalysisResult | null>(ctxResult);
  const [chartsReady, setChartsReady] = useState(hasData);

  const [logsCollected,  setLogsCollected]  = useState<number | undefined>();
  const [predictionsRun, setPredictionsRun] = useState<number | undefined>();
  const [threatsFound,   setThreatsFound]   = useState<number | undefined>();

  const result = ctxResult ?? localResult;

  const advance = useCallback((id: string) => {
    setActiveStage(id);
    const idx = STAGE_DEFS.findIndex(s => s.id === id);
    setDoneStages(STAGE_DEFS.slice(0, idx).map(s => s.id));
  }, []);

  const complete = useCallback((id: string) => {
    setDoneStages(prev => prev.includes(id) ? prev : [...prev, id]);
  }, []);

  const runAnalysis = useCallback(async (sources: string[]) => {
    setPermState("granted");
    setIsLoading(true);
    setLoadError("");
    setLocalResult(null);
    setLogsCollected(undefined);
    setPredictionsRun(undefined);
    setThreatsFound(undefined);
    setChartsReady(false);

    try {
      advance("connect"); await delay(400); complete("connect");
      advance("read");
      const data = await collectAndAnalyze(sources);  // no limit — last 24 h
      complete("read");
      setLogsCollected(data.total_collected);
      advance("normalize"); await delay(300); complete("normalize");
      advance("predict");   await delay(400); complete("predict");
      setPredictionsRun(data.total_collected);
      advance("threat");    await delay(250); complete("threat");
      setThreatsFound(data.total_threats);
      advance("remediate"); await delay(250); complete("remediate");
      advance("render");
      setLocalResult(data);
      saveAnalysis(data, sources);
      await delay(300); complete("render");
      setActiveStage(null);
      setTimeout(() => setChartsReady(true), 150);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message
        : typeof err === "object" && err !== null && "response" in err
          ? ((err as { response?: { data?: { detail?: string } } }).response?.data?.detail ?? "Unknown error")
          : "Unknown error";
      setLoadError(`Failed to collect or analyse logs. ${msg}. Make sure the backend is running.`);
    } finally {
      setIsLoading(false);
    }
  }, [advance, complete, saveAnalysis]);

  useEffect(() => {
    if (ctxResult && !chartsReady) setTimeout(() => setChartsReady(true), 150);
  }, [ctxResult, chartsReady]);

  // ── Derived data ─────────────────────────────────────────────────────────────
  const attackDistData: AttackDataItem[] = result
    ? Object.entries(result.summary.by_threat_type).map(([name, value], i) => ({
        name: name.replace(/_/g, " "), value,
        color: THREAT_PALETTE[i % THREAT_PALETTE.length],
      }))
    : [];

  // Windows = all windows_* channels (security, system, application, network, firewall)
  // Network = dedicated "network" source (WFP events / netstat / firewall log)
  // Syslog  = all syslog_* sources (syslog_windows, syslog_auth, etc.)
  const logVolumeData: LogVolumeDataItem[] = result
    ? Object.entries(result.hourly_volume).map(([label, src]) => ({
        label,
        windows: Object.entries(src)
          .filter(([k]) => k.startsWith("windows_"))
          .reduce((s, [, v]) => s + v, 0),
        network: src["network"] ?? 0,
        syslog:  Object.entries(src)
          .filter(([k]) => k.startsWith("syslog_"))
          .reduce((s, [, v]) => s + v, 0),
      }))
    : [];

  const windowsCount = result
    ? Object.entries(result.summary.by_source).filter(([k]) => k.startsWith("windows_")).reduce((s, [, v]) => s + v, 0)
    : 0;
  const networkCount = result?.summary.by_source["network"] ?? 0;
  const syslogCount  = result
    ? Object.entries(result.summary.by_source).filter(([k]) => k.startsWith("syslog_")).reduce((s, [, v]) => s + v, 0)
    : 0;

  // ── Render states ─────────────────────────────────────────────────────────────
  if (permState === "asking") return <PermissionDialog onAllow={runAnalysis} onDeny={() => setPermState("denied")} />;
  if (permState === "denied") return <AccessDenied onRetry={() => setPermState("asking")} />;
  if (isLoading || (permState === "granted" && !result && !loadError)) {
    return (
      <LogLoadingScreen
        stages={makeStages(activeStage, doneStages)}
        logsCollected={logsCollected} predictionsRun={predictionsRun} threatsFound={threatsFound}
        errorMessage={loadError || undefined}
      />
    );
  }
  if (loadError) {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "50vh", gap: 20, padding: 40 }}>
        <LogLoadingScreen stages={makeStages(null, [])} errorMessage={loadError} />
        <button onClick={() => { setLoadError(""); setPermState("asking"); }} style={{
          ...M, fontSize: 12, fontWeight: 700, cursor: "pointer",
          background: "rgba(0,217,255,.1)", color: ACC.cyan,
          border: "1px solid rgba(0,217,255,.3)", borderRadius: 10, padding: "11px 28px",
        }}>TRY AGAIN →</button>
      </div>
    );
  }

  // ── Full dashboard ────────────────────────────────────────────────────────────
  return (
    <>
      {/* ROW 1 — stat cards */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: -2 }}>
        <span style={{ ...M, fontSize: 9, color: T.lo, letterSpacing: ".14em", textTransform: "uppercase" }}>
          Log Sources {polling && <span style={{ color: ACC.cyan }}>· live</span>}
        </span>
        <ViewMoreBtn onClick={() => navigate("/threats")} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14 }}>
        <StatCard label="Windows Events"  value={windowsCount.toLocaleString()} sub={`Host: ${result?.hostname ?? "—"}`}  color={ACC.purple} icon="⊞" />
        <StatCard label="Network Flows"   value={networkCount.toLocaleString()}  sub="NetFlow / IPFIX captured"            color={ACC.cyan}   icon="📡" />
        <StatCard label="Syslog Lines"    value={syslogCount.toLocaleString()}   sub="Linux / application logs"            color={ACC.green}  icon="📋" />
        <StatCard label="Total Processed" value={(result?.total_collected ?? 0).toLocaleString()} sub={polling ? "Syncing…" : "All sources combined"} color={ACC.orange} icon="∑" />
      </div>

      {/* ROW 2 — 2 charts + recent alerts table */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>
        <Panel title="Attack Distribution" badge={<ViewMoreBtn onClick={() => navigate("/analytics")} />} pad={12}>
          <AttackDistributionChart ready={chartsReady} data={attackDistData.length > 0 ? attackDistData : undefined} />
        </Panel>

        <Panel title="Log Volume (Hourly)" badge={<ViewMoreBtn onClick={() => navigate("/analytics")} />} pad={12}>
          <LogVolumeChart ready={chartsReady} data={logVolumeData.length > 0 ? logVolumeData : undefined} />
        </Panel>

        <Panel title="Recent Alerts" badge={<ViewMoreBtn onClick={() => navigate("/threats")} />} pad={16} flex>
          <RecentAlertsTable entries={result?.results ?? []} />
        </Panel>
      </div>

      {/* Footer */}
      <div style={{ display: "flex", justifyContent: "space-between", paddingTop: 14, borderTop: `1px solid ${BORD.dim}` }}>
        <span style={{ ...M, fontSize: 9, color: T.dim }}>SENTINEL·AI · Log Analysis for Cyber Threat Detection</span>
        <span style={{ ...M, fontSize: 9, color: T.dim }}>
          {result?.total_collected ?? 0} logs · {result?.total_threats ?? 0} threats · {result?.timestamp ? new Date(result.timestamp).toLocaleTimeString() : "—"}
          {polling && <span style={{ color: ACC.cyan }}> · syncing</span>}
        </span>
      </div>
    </>
  );
};

const delay = (ms: number) => new Promise(r => setTimeout(r, ms));

export default Dashboard;
