/**
 * AnalysisContext — global store for SystemAnalysisResult.
 *
 * - Loads from localStorage SYNCHRONOUSLY on first render (lazy initializer),
 *   so hasData is already true before any child mounts → no permission re-ask.
 * - Background polling every 5 seconds using the approved sources.
 * - saveAnalysis() persists new results; clearStore() revokes access.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import { collectAndAnalyze } from "../services/api";
import type { SystemAnalysisResult } from "../services/api";

const RESULT_KEY    = "sentinel_result_v2";
const SOURCES_KEY   = "sentinel_sources_v2";
const LAST_TS_KEY   = "sentinel_last_ts_v2";
const POLL_MS       = 10_000;  // poll every 10 seconds

// Clear any stale v1 keys on module load
try {
  localStorage.removeItem("sentinel_result_v1");
  localStorage.removeItem("sentinel_sources_v1");
  localStorage.removeItem("sentinel_last_ts_v1");
} catch { /* ignore */ }

// ── Helpers ───────────────────────────────────────────────────────────────────

function load(): { result: SystemAnalysisResult; sources: string[]; lastTs: string | null } | null {
  try {
    const r = localStorage.getItem(RESULT_KEY);
    const s = localStorage.getItem(SOURCES_KEY);
    if (!r || !s) return null;
    return {
      result:  JSON.parse(r) as SystemAnalysisResult,
      sources: JSON.parse(s) as string[],
      lastTs:  localStorage.getItem(LAST_TS_KEY),
    };
  } catch {
    return null;
  }
}

function persist(result: SystemAnalysisResult, sources: string[]) {
  try {
    localStorage.setItem(RESULT_KEY, JSON.stringify(result));
    localStorage.setItem(SOURCES_KEY, JSON.stringify(sources));
    localStorage.setItem(LAST_TS_KEY, result.timestamp);
  } catch { /* storage quota — ignore */ }
}

// ── Context shape ─────────────────────────────────────────────────────────────

interface AnalysisContextValue {
  result:       SystemAnalysisResult | null;
  sources:      string[];
  polling:      boolean;
  hasData:      boolean;
  saveAnalysis: (result: SystemAnalysisResult, sources: string[]) => void;
  clearStore:   () => void;
}

const AnalysisContext = createContext<AnalysisContextValue>({
  result:       null,
  sources:      [],
  polling:      false,
  hasData:      false,
  saveAnalysis: () => {},
  clearStore:   () => {},
});

// ── Merge helpers ─────────────────────────────────────────────────────────────

function _mergeCounts(
  a: Record<string, number>,
  b: Record<string, number>,
): Record<string, number> {
  const out: Record<string, number> = { ...a };
  for (const [k, v] of Object.entries(b)) out[k] = (out[k] ?? 0) + v;
  return out;
}

function _mergeHourly(
  a: Record<string, Record<string, number>>,
  b: Record<string, Record<string, number>>,
): Record<string, Record<string, number>> {
  const out: Record<string, Record<string, number>> = { ...a };
  for (const [hour, srcs] of Object.entries(b)) {
    out[hour] = _mergeCounts(out[hour] ?? {}, srcs);
  }
  return out;
}

// ── Provider ──────────────────────────────────────────────────────────────────

export const AnalysisProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // CRITICAL: use lazy initializers so localStorage is read SYNCHRONOUSLY
  // on the very first render. This ensures hasData is true from render #1
  // if data exists, preventing the Dashboard from showing the permission dialog.
  const [result,  setResult]  = useState<SystemAnalysisResult | null>(() => load()?.result  ?? null);
  const [sources, setSources] = useState<string[]>                   (() => load()?.sources ?? []);
  const [polling, setPolling] = useState(false);
  const timerRef  = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastTsRef = useRef<string | null>(load()?.lastTs ?? null);

  // ── Persist + state update ─────────────────────────────────────────────────
  const saveAnalysis = useCallback((r: SystemAnalysisResult, s: string[]) => {
    setResult(r);
    setSources(s);
    lastTsRef.current = r.timestamp;
    persist(r, s);
  }, []);

  // ── Background polling — starts whenever sources array is set ─────────────
  useEffect(() => {
    if (sources.length === 0) return;

    if (timerRef.current) clearInterval(timerRef.current);

    timerRef.current = setInterval(async () => {
      try {
        setPolling(true);
        // Pass `since` so only NEW events (after last fetch) are returned
        const since = lastTsRef.current ?? undefined;
        const fresh = await collectAndAnalyze(sources, 0, since);

        // Record new high-water timestamp immediately
        lastTsRef.current = fresh.timestamp;

        setResult(prev => {
          if (!prev) {
            persist(fresh, sources);
            return fresh;
          }

          // Merge: prepend genuinely new entries (deduplicate by raw_log)
          const seen = new Set(prev.results.map(r => r.raw_log));
          const newEntries = fresh.results.filter(r => !seen.has(r.raw_log));

          // Accumulate running totals
          const merged: SystemAnalysisResult = {
            ...fresh,
            // Carry forward running totals so numbers grow over time
            total_collected: prev.total_collected + fresh.total_collected,
            total_threats:   prev.total_threats   + fresh.total_threats,
            total_normal:    prev.total_normal    + fresh.total_normal,
            // Merge summary counts
            summary: {
              by_threat_type: _mergeCounts(prev.summary.by_threat_type, fresh.summary.by_threat_type),
              by_severity:    _mergeCounts(prev.summary.by_severity,    fresh.summary.by_severity),
              by_source:      _mergeCounts(prev.summary.by_source,      fresh.summary.by_source),
            },
            // Merge hourly volume buckets
            hourly_volume: _mergeHourly(prev.hourly_volume, fresh.hourly_volume),
            // Prepend new entries, keep up to 5000 in history
            results: [...newEntries, ...prev.results].slice(0, 5000),
            threat_rate: fresh.threat_rate,
            timestamp:   fresh.timestamp,
          };
          persist(merged, sources);
          return merged;
        });
      } catch {
        // keep existing data on error — don't reset lastTsRef
      } finally {
        setPolling(false);
      }
    }, POLL_MS);

    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [sources]);

  // ── Clear ──────────────────────────────────────────────────────────────────
  const clearStore = useCallback(() => {
    localStorage.removeItem(RESULT_KEY);
    localStorage.removeItem(SOURCES_KEY);
    localStorage.removeItem(LAST_TS_KEY);
    lastTsRef.current = null;
    setResult(null);
    setSources([]);
    if (timerRef.current) clearInterval(timerRef.current);
  }, []);

  return (
    <AnalysisContext.Provider value={{
      result,
      sources,
      polling,
      hasData: result !== null,
      saveAnalysis,
      clearStore,
    }}>
      {children}
    </AnalysisContext.Provider>
  );
};

// ── Consumer hook ─────────────────────────────────────────────────────────────
export const useAnalysis = () => useContext(AnalysisContext);
