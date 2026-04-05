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

const RESULT_KEY  = "sentinel_result_v1";
const SOURCES_KEY = "sentinel_sources_v1";
const POLL_MS     = 5_000;   // poll every 5 seconds
const POLL_EVENTS = 200;     // events per background poll

// ── Helpers ───────────────────────────────────────────────────────────────────

function load(): { result: SystemAnalysisResult; sources: string[] } | null {
  try {
    const r = localStorage.getItem(RESULT_KEY);
    const s = localStorage.getItem(SOURCES_KEY);
    if (!r || !s) return null;
    return {
      result:  JSON.parse(r) as SystemAnalysisResult,
      sources: JSON.parse(s) as string[],
    };
  } catch {
    return null;
  }
}

function persist(result: SystemAnalysisResult, sources: string[]) {
  try {
    localStorage.setItem(RESULT_KEY, JSON.stringify(result));
    localStorage.setItem(SOURCES_KEY, JSON.stringify(sources));
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

// ── Provider ──────────────────────────────────────────────────────────────────

export const AnalysisProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // CRITICAL: use lazy initializers so localStorage is read SYNCHRONOUSLY
  // on the very first render. This ensures hasData is true from render #1
  // if data exists, preventing the Dashboard from showing the permission dialog.
  const [result,  setResult]  = useState<SystemAnalysisResult | null>(() => load()?.result  ?? null);
  const [sources, setSources] = useState<string[]>                   (() => load()?.sources ?? []);
  const [polling, setPolling] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Persist + state update ─────────────────────────────────────────────────
  const saveAnalysis = useCallback((r: SystemAnalysisResult, s: string[]) => {
    setResult(r);
    setSources(s);
    persist(r, s);
  }, []);

  // ── Background polling — starts whenever sources array is set ─────────────
  useEffect(() => {
    if (sources.length === 0) return;

    if (timerRef.current) clearInterval(timerRef.current);

    timerRef.current = setInterval(async () => {
      try {
        setPolling(true);
        const fresh = await collectAndAnalyze(sources, POLL_EVENTS);
        setResult(prev => {
          if (!prev) return fresh;
          // Keep fresh stats (total_collected etc.) from the latest backend response
          // so numbers always match what the backend actually processed.
          // Only accumulate the results list so history is preserved.
          const seen = new Set(prev.results.map(r => r.raw_log));
          const newEntries = fresh.results.filter(r => !seen.has(r.raw_log));
          const merged: SystemAnalysisResult = {
            ...fresh,                                                        // use fresh totals/stats
            results: [...newEntries, ...prev.results].slice(0, 1000),       // keep growing history
          };
          persist(merged, sources);
          return merged;
        });
      } catch {
        // keep existing data on error
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
