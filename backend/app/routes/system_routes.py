"""
system_routes.py — Collect actual system logs from the host machine,
feed them to UpgradedAMIDES, and return real predictions.

Endpoints:
  GET  /api/system/sources          — list available log sources on this host
  POST /api/system/collect-analyze  — collect logs from requested sources,
                                      run model, return predictions + stats

Log sources supported:
  Windows  : Security, System, Application event logs  (wevtutil / win32evtlog)
  Linux    : /var/log/auth.log, /var/log/syslog, /var/log/kern.log
  Cross-OS : any .log files in a user-supplied directory path
"""

import json
import logging
import platform
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.model_service import get_model
from app.services.log_normalizer import normalize_windows_event, normalize_syslog

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/system", tags=["System Log Collection"])

IS_WINDOWS = platform.system() == "Windows"
_MAX_EVENTS_PER_SOURCE = 500   # cap per channel — raised so totals stay consistent


# ── Request / Response models ─────────────────────────────────────────────────

class CollectRequest(BaseModel):
    sources: List[str]          # e.g. ["windows_security", "windows_system", "syslog_auth"]
    max_events: Optional[int] = 150   # per source


class PredictionEntry(BaseModel):
    log_source: str
    raw_log: str
    normalized: str
    threat_type: str
    severity: str
    confidence: float
    is_threat: bool
    remediation_actions: List[str]
    top_signals: dict


# ── Available sources discovery ───────────────────────────────────────────────

@router.get("/sources")
def get_available_sources():
    """
    Return all log sources that are accessible on this host machine.
    Used by the frontend to know what to request.
    """
    available: List[dict] = []

    if IS_WINDOWS:
        for channel, label, source_id in [
            ("Security",                                  "Windows Security Events (logins, auth, privilege)", "windows_security"),
            ("System",                                    "Windows System Events (services, drivers, crashes)", "windows_system"),
            ("Application",                               "Windows Application Events",                        "windows_application"),
            ("Microsoft-Windows-NetworkProfile/Operational", "Windows Network Events (connections, profiles)", "windows_network"),
            ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                                                          "Windows Firewall Events (blocked/allowed traffic)", "windows_firewall"),
        ]:
            if _windows_channel_available(channel):
                available.append({
                    "id":          source_id,
                    "label":       label,
                    "channel":     channel,
                    "platform":    "windows",
                    "event_count": _windows_channel_count(channel),
                })
    else:
        for path, label in [
            ("/var/log/auth.log",   "Linux Auth Log (SSH, sudo, PAM)"),
            ("/var/log/syslog",     "Linux Syslog"),
            ("/var/log/kern.log",   "Linux Kernel Log"),
            ("/var/log/secure",     "RHEL/CentOS Secure Log"),
            ("/var/log/messages",   "RHEL/CentOS Messages Log"),
        ]:
            if Path(path).exists():
                available.append({
                    "id":       f"syslog_{Path(path).stem}",
                    "label":    label,
                    "path":     path,
                    "platform": "linux",
                })

    return {
        "status":    "success",
        "platform":  platform.system(),
        "hostname":  platform.node(),
        "available": available,
        "timestamp": datetime.now().isoformat(),
    }


# ── Main collect-and-analyze endpoint ────────────────────────────────────────

@router.post("/collect-analyze")
def collect_and_analyze(req: CollectRequest):
    """
    1. Collect real log events from each requested source.
    2. Normalize each event into a model-compatible string.
    3. Run UpgradedAMIDES predictions.
    4. Return per-event results + summary statistics.
    """
    try:
        model = get_model()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=f"ML model unavailable: {exc}")

    cap = min(req.max_events or 150, _MAX_EVENTS_PER_SOURCE)

    collected: List[dict] = []   # {"source": str, "raw": str, "event_dict": dict|None}

    for source_id in req.sources:
        try:
            events = _collect_source(source_id, cap)
            collected.extend(events)
        except Exception as exc:
            logger.warning("[system] Failed to collect '%s': %s", source_id, exc)

    if not collected:
        raise HTTPException(
            status_code=404,
            detail="No log events could be collected from the requested sources. "
                   "The sources may be empty, inaccessible, or require elevated privileges.",
        )

    # Normalize
    normalized_lines: List[str] = []
    for item in collected:
        if item.get("event_dict"):
            normalized_lines.append(normalize_windows_event(item["event_dict"]))
        else:
            normalized_lines.append(normalize_syslog(item["raw"]))

    # Predict in batch
    predictions = model.predict_batch(normalized_lines)

    # Trigger remediation for high/critical (non-blocking)
    _run_remediation(normalized_lines, predictions)

    # Build results
    results: List[dict] = []
    for item, norm_line, pred in zip(collected, normalized_lines, predictions):
        results.append({
            "log_source":          item["source"],
            "raw_log":             item["raw"][:400],
            "normalized":          norm_line[:400],
            "threat_type":         pred["threat_type"],
            "severity":            pred["severity"],
            "confidence":          round(pred["confidence"], 4),
            "is_threat":           pred["is_threat"],
            "remediation_actions": pred["remediation_actions"],
            "top_signals":         dict(pred["top_signals"]),
        })

    threats     = [r for r in results if r["is_threat"]]
    normals     = [r for r in results if not r["is_threat"]]
    threat_type_counts: dict = {}
    severity_counts: dict    = {}
    source_counts: dict      = {}

    for r in results:
        threat_type_counts[r["threat_type"]] = threat_type_counts.get(r["threat_type"], 0) + 1
        severity_counts[r["severity"]]       = severity_counts.get(r["severity"], 0) + 1
        source_counts[r["log_source"]]       = source_counts.get(r["log_source"], 0) + 1

    # Per-source volume for the log-volume bar chart
    hourly_volume: dict = _build_hourly_volume(collected)

    return {
        "status":         "success",
        "platform":       platform.system(),
        "hostname":       platform.node(),
        "total_collected": len(collected),
        "total_threats":  len(threats),
        "total_normal":   len(normals),
        "threat_rate":    round(len(threats) / len(results), 4) if results else 0.0,
        "summary": {
            "by_threat_type": threat_type_counts,
            "by_severity":    severity_counts,
            "by_source":      source_counts,
        },
        "hourly_volume":  hourly_volume,
        "results":        results,
        "timestamp":      datetime.now().isoformat(),
    }


# ── Source collectors ─────────────────────────────────────────────────────────

def _collect_source(source_id: str, cap: int) -> List[dict]:
    """Dispatch to the right collector based on source_id."""
    if source_id.startswith("windows_"):
        channel_map = {
            "windows_security":    "Security",
            "windows_system":      "System",
            "windows_application": "Application",
            "windows_network":     "Microsoft-Windows-NetworkProfile/Operational",
            "windows_firewall":    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        }
        channel = channel_map.get(source_id)
        if not channel:
            raise ValueError(f"Unknown windows source: {source_id}")
        return _collect_windows_events(channel, cap)

    if source_id.startswith("syslog_"):
        stem = source_id.replace("syslog_", "")
        # find the matching file
        candidates = [
            f"/var/log/{stem}.log",
            f"/var/log/{stem}",
            f"/var/log/auth.log",
            f"/var/log/syslog",
        ]
        for p in candidates:
            if Path(p).exists():
                return _collect_syslog_file(p, source_id, cap)

    raise ValueError(f"Unknown or unavailable source: {source_id}")


# ── Windows Event Log collector ───────────────────────────────────────────────

def _collect_windows_events(channel: str, cap: int) -> List[dict]:
    """
    Read recent Windows Event Log entries via wevtutil (no extra dependencies).
    Falls back to win32evtlog if available.
    """
    try:
        return _collect_via_wevtutil(channel, cap)
    except Exception as e:
        logger.warning("[system] wevtutil failed (%s), trying win32evtlog: %s", channel, e)
    try:
        return _collect_via_win32evtlog(channel, cap)
    except Exception as e2:
        logger.error("[system] win32evtlog also failed for %s: %s", channel, e2)
        return []


def _collect_via_wevtutil(channel: str, cap: int) -> List[dict]:
    """
    Use wevtutil to export the last `cap` events from a channel as XML,
    then parse the minimal fields we need.
    """
    cmd = [
        "wevtutil", "qe", channel,
        f"/c:{cap}",
        "/rd:true",      # newest first
        "/f:xml",
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"wevtutil exit {proc.returncode}: {proc.stderr[:200]}")

    return _parse_wevtutil_xml(proc.stdout, channel)


def _parse_wevtutil_xml(xml_text: str, channel: str) -> List[dict]:
    """
    Minimal XML parse — no external dependency, just regex for the fields we need.
    """
    import xml.etree.ElementTree as ET

    results: List[dict] = []
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"

    # wevtutil returns multiple root-level <Event> elements — wrap them
    try:
        root = ET.fromstring(f"<Root>{xml_text}</Root>")
    except ET.ParseError:
        # fallback: try to extract individual events
        events_xml = re.findall(r"<Event[^>]*>.*?</Event>", xml_text, re.DOTALL)
        root_text  = "".join(events_xml)
        try:
            root = ET.fromstring(f"<Root>{root_text}</Root>")
        except ET.ParseError:
            return []

    for event_el in root.findall(f"{{{ns}}}Event"):
        try:
            sys_el  = event_el.find(f"{{{ns}}}System")
            if sys_el is None:
                continue
            event_id_el = sys_el.find(f"{{{ns}}}EventID")
            event_id    = int(event_id_el.text.strip()) if event_id_el is not None and event_id_el.text else 0
            provider    = sys_el.find(f"{{{ns}}}Provider")
            source      = provider.get("Name", channel) if provider is not None else channel
            computer_el = sys_el.find(f"{{{ns}}}Computer")
            computer    = computer_el.text if computer_el is not None and computer_el.text else ""
            time_el     = sys_el.find(f"{{{ns}}}TimeCreated")
            time_str    = time_el.get("SystemTime", "") if time_el is not None else ""
            level_el    = sys_el.find(f"{{{ns}}}Level")
            level_num   = int(level_el.text.strip()) if level_el is not None and level_el.text else 4
            level_str   = {1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}.get(level_num, "Information")
            keywords_el = sys_el.find(f"{{{ns}}}Keywords")
            keywords    = keywords_el.text if keywords_el is not None and keywords_el.text else ""

            # EventData key-value pairs
            user_data: dict = {}
            for parent_tag in [f"{{{ns}}}EventData", f"{{{ns}}}UserData"]:
                parent = event_el.find(parent_tag)
                if parent is not None:
                    for data in parent.iter():
                        name = data.get("Name", data.tag.split("}")[-1] if "}" in data.tag else data.tag)
                        if data.text and data.text.strip():
                            user_data[name] = data.text.strip()

            event_dict = {
                "EventID":     event_id,
                "Source":      source,
                "Computer":    computer,
                "TimeCreated": time_str,
                "Level":       level_str,
                "Keywords":    _decode_keywords(keywords),
                "UserData":    user_data,
            }

            raw = (
                f"{source}[{event_id}] {level_str} {time_str} {computer} "
                + " ".join(f"{k}={v}" for k, v in user_data.items())
            )

            # Map full channel name back to source_id
            _channel_to_id = {
                "security":    "windows_security",
                "system":      "windows_system",
                "application": "windows_application",
            }
            chan_lower = channel.lower().split("/")[0].strip()
            src_id = _channel_to_id.get(chan_lower)
            if not src_id:
                if "network" in chan_lower:
                    src_id = "windows_network"
                elif "firewall" in chan_lower:
                    src_id = "windows_firewall"
                else:
                    src_id = f"windows_{chan_lower.replace(' ', '_')}"

            results.append({
                "source":     src_id,
                "raw":        raw,
                "event_dict": event_dict,
            })
        except Exception as exc:
            logger.debug("[system] Failed to parse event: %s", exc)
            continue

    return results


def _decode_keywords(kw_hex: str) -> str:
    """Convert hex keyword bitmask to human-readable string."""
    try:
        kw_int = int(kw_hex, 16)
        if kw_int & 0x8010000000000000:
            return "Audit Failure"
        if kw_int & 0x8020000000000000:
            return "Audit Success"
    except (ValueError, TypeError):
        pass
    return kw_hex or ""


def _collect_via_win32evtlog(channel: str, cap: int) -> List[dict]:
    """Fallback: use pywin32 if installed."""
    import win32evtlog  # type: ignore
    import win32con      # type: ignore

    hand = win32evtlog.OpenEventLog(None, channel)
    flags = win32con.EVENTLOG_BACKWARDS_READ | win32con.EVENTLOG_SEQUENTIAL_READ

    results: List[dict] = []
    try:
        while len(results) < cap:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break
            for ev in events:
                if len(results) >= cap:
                    break
                raw = f"{channel}[{ev.EventID}] {ev.TimeGenerated} Category={ev.EventCategory}"
                results.append({
                    "source":     f"windows_{channel.lower()}",
                    "raw":        raw,
                    "event_dict": {
                        "EventID":     ev.EventID,
                        "Source":      ev.SourceName or channel,
                        "Computer":    ev.ComputerName or "",
                        "TimeCreated": str(ev.TimeGenerated),
                        "Level":       "Information",
                        "UserData":    {},
                    },
                })
    finally:
        win32evtlog.CloseEventLog(hand)

    return results


# ── Linux syslog collector ────────────────────────────────────────────────────

def _collect_syslog_file(path: str, source_id: str, cap: int) -> List[dict]:
    """Read the last `cap` non-empty lines from a syslog file."""
    try:
        # Use tail equivalent: read last N lines efficiently
        proc = subprocess.run(
            ["tail", "-n", str(cap), path],
            capture_output=True, text=True, timeout=10,
        )
        lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
    except Exception:
        # Pure Python fallback for systems without tail
        with open(path, encoding="utf-8", errors="replace") as fh:
            all_lines = [l.strip() for l in fh.readlines() if l.strip()]
        lines = all_lines[-cap:]

    return [{"source": source_id, "raw": line, "event_dict": None} for line in lines]


# ── Helper utilities ──────────────────────────────────────────────────────────

def _windows_channel_available(channel: str) -> bool:
    if not IS_WINDOWS:
        return False
    try:
        proc = subprocess.run(
            ["wevtutil", "gli", channel],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _windows_channel_count(channel: str) -> int:
    try:
        proc = subprocess.run(
            ["wevtutil", "gli", channel],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        m = re.search(r"numberOfLogRecords:\s*(\d+)", proc.stdout, re.IGNORECASE)
        return int(m.group(1)) if m else 0
    except Exception:
        return 0


def _build_hourly_volume(collected: List[dict]) -> dict:
    """
    Bucket collected events by hour for the log-volume bar chart.
    Returns {hour_label: {source_id: count}}.
    """
    from collections import defaultdict
    buckets: dict = defaultdict(lambda: defaultdict(int))
    for item in collected:
        hour_label = datetime.now().strftime("%H:00")  # default to now if no timestamp
        # try to extract timestamp from raw or event_dict
        if item.get("event_dict"):
            tc = item["event_dict"].get("TimeCreated", "")
            m  = re.search(r"(\d{2}):\d{2}:\d{2}", tc)
            if m:
                hour_label = f"{m.group(1)}:00"
        else:
            m = re.match(r"\w+\s+\d+\s+(\d{2}):\d{2}:\d{2}", item["raw"])
            if m:
                hour_label = f"{m.group(1)}:00"
        buckets[hour_label][item["source"]] += 1

    return {hour: dict(srcs) for hour, srcs in sorted(buckets.items())}


def _run_remediation(lines: list, predictions: list) -> None:
    try:
        from app.services.remediation import RemediationEngine
        engine = RemediationEngine()
        for log_line, result in zip(lines, predictions):
            if result.get("severity") in ("high", "critical"):
                engine.execute(result["remediation_actions"], log_line, result)
    except Exception as exc:
        logger.warning("[system] Remediation error (non-fatal): %s", exc)
