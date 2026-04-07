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
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.model_service import get_model
from app.services.log_normalizer import normalize_windows_event, normalize_syslog

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/system", tags=["System Log Collection"])

IS_WINDOWS = platform.system() == "Windows"
_INITIAL_HOURS_BACK = 24        # initial load: last 24 hours of events
_WEVTUTIL_TIMEOUT   = 120       # seconds — allow large log reads


# ── Request / Response models ─────────────────────────────────────────────────

class CollectRequest(BaseModel):
    sources:    List[str]           # e.g. ["windows_security", "windows_system", "syslog_auth"]
    max_events: Optional[int] = 0  # 0 = unlimited; >0 = hard cap per source
    since:      Optional[str] = None  # ISO-8601 UTC timestamp — only return events after this
    hours_back: Optional[int] = None  # if no `since`, look back N hours (default 24)


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
        # ── Standard Windows event channels ────────────────────────────────────
        for channel, label, source_id in [
            ("Security",    "Windows Security Events (auth, privilege, account changes)", "windows_security"),
            ("System",      "Windows System Events (services, drivers, OS errors)",       "windows_system"),
            ("Application", "Windows Application Events (app crashes, service starts)",   "windows_application"),
            ("Microsoft-Windows-NetworkProfile/Operational",
             "Windows Network Profile Events (Wi-Fi / LAN connect/disconnect)",           "windows_network"),
            ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
             "Windows Firewall Events (allowed/blocked rules)",                           "windows_firewall"),
        ]:
            if _windows_channel_available(channel):
                available.append({
                    "id":          source_id,
                    "label":       label,
                    "channel":     channel,
                    "platform":    "windows",
                    "event_count": _windows_channel_count(channel),
                })

        # ── Network activity source (WFP events 5156/5157 → netstat fallback) ─
        net_count = _windows_channel_count("Security")
        available.append({
            "id":          "network",
            "label":       "Network Connections (WFP allow/block events, TCP/UDP flows, firewall log)",
            "platform":    "windows",
            "event_count": net_count,
        })

        # ── Windows syslog-equivalent (LogFiles + IIS + Application events) ───
        log_files = _find_windows_log_files()
        available.append({
            "id":          "syslog_windows",
            "label":       f"Windows Service Logs (syslog-style: IIS, DHCP, DNS, App events — {len(log_files)} log files found)",
            "platform":    "windows",
            "event_count": len(log_files) * 50,   # rough estimate
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

    cap = req.max_events or 0  # 0 = unlimited

    # Resolve the `since` UTC timestamp (ISO-8601 string for wevtutil XPath)
    since_utc: Optional[str] = req.since
    if not since_utc:
        hours = req.hours_back if req.hours_back is not None else _INITIAL_HOURS_BACK
        since_dt = datetime.now(timezone.utc) - timedelta(hours=hours)
        since_utc = since_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Always ensure network + syslog sources are collected on Windows
    # regardless of what the frontend cached in localStorage
    sources = list(req.sources)
    if IS_WINDOWS:
        if "network" not in sources:
            sources.append("network")
        if "syslog_windows" not in sources:
            sources.append("syslog_windows")

    collected: List[dict] = []   # {"source": str, "raw": str, "event_dict": dict|None}

    for source_id in sources:
        try:
            events = _collect_source(source_id, cap, since_utc)
            collected.extend(events)
            logger.info("[collect] %s → %d events", source_id, len(events))
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

    # Event IDs that are routine Windows operational noise — always NORMAL
    _FORCED_NORMAL_IDS = {247, 2051, 2010}

    # Build results
    results: List[dict] = []
    for item, norm_line, pred in zip(collected, normalized_lines, predictions):
        event_id = (item.get("event_dict") or {}).get("EventID", 0)
        if event_id in _FORCED_NORMAL_IDS:
            entry_pred = {
                "threat_type":         "NORMAL",
                "severity":            "none",
                "confidence":          pred["confidence"],
                "is_threat":           False,
                "remediation_actions": [],
                "top_signals":         pred["top_signals"],
            }
        else:
            entry_pred = pred
        results.append({
            "log_source":          item["source"],
            "raw_log":             item["raw"][:400],
            "normalized":          norm_line[:400],
            "event_id":            event_id,
            "threat_type":         entry_pred["threat_type"],
            "severity":            entry_pred["severity"],
            "confidence":          round(entry_pred["confidence"], 4),
            "is_threat":           entry_pred["is_threat"],
            "remediation_actions": entry_pred["remediation_actions"],
            "top_signals":         dict(entry_pred["top_signals"]),
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
        "timestamp":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }


# ── Source collectors ─────────────────────────────────────────────────────────

def _collect_source(source_id: str, cap: int, since_utc: Optional[str] = None) -> List[dict]:
    """Dispatch to the right collector based on source_id."""

    # ── Windows event channels ─────────────────────────────────────────────────
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
        return _collect_windows_events(channel, cap, since_utc)

    # ── Network activity (WFP events → firewall log → netstat) ────────────────
    if source_id == "network":
        return _collect_network_windows(cap, since_utc)

    # ── Syslog: Windows log files + Application event log ─────────────────────
    if source_id == "syslog_windows":
        return _collect_windows_syslog(cap, since_utc)

    # ── Linux syslog ──────────────────────────────────────────────────────────
    if source_id.startswith("syslog_"):
        stem = source_id.replace("syslog_", "")
        candidates = [
            f"/var/log/{stem}.log",
            f"/var/log/{stem}",
            f"/var/log/auth.log",
            f"/var/log/syslog",
        ]
        for p in candidates:
            if Path(p).exists():
                return _collect_syslog_file(p, source_id, cap, since_utc)

    raise ValueError(f"Unknown or unavailable source: {source_id}")


# ── Windows Event Log collector ───────────────────────────────────────────────

def _collect_windows_events(channel: str, cap: int, since_utc: Optional[str] = None) -> List[dict]:
    """
    Read Windows Event Log entries via wevtutil.
    Uses XPath time-filter so only events after `since_utc` are returned.
    Falls back to win32evtlog if wevtutil fails.
    """
    try:
        return _collect_via_wevtutil(channel, cap, since_utc)
    except Exception as e:
        logger.warning("[system] wevtutil failed (%s), trying win32evtlog: %s", channel, e)
    try:
        return _collect_via_win32evtlog(channel, cap)
    except Exception as e2:
        logger.error("[system] win32evtlog also failed for %s: %s", channel, e2)
        return []


def _collect_via_wevtutil(channel: str, cap: int, since_utc: Optional[str] = None) -> List[dict]:
    """
    Use wevtutil to export Windows Event Log entries as XML.
    When `since_utc` is provided, an XPath time-filter is injected so only
    new events (after that timestamp) are returned — enabling true delta polling.
    When `cap` > 0, a /c: count limit is also applied.
    """
    cmd = ["wevtutil", "qe", channel, "/rd:true", "/f:xml"]

    if since_utc:
        # XPath 1.0 predicate accepted by wevtutil
        xpath = f"*[System[TimeCreated[@SystemTime>='{since_utc}']]]"
        cmd += [f"/q:{xpath}"]
    if cap > 0:
        cmd += [f"/c:{cap}"]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_WEVTUTIL_TIMEOUT,
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

            keywords_decoded = _decode_keywords(keywords)

            event_dict = {
                "EventID":     event_id,
                "Source":      source,
                "Computer":    computer,
                "TimeCreated": time_str,
                "Level":       level_str,
                "Keywords":    keywords_decoded,
                "UserData":    user_data,
            }

            # Fully-detailed raw log — every field, human-readable
            from app.services.log_normalizer import WINDOWS_EVENT_LABELS
            event_label = WINDOWS_EVENT_LABELS.get(event_id, f"event_{event_id}")
            ts_readable  = time_str[:19].replace("T", " ") if time_str else "unknown_time"
            kv_str = "  ".join(f"{k}={v}" for k, v in user_data.items() if v and v not in {"-","N/A","n/a","null","NULL",""})
            raw = (
                f"[{ts_readable}] {source}[{event_id}:{event_label}]"
                f" host={computer}"
                f" level={level_str}"
                f" keywords={keywords_decoded}"
                + (f"  {kv_str}" if kv_str else "")
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


# ── Windows network activity collector ───────────────────────────────────────

# Port → service name (for netstat enrichment)
_PORT_SVC = {
    "20": "ftp-data", "21": "ftp", "22": "ssh", "23": "telnet",
    "25": "smtp", "53": "dns", "67": "dhcp", "80": "http",
    "110": "pop3", "143": "imap", "443": "https", "445": "smb",
    "3306": "mysql", "3389": "rdp", "5432": "postgres",
    "5900": "vnc", "6379": "redis", "8080": "http-alt",
    "8443": "https-alt", "27017": "mongodb", "1433": "mssql",
}


def _build_pid_map() -> dict:
    """Return {pid_str: process_name} from tasklist."""
    pid_map: dict = {}
    try:
        proc = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        for line in proc.stdout.splitlines():
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2:
                pid_map[parts[1].strip()] = parts[0].strip()
    except Exception:
        pass
    return pid_map


def _collect_network_windows(cap: int, since_utc: Optional[str] = None) -> List[dict]:
    """
    Collect real Windows network activity.

    Layer 1 — NetworkProfile/Operational event log  (network connect/disconnect, SSID, type)
    Layer 2 — PowerShell/Operational network-related events
    Layer 3 — netstat -ano with process name resolution via tasklist
               covers all TCP/UDP connections: ESTABLISHED, LISTENING, TIME_WAIT, etc.
    All layers combined into a single 'network' source.
    """
    results: List[dict] = []
    hostname = platform.node()
    now_str  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    # ── Layer 1: NetworkProfile events (EventID 10000/10001 = connect/disconnect) ──
    try:
        channel = "Microsoft-Windows-NetworkProfile/Operational"
        cmd = ["wevtutil", "qe", channel, "/rd:true", "/f:xml"]
        if since_utc:
            cmd += [f"/q:*[System[TimeCreated[@SystemTime>='{since_utc}']]]"]
        if cap > 0:
            cmd += [f"/c:{min(cap, 200)}"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                              creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0)
        if proc.returncode == 0 and proc.stdout.strip():
            parsed = _parse_wevtutil_xml(proc.stdout, channel)
            for item in parsed:
                item["source"] = "network"
            results.extend(parsed)
            logger.info("[network] NetworkProfile events: %d", len(parsed))
    except Exception as exc:
        logger.debug("[network] NetworkProfile unavailable: %s", exc)

    # ── Layer 2: PowerShell network-related events ─────────────────────────────
    try:
        channel = "Microsoft-Windows-PowerShell/Operational"
        cmd = ["wevtutil", "qe", channel, "/rd:true", "/f:xml"]
        if since_utc:
            cmd += [f"/q:*[System[TimeCreated[@SystemTime>='{since_utc}']]]"]
        if cap > 0:
            cmd += [f"/c:{min(cap, 100)}"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                              creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0)
        if proc.returncode == 0 and proc.stdout.strip():
            parsed = _parse_wevtutil_xml(proc.stdout, channel)
            for item in parsed:
                item["source"] = "network"
            results.extend(parsed)
            logger.info("[network] PowerShell events: %d", len(parsed))
    except Exception as exc:
        logger.debug("[network] PowerShell log unavailable: %s", exc)

    # ── Layer 3: netstat -ano with process name enrichment ────────────────────
    # Always run — gives real TCP/UDP connection table (ESTABLISHED + LISTENING)
    pid_map = _build_pid_map()
    try:
        proc = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        netstat_results: List[dict] = []
        seen_conns: set = set()

        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if not parts or parts[0] not in ("TCP", "UDP"):
                continue
            if len(parts) < 4:
                continue

            proto  = parts[0]
            local  = parts[1]
            remote = parts[2] if len(parts) > 2 else "*:*"
            state  = parts[3] if len(parts) > 3 and proto == "TCP" else ("active" if proto == "UDP" else "")
            pid    = parts[4] if len(parts) > 4 else (parts[3] if proto == "UDP" and len(parts) > 3 else "0")

            # Deduplicate
            dedup_key = f"{proto}:{local}:{remote}:{state}"
            if dedup_key in seen_conns:
                continue
            seen_conns.add(dedup_key)

            # Parse addresses
            src_split = local.rsplit(":", 1)
            src_ip    = src_split[0].strip("[]") if src_split else local
            src_port  = src_split[1] if len(src_split) > 1 else "0"

            if remote in ("*:*", ""):
                dst_ip, dst_port = "*", "*"
            else:
                dst_split = remote.rsplit(":", 1)
                dst_ip    = dst_split[0].strip("[]") if dst_split else remote
                dst_port  = dst_split[1] if len(dst_split) > 1 else "0"

            proc_name = pid_map.get(pid.strip(), "unknown")
            service   = _PORT_SVC.get(dst_port, _PORT_SVC.get(src_port, "other"))

            # Classify connection type for model signal
            conn_type = "network_connection_allowed"
            if state == "LISTENING":
                conn_type = "network_port_listening"
            elif state in ("TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT_2"):
                conn_type = "network_connection_closing"

            user_data = {
                "SourceAddress": src_ip,
                "SourcePort":    src_port,
                "DestAddress":   dst_ip,
                "DestPort":      dst_port,
                "Protocol":      proto.lower(),
                "State":         state,
                "ProcessID":     pid.strip(),
                "Application":   proc_name,
                "Service":       service,
            }

            event_dict = {
                "EventID":     5156,
                "Source":      "netstat",
                "Computer":    hostname,
                "TimeCreated": now_str,
                "Level":       "Information",
                "Keywords":    f"{state} {proto.lower()} {service}",
                "UserData":    user_data,
            }

            raw = (
                f"[{now_str}] netstat[5156:{conn_type}]"
                f" host={hostname} level=Information"
                f" keywords={state} {proto.lower()} {service}"
                f"  SourceAddress={src_ip}  SourcePort={src_port}"
                f"  DestAddress={dst_ip}  DestPort={dst_port}"
                f"  Protocol={proto.lower()}  State={state}"
                f"  ProcessID={pid.strip()}  Application={proc_name}  Service={service}"
            )
            netstat_results.append({"source": "network", "raw": raw, "event_dict": event_dict})

        # Cap netstat at 500 entries max to keep model inference fast
        results.extend(netstat_results[:500])
        logger.info("[network] netstat connections: %d (capped at 500)", len(netstat_results))

    except Exception as exc:
        logger.warning("[network] netstat failed: %s", exc)

    if cap > 0:
        results = results[:cap]
    return results


# ── Windows syslog-equivalent collector ──────────────────────────────────────

def _collect_windows_syslog(cap: int, since_utc: Optional[str] = None) -> List[dict]:
    """
    Collect syslog-style entries from Windows.

    Priority:
      1. Real .log files from Windows LogFiles directories and common service paths
         (IIS, DHCP, DNS, nxlog, rsyslog-for-Windows, etc.)
      2. Windows Application event log formatted as syslog-style text lines.
    """
    results: List[dict] = []
    sysroot  = os.environ.get("SystemRoot", r"C:\Windows")
    hostname = platform.node()

    # Search for actual log files in known Windows locations
    search_dirs = [
        Path(sysroot) / "System32" / "LogFiles",
        Path(r"C:\inetpub\logs\LogFiles"),
        Path(r"C:\ProgramData"),
        Path(r"C:\Program Files (x86)\nxlog\data"),
        Path(r"C:\Program Files\rsyslog"),
    ]
    import itertools
    found_files: List[Path] = []
    for d in search_dirs:
        if not d.exists():
            continue
        try:
            if d == Path(r"C:\ProgramData"):
                # Shallow 2-level scan — avoids the deep Microsoft/Windows subtrees
                try:
                    subs = list(d.iterdir())
                except (PermissionError, OSError):
                    subs = []
                for sub in subs:
                    if not sub.is_dir():
                        continue
                    try:
                        found_files.extend(sub.glob("*.log"))
                    except (PermissionError, OSError):
                        pass
                    try:
                        for subsub in sub.iterdir():
                            if subsub.is_dir():
                                try:
                                    found_files.extend(subsub.glob("*.log"))
                                except (PermissionError, OSError):
                                    pass
                    except (PermissionError, OSError):
                        pass
                    if len(found_files) >= 30:
                        break
            else:
                found_files.extend(itertools.islice(d.rglob("*.log"), 8))
        except (PermissionError, OSError):
            continue

    for log_file in found_files:
        if cap > 0 and len(results) >= cap:
            break
        per_file_cap = max(1, (cap // max(len(found_files), 1))) if cap > 0 else 200
        try:
            entries = _collect_syslog_file(str(log_file), "syslog_windows", per_file_cap, since_utc)
            results.extend(entries)
        except Exception:
            continue

    # Always supplement with Windows Application + PowerShell event logs as syslog-equivalents
    # These are always available on Windows and provide real service/app activity
    for evtchannel, evtcap in [
        ("Application",                               cap or 200),
        ("Microsoft-Windows-PowerShell/Operational",  cap or 100),
        ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", cap or 50),
    ]:
        try:
            app_events = _collect_windows_events(evtchannel, evtcap, since_utc)
            for ev in app_events:
                ev["source"] = "syslog_windows"
                ed  = ev.get("event_dict") or {}
                ud  = ed.get("UserData", {})
                ts  = (ed.get("TimeCreated") or now_iso())[:19].replace("T", " ")
                src = ed.get("Source", evtchannel.split("/")[0])
                eid = ed.get("EventID", 0)
                lvl = ed.get("Level", "Information")
                kws = ed.get("Keywords", "")
                kv  = "  ".join(f"{k}={v}" for k, v in ud.items() if v and v not in {"-", "N/A", "null", ""})
                ev["raw"] = (
                    f"{ts} {hostname} {src}[{eid}]:"
                    f" {lvl}{f' {kws}' if kws else ''}"
                    + (f"  {kv}" if kv else "")
                )
            results.extend(app_events)
            logger.info("[syslog_windows] %s events: %d", evtchannel, len(app_events))
        except Exception as exc:
            logger.debug("[syslog_windows] %s fallback failed: %s", evtchannel, exc)

    return results[:cap] if cap > 0 else results


def _find_windows_log_files() -> List[Path]:
    """Enumerate accessible .log files in common Windows log directories."""
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    search_dirs = [
        Path(sysroot) / "System32" / "LogFiles",
        Path(r"C:\inetpub\logs\LogFiles"),
    ]
    files: List[Path] = []
    for d in search_dirs:
        if d.exists():
            try:
                files.extend(list(d.rglob("*.log"))[:20])
            except PermissionError:
                pass
    return files


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


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

def _collect_syslog_file(path: str, source_id: str, cap: int, since_utc: Optional[str] = None) -> List[dict]:
    """
    Read syslog lines, optionally filtering to only lines newer than `since_utc`.
    When `since_utc` is provided, all lines are read and those with a parseable
    timestamp after `since_utc` are kept. Otherwise, the last `cap` lines are used.
    """
    # Parse since_utc to a comparable datetime (UTC)
    since_dt: Optional[datetime] = None
    if since_utc:
        try:
            since_dt = datetime.fromisoformat(since_utc.replace("Z", "+00:00"))
        except ValueError:
            pass

    if since_dt:
        # Read entire file and filter by timestamp
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                all_lines = [l.rstrip() for l in fh if l.strip()]
        except Exception:
            all_lines = []
        lines = _filter_syslog_since(all_lines, since_dt)
    else:
        # Read file directly with Python (cross-platform, no `tail` dependency)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                all_lines = [l.strip() for l in fh if l.strip()]
            lines = all_lines[-cap:] if cap > 0 else all_lines
        except Exception:
            lines = []

    # Always respect the cap — the since_dt branch may return too many lines
    if cap > 0:
        lines = lines[-cap:]
    return [{"source": source_id, "raw": line, "event_dict": None} for line in lines]


def _filter_syslog_since(lines: List[str], since_dt: datetime) -> List[str]:
    """
    Return only syslog lines whose leading timestamp is >= since_dt.
    Handles both traditional format (Jan  1 12:00:00) and ISO-8601.
    Lines without a parseable timestamp are always included (safe default).
    """
    current_year = datetime.now().year
    out: List[str] = []
    for line in lines:
        ts = _parse_syslog_ts(line, current_year)
        if ts is None or ts >= since_dt:
            out.append(line)
    return out


def _parse_syslog_ts(line: str, year: int) -> Optional[datetime]:
    """Try to extract a UTC datetime from the start of a syslog line."""
    # ISO-8601: 2024-01-15T12:00:00...
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            return datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    # Traditional: Jan  1 12:00:00 or Jan 01 12:00:00
    m2 = re.match(r"([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})", line)
    if m2:
        try:
            ts_str = f"{m2.group(1)} {m2.group(2).zfill(2)} {m2.group(3)} {year}"
            return datetime.strptime(ts_str, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


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
