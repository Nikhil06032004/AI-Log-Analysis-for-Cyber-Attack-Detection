"""
ingest_routes.py — Log ingestion endpoints for Windows Event Logs,
network flows, and raw syslog lines.

Endpoints:
  POST /api/ingest/windows   — Windows Event Log JSON array
  POST /api/ingest/network   — Network flow JSON array or NSL-KDD CSV text
  POST /api/ingest/syslog    — Raw syslog text lines
  GET  /api/ingest/stats     — Cumulative ingestion statistics

All endpoints normalise incoming data, run UpgradedAMIDES predictions,
and trigger remediation for high/critical threats.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel

from app.services.model_service import get_model
from app.services.log_normalizer import (
    normalize_windows_event,
    normalize_network_flow,
    normalize_syslog,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ingest", tags=["Log Ingestion"])

# ── Cumulative stats (reset on server restart) ────────────────────────────────

_stats: Dict[str, int] = {
    "windows": 0,
    "network": 0,
    "syslog":  0,
    "threats": 0,
}

_MAX_BATCH = 5_000   # max events per request for windows / network
_MAX_LINES = 10_000  # max lines per request for syslog / csv


# ── Pydantic models ───────────────────────────────────────────────────────────

class WindowsEvent(BaseModel):
    """
    A single Windows Event Log entry.
    All fields are optional — only EventID is strongly recommended.
    """
    EventID:     int
    Source:      Optional[str] = "Windows"
    Computer:    Optional[str] = ""
    TimeCreated: Optional[str] = ""
    Level:       Optional[str] = "Information"
    Message:     Optional[str] = ""
    Keywords:    Optional[str] = ""
    UserData:    Optional[Dict[str, Any]] = {}
    EventData:   Optional[Dict[str, Any]] = {}   # alias used by some parsers

    model_config = {"extra": "allow"}


class NetworkFlow(BaseModel):
    """
    A single network flow entry.  Accepts both custom field names (src_ip,
    dst_ip, …) and native NSL-KDD column names (protocol_type, flag, …).
    """
    src_ip:    Optional[str]   = ""
    dst_ip:    Optional[str]   = ""
    src_port:  Optional[int]   = 0
    dst_port:  Optional[int]   = 0
    protocol:  Optional[str]   = "tcp"
    src_bytes: Optional[int]   = 0
    dst_bytes: Optional[int]   = 0
    duration:  Optional[float] = 0.0
    flags:     Optional[str]   = "SF"
    service:   Optional[str]   = ""
    logged_in: Optional[int]   = 0

    model_config = {"extra": "allow"}   # allow NSL-KDD passthrough fields


# ── Internal helpers ──────────────────────────────────────────────────────────

def _run_remediation(lines: list, predictions: list) -> None:
    """Trigger RemediationEngine for high/critical threats (non-blocking)."""
    try:
        from app.services.remediation import RemediationEngine
        engine = RemediationEngine()
        for log_line, result in zip(lines, predictions):
            if result.get("severity") in ("high", "critical"):
                engine.execute(result["remediation_actions"], log_line, result)
    except Exception as exc:
        logger.warning("[ingest] Remediation error (non-fatal): %s", exc)


def _require_model():
    """Return model or raise HTTP 503."""
    try:
        return get_model()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=f"ML model unavailable: {exc}")


def _prediction_dict(i: int, line: str, pred: dict) -> dict:
    """Build a standard prediction result dict."""
    return {
        "event_index":         i,
        "normalized_line":     line[:300],
        "threat_type":         pred["threat_type"],
        "severity":            pred["severity"],
        "confidence":          round(pred["confidence"], 4),
        "is_threat":           pred["is_threat"],
        "remediation_actions": pred["remediation_actions"],
        "top_signals":         dict(pred["top_signals"]),
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/windows")
async def ingest_windows_logs(events: List[WindowsEvent] = Body(...)):
    """
    Analyse Windows Event Log entries for cyber threats.

    Accepts a JSON array of Windows Event Log objects and returns an
    ML prediction for every event.

    **Example request body:**
    ```json
    [
      {
        "EventID": 4625,
        "Source": "Microsoft-Windows-Security-Auditing",
        "Computer": "WORKSTATION-01",
        "Level": "Warning",
        "Message": "An account failed to log on.",
        "Keywords": "Audit Failure",
        "UserData": {
          "TargetUserName": "administrator",
          "IpAddress": "192.168.1.100",
          "LogonType": "3"
        }
      }
    ]
    ```

    **Key EventIDs and their attack mapping:**
    | EventID | Meaning              | Likely Threat      |
    |---------|----------------------|--------------------|
    | 4625    | Failed logon         | BRUTE_FORCE        |
    | 4688    | Process created      | MALWARE            |
    | 4697    | Service installed    | MALWARE            |
    | 4698    | Scheduled task       | MALWARE            |
    | 4672    | Privilege assigned   | MALWARE            |
    | 1102    | Audit log cleared    | LOG_EVASION        |
    | 4657    | Registry modified    | MALWARE            |
    | 7045    | New service          | MALWARE            |
    """
    if not events:
        raise HTTPException(status_code=400, detail="No events provided.")
    if len(events) > _MAX_BATCH:
        raise HTTPException(
            status_code=400,
            detail=f"Too many events ({len(events)}). Maximum is {_MAX_BATCH}.",
        )

    model = _require_model()

    normalized = [normalize_windows_event(e.model_dump()) for e in events]
    predictions = model.predict_batch(normalized)
    _run_remediation(normalized, predictions)

    threats_found = sum(1 for r in predictions if r["is_threat"])
    _stats["windows"] += len(events)
    _stats["threats"] += threats_found

    results = []
    for i, (event, line, pred) in enumerate(zip(events, normalized, predictions)):
        entry = _prediction_dict(i, line, pred)
        entry["event_id"]    = event.EventID
        entry["computer"]    = event.Computer or ""
        entry["time_created"] = event.TimeCreated or ""
        results.append(entry)

    return {
        "status":        "success",
        "source":        "windows_event_log",
        "total_events":  len(events),
        "threats_found": threats_found,
        "results":       results,
        "timestamp":     datetime.now().isoformat(),
    }


@router.post("/network")
async def ingest_network_logs(payload: dict = Body(...)):
    """
    Analyse network flow logs for cyber threats.

    Accepts one of:

    **Option A — JSON flow array:**
    ```json
    {
      "flows": [
        {
          "src_ip": "192.168.1.100",
          "dst_ip": "10.0.0.1",
          "src_port": 54321,
          "dst_port": 22,
          "protocol": "tcp",
          "src_bytes": 2048,
          "dst_bytes": 512,
          "duration": 5.3,
          "flags": "SF"
        }
      ]
    }
    ```

    **Option B — NSL-KDD CSV text:**
    ```json
    {
      "csv_text": "0,tcp,http,SF,215,45076,0,0,0,0,0,1,...\\n0,udp,domain_u,SF,..."
    }
    ```

    NSL-KDD flows with native column names (protocol_type, flag, etc.) are
    also accepted inside the `flows` array and routed directly to the
    model's numerical feature extractor.
    """
    flows_json = payload.get("flows", [])
    csv_text   = payload.get("csv_text", "")

    if not flows_json and not csv_text:
        raise HTTPException(
            status_code=400,
            detail="Provide either 'flows' (JSON array) or 'csv_text' (NSL-KDD CSV).",
        )

    model = _require_model()

    normalized: List[str] = []
    source_refs: List[dict] = []

    if flows_json:
        if len(flows_json) > _MAX_BATCH:
            raise HTTPException(
                status_code=400,
                detail=f"Too many flows ({len(flows_json)}). Maximum is {_MAX_BATCH}.",
            )
        for flow in flows_json:
            normalized.append(normalize_network_flow(flow))
            source_refs.append({
                "src_ip":   flow.get("src_ip", ""),
                "dst_ip":   flow.get("dst_ip", ""),
                "src_port": flow.get("src_port", 0),
                "dst_port": flow.get("dst_port", 0),
                "protocol": flow.get("protocol") or flow.get("protocol_type", ""),
            })
    else:
        raw_lines = [ln.strip() for ln in csv_text.splitlines() if ln.strip()]
        if len(raw_lines) > _MAX_LINES:
            raise HTTPException(
                status_code=400,
                detail=f"Too many CSV lines ({len(raw_lines)}). Maximum is {_MAX_LINES}.",
            )
        normalized   = raw_lines
        source_refs  = [{"csv_line": i + 1} for i in range(len(raw_lines))]

    predictions = model.predict_batch(normalized)
    _run_remediation(normalized, predictions)

    threats_found = sum(1 for r in predictions if r["is_threat"])
    _stats["network"] += len(normalized)
    _stats["threats"] += threats_found

    results = []
    for i, (ref, line, pred) in enumerate(zip(source_refs, normalized, predictions)):
        entry = _prediction_dict(i, line, pred)
        entry.update(ref)
        results.append(entry)

    return {
        "status":        "success",
        "source":        "network_flow",
        "total_events":  len(normalized),
        "threats_found": threats_found,
        "results":       results,
        "timestamp":     datetime.now().isoformat(),
    }


@router.post("/syslog")
async def ingest_syslog(payload: dict = Body(...)):
    """
    Analyse raw syslog lines for cyber threats.

    Accepts any syslog format (RFC 3164, RFC 5424, custom) as plain text lines.

    **Example request body:**
    ```json
    {
      "lines": [
        "Apr  3 14:32:07 host sshd[1234]: Failed password for root from 192.168.1.5 port 54321 ssh2",
        "Apr  3 14:32:09 host sshd[1234]: Failed password for root from 192.168.1.5 port 54322 ssh2",
        "Apr  3 14:32:11 host kernel: Firewall: IN=eth0 SRC=203.0.113.88 DST=10.0.0.1 PROTO=TCP DPT=22"
      ]
    }
    ```
    """
    lines_raw = payload.get("lines", [])
    if not lines_raw:
        raise HTTPException(
            status_code=400,
            detail="'lines' array is required and cannot be empty.",
        )
    if len(lines_raw) > _MAX_LINES:
        raise HTTPException(
            status_code=400,
            detail=f"Too many lines ({len(lines_raw)}). Maximum is {_MAX_LINES}.",
        )

    model = _require_model()

    normalized = [normalize_syslog(str(ln)) for ln in lines_raw if str(ln).strip()]
    if not normalized:
        raise HTTPException(status_code=400, detail="All provided lines were empty.")

    predictions = model.predict_batch(normalized)
    _run_remediation(normalized, predictions)

    threats_found = sum(1 for r in predictions if r["is_threat"])
    _stats["syslog"]  += len(normalized)
    _stats["threats"] += threats_found

    results = []
    for i, (line, pred) in enumerate(zip(normalized, predictions)):
        entry = _prediction_dict(i, line, pred)
        entry["line_number"] = i + 1
        results.append(entry)

    return {
        "status":        "success",
        "source":        "syslog",
        "total_lines":   len(normalized),
        "threats_found": threats_found,
        "results":       results,
        "timestamp":     datetime.now().isoformat(),
    }


@router.get("/stats")
def get_ingest_stats():
    """
    Return cumulative ingestion statistics since the server started.

    Useful for dashboards and health monitoring.
    """
    total = _stats["windows"] + _stats["network"] + _stats["syslog"]
    return {
        "status": "success",
        "stats": {
            "total_logs_processed":  total,
            "windows_events":        _stats["windows"],
            "network_flows":         _stats["network"],
            "syslog_lines":          _stats["syslog"],
            "total_threats_detected": _stats["threats"],
            "threat_rate": round(_stats["threats"] / total, 4) if total > 0 else 0.0,
        },
        "timestamp": datetime.now().isoformat(),
    }
