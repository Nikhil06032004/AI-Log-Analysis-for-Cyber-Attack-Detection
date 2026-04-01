"""
threat_routes.py — FastAPI routes for AI Log Threat Detection.

Static endpoints (preserved):
  GET  /api/threats          — static threat feed
  GET  /api/logs             — static log feed
  GET  /api/health           — health check

ML endpoints (new):
  GET  /api/status           — model load status
  POST /api/analyze          — upload .log / .csv file for bulk analysis
  POST /api/analyze/line     — analyze a single log line string
"""

import sys
import io
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, UploadFile, File, HTTPException, Body
from fastapi.responses import JSONResponse

# Add project root to sys.path so ml_engine is importable from the backend
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

MODEL_PATH = PROJECT_ROOT / 'ml_engine' / 'upgraded_amides.pkl'

# Lazy-loaded model singleton — loaded once on first ML request
_model = None
_model_load_error: str = ""


def _get_model():
    """Load and cache the UpgradedAMIDES model. Raises RuntimeError if unavailable."""
    global _model, _model_load_error
    if _model is not None:
        return _model
    if _model_load_error:
        raise RuntimeError(_model_load_error)
    try:
        from ml_engine.upgraded_amides import UpgradedAMIDES
        _model = UpgradedAMIDES.load(str(MODEL_PATH))
    except FileNotFoundError:
        _model_load_error = (
            f"Model file not found at {MODEL_PATH}. "
            "Run 'python ml_engine/train.py' to train and save the model."
        )
        raise RuntimeError(_model_load_error)
    except Exception as exc:
        _model_load_error = f"Failed to load model: {exc}"
        raise RuntimeError(_model_load_error)
    return _model


router = APIRouter(prefix="/api", tags=["Threat Detection"])

# ── Static data (legacy endpoints) ───────────────────────────────────────────

THREATS = [
    {
        "id": "THR-0041",
        "threatType": "Brute Force",
        "sourceIP": "192.168.4.21",
        "destinationIP": "10.0.0.5",
        "severity": "critical",
        "status": "active",
        "timestamp": "14:32:07",
        "description": "429 failed SSH login attempts detected from single source over 4 minutes. Lockout threshold exceeded.",
        "protocol": "SSH",
        "eventCount": 429,
        "confidence": 97,
    },
    {
        "id": "THR-0040",
        "threatType": "Port Scan",
        "sourceIP": "203.0.113.88",
        "destinationIP": "10.0.0.1",
        "severity": "high",
        "status": "investigating",
        "timestamp": "14:28:55",
        "description": "Systematic TCP SYN scan detected on 1,024 ports. Likely network reconnaissance phase.",
        "protocol": "TCP",
        "eventCount": 1024,
        "confidence": 91,
    },
    {
        "id": "THR-0039",
        "threatType": "Data Exfiltration",
        "sourceIP": "10.0.0.45",
        "destinationIP": "185.220.101.5",
        "severity": "critical",
        "status": "active",
        "timestamp": "14:15:30",
        "description": "Unusual outbound traffic spike: 2.3GB transferred to unknown external host over encrypted channel.",
        "protocol": "HTTPS",
        "eventCount": 156,
        "confidence": 88,
    },
    {
        "id": "THR-0038",
        "threatType": "SQL Injection",
        "sourceIP": "198.51.100.23",
        "destinationIP": "10.0.0.12",
        "severity": "high",
        "status": "resolved",
        "timestamp": "13:52:11",
        "description": "Malicious SQL payload detected in POST request. Classic UNION-based injection attempt on /api/login.",
        "protocol": "HTTP",
        "eventCount": 7,
        "confidence": 99,
    },
    {
        "id": "THR-0037",
        "threatType": "Privilege Escalation",
        "sourceIP": "10.0.0.78",
        "destinationIP": "10.0.0.1",
        "severity": "medium",
        "status": "investigating",
        "timestamp": "13:40:02",
        "description": "Internal user attempted to access root-level resources without authorization. SUDO abuse pattern detected.",
        "protocol": "Internal",
        "eventCount": 12,
        "confidence": 76,
    },
    {
        "id": "THR-0036",
        "threatType": "Phishing",
        "sourceIP": "mail.evil-domain.ru",
        "destinationIP": "10.0.0.55",
        "severity": "medium",
        "status": "pending",
        "timestamp": "13:25:44",
        "description": "Email with malicious URL detected. Domain registered 2 days ago. Spoofed sender identity.",
        "protocol": "SMTP",
        "eventCount": 3,
        "confidence": 82,
    },
]

LOGS = [
    {"id": "L001", "time": "14:32:07", "level": "CRITICAL", "source": "auth-service",   "message": "Multiple failed login attempts — IP 192.168.4.21 blocked"},
    {"id": "L002", "time": "14:31:55", "level": "ERROR",    "source": "firewall",        "message": "Outbound connection to blacklisted IP 185.220.101.5 blocked"},
    {"id": "L003", "time": "14:30:12", "level": "WARN",     "source": "ids-engine",      "message": "Port scan detected from 203.0.113.88 — 1024 ports probed"},
    {"id": "L004", "time": "14:28:40", "level": "INFO",     "source": "siem-core",       "message": "DNN model retrain completed — accuracy: 96.4%"},
    {"id": "L005", "time": "14:27:03", "level": "WARN",     "source": "network-monitor", "message": "Unusual bandwidth spike: 2.3GB outbound in 8 min"},
    {"id": "L006", "time": "14:25:19", "level": "ERROR",    "source": "web-server",      "message": "SQL injection attempt blocked on endpoint /api/login"},
    {"id": "L007", "time": "14:22:55", "level": "INFO",     "source": "ansible-agent",   "message": "Log collection completed from 4 VMs (Ubuntu/Windows)"},
    {"id": "L008", "time": "14:20:10", "level": "INFO",     "source": "elasticsearch",   "message": "Index optimized — 1.2M documents indexed successfully"},
    {"id": "L009", "time": "14:18:34", "level": "WARN",     "source": "auth-service",    "message": "SUDO privilege escalation attempt by user [jdoe]"},
    {"id": "L010", "time": "14:15:02", "level": "INFO",     "source": "siem-core",       "message": "Ruleset update applied — 342 new signatures loaded"},
]


# ── Legacy static endpoints ───────────────────────────────────────────────────

@router.get("/threats")
def get_threats():
    return {"status": "success", "data": THREATS}


@router.get("/logs")
def get_logs():
    return {"status": "success", "data": LOGS}


@router.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


# ── ML endpoints ──────────────────────────────────────────────────────────────

@router.get("/status")
def get_status():
    """Check whether the ML model file exists and is loaded in memory."""
    model_exists = MODEL_PATH.exists()
    model_loaded = _model is not None

    if model_loaded:
        status = "ready"
    elif model_exists:
        status = "model_file_found_not_loaded"
    else:
        status = "model_not_trained"

    return {
        "status":                  status,
        "model_path":              str(MODEL_PATH),
        "model_file_exists":       model_exists,
        "model_loaded_in_memory":  model_loaded,
        "timestamp":               datetime.now().isoformat(),
    }


@router.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """
    Analyze a .log, .txt, or .csv file for cyber threats.

    Each non-empty line is classified by UpgradedAMIDES.
    High/critical threats automatically trigger remediation actions.

    Returns:
        status, filename, total_lines, threats_found, results[]
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided.")

    ext = Path(file.filename).suffix.lower()
    if ext not in ('.log', '.txt', '.csv'):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Accepted: .log, .txt, .csv",
        )

    # Read and decode file content
    try:
        raw = await file.read()
        text = raw.decode('utf-8', errors='replace')
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {exc}")

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise HTTPException(status_code=400, detail="File is empty or contains no valid lines.")
    if len(lines) > 10_000:
        raise HTTPException(
            status_code=400,
            detail=f"File too large: {len(lines)} lines. Maximum is 10,000 lines per request.",
        )

    # Load model (raises 503 if unavailable)
    try:
        model = _get_model()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=f"ML model unavailable: {exc}")

    predictions = model.predict_batch(lines)

    # Trigger remediation for high/critical threats (non-blocking)
    _run_remediation(lines, predictions)

    threats_found = sum(1 for r in predictions if r['is_threat'])

    return {
        "status":        "success",
        "filename":      file.filename,
        "total_lines":   len(lines),
        "threats_found": threats_found,
        "results": [
            {
                "line_number":          i + 1,
                "log_line":             lines[i][:300],
                "threat_type":          predictions[i]['threat_type'],
                "severity":             predictions[i]['severity'],
                "confidence":           predictions[i]['confidence'],
                "is_threat":            predictions[i]['is_threat'],
                "remediation_actions":  predictions[i]['remediation_actions'],
                "top_signals":          dict(predictions[i]['top_signals']),
            }
            for i in range(len(lines))
        ],
        "timestamp": datetime.now().isoformat(),
    }


@router.post("/analyze/line")
async def analyze_line(payload: dict = Body(...)):
    """
    Analyze a single log line string.

    Request body:
        { "log_line": "your log text here" }

    Returns:
        threat_type, severity, confidence, is_threat,
        remediation_actions, top_signals, timestamp
    """
    log_line = payload.get("log_line", "").strip()
    if not log_line:
        raise HTTPException(
            status_code=400,
            detail="'log_line' is required and cannot be empty.",
        )
    if len(log_line) > 10_000:
        raise HTTPException(
            status_code=400,
            detail="log_line too long. Maximum is 10,000 characters.",
        )

    try:
        model = _get_model()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=f"ML model unavailable: {exc}")

    result = model.predict(log_line)

    # Trigger remediation for high/critical threats (non-blocking)
    _run_remediation([log_line], [result])

    return {
        "status":               "success",
        "log_line":             log_line[:300],
        "threat_type":          result['threat_type'],
        "severity":             result['severity'],
        "confidence":           result['confidence'],
        "is_threat":            result['is_threat'],
        "remediation_actions":  result['remediation_actions'],
        "top_signals":          dict(result['top_signals']),
        "timestamp":            datetime.now().isoformat(),
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _run_remediation(lines: list, predictions: list):
    """
    Trigger RemediationEngine for high/critical threats.
    Errors are silently logged — they must not fail the HTTP response.
    """
    try:
        from app.services.remediation import RemediationEngine
        engine = RemediationEngine()
        for log_line, result in zip(lines, predictions):
            if result.get('severity') in ('high', 'critical'):
                engine.execute(result['remediation_actions'], log_line, result)
    except Exception:
        pass  # remediation failure is non-fatal
