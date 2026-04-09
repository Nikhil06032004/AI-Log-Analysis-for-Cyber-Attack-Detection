<div align="center">

# AI Log Analysis

### Intelligent SIEM Platform with Real-Time Threat Detection

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-ML%20Engine-FF6600?style=flat-square)](https://xgboost.readthedocs.io/)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vite.dev/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

A production-ready, full-stack **Security Information & Event Management (SIEM)** platform powered by a custom-trained XGBoost ensemble. Ingests live Windows Event Logs, network flows, and syslog streams — classifies threats in real time and triggers automated remediation — all visualized through a 9-page interactive React dashboard.

[Getting Started](#setup--installation) · [API Reference](#api-reference) · [ML Engine](#ml-engine--upgradedamides) · [Architecture](#architecture)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [ML Engine — UpgradedAMIDES](#ml-engine--upgradedamides)
- [Backend](#backend)
- [Frontend](#frontend)
- [Threat Detection](#threat-detection)
- [Automated Remediation](#automated-remediation)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Running the Application](#running-the-application)
- [API Reference](#api-reference)
- [Tech Stack](#tech-stack)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

AI Log Analysis brings enterprise-grade threat detection to a self-hosted platform. At its core is **UpgradedAMIDES** — a hybrid XGBoost + TF-IDF classifier trained on NSL-KDD network intrusion data and SOCBED synthetic security events. The model classifies every log entry into one of six categories and immediately triggers appropriate remediation actions.

The platform operates in two modes:

| Mode | Description |
|---|---|
| **Live Collection** | Reads directly from Windows Event Logs (`wevtutil`) or Linux `/var/log` sources, normalizes entries, runs inference, and streams results to the dashboard |
| **File Upload** | Accepts `.log`, `.txt`, or `.csv` files (up to 10,000 lines) for batch analysis via drag-and-drop |

**What makes it different:**

- No third-party SIEM subscription required — fully self-hosted
- Custom-engineered BRUTE_FORCE features that fix a known NSL-KDD recall failure (see [ML Engine](#ml-engine--upgradedamides))
- Unified normalization pipeline handles Windows Event IDs, NSL-KDD CSV, and syslog in a single model
- Automated remediation executes without human intervention for high/critical severity events
- Live system resource monitoring (CPU, RAM, disk, network) alongside threat data

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          React Frontend                              │
│                                                                      │
│   Dashboard  ·  Threats  ·  Log Explorer  ·  Network Map            │
│   Analytics  ·  SIEM Rules  ·  AI Model  ·  System Monitor          │
│                                                                      │
│              React 19  ·  TypeScript 5.9  ·  Vite 8                 │
│              ECharts 6  ·  React Router 7  ·  Axios                 │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ HTTP REST  ·  localhost:8000
┌──────────────────────────────▼──────────────────────────────────────┐
│                        FastAPI Backend                               │
│                                                                      │
│   threat_routes   ·   ingest_routes   ·   system_routes             │
│   metrics_routes  ·   log_normalizer  ·   model_service             │
└──────────┬────────────────────────────────────┬─────────────────────┘
           │                                    │
┌──────────▼─────────────┐        ┌─────────────▼──────────────────────┐
│    UpgradedAMIDES       │        │         System Log Sources          │
│                         │        │                                     │
│  XGBoost  600 trees     │        │  Windows  Security / System /       │
│  TF-IDF   char 1–4 gram │        │           Application / Firewall    │
│  NSL-KDD  41 features   │        │                                     │
│  SOCBED   synthetic     │        │  Linux    /var/log/auth.log         │
│  SMOTE    oversampling  │        │           /var/log/syslog           │
│                         │        │           /var/log/kern.log         │
└──────────┬─────────────┘        │                                     │
           │                       │  Network  JSON flows / NSL-KDD CSV │
           │                       └────────────────────────────────────┘
┌──────────▼──────────────────────────────────────────────────────────┐
│                       RemediationEngine                              │
│                                                                      │
│   BLOCK_IP  ·  ALERT_ADMIN  ·  LOG_AND_MONITOR                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Data flow:**

1. Log source (Windows / Linux / network) → `log_normalizer.py` → canonical string
2. Canonical string → `clean_for_model()` → stripped of entropy noise (GUIDs, hex, timestamps)
3. Cleaned string → `UpgradedAMIDES.predict()` → `{ threat_type, severity, confidence, remediation_actions }`
4. If `severity ∈ {high, critical}` → `RemediationEngine.execute()` → isolated, non-blocking action chain
5. All results → REST response → React dashboard

---

## ML Engine — UpgradedAMIDES

The core classifier is **UpgradedAMIDES**, a custom-engineered threat detection model combining gradient boosted trees with a dual-input feature pipeline designed to handle both unstructured log text and structured network flow data in a single inference call.

### Feature Pipeline

The model extracts features from three independent sources and concatenates them into a single sparse feature matrix before training:

| Layer | Source Input | Technique | Dimensionality |
|---|---|---|---|
| **Text** | Syslog lines, Windows Event strings | TF-IDF, char n-grams (1–4), sublinear TF | High-dimensional sparse |
| **Numerical** | NSL-KDD 41-column flow vectors | Direct pass-through + normalization | 41 features |
| **Engineered** | R2L/BRUTE_FORCE sub-type signals | Hand-crafted score functions | 5 features |
| **Structural** | Protocol, TCP flag, service type | Binary one-hot encoding | ~20 features |

### Training Data

| Dataset | Description | Role |
|---|---|---|
| **NSL-KDD** | 41-feature network intrusion benchmark | Primary numerical training source |
| **SOCBED** | Synthetic SOC event logs per category | Text feature training source |
| **Augmentation** | `RandomOverSampler` (imbalanced-learn) | Class balancing before fit |
| **Weighting** | `compute_sample_weight('balanced')` | XGBoost sample weighting |

The NSL-KDD dataset is auto-downloaded via `kagglehub` if `data/KDDTrain+.csv` is not present locally.

### Key Engineering Fix — BRUTE_FORCE Recall

Prior AMIDES implementations consistently underperform on BRUTE_FORCE detection (~4% recall) because they rely on `num_failed_logins > 0` as the primary signal. Root-cause analysis of actual NSL-KDD BRUTE_FORCE rows shows that **`num_failed_logins` is `0` for nearly every R2L attack record** — the feature carries no discriminative signal for this class.

UpgradedAMIDES replaces this with five engineered sub-type score features that match the actual statistical patterns in the dataset:

| Score Feature | Logic |
|---|---|
| `warezclient_score` | `service=ftp_data` AND `logged_in=1` AND `num_file_creations≥1` AND `src_bytes>100` |
| `guess_passwd_score` | `service∈{ftp, telnet, imap, pop_3}` AND `rerror_rate>0` AND `dst_bytes≈0` |
| `snmpguess_score` | `protocol=udp` AND (`service=snmp` OR `rerror_rate>0.05`) |
| `ftp_write_score` | `service=ftp` AND `logged_in=1` AND `num_file_creations>0` AND `dst_bytes<1000` |
| `httptunnel_score` | `service∈{http, http_443}` AND `src_bytes>50,000` AND `dst_bytes>50,000` |

### Training the Model

```bash
# Run from the project root directory
python ml_engine/train.py
```

The script will:
1. Load SOCBED synthetic samples from `ml_engine/model/`
2. Locate `data/KDDTrain+.csv`, or auto-download from Kaggle via `kagglehub`
3. Combine both datasets and apply oversampling
4. Train the XGBoost 600-tree ensemble
5. Save the serialized model to `ml_engine/upgraded_amides.pkl`

> **Note:** Kaggle credentials (`~/.kaggle/kaggle.json`) are required for auto-download. Alternatively, place `KDDTrain+.csv` manually in the `data/` directory.

---

## Backend

Built with **FastAPI**, served via Uvicorn at `localhost:8000`. The application registers four independent routers, each responsible for a specific domain.

### Routers

| Module | Prefix | Responsibility |
|---|---|---|
| `threat_routes` | `/api` | Static threat/log feeds, file upload analysis, single-line analysis |
| `ingest_routes` | `/api/ingest` | Structured ingestion — Windows Events, network flows, syslog |
| `system_routes` | `/api/system` | Live host log collection via `wevtutil` (Windows) or `/var/log` (Linux) |
| `metrics_routes` | `/api/metrics` | Real-time host resource metrics via `psutil` |

### Log Normalization Pipeline

Every log entry passes through `log_normalizer.py` before reaching the model. Three normalizers handle distinct input formats:

**`normalize_windows_event(event: dict) → str`**
- Maps EventID to a semantic label using a 40+ entry lookup table (e.g., `4625` → `failed_logon`, `1102` → `audit_log_cleared`)
- Extracts key-value pairs from `UserData`/`EventData` (TargetUserName, IpAddress, LogonType, CommandLine, etc.)
- Decodes WFP protocol numbers (`6` → `tcp`) and direction codes (`%%14592` → `Inbound`)
- Produces: `Security[4625:failed_logon] warning AUDIT_FAILURE TargetUserName=admin IpAddress=10.0.0.1`

**`normalize_network_flow(flow: dict) → str`**
- Accepts flexible field names (`src_ip`/`source_ip`, `proto`/`protocol`/`protocol_type`)
- Automatically detects NSL-KDD input when ≥4 standard column names are present and serializes as a 41-column CSV row for the numerical feature extractor
- Produces: `NETWORK_FLOW proto=tcp src=192.168.1.5:54321 dst=10.0.0.1:22 service=ssh flags=SF bytes_sent=2048`

**`normalize_syslog(line: str) → str`**
- Strips ANSI escape codes, collapses whitespace
- Passes through to the model's TF-IDF text extractor

**`clean_for_model(text: str) → str`**  
Strips high-entropy tokens before inference to prevent TF-IDF noise from inflating LOG_EVASION false positives:

| Pattern Removed | Example |
|---|---|
| ISO-8601 timestamps | `2026-04-09T14:32:07.776Z` → `[TS]` |
| GUIDs | `{6bffd098-a112-...}` → `[GUID]` |
| Hex literals | `0xFFFFFF`, `1912621072` → `[HEX]` |
| Windows format codes | `%%1832`, `%%2313` → `[CODE]` |
| Large numerics (≥7 digits) | Memory addresses, ticks → `[NUM]` |
| Long tokens (>40 chars) | Base64 / binary blobs → `[BLOB]` |

### Model Service

`model_service.py` implements a **singleton loader** — the model is deserialized from `ml_engine/upgraded_amides.pkl` exactly once per server process, regardless of how many concurrent requests arrive. Subsequent calls return the cached instance. If the model file is missing, the API returns HTTP 503 with a clear message directing the user to run the training script.

---

## Frontend

A 9-page SIEM dashboard built with **React 19 + TypeScript 5.9**, bundled by **Vite 8**, visualized with **Apache ECharts 6**.

### Pages

| Route | Page | Description |
|---|---|---|
| `/dashboard` | **Dashboard** | Central threat command center — live model predictions from system logs, attack distribution chart, severity breakdown, per-source stats, scrollable threat log |
| `/threats` | **Threats** | Structured threat feed with severity badges, protocol tags, confidence scores, and status tracking (active / investigating / resolved / pending) |
| `/logs` | **Log Explorer** | Full log stream with level-based filtering (INFO / WARN / ERROR / CRITICAL), source filter, and timestamped entries |
| `/network` | **Network Map** | Interactive network topology visualization — connection flows, IP relationships, traffic volume |
| `/analytics` | **Analytics** | Historical data views — threat volume trends, attack category frequency, time-series analysis |
| `/siem` | **SIEM Rules** | Detection rule browser and management interface |
| `/system-monitor` | **System Monitor** | Live host resource dashboard polling `/api/metrics/live` every 2–3 seconds — per-core CPU, RAM usage, disk I/O, network bytes/sec, top 8 processes by CPU |
| `/ai-model` | **AI Model** | Model health status, training metadata, per-class performance charts (precision, recall, F1) |
| `/settings` | **Settings** | Application preferences, notification configuration, API connectivity |

### Chart Components

All charts are thin React wrappers around ECharts 6 instances:

| Component | Chart Type | Data Source |
|---|---|---|
| `AttackDistributionChart` | Donut / bar | Threat type counts from analysis results |
| `LogVolumeChart` | Area time-series | Log ingestion volume over time |
| `ThreatTrendChart` | Line time-series | Threat detections over time |
| `RiskGaugeChart` | Gauge | Computed overall risk score |
| `AttackOriginChart` | Scatter / geo | Source IP distribution |
| `ModelPerformanceChart` | Radar / grouped bar | Per-class precision, recall, F1 |

### Architecture Patterns

**`AnalysisContext`** — A React context that caches the most recent `SystemAnalysisResult` object across page navigations. Once the Dashboard performs the initial `POST /api/system/collect-analyze`, subsequent navigation to Threats, Analytics, or Log Explorer reads from this shared state without triggering additional API calls.

**`api.ts`** — Centralized Axios client with a typed function for every endpoint. All response shapes are declared as TypeScript interfaces (`Threat`, `LogEntry`, `SystemAnalysisResult`, `LiveMetrics`, etc.), providing end-to-end type safety from API response to component props.

---

## Threat Detection

### Threat Categories

| Category | Severity | Auto-Remediation |
|---|---|---|
| `NORMAL` | None | — |
| `BRUTE_FORCE` | **High** | BLOCK_IP · LOG_AND_MONITOR · ALERT_ADMIN |
| `PORT_SCAN` | **Medium** | BLOCK_IP · LOG_AND_MONITOR |
| `LOG_EVASION` | **High** | ALERT_ADMIN · LOG_AND_MONITOR |
| `DOS_ATTACK` | **Critical** | BLOCK_IP · ALERT_ADMIN · LOG_AND_MONITOR |
| `MALWARE` | **Critical** | BLOCK_IP · ALERT_ADMIN · LOG_AND_MONITOR |

### Windows Event ID Mapping

The normalizer maps over 40 Windows Event IDs to semantic labels. High-signal IDs and their threat mappings:

| Event ID | Description | Threat Category |
|---|---|---|
| `4625` | An account failed to log on | `BRUTE_FORCE` |
| `4768` / `4771` | Kerberos ticket request / pre-auth failed | `BRUTE_FORCE` |
| `4688` | A new process has been created | `MALWARE` |
| `4697` / `7045` | A service was installed in the system | `MALWARE` |
| `4698` | A scheduled task was created | `MALWARE` |
| `4657` | A registry value was modified | `MALWARE` |
| `4672` | Special privileges assigned to new logon | `MALWARE` |
| `5156` / `5157` | WFP network connection permitted / blocked | `PORT_SCAN` / `DOS_ATTACK` |
| `1102` | The audit log was cleared | `LOG_EVASION` |
| `4719` | System audit policy was changed | `LOG_EVASION` |
| `5140` / `5145` | Network share accessed / checked | `MALWARE` |

### NSL-KDD Attack Mappings

The model maps all 23 NSL-KDD attack subcategories to the five internal threat classes:

| NSL-KDD Subcategory | Threat Class |
|---|---|
| `neptune`, `smurf`, `pod`, `teardrop`, `back`, `apache2`, `udpstorm` | `DOS_ATTACK` |
| `portsweep`, `nmap`, `satan`, `saint`, `mscan`, `ipsweep` | `PORT_SCAN` |
| `guess_passwd`, `ftp_write`, `imap`, `warezclient`, `httptunnel`, `snmpguess` | `BRUTE_FORCE` |
| `rootkit`, `buffer_overflow`, `loadmodule`, `sqlattack`, `worm`, `ps` | `MALWARE` |
| `normal` | `NORMAL` |

---

## Automated Remediation

`RemediationEngine` is invoked automatically for any prediction with `severity ∈ {high, critical}`. Actions are executed in sequence but are fully isolated — an exception in one action does not prevent subsequent actions from running. Failures are logged at `WARNING` level and never surface to the HTTP response.

### BLOCK_IP

Extracts all IPv4 addresses from the log line using regex, filters out RFC-1918 private ranges, and applies a firewall block to the first three external IPs found.

| Platform | Mechanism | Privilege Required |
|---|---|---|
| Linux | `iptables -I INPUT -s <ip> -j DROP` | Root |
| Windows | Records intended block to `logs/threats.log` for operator action | — (netsh requires elevation) |

Private prefixes skipped: `10.*`, `192.168.*`, `172.16–31.*`, `127.*`, `0.0.0.0`

### ALERT_ADMIN

Sends an SMTP email alert to the configured `ADMIN_EMAIL` address. The email body includes threat type, severity, confidence percentage, triggered remediation actions, top model signals, and the truncated log line.

Silently skips if `ADMIN_EMAIL` environment variable is not set — no error is raised.

### LOG_AND_MONITOR

Appends a structured pipe-delimited record to `logs/threats.log`:

```
2026-04-09T14:32:07.123456 | BRUTE_FORCE     | HIGH     | conf= 97.3% | Security[4625:failed_logon] warning AUDIT_FAILURE TargetUserName=admin IpAddress=203.0.113.5
```

The log directory is created automatically if it does not exist.

---

## Project Structure

```
Log-Analysis/
│
├── backend/
│   └── app/
│       ├── main.py                    # FastAPI application, CORS middleware, router registration
│       ├── configs/
│       │   └── settings.py            # Pydantic BaseSettings
│       ├── routes/
│       │   ├── threat_routes.py       # GET /api/threats|logs|health|status
│       │   │                          # POST /api/analyze, /api/analyze/line
│       │   ├── ingest_routes.py       # POST /api/ingest/windows|network|syslog
│       │   │                          # GET  /api/ingest/stats
│       │   ├── system_routes.py       # GET  /api/system/sources
│       │   │                          # POST /api/system/collect-analyze
│       │   └── metrics_routes.py      # GET  /api/metrics/live
│       └── services/
│           ├── model_service.py       # Singleton model loader with error state
│           ├── log_normalizer.py      # normalize_windows_event / network_flow / syslog
│           │                          # clean_for_model (entropy noise removal)
│           └── remediation.py         # RemediationEngine: BLOCK_IP, ALERT_ADMIN, LOG_AND_MONITOR
│
├── ml_engine/
│   ├── upgraded_amides.py             # UpgradedAMIDES model — feature pipeline + XGBoost
│   ├── train.py                       # Training script: NSL-KDD + SOCBED → upgraded_amides.pkl
│   ├── test.py                        # Evaluation script
│   └── model/                         # SOCBED per-category synthetic log samples
│
├── frontend/
│   └── Log Analysis/
│       ├── package.json
│       ├── vite.config.ts
│       └── src/
│           ├── App.tsx                # Root router, AnalysisProvider wrapper
│           ├── main.tsx               # React DOM entry point
│           ├── pages/
│           │   ├── Dashboard.tsx      # Live system log collection + threat visualization
│           │   ├── Threats.tsx        # Threat feed with severity/status controls
│           │   ├── LogExplorer.tsx    # Filterable log stream
│           │   ├── NetworkMap.tsx     # Network topology visualization
│           │   ├── Analytics.tsx      # Historical trend charts
│           │   ├── SIEMRules.tsx      # Detection rule management
│           │   ├── SystemMonitor.tsx  # Live host resource metrics
│           │   ├── AIModel.tsx        # Model status and performance metrics
│           │   └── Settings.tsx       # Application configuration
│           ├── components/
│           │   ├── charts/            # AttackDistribution, LogVolume, ThreatTrend,
│           │   │                      # RiskGauge, AttackOrigin, ModelPerformance
│           │   ├── layout/            # AppLayout (sidebar + outlet), Header
│           │   ├── ui/                # Panel, StatCard, StatusStrip, PermissionDialog,
│           │   │                      # LogLoadingScreen, AccessDenied
│           │   ├── threats/           # ThreatCard, ThreatFeed
│           │   └── logs/              # LogStream
│           ├── context/
│           │   └── AnalysisContext.tsx  # Shared SystemAnalysisResult state
│           ├── services/
│           │   └── api.ts             # Typed Axios client — all endpoints + interfaces
│           └── constants/
│               └── theme.ts           # Design system: colors, typography, spacing
│
├── data/
│   └── KDDTrain+.csv                  # NSL-KDD training dataset (gitignored if large)
│
├── logs/
│   └── threats.log                    # Append-only threat log (written by RemediationEngine)
│
├── requirements.txt                   # Python dependencies
└── README.md
```

---

## Setup & Installation

### Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.9 or higher |
| Node.js | 18 or higher |
| pip | Latest recommended |
| Kaggle account | Required only for auto-downloading NSL-KDD |

### Step 1 — Clone the Repository

```bash
git clone https://github.com/Nikhil06032004/Log-Analysis.git
cd Log-Analysis
```

### Step 2 — Backend Setup

```bash
# Create a virtual environment
python -m venv venv

# Activate it
source venv/bin/activate          # macOS / Linux
venv\Scripts\activate             # Windows (Command Prompt)
.\venv\Scripts\Activate.ps1       # Windows (PowerShell)

# Install all dependencies
pip install -r requirements.txt
```

### Step 3 — Train the ML Model

```bash
python ml_engine/train.py
```

The script automatically handles dataset acquisition:

- If `data/KDDTrain+.csv` exists locally — uses it directly
- If not — downloads from Kaggle via `kagglehub` (requires `~/.kaggle/kaggle.json`)

Output: `ml_engine/upgraded_amides.pkl`

> To obtain Kaggle credentials: sign in at kaggle.com → Account → API → Create New API Token. Place the downloaded `kaggle.json` at `~/.kaggle/kaggle.json`.

### Step 4 — Frontend Setup

```bash
cd "frontend/Log Analysis"
npm install
```

### Step 5 — Environment Variables (Optional)

Create a `.env` file in the project root to enable email alerting:

```env
# Remediation — email alerts
ADMIN_EMAIL=security@yourorg.com
SMTP_HOST=smtp.yourorg.com
SMTP_PORT=587
SMTP_USER=alerts@yourorg.com
SMTP_PASS=your_smtp_password
```

All variables are optional. If `ADMIN_EMAIL` is not set, the `ALERT_ADMIN` remediation action is silently skipped.

---

## Running the Application

### 1. Start the Backend

```bash
# From the project root, with venv activated
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`.  
Interactive API documentation (Swagger UI): `http://localhost:8000/docs`

### 2. Start the Frontend

```bash
cd "frontend/Log Analysis"
npm run dev
```

The dashboard will be available at `http://localhost:5173`.

### 3. Verify the Stack

```bash
# Health check
curl http://localhost:8000/api/health
# → {"status":"ok","timestamp":"2026-04-09T14:32:07.123456"}

# Model status
curl http://localhost:8000/api/status
# → {"status":"ready","model_file_exists":true,"model_loaded_in_memory":true,"model_path":"..."}

# Analyze a single log line
curl -X POST http://localhost:8000/api/analyze/line \
  -H "Content-Type: application/json" \
  -d '{"log_line": "Apr 9 14:32:07 host sshd[1234]: Failed password for root from 203.0.113.5 port 54321 ssh2"}'
```

---

## API Reference

### Core

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Returns server status and current timestamp |
| `GET` | `/api/status` | Returns model file existence and load state |
| `GET` | `/api/threats` | Returns the static threat feed (6 sample threats) |
| `GET` | `/api/logs` | Returns the static log feed (10 sample entries) |

### Analysis

| Method | Endpoint | Body | Description |
|---|---|---|---|
| `POST` | `/api/analyze` | `multipart/form-data` — `file` | Upload `.log`/`.txt`/`.csv` for batch analysis. Max 10,000 lines. |
| `POST` | `/api/analyze/line` | `{ "log_line": "string" }` | Classify a single log line. Returns full prediction. |

**Example — analyze a single line:**

```bash
POST /api/analyze/line
Content-Type: application/json

{ "log_line": "Security[4625:failed_logon] warning TargetUserName=admin IpAddress=203.0.113.5" }
```

```json
{
  "status": "success",
  "threat_type": "BRUTE_FORCE",
  "severity": "high",
  "confidence": 0.973,
  "is_threat": true,
  "remediation_actions": ["BLOCK_IP", "LOG_AND_MONITOR", "ALERT_ADMIN"],
  "top_signals": { "failed_logon": 0.41, "IpAddress": 0.28, "warning": 0.19 },
  "timestamp": "2026-04-09T14:32:07.123456"
}
```

### Log Ingestion

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/ingest/windows` | JSON array of Windows Event Log objects (max 5,000) |
| `POST` | `/api/ingest/network` | `{ "flows": [...] }` JSON array or `{ "csv_text": "..." }` NSL-KDD CSV |
| `POST` | `/api/ingest/syslog` | `{ "lines": ["...", "..."] }` raw syslog array (max 10,000) |
| `GET` | `/api/ingest/stats` | Cumulative event counts and threat rate since server start |

**Example — ingest a Windows Event:**

```bash
POST /api/ingest/windows
Content-Type: application/json

[{
  "EventID": 4625,
  "Source": "Microsoft-Windows-Security-Auditing",
  "Computer": "WORKSTATION-01",
  "Level": "Warning",
  "Keywords": "Audit Failure",
  "UserData": {
    "TargetUserName": "administrator",
    "IpAddress": "203.0.113.5",
    "LogonType": "3"
  }
}]
```

### System Log Collection

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/system/sources` | Returns available log sources on the current host with platform and event counts |
| `POST` | `/api/system/collect-analyze` | Collect from specified sources, run inference, return full results |

**Request body for `collect-analyze`:**

```json
{
  "sources": ["windows_security", "windows_system"],
  "max_events": 500,
  "hours_back": 24
}
```

Available sources: `windows_security`, `windows_system`, `windows_application`, `windows_firewall`, `syslog_auth`, `syslog_kern`, `syslog_messages`

### Metrics

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/metrics/live` | Snapshot of CPU (per-core), RAM, disk partitions, network I/O (bytes/sec), and top 8 processes by CPU usage |

---

## Tech Stack

### Backend

| Package | Purpose |
|---|---|
| **FastAPI** | High-performance async REST API framework |
| **Uvicorn** | ASGI server (standard extras: websockets, http-tools) |
| **Pydantic / pydantic-settings** | Request validation and settings management |
| **XGBoost** | Core ML classifier — 600-tree gradient boosted ensemble |
| **scikit-learn** | TF-IDF vectorizer, LabelEncoder, sample weight computation |
| **imbalanced-learn** | `RandomOverSampler` for training class balancing |
| **NumPy** | Dense array operations throughout the feature pipeline |
| **SciPy** | Sparse matrix concatenation (`scipy.sparse.hstack`) |
| **Pandas** | NSL-KDD CSV ingestion and DataFrame manipulation |
| **joblib** | Model serialization and deserialization (`.pkl`) |
| **psutil** | Cross-platform live system resource metrics |
| **python-multipart** | Multipart form data for file upload endpoints |
| **python-dotenv** | `.env` file loading |
| **kagglehub** | Automatic NSL-KDD dataset download from Kaggle (optional) |

### Frontend

| Package | Version | Purpose |
|---|---|---|
| **React** | 19 | Declarative UI framework |
| **TypeScript** | 5.9 | Static type safety across all components and services |
| **Vite** | 8 | Sub-second HMR dev server and optimized production builds |
| **React Router** | 7 | Client-side routing with nested layout support |
| **Apache ECharts** | 6 | Rich interactive charting library |
| **Axios** | 1.x | Promise-based HTTP client with interceptors |

---

## Contributing

Contributions are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes with a clear message
4. Push to your fork and open a Pull Request against `main`

For significant changes, please open an issue first to discuss the approach.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

Built by [Nikhil Sharma](https://github.com/Nikhil06032004)

</div>
