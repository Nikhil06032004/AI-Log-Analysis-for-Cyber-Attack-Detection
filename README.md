<div align="center">

<img src="frontend/Log Analysis/public/favicon.svg" width="80" height="80" alt="LogSentinel AI Logo"/>

# LogSentinel AI

### Intelligent SIEM Platform with Real-Time Cyber Threat Detection

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-ML%20Engine-FF6600?style=flat-square)](https://xgboost.readthedocs.io/)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vite.dev/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-Vercel-000000?style=flat-square&logo=vercel&logoColor=white)](https://ai-log-analysis-cyber-attack.vercel.app/dashboard)

A production-ready, full-stack **Security Information & Event Management (SIEM)** platform powered by a custom-trained XGBoost ensemble. Ingests live Windows Event Logs, network flows, and syslog streams — classifies threats in real time and triggers automated remediation — all visualized through a 9-page interactive React dashboard.

**[🚀 Live Demo](https://ai-log-analysis-cyber-attack.vercel.app/dashboard)** · [Getting Started](#setup--installation) · [API Reference](#api-reference) · [ML Engine](#ml-engine--upgradedamides) · [Architecture](#architecture)

</div>

---

## Table of Contents

- [Live Demo](#live-demo)
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

## Live Demo

> **Deployed on Vercel (static frontend, no backend required)**
>
> 🌐 **[https://ai-log-analysis-cyber-attack.vercel.app/dashboard](https://ai-log-analysis-cyber-attack.vercel.app/dashboard)**

The live demo runs the full React dashboard with mock/graceful data fallback since no backend is connected. To use real threat detection, clone the repo and run the full stack locally (see [Setup & Installation](#setup--installation)).

### What you can explore in the demo

| Page | URL | What to see |
|---|---|---|
| Dashboard | `/dashboard` | Threat command center, live metrics, attack distribution charts |
| Threats | `/threats` | Structured threat feed with severity badges and confidence scores |
| Log Explorer | `/logs` | Full log stream with level filtering (INFO / WARN / ERROR / CRITICAL) |
| Network Map | `/network` | Interactive network topology and connection flow visualization |
| Analytics | `/analytics` | Historical threat trends, attack frequency, time-series charts |
| SIEM Rules | `/siem` | Detection rule browser |
| AI Model | `/ai-model` | Model health, training metadata, per-class precision/recall/F1 |
| System Monitor | `/system-monitor` | CPU (per-core), RAM, disk I/O, network bytes/sec, top processes |
| Settings | `/settings` | App preferences, notification config, API connectivity |

---

## Overview

LogSentinel AI brings enterprise-grade threat detection to a self-hosted platform. At its core is **UpgradedAMIDES** — a hybrid XGBoost + TF-IDF classifier trained on NSL-KDD network intrusion data and SOCBED synthetic security events. The model classifies every log entry into one of six threat categories and immediately triggers appropriate remediation actions.

### Platform Modes

| Mode | Description |
|---|---|
| **Live Collection** | Reads directly from Windows Event Logs (`wevtutil`) or Linux `/var/log` sources, normalizes entries, runs inference, and streams results to the dashboard |
| **File Upload** | Accepts `.log`, `.txt`, or `.csv` files (up to 10,000 lines) for batch analysis via drag-and-drop |
| **Static Demo** | Full React dashboard deployed on Vercel — no backend required, data loads gracefully from cache or falls back to empty state |

### Key Differentiators

- **No third-party SIEM subscription** — fully self-hosted, zero licensing cost
- **Custom BRUTE_FORCE engineering** — fixes a known NSL-KDD recall failure where `num_failed_logins` is `0` for ~95% of actual R2L records (see [ML Engine](#ml-engine--upgradedamides))
- **Unified normalization pipeline** — Windows Event IDs, NSL-KDD CSV rows, and raw syslog lines all enter the same model through a single clean-and-tokenize pipeline
- **Non-blocking automated remediation** — high/critical severity events trigger firewall rules, email alerts, and threat logs concurrently without delaying the API response
- **Live resource monitoring** — CPU, RAM, disk, network, and top processes polled every 2–3 seconds alongside threat data on the same dashboard
- **End-to-end TypeScript** — every API response shape is a typed interface from `api.ts` through to component props, eliminating runtime shape mismatches

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
           │                       │  Network  JSON flows / NSL-KDD CSV  │
           │                       └─────────────────────────────────────┘
┌──────────▼──────────────────────────────────────────────────────────┐
│                       RemediationEngine                              │
│                                                                      │
│   BLOCK_IP  ·  ALERT_ADMIN  ·  LOG_AND_MONITOR                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. Log source (Windows / Linux / network) → `log_normalizer.py` → canonical string
2. Canonical string → `clean_for_model()` → stripped of entropy noise (GUIDs, hex, timestamps)
3. Cleaned string → `UpgradedAMIDES.predict()` → `{ threat_type, severity, confidence, remediation_actions }`
4. If `severity ∈ {high, critical}` → `RemediationEngine.execute()` → isolated, non-blocking action chain
5. All results → REST response → React dashboard updates in real time

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

Built with **FastAPI**, served via Uvicorn at `localhost:8000`. Four independent routers handle distinct domains.

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
- Auto-detects NSL-KDD input when ≥4 standard column names are present and serializes as a 41-column CSV row for the numerical feature extractor
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

`model_service.py` implements a **singleton loader** — the model is deserialized from `ml_engine/upgraded_amides.pkl` exactly once per server process. Subsequent calls return the cached instance. If the model file is missing, the API returns HTTP 503 directing the user to run the training script.

---

## Frontend

A 9-page SIEM dashboard built with **React 19 + TypeScript 5.9**, bundled by **Vite 8**, visualized with **Apache ECharts 6**.

### Pages

| Route | Page | Description |
|---|---|---|
| `/dashboard` | **Dashboard** | Central threat command center — live model predictions, attack distribution chart, severity breakdown, per-source stats, scrollable threat log |
| `/threats` | **Threats** | Structured threat feed with severity badges, protocol tags, confidence scores, and status tracking (active / investigating / resolved / pending) |
| `/logs` | **Log Explorer** | Full log stream with level-based filtering (INFO / WARN / ERROR / CRITICAL), source filter, and timestamped entries |
| `/network` | **Network Map** | Interactive network topology visualization — connection flows, IP relationships, traffic volume |
| `/analytics` | **Analytics** | Historical data views — threat volume trends, attack category frequency, time-series analysis |
| `/siem` | **SIEM Rules** | Detection rule browser and management interface |
| `/system-monitor` | **System Monitor** | Live host resource dashboard polling `/api/metrics/live` every 2–3 seconds — per-core CPU, RAM usage, disk I/O, network bytes/sec, top 8 processes |
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

**`AnalysisContext`** — A React context that caches the most recent `SystemAnalysisResult` across page navigations. Once the Dashboard performs the initial `POST /api/system/collect-analyze`, subsequent navigation to Threats, Analytics, or Log Explorer reads from this shared state without additional API calls. Results are persisted to `localStorage` so they survive page refreshes.

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

The normalizer maps over 40 Windows Event IDs to semantic labels:

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

| NSL-KDD Subcategory | Threat Class |
|---|---|
| `neptune`, `smurf`, `pod`, `teardrop`, `back`, `apache2`, `udpstorm` | `DOS_ATTACK` |
| `portsweep`, `nmap`, `satan`, `saint`, `mscan`, `ipsweep` | `PORT_SCAN` |
| `guess_passwd`, `ftp_write`, `imap`, `warezclient`, `httptunnel`, `snmpguess` | `BRUTE_FORCE` |
| `rootkit`, `buffer_overflow`, `loadmodule`, `sqlattack`, `worm`, `ps` | `MALWARE` |
| `normal` | `NORMAL` |

---

## Automated Remediation

`RemediationEngine` is invoked automatically for any prediction with `severity ∈ {high, critical}`. Actions execute in sequence but are fully isolated — an exception in one action does not prevent subsequent actions from running. Failures are logged at `WARNING` level and never surface to the HTTP response.

### BLOCK_IP

Extracts all IPv4 addresses from the log line using regex, filters out RFC-1918 private ranges, and applies a firewall block to the first three external IPs found.

| Platform | Mechanism | Privilege Required |
|---|---|---|
| Linux | `iptables -I INPUT -s <ip> -j DROP` | Root |
| Windows | Records intended block to `logs/threats.log` for operator action | — (netsh requires elevation) |

Private prefixes skipped: `10.*`, `192.168.*`, `172.16–31.*`, `127.*`, `0.0.0.0`

### ALERT_ADMIN

Sends an SMTP email alert to the configured `ADMIN_EMAIL` address. The email body includes threat type, severity, confidence percentage, triggered remediation actions, top model signals, and the truncated log line.

Silently skips if `ADMIN_EMAIL` environment variable is not set.

### LOG_AND_MONITOR

Appends a structured pipe-delimited record to `logs/threats.log`:

```
2026-04-09T14:32:07.123456 | BRUTE_FORCE | HIGH | conf=97.3% | Security[4625:failed_logon] warning AUDIT_FAILURE TargetUserName=admin IpAddress=203.0.113.5
```

The log directory is created automatically if it does not exist.

---

## Project Structure

```
Log-Analysis/
├── backend/
│   ├── main.py                        # FastAPI app — registers all routers
│   ├── routes/
│   │   ├── threat_routes.py           # GET  /api/threats, /api/logs, /api/health
│   │   ├── ingest_routes.py           # POST /api/ingest/{windows,network,syslog}
│   │   ├── system_routes.py           # POST /api/system/collect-analyze
│   │   └── metrics_routes.py          # GET  /api/metrics/live
│   ├── services/
│   │   ├── model_service.py           # Singleton model loader (pkl → cached instance)
│   │   ├── log_normalizer.py          # Windows / network / syslog → canonical string
│   │   └── remediation_engine.py      # BLOCK_IP · ALERT_ADMIN · LOG_AND_MONITOR
│   └── requirements.txt
├── ml_engine/
│   ├── train.py                       # Full training pipeline (NSL-KDD + SOCBED)
│   ├── upgraded_amides.pkl            # Serialized trained model (git-ignored)
│   └── model/
│       └── socbed_samples/            # Synthetic per-class log samples
├── frontend/
│   └── log-analysis/                  # Vite + React + TypeScript app
│       ├── public/
│       │   └── favicon.svg            # Shield logo (pink → purple → cyan gradient)
│       ├── src/
│       │   ├── pages/                 # 9 route-level page components
│       │   ├── components/
│       │   │   ├── layout/            # AppLayout · Header · Sidebar
│       │   │   └── ui/                # Charts · Cards · Dialogs
│       │   ├── context/
│       │   │   └── AnalysisContext.tsx # Global state + localStorage persistence
│       │   ├── services/
│       │   │   └── api.ts             # Axios client — all typed API functions
│       │   ├── constants/
│       │   │   ├── theme.ts           # Design tokens (colors, spacing)
│       │   │   └── mockData.ts        # Fallback data for static/demo mode
│       │   └── styles/
│       │       ├── dashboard.css
│       │       └── layout.css
│       ├── vercel.json                # SPA rewrite rule for React Router
│       ├── .env.production            # VITE_API_URL= (blank for static deploy)
│       ├── vite.config.ts
│       └── package.json
├── data/
│   └── KDDTrain+.csv                  # NSL-KDD dataset (auto-downloaded via kagglehub)
├── logs/
│   └── threats.log                    # Auto-created by RemediationEngine
├── docker/
│   ├── Dockerfile.backend
│   └── docker-compose.yml
└── scripts/
    └── collect_logs.py                # Standalone log collection utility
```

---

## Setup & Installation

### Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.9+ |
| Node.js | 18+ |
| npm | 9+ |
| Git | Any |

### 1 — Clone the Repository

```bash
git clone https://github.com/Nikhil06032004/AI-Log-Analysis-for-Cyber-Attack-Detection.git
cd AI-Log-Analysis-for-Cyber-Attack-Detection
```

### 2 — Backend Setup

```bash
# Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3 — Train the ML Model

```bash
python ml_engine/train.py
```

> First run will auto-download NSL-KDD from Kaggle. Requires `~/.kaggle/kaggle.json`.
> Alternatively, place `KDDTrain+.csv` in the `data/` directory manually.

### 4 — Frontend Setup

```bash
cd "frontend/log-analysis"
npm install
```

### 5 — Environment Variables (Optional)

Create `backend/.env` for optional features:

```env
ADMIN_EMAIL=your@email.com       # Enables email alerts on critical threats
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASS=your_app_password
```

---

## Running the Application

### Backend

```bash
# From project root, with venv activated
uvicorn backend.main:app --reload --port 8000
```

API will be available at `http://localhost:8000`
Interactive docs at `http://localhost:8000/docs`

### Frontend (Development)

```bash
cd "frontend/log-analysis"
npm run dev
```

Dashboard available at `http://localhost:5173/dashboard`

### Frontend (Production Build)

```bash
cd "frontend/log-analysis"
npm run build
npm run preview
```

### Docker (Full Stack)

```bash
docker-compose -f docker/docker-compose.yml up --build
```

---

## API Reference

### Health & Status

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health check — returns `{ status, timestamp }` |
| `GET` | `/api/status` | Model status — loaded, file exists, version |

### Threat Intelligence

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/threats` | Paginated threat feed with severity, confidence, protocol, status |
| `GET` | `/api/logs` | Full log stream with level and source metadata |
| `POST` | `/api/analyze/line` | Analyze a single raw log line — returns full prediction |

**Example — Single Line Analysis:**

```bash
curl -X POST http://localhost:8000/api/analyze/line \
  -H "Content-Type: application/json" \
  -d '{"log_line": "Failed password for root from 203.0.113.5 port 22 ssh2"}'
```

```json
{
  "threat_type": "BRUTE_FORCE",
  "severity": "high",
  "confidence": 0.97,
  "is_threat": true,
  "remediation_actions": ["BLOCK_IP", "LOG_AND_MONITOR", "ALERT_ADMIN"],
  "top_signals": { "failed_login": 0.82, "ssh_root": 0.71 }
}
```

### Log Ingestion

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/ingest/windows` | Ingest array of Windows Event Log objects |
| `POST` | `/api/ingest/network` | Ingest network flow records (JSON or NSL-KDD format) |
| `POST` | `/api/ingest/syslog` | Ingest array of raw syslog strings |
| `GET` | `/api/ingest/stats` | Cumulative ingestion statistics |

### System Log Collection

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/system/sources` | List available log sources for current platform |
| `POST` | `/api/system/collect-analyze` | Collect live host logs and run full inference pipeline |

**Example — Collect and Analyze:**

```bash
curl -X POST http://localhost:8000/api/system/collect-analyze \
  -H "Content-Type: application/json" \
  -d '{"sources": ["windows_security", "windows_system"], "max_events": 500}'
```

### System Metrics

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/metrics/live` | Snapshot of CPU (per-core), RAM, disk partitions, network I/O, top 8 processes |

**Example — Live Metrics:**

```bash
curl http://localhost:8000/api/metrics/live
```

```json
{
  "timestamp": "2026-04-27T10:30:00Z",
  "platform": "Windows",
  "hostname": "DESKTOP-XYZ",
  "cpu": { "percent": 14.2, "per_core": [12.1, 16.3, 11.8, 16.6], "count_logical": 4 },
  "ram": { "total_gb": 16.0, "used_gb": 9.4, "percent": 58.8 },
  "disk": { "root_total_gb": 476.0, "root_used_gb": 214.3, "root_percent": 45.0 }
}
```

---

## Tech Stack

### Backend

| Technology | Version | Role |
|---|---|---|
| **Python** | 3.9+ | Runtime |
| **FastAPI** | 0.100+ | REST API framework |
| **Uvicorn** | Latest | ASGI server |
| **XGBoost** | Latest | Primary ML classifier (600 trees) |
| **scikit-learn** | Latest | TF-IDF vectorizer, oversampling, pipeline |
| **imbalanced-learn** | Latest | `RandomOverSampler` for class balancing |
| **psutil** | Latest | Cross-platform live system resource metrics |
| **kagglehub** | Latest | Auto-download NSL-KDD dataset |

### Frontend

| Technology | Version | Role |
|---|---|---|
| **React** | 19 | UI framework |
| **TypeScript** | 5.9 | Static typing |
| **Vite** | 8 | Build tool and dev server |
| **React Router** | 7 | Client-side routing |
| **Apache ECharts** | 6 | Charts and data visualization |
| **Axios** | 1.x | HTTP client |

### Infrastructure

| Technology | Role |
|---|---|
| **Vercel** | Frontend static hosting (live demo) |
| **Docker** | Full-stack containerization |
| **GitHub Actions** | CI/CD (optional) |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Commit your changes: `git commit -m "feat: add your feature"`
4. Push to the branch: `git push origin feat/your-feature`
5. Open a Pull Request

Please follow conventional commits (`feat:`, `fix:`, `chore:`, `docs:`).

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built by [Nikhil S.](https://github.com/Nikhil06032004) · Powered by XGBoost + React · Deployed on Vercel

**[🚀 View Live Demo](https://ai-log-analysis-cyber-attack.vercel.app/dashboard)**

</div>
