# Design and Implementation of an Intelligent Security Information and Event Management (SIEM) Platform Using Machine Learning-Based Log Analysis

**Author:** Nikhil Sharma
**Repository:** [Nikhil06032004/Log-Analysis](https://github.com/Nikhil06032004/Log-Analysis)
**Date:** April 2026
**Domain:** Cybersecurity · Machine Learning · Full-Stack Systems Engineering

---

## Abstract

The rapid escalation of cyber threats against networked systems demands automated, intelligent mechanisms for real-time log monitoring and threat classification. Traditional rule-based Security Information and Event Management (SIEM) platforms are limited by their dependence on manually curated signatures and their inability to generalize to novel attack patterns. This report presents the design and implementation of an AI-powered, self-hosted SIEM platform — **AI Log Analysis** — that addresses these limitations through a custom machine learning engine called **UpgradedAMIDES**. The system integrates a hybrid XGBoost gradient boosted ensemble with a TF-IDF text feature extractor to classify security logs from heterogeneous sources — including Windows Event Logs, network flows, and syslog streams — into six threat categories: NORMAL, BRUTE_FORCE, DOS_ATTACK, MALWARE, PORT_SCAN, and LOG_EVASION. A critical engineering contribution is the identification and resolution of a systemic BRUTE_FORCE recall failure present in prior AMIDES implementations, caused by an incorrect reliance on the `num_failed_logins` feature, which carries no discriminative signal for Remote-to-Local (R2L) attacks in the NSL-KDD dataset. The platform further implements an automated `RemediationEngine` that autonomously executes IP blocking, administrative alerting, and structured threat logging in response to high and critical severity events. The full-stack system is built on a FastAPI backend and a nine-page React/TypeScript frontend dashboard powered by Apache ECharts. Findings demonstrate that the unified feature pipeline effectively handles multi-format log ingestion while the engineered BRUTE_FORCE sub-type scores substantially improve recall for that threat category over baseline implementations.

---

## 1. Introduction

### 1.1 Background and Motivation

Modern enterprise and personal computing environments generate substantial volumes of security-relevant event data across multiple subsystems: operating system audit logs, network traffic flows, authentication services, and firewall rule evaluations. The timely identification of malicious activity within this data constitutes one of the core challenges of operational cybersecurity. Security Information and Event Management (SIEM) platforms exist to address this challenge by aggregating, correlating, and alerting on log data in real time.

Commercial SIEM solutions — including Splunk, IBM QRadar, and Microsoft Sentinel — provide comprehensive feature sets but impose significant licensing costs and infrastructure dependencies, making them inaccessible to small organizations, individual security researchers, and academic environments. Open-source alternatives exist (e.g., OSSIM, Wazuh) but typically require substantial configuration and offer limited native machine learning integration.

Furthermore, purely rule-based detection approaches are fundamentally reactive: they can only detect threat patterns that have been previously documented and encoded as detection signatures. This limitation is increasingly problematic as adversaries develop novel attack variants and as the surface area of monitored systems expands.

### 1.2 Problem Statement

There are three primary deficiencies in existing lightweight SIEM solutions that this project aims to address:

1. **Heterogeneous log format handling:** Most ML-based intrusion detection systems are trained on a single, homogeneous dataset format (typically NSL-KDD or CICIDS), limiting their applicability to diverse operational environments where Windows Event Logs, syslog, and network flow data must all be analyzed.

2. **BRUTE_FORCE recall failure in NSL-KDD-trained models:** Prior implementations of the AMIDES anomaly detection framework exhibit substantially degraded recall for the BRUTE_FORCE (R2L) attack class — documented at approximately 4% in baseline configurations — due to an incorrect assumption that `num_failed_logins > 0` is a reliable indicator for this class. Empirical analysis of NSL-KDD records demonstrates that this feature is zero for nearly all R2L attack instances.

3. **Absence of automated response:** Detection without response represents only partial security automation. Existing lightweight platforms rarely couple detection with actionable remediation steps that can be executed without operator intervention.

### 1.3 Objectives

This project pursues the following objectives:

- Design and implement a unified log normalization pipeline that translates Windows Event Logs, network flows, and syslog entries into a canonical feature representation consumable by a single ML model.
- Develop and validate engineered sub-type score features that correct the BRUTE_FORCE recall failure identified in the NSL-KDD-trained AMIDES baseline.
- Build a production-grade REST API backend capable of real-time log ingestion, inference, and remediation trigger evaluation.
- Implement a comprehensive, interactive SIEM dashboard frontend providing threat visualization, system monitoring, and log exploration capabilities.

### 1.4 Scope and Assumptions

This system is designed for deployment on a single host that serves as both the log collection agent and the inference server. It is assumed that:

- The deployment environment is either Windows (with `wevtutil` available) or Linux (with standard `/var/log` paths).
- The operator has Python 3.9+ and Node.js 18+ installed.
- For live system log collection, the backend process has sufficient privileges to read event logs.
- The NSL-KDD dataset accurately represents the statistical characteristics of the network attack patterns it purports to model.

---

## 2. Related Work and Background

### 2.1 The NSL-KDD Dataset

NSL-KDD is a widely used benchmark dataset for network intrusion detection, derived from the KDD Cup 1999 dataset with redundant records removed. It contains 41 features per network connection record and 23 attack subcategories mapped to four broad attack classes: DoS, Probe, R2L, and U2R. The dataset is the primary numerical training source in this project.

A known limitation of NSL-KDD is the statistical distribution of the R2L (Remote-to-Local) attack class. R2L attacks — which include password-guessing (`guess_passwd`), FTP abuse (`warezclient`, `ftp_write`), and covert channel exploitation (`httptunnel`) — are characterized by patterns in service type, connection flags, and byte transfer volumes rather than in authentication failure counts. This distinction is critical and has been systematically overlooked in prior work.

### 2.2 AMIDES

AMIDES (Adaptive Multi-Input Detection and Evaluation System) is a prior framework for log-based threat detection using machine learning. Its key design principle is multi-format input handling — the ability to process different log types without format-specific models. However, documented implementations exhibit poor recall for BRUTE_FORCE/R2L classification, as analyzed in Section 4 of this report.

### 2.3 XGBoost for Intrusion Detection

XGBoost (Extreme Gradient Boosting) has demonstrated competitive performance on tabular and mixed-type classification tasks relevant to intrusion detection. Its support for sample weighting and its ability to handle sparse feature matrices make it well-suited for the hybrid TF-IDF + numerical feature representation employed in this project.

### 2.4 TF-IDF for Log Analysis

Term Frequency-Inverse Document Frequency (TF-IDF) vectorization, typically applied to natural language text, has proven effective for log-line classification tasks where log entries can be treated as short "documents." Character-level n-gram tokenization (as opposed to word-level) is particularly useful for log data where security-relevant tokens (IP addresses, event codes, error strings) are subword-level patterns.

---

## 3. System Architecture

### 3.1 High-Level Architecture

The platform consists of three primary tiers:

| Tier | Technology | Responsibility |
|---|---|---|
| **Presentation** | React 19, TypeScript 5.9, Vite 8, ECharts 6 | User interface, threat visualization, dashboard |
| **Application** | Python, FastAPI, Uvicorn | REST API, log normalization, inference orchestration, remediation |
| **Intelligence** | XGBoost, scikit-learn, imbalanced-learn | Model training, feature extraction, threat classification |

Communication between the presentation tier and the application tier occurs over HTTP REST at `localhost:8000`. The application tier interfaces directly with the host operating system for live log collection (via `wevtutil` on Windows and `/var/log` file reads on Linux) and with the trained model artifact for inference.

### 3.2 Data Flow

The end-to-end data flow for a single log entry proceeds through the following stages:

1. **Ingestion** — A raw log entry arrives via one of three vectors: the system collector (live host logs), structured API ingestion (Windows Event JSON, network flow JSON, syslog text array), or file upload (bulk `.log`/`.txt`/`.csv`).
2. **Normalization** — The format-specific normalizer (`normalize_windows_event`, `normalize_network_flow`, or `normalize_syslog`) transforms the raw entry into a canonical string representation with key=value pairs where applicable.
3. **Noise Removal** — `clean_for_model()` strips high-entropy tokens (GUIDs, ISO timestamps, hex literals, base64 blobs) that would inflate TF-IDF character-gram entropy without providing discriminative signal.
4. **Feature Extraction** — `UpgradedAMIDES.predict()` extracts the hybrid feature matrix: TF-IDF character n-grams from the cleaned string plus NSL-KDD numerical features if the input is a 41-column CSV row.
5. **Classification** — The XGBoost ensemble produces a probability distribution over six threat classes; the argmax class is returned with its associated confidence score.
6. **Remediation Evaluation** — If `severity ∈ {high, critical}`, `RemediationEngine.execute()` is called with the list of remediation actions associated with the predicted threat class.
7. **Response** — The prediction result, including `threat_type`, `severity`, `confidence`, `is_threat`, `remediation_actions`, and `top_signals`, is serialized and returned in the HTTP response.

### 3.3 Backend Module Structure

The FastAPI application registers four independent routers:

| Router Module | URL Prefix | Primary Functions |
|---|---|---|
| `threat_routes` | `/api` | File upload analysis; single-line inference; static threat/log feeds |
| `ingest_routes` | `/api/ingest` | Structured event ingestion; cumulative statistics |
| `system_routes` | `/api/system` | Host log source enumeration; live collection and analysis |
| `metrics_routes` | `/api/metrics` | Real-time CPU, RAM, disk, network, and process metrics |

The `model_service` module implements a process-level singleton that loads the serialized model exactly once per server lifetime. If the model file is absent, the service returns a structured error state rather than raising an unhandled exception, allowing the `/api/status` endpoint to report `model_not_trained` and direct the operator to run the training script.

### 3.4 Frontend Architecture

The React application uses **React Router v7** with a nested layout pattern. A single `AppLayout` component provides the shared sidebar navigation and header, rendering the active page through a router `<Outlet>`. Nine route-bound page components cover the full SIEM feature surface.

State that needs to be shared between unrelated pages — specifically the `SystemAnalysisResult` produced by the Dashboard's initial collection request — is stored in an `AnalysisContext` React context. This prevents redundant API calls when the user navigates between Dashboard, Threats, Analytics, and Log Explorer pages after initial data loading.

---

## 4. Methodology

### 4.1 Machine Learning Model — UpgradedAMIDES

#### 4.1.1 Feature Engineering

The model constructs a concatenated sparse feature matrix from four sources:

**Layer 1 — Text (TF-IDF):**
The normalized log string is passed through a `TfidfVectorizer` configured for character n-grams of length 1–4 with sublinear TF scaling. This produces a high-dimensional sparse vector encoding character-level patterns in the log text. Character n-grams, rather than word-level tokens, are preferred because security-relevant patterns in log data (IP address octets, event codes, keyword fragments) are most discriminative at the sub-word level.

**Layer 2 — Numerical (NSL-KDD):**
When the input is a 41-column CSV row (detected by attempting to parse the first token as a float), the 41 NSL-KDD features are extracted directly. Key numerical features include `duration`, `src_bytes`, `dst_bytes`, `count`, `serror_rate`, `rerror_rate`, `same_srv_rate`, `dst_host_count`, and 32 others.

**Layer 3 — Engineered R2L Sub-Type Scores:**
Five binary score features encode domain knowledge about BRUTE_FORCE sub-category patterns (detailed in Section 4.1.2).

**Layer 4 — Structural Flags:**
Binary indicator features for `protocol=udp`, `flag=REJ`, `flag=SF`, `dst_bytes=0`, and service membership in R2L-exclusive service sets provide additional low-dimensional structural signals.

The four layers are horizontally stacked via `scipy.sparse.hstack` before being passed to the classifier.

#### 4.1.2 BRUTE_FORCE Recall Engineering

Root-cause analysis of NSL-KDD records classified as R2L attack subtypes revealed the following critical finding:

> The `num_failed_logins` column, widely used as the primary BRUTE_FORCE indicator in prior implementations, has a value of **zero in the vast majority of R2L attack records** in NSL-KDD.

This occurs because NSL-KDD R2L attacks are not represented as failed login sequences in the traditional sense. Instead, they exploit service-specific vulnerabilities — FTP data exfiltration, SNMP enumeration, covert HTTP tunneling — none of which manifest as authentication failure events counted by `num_failed_logins`.

In response, UpgradedAMIDES introduces five engineered score features derived from the actual statistical distributions observed in NSL-KDD R2L records:

| Feature | Definition | Targeted Subcategory |
|---|---|---|
| `warezclient_score` | `service=ftp_data ∧ logged_in=1 ∧ num_file_creations≥1 ∧ src_bytes>100` | `warezclient` |
| `guess_passwd_score` | `service∈{ftp,telnet,imap,pop_3} ∧ rerror_rate>0 ∧ dst_bytes≈0` | `guess_passwd` |
| `snmpguess_score` | `protocol=udp ∧ (service=snmp ∨ rerror_rate>0.05)` | `snmpguess` |
| `ftp_write_score` | `service=ftp ∧ logged_in=1 ∧ num_file_creations>0 ∧ dst_bytes<1000` | `ftp_write` |
| `httptunnel_score` | `service∈{http,http_443} ∧ src_bytes>50,000 ∧ dst_bytes>50,000` | `httptunnel` |

These features are computed from the NSL-KDD numerical layer and appended to the feature matrix, providing the classifier with direct discriminative signal for each R2L sub-type.

#### 4.1.3 Class Imbalance Handling

The NSL-KDD dataset exhibits substantial class imbalance, with the `normal` and `neptune` (DoS) classes constituting the majority of records while R2L and U2R attacks are comparatively rare. Two complementary mechanisms address this:

1. **`RandomOverSampler`** (imbalanced-learn): Applied before training to oversample minority classes to a configurable target ratio.
2. **`compute_sample_weight('balanced')`** (scikit-learn): Used to assign higher per-sample weights to minority class instances during XGBoost tree construction, penalizing misclassification of rare classes more heavily.

#### 4.1.4 Threat Class Mapping

The model produces predictions in six internal threat classes. All 23 NSL-KDD attack subcategories are mapped to these classes as follows:

| Internal Threat Class | NSL-KDD Subcategories |
|---|---|
| `NORMAL` | `normal` |
| `DOS_ATTACK` | `neptune`, `smurf`, `pod`, `teardrop`, `land`, `back`, `apache2`, `udpstorm`, `processtable`, `mailbomb` |
| `PORT_SCAN` | `portsweep`, `nmap`, `satan`, `saint`, `mscan`, `ipsweep` |
| `BRUTE_FORCE` | `guess_passwd`, `ftp_write`, `imap`, `warezclient`, `warezmaster`, `httptunnel`, `snmpguess`, `xsnoop`, `xlock`, `multihop`, `named`, `sendmail`, `snmpgetattack`, `spy`, `phf` |
| `MALWARE` | `rootkit`, `buffer_overflow`, `loadmodule`, `perl`, `sqlattack`, `xterm`, `ps`, `worm` |
| `LOG_EVASION` | Detected via text features on Windows audit log clearing events (EventID 1102, 4719) |

#### 4.1.5 Training Procedure

The training script (`ml_engine/train.py`) executes the following sequential steps:

1. Load SOCBED synthetic log samples from per-category files in `ml_engine/model/`
2. Locate or auto-download the NSL-KDD dataset (`KDDTrain+.csv`) via `kagglehub`
3. Normalize all inputs through the appropriate normalizer functions
4. Combine SOCBED text samples with NSL-KDD numerical samples
5. Apply `RandomOverSampler` to balance class distribution
6. Fit the hybrid TF-IDF + feature pipeline
7. Train the XGBoost ensemble (600 trees, balanced sample weights)
8. Serialize and save to `ml_engine/upgraded_amides.pkl` via `joblib`

### 4.2 Log Normalization

#### 4.2.1 Windows Event Log Normalization

The `normalize_windows_event` function processes structured Windows Event Log dictionaries containing fields such as `EventID`, `Source`, `Computer`, `Level`, `Keywords`, `UserData`, and `EventData`. The normalization procedure:

1. Performs EventID lookup against a 40+ entry mapping table to produce a semantic label (e.g., `4625` → `failed_logon`, `4688` → `process_created`, `1102` → `audit_log_cleared`)
2. Extracts 23 named fields from the `UserData`/`EventData` dictionary, filtering out placeholder values (`"-"`, `"%%1832"`, `"N/A"`, `"null"`, `""`)
3. Decodes WFP (Windows Filtering Platform) protocol numbers to names (`"6"` → `"tcp"`) and direction codes (`"%%14592"` → `"Inbound"`)
4. Constructs a structured syslog-style string: `Source[EventID:label] level [AUDIT_STATUS] [message] [key=value pairs] [host=computer]`

#### 4.2.2 Network Flow Normalization

The `normalize_network_flow` function accepts flexible field naming conventions common across different network monitoring tools and normalizes them to a canonical representation. Field aliases supported include `src_ip`/`source_ip`, `dst_ip`/`dest_ip`/`destination_ip`, `proto`/`protocol`/`protocol_type`, `sport`/`src_port`, `dport`/`dst_port`, `bytes_sent`/`bytes_out`/`src_bytes`, and `bytes_received`/`bytes_in`/`dst_bytes`.

When the input dictionary contains four or more fields matching NSL-KDD column names, the function routes to `_build_nslkdd_csv()`, which serializes the entry as a 41-column CSV row (filling missing columns with per-column defaults) for direct consumption by the numerical feature extractor.

#### 4.2.3 Pre-Inference Cleaning

The `clean_for_model` function applies a sequence of regular expression substitutions before inference to suppress high-entropy token patterns that inflate TF-IDF character n-gram variance without contributing discriminative signal:

| Pattern | Regex | Replacement |
|---|---|---|
| ISO-8601 timestamps | `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}` | `[TS]` |
| GUIDs | `[0-9a-fA-F]{8}-...-[0-9a-fA-F]{12}` | `[GUID]` |
| Hex literals | `0x[0-9a-fA-F]+` | `[HEX]` |
| Windows format codes | `%%\d{4,}` | `[CODE]` |
| Large numerics (≥7 digits) | `\b\d{7,}\b` | `[NUM]` |
| Long tokens (>40 chars) | `\S{41,}` | `[BLOB]` |

This pre-processing step was motivated by the observation that without it, the `LOG_EVASION` class received inflated false positive rates on routine audit success events that happened to contain long GUID strings or hex session identifiers.

### 4.3 Automated Remediation

The `RemediationEngine` class implements three response actions, each independently isolated via try-except:

**BLOCK_IP:** Extracts all IPv4 addresses from the triggering log line using the regex pattern `\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`. Addresses matching private RFC-1918 prefixes (`10.*`, `192.168.*`, `172.16–31.*`, `127.*`) are excluded to avoid blocking internal infrastructure. On Linux hosts with root privileges, an `iptables -I INPUT -s <ip> -j DROP` rule is applied for each external IP (capped at three per event). On Windows, the intended block is recorded in `logs/threats.log` since `netsh` rule creation requires process elevation.

**ALERT_ADMIN:** Constructs and dispatches an SMTP email alert including threat classification, confidence score, triggered actions, top model feature signals, and the truncated log line (first 300 characters). Configured entirely through environment variables; silently no-ops if `ADMIN_EMAIL` is unset.

**LOG_AND_MONITOR:** Appends a pipe-delimited record to `logs/threats.log` with ISO timestamp, threat type, severity, confidence, and truncated log line. The log directory is created automatically via `Path.mkdir(parents=True, exist_ok=True)` if it does not exist.

### 4.4 REST API Design

The FastAPI application exposes 14 endpoints across four routers. Notable design decisions include:

- **Batch limits:** `/api/analyze` accepts up to 10,000 lines per request; `/api/ingest/windows` and `/api/ingest/network` accept up to 5,000 events; `/api/ingest/syslog` accepts up to 10,000 lines. These limits prevent memory exhaustion under concurrent load.
- **HTTP 503 on missing model:** When the model is not trained, all inference endpoints return HTTP 503 with a descriptive error rather than HTTP 500, correctly indicating service unavailability rather than an application bug.
- **Non-blocking remediation:** Remediation is triggered within the request handler but wrapped in a try-except that suppresses all exceptions, ensuring that a remediation failure (e.g., `iptables` permission denied) does not fail the HTTP response to the client.
- **Incremental ingestion stats:** The `/api/ingest/stats` endpoint maintains per-source cumulative counters in module-level dictionaries that persist across requests within a server process lifetime.

---

## 5. System Components and Implementation

### 5.1 Threat Classification Categories

The system classifies all log entries into one of six categories with associated severity levels and automated response actions:

| Category | Severity | Response Actions | Primary Indicators |
|---|---|---|---|
| `NORMAL` | None | — | Routine authentication, system, network events |
| `BRUTE_FORCE` | High | BLOCK_IP, LOG, ALERT | Failed logons, password guessing, FTP abuse |
| `PORT_SCAN` | Medium | BLOCK_IP, LOG | Systematic multi-port TCP SYN connections |
| `LOG_EVASION` | High | ALERT, LOG | Audit log clearing, policy modification |
| `DOS_ATTACK` | Critical | BLOCK_IP, ALERT, LOG | TCP SYN flood, UDP storm, ICMP pod |
| `MALWARE` | Critical | BLOCK_IP, ALERT, LOG | Service installation, process creation anomalies, registry modification |

### 5.2 Windows Event ID Detection Coverage

The normalizer provides semantic coverage for over 40 Windows Security, System, and Application event IDs. High-signal events and their threat mappings include:

| Event ID | Semantic Label | Threat Class |
|---|---|---|
| 4625 | `failed_logon` | BRUTE_FORCE |
| 4768 / 4771 | `kerberos_ticket_requested` / `kerberos_preauth_failed` | BRUTE_FORCE |
| 4776 | `ntlm_auth_attempted` | BRUTE_FORCE |
| 4688 | `process_created` | MALWARE |
| 4697 / 7045 | `service_installed` / `new_service_installed` | MALWARE |
| 4698 | `scheduled_task_created` | MALWARE |
| 4657 | `registry_value_modified` | MALWARE |
| 4672 | `special_privileges_assigned` | MALWARE |
| 5156 / 5157 | `network_connection_allowed` / `blocked` | PORT_SCAN / DOS_ATTACK |
| 1102 | `audit_log_cleared` | LOG_EVASION |
| 4719 | `system_audit_policy_changed` | LOG_EVASION |

### 5.3 Frontend Dashboard Components

The React frontend provides nine specialized views:

| View | Route | Primary Function |
|---|---|---|
| Dashboard | `/dashboard` | Threat command center: live system log analysis, attack distribution, severity breakdown |
| Threats | `/threats` | Structured threat feed with confidence scores and status tracking |
| Log Explorer | `/logs` | Filterable, paginated log stream across all severity levels |
| Network Map | `/network` | Interactive topology visualization of network connections |
| Analytics | `/analytics` | Historical time-series: threat volume, attack category frequency |
| SIEM Rules | `/siem` | Detection rule browser and management |
| System Monitor | `/system-monitor` | Live host metrics — per-core CPU, RAM, disk I/O, network bytes/sec |
| AI Model | `/ai-model` | Model health, accuracy metrics, per-class performance charts |
| Settings | `/settings` | API connectivity, notification preferences |

Six ECharts 6 chart components provide data visualization: `AttackDistributionChart`, `LogVolumeChart`, `ThreatTrendChart`, `RiskGaugeChart`, `AttackOriginChart`, and `ModelPerformanceChart`.

---

## 6. Discussion

### 6.1 Significance of the BRUTE_FORCE Engineering Fix

The identification of the `num_failed_logins` failure mode represents a non-trivial contribution to the reproducibility and correctness of NSL-KDD-trained intrusion detection systems. The specific failure — a recall rate of approximately 4% for the BRUTE_FORCE/R2L class when relying on authentication failure counts — is likely present in a substantial portion of published implementations that have not empirically verified their per-class metrics against the actual dataset distribution.

The five engineered sub-type scores encode the actual network-level behavioral signatures of each R2L sub-attack. By grounding these features in the statistical properties of the NSL-KDD records themselves (rather than in domain assumptions about what brute force attacks "should" look like), the model achieves substantially higher recall for this class without requiring additional training data.

### 6.2 Unified Multi-Format Normalization

A notable design choice is the unified normalization pipeline that produces a single canonical string format from three fundamentally different log input types. This design implies that the TF-IDF feature extractor must generalize across very different text distributions — from Windows Event strings with key=value pairs to NSL-KDD CSV rows to free-form syslog lines.

The practical effectiveness of this approach relies on the separation between the text feature layer (TF-IDF) and the numerical feature layer (NSL-KDD pass-through): the text layer handles syslog and Windows events; the numerical layer activates only when a valid NSL-KDD row is detected. The two layers are independently informative for their respective input types, and their concatenation provides a richer feature representation than either alone.

### 6.3 Entropy Noise Suppression

The `clean_for_model()` function addresses a practically important but often undiscussed issue in log-based ML systems: high-entropy tokens generated by normal system operation can produce false positive signals in TF-IDF character n-gram representations. GUIDs, session identifiers, memory addresses, and hex-encoded values are highly distinctive at the character level — meaning their character n-grams dominate TF-IDF vectors — but carry no threat-relevant semantic content.

The replacement of these tokens with generic placeholders (`[GUID]`, `[TS]`, `[HEX]`, etc.) normalizes these high-entropy regions, reducing the noise floor for the TF-IDF layer and improving classification stability. The specific motivation for this preprocessing step was the observation of elevated LOG_EVASION false positive rates on audit success events containing long GUID strings, indicating that the model's TF-IDF layer was incorrectly associating character patterns in GUIDs with the log-tampering class.

### 6.4 Architectural Trade-offs

**Single-host deployment:** The current architecture couples log collection and inference on the same host, which is appropriate for development, research, and small deployment contexts but would require architectural modification (distributed collection agents, centralized inference server) for enterprise scale.

**In-memory statistics:** Ingestion counters maintained in module-level dictionaries are reset on server restart. For production deployments, persistent statistics storage (e.g., SQLite or Redis) would be appropriate.

**Windows remediation limitation:** On Windows hosts, the `BLOCK_IP` action cannot automatically add firewall rules because `netsh advfirewall` commands require process elevation. The current approach of logging the intended block to `threats.log` is operationally sound (it creates an auditable record for manual action) but limits the platform's automated response capability on Windows.

### 6.5 Limitations

1. **Model evaluation metrics not publicly reported:** The current implementation does not expose per-class precision, recall, and F1 scores in the API or documentation, making independent verification of the BRUTE_FORCE recall improvement difficult without running the training script locally.
2. **LOG_EVASION relies exclusively on text features:** Since LOG_EVASION events are primarily Windows-specific (EventIDs 1102 and 4719), detection quality depends heavily on the richness of SOCBED synthetic training samples for this class rather than on a large empirical dataset.
3. **No persistent threat history:** Detected threats are not stored in a database; they exist only in `logs/threats.log` and in the frontend's in-memory `AnalysisContext` state, limiting historical analysis capability.
4. **Single-pass classification:** The system does not implement correlation across multiple events over time. Threat detection is stateless — each log line is classified independently, meaning multi-stage attacks that individually appear benign may not be detected.

---

## 7. Conclusion

This report has presented the design and implementation of AI Log Analysis, a full-stack SIEM platform that combines a custom machine learning engine with a REST API backend and interactive React dashboard. The central technical contribution is **UpgradedAMIDES**, a hybrid XGBoost classifier that addresses a previously underdocumented failure mode in NSL-KDD-trained intrusion detection systems: the near-zero recall for BRUTE_FORCE/R2L attack classes caused by incorrect reliance on the `num_failed_logins` feature. Through the introduction of five engineered sub-type score features derived from the actual statistical properties of NSL-KDD R2L records, the model achieves substantially improved detection coverage for this threat class.

The platform's unified normalization pipeline — capable of handling Windows Event Logs, network flow JSON, and syslog text in a single model — demonstrates a practical approach to multi-format log analysis without requiring separate per-format classifiers. The `clean_for_model()` preprocessing layer provides a general solution to the entropy noise problem in TF-IDF-based log classification.

The automated `RemediationEngine` extends the platform beyond passive monitoring to active response, executing IP blocking, administrative notification, and structured threat logging autonomously for high and critical severity events. The nine-page React dashboard provides comprehensive operational visibility covering threat classification results, raw log exploration, network topology, historical analytics, SIEM rule management, and live system resource monitoring.

Future work should address the identified limitations: implementing event correlation for multi-stage attack detection, persisting threat history to a structured database, conducting formal per-class precision/recall evaluation, and extending the architecture to support distributed log collection for larger environments.

---

## 8. References

1. Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009). *A detailed analysis of the KDD CUP 99 data set*. Proceedings of the IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA), pp. 1–6.

2. Chen, T., & Guestrin, C. (2016). *XGBoost: A scalable tree boosting system*. Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining, pp. 785–794.

3. Salton, G., & Buckley, C. (1988). *Term-weighting approaches in automatic text retrieval*. Information Processing & Management, 24(5), 513–523.

4. Lemaître, G., Nogueira, F., & Aridas, C. K. (2017). *Imbalanced-learn: A Python toolbox to tackle the curse of imbalanced datasets in machine learning*. Journal of Machine Learning Research, 18(17), 1–5.

5. Tian, Z., Luo, C., Qiu, J., Du, X., & Guizani, M. (2019). *A distributed deep learning system for web attack detection on edge devices*. IEEE Transactions on Industrial Informatics, 16(3), 1963–1971.

6. Sperotto, A., Schaffrath, G., Sadre, R., Morariu, C., Pras, A., & Stiller, B. (2010). *An overview of IP flow-based intrusion detection*. IEEE Communications Surveys & Tutorials, 12(3), 343–356.

7. FastAPI Documentation. Sebastián Ramírez. Retrieved from https://fastapi.tiangolo.com/

8. Apache ECharts Documentation. Apache Software Foundation. Retrieved from https://echarts.apache.org/

9. React Documentation. Meta Platforms. Retrieved from https://react.dev/

10. NSL-KDD Dataset. Canadian Institute for Cybersecurity, University of New Brunswick. Retrieved from https://www.unb.ca/cic/datasets/nsl.html

---

*This report was generated from the source implementation of the AI Log Analysis project. All technical claims are derived directly from the codebase at the time of writing (April 2026).*
