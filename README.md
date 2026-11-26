# NetSentinel AI

An AI-powered cybersecurity threat detection dashboard built with Python, Flask, SQLite, Scapy, Scikit-learn, and Chart.js.

## Tech Stack

- **Backend:** Python 3.13, Flask, Flask-SQLAlchemy, SQLite
- **Packet & Data Processing:** Scapy, Pandas, NumPy
- **Machine Learning:** Scikit-learn (`IsolationForest`), Joblib
- **Frontend:** HTML, CSS, JavaScript, Chart.js
- **Optional Integrations:** OpenAI API, AbuseIPDB API, VirusTotal API

## Project Structure

```text
netsentinel-ai/
├── app/
│   ├── __init__.py          # Flask application factory & SQLite initialization
│   ├── extensions.py        # Shared Flask-SQLAlchemy db instance
│   ├── models.py            # SQLAlchemy Alert model
│   ├── validators.py        # Request payload validation helpers
│   ├── routes.py            # Web, health-check, and alert API routes
│   ├── ml/
│   │   ├── __init__.py      # ML package marker
│   │   ├── feature_schema.py# Standard 11-feature flow schema & validation
│   │   └── predict.py       # Reusable IsolationForest prediction helpers
│   ├── services/
│   │   ├── __init__.py      # Service layer package marker
│   │   ├── detection_engine.py# Hybrid ML + rules + threat-intel risk scoring engine
│   │   ├── flow_aggregator.py# Deterministic 5-tuple bidirectional flow aggregator
│   │   ├── llm_explainer.py # Optional sanitized OpenAI alert explanation generator
│   │   ├── monitoring_service.py# End-to-end capture -> flow -> ML -> SQLite pipeline
│   │   ├── packet_capture.py# Controlled Scapy metadata-only packet capture service
│   │   ├── rule_engine.py   # Explainable heuristic flow rules
│   │   └── threat_intel.py  # Optional AbuseIPDB lookup with TTL cache & safety guards
│   ├── static/
│   │   ├── css/style.css    # Dashboard stylesheet
│   │   └── js/dashboard.js  # Live API polling & Chart.js severity chart
│   └── templates/
│       └── dashboard.html   # Main dashboard HTML template
├── scripts/
│   ├── benchmark_unsw_models.py# Compare IsolationForest vs balanced RandomForest on UNSW-NB15
│   ├── generate_demo_data.py# Synthetic benign & anomalous flow data generator
│   ├── run_capture.py       # Controlled packet capture CLI (--demo / --live)
│   ├── run_monitor.py       # Full monitoring pipeline CLI (--demo / --live)
│   ├── train_model.py       # Train IsolationForest on synthetic benign flows
│   └── train_unsw_model.py  # Train & evaluate IsolationForest on UNSW-NB15
├── tests/
│   ├── test_alerts.py       # Alert model and API endpoint tests
│   ├── test_benchmark_unsw.py# UNSW-NB15 benchmarking & RandomForest prediction tests
│   ├── test_detection_engine.py# RuleEngine and DetectionEngine tests
│   ├── test_flow_aggregator.py# FlowAggregator unit tests
│   ├── test_health.py       # Health and homepage route tests
│   ├── test_llm_explainer.py# Mocked LLM explainer & /explain endpoint tests
│   ├── test_ml.py           # Feature schema, training, evaluation & prediction tests
│   ├── test_monitoring.py   # End-to-end monitoring pipeline & CLI tests
│   ├── test_packet_capture.py# Mocked Scapy packet capture & CLI safety tests
│   ├── test_threat_intel.py # Mocked AbuseIPDB lookup, caching & API route tests
│   └── test_unsw_training.py# UNSW-NB15 mapping, chunked training & ML_MODEL_PATH tests
├── .env.example             # Sample environment configuration
├── .gitignore               # Git ignore rules for secrets, DBs, models, and caches
├── README.md                # Project documentation
├── requirements.txt         # Python dependencies
└── run.py                   # Application entry point
```

## API Endpoints

- `GET /` — Threat detection dashboard UI
- `GET /health` — Service health status JSON
- `GET /api/alerts` — List stored alerts (supports `?severity=`, `?status=`, `?source_ip=`, `?destination_ip=`, `?limit=`)
- `POST /api/alerts` — Validate and persist a new security alert
- `POST /api/alerts/<id>/explain` — Generate a structured explanation on demand (OpenAI if configured, else rule-based fallback)
- `GET /api/summary` — Aggregated counts (`total_alerts`, `critical_alerts`, `high_alerts`, `suspicious_ip_count`)
- `GET /api/threat-intel/<ip>` — Optional AbuseIPDB IP reputation lookup (returns `private` for non-public IPs, `unknown` when `ABUSEIPDB_API_KEY` is unconfigured)

## Getting Started

1. **Activate the existing virtual environment:**
   - Windows (PowerShell):
     ```powershell
     .\.venv\Scripts\Activate.ps1
     ```

2. **Create your local `.env` file (optional for initial run):**
   ```powershell
   Copy-Item .env.example .env
   ```

3. **Run the Flask development server:**
   ```powershell
   .\.venv\Scripts\python.exe run.py
   ```
   The SQLite database is created automatically on startup. Open `http://127.0.0.1:5000/` in your browser.

## ML Training & Anomaly Detection

NetSentinel AI uses an unsupervised `IsolationForest` model trained **only on benign network-flow data** across the 11 standard flow features defined in `app/ml/feature_schema.py`:
`duration`, `protocol`, `source_port`, `destination_port`, `flow_bytes`, `flow_packets`, `forward_packets`, `backward_packets`, `average_packet_size`, `packet_rate`, and `byte_rate`.

1. **Generate synthetic benign training and evaluation datasets:**
   ```powershell
   .\.venv\Scripts\python.exe scripts/generate_demo_data.py
   ```
   This writes `data/benign_train.csv`, `data/benign_eval.csv`, and `data/anomalous_eval.csv`.

2. **Train and evaluate the IsolationForest pipeline:**
   ```powershell
   .\.venv\Scripts\python.exe scripts/train_model.py
   ```
   This trains the preprocessing (`StandardScaler` + `OneHotEncoder`) and `IsolationForest` pipeline solely on `data/benign_train.csv`, saves the artifact to `models/isolation_forest.joblib` (excluded from Git via `.gitignore`), and prints Precision, Recall, F1-Score, and the 2x2 Confusion Matrix on the synthetic evaluation data.

3. **Run predictions in Python:**
   ```python
   from app.ml.predict import predict_flow

   result = predict_flow({
       "duration": 0.25,
       "protocol": "TCP",
       "source_port": 51234,
       "destination_port": 443,
       "flow_bytes": 4200.0,
       "flow_packets": 10,
       "forward_packets": 5,
       "backward_packets": 5,
       "average_packet_size": 420.0,
       "packet_rate": 40.0,
       "byte_rate": 16800.0,
   })
   # {"anomaly_score": ..., "prediction": "normal", "confidence": ...}
   ```

## Network-Flow Aggregation

`app/services/flow_aggregator.py` provides `FlowAggregator`, which converts normalized packet metadata into bidirectional network flows ready for ML inference and alert creation:

- **Flow Key & Directionality:** Groups packets using a canonical bidirectional 5-tuple (`source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`). The first packet seen establishes the initiator direction (`source_ip`/`source_port` -> `destination_ip`/`destination_port`) and increments `forward_packets`; reply packets on the reverse 5-tuple merge into the same flow and increment `backward_packets`.
- **Tracked Metrics:** Maintains `first_seen`, `last_seen`, `duration`, `flow_bytes`, `flow_packets`, `forward_packets`, `backward_packets`, `average_packet_size`, `packet_rate`, `byte_rate`, and observed `tcp_flags`.
- **Zero-Duration Handling:** Single-packet or identical-timestamp flows produce `duration = 0.0`, `packet_rate = 0.0`, and `byte_rate = 0.0` (avoiding division by zero).
- **Inactivity Timeout & Flushing:** Flows idle for at least `inactivity_timeout` seconds are expired via `flush_expired(current_time=...)` (or an injected `time_fn`), and all remaining flows can be drained via `flush_all()`.
- **Output Compatibility:** Every returned dictionary preserves `source_ip` and `destination_ip` for alert reporting and satisfies `app/ml/feature_schema.py` (`validate_flow_record()` and `predict_flow()`).

## Controlled Packet Capture & Legal/Safety Notice

> **Important Legal & Safety Notice:**
> - **Authorized Use Only:** Only run live packet capture on a network interface you own or have explicit written authorization to monitor. Unauthorized network interception may violate local, state, or federal laws and organizational policies.
> - **Metadata Only:** `app/services/packet_capture.py` uses Scapy with `store=False` and extracts only packet header metadata (`timestamp`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`, `packet_length`, `tcp_flags`). Packet payloads are never captured, stored, or logged.
> - **No Auto-Capture:** Starting the Flask web application (`run.py`) never starts packet capture.
> - **Explicit `--live` Guard:** `scripts/run_capture.py` refuses to start live capture unless `--live` is explicitly provided.

1. **Run safe synthetic demo mode (no network interface touched):**
   ```powershell
   .\.venv\Scripts\python.exe scripts/run_capture.py --demo
   ```

2. **Run authorized live capture on an interface you control:**
   ```powershell
   .\.venv\Scripts\python.exe scripts/run_capture.py --live --interface "Wi-Fi" --limit 50 --timeout 15 --filter "tcp or udp"
   ```
   Press `Ctrl+C` at any time to stop capture gracefully and flush active flows.

## Explainable Detection & Risk-Scoring Design

`app/services/rule_engine.py` and `app/services/detection_engine.py` combine machine learning with transparent heuristics to evaluate aggregated flows without claiming certainty:

- **Heuristic Rules (`RuleEngine`):** Checks four categories—unusually high packet rate, unusually high byte rate, unusually large flow size, and suspicious protocol/port combinations (e.g., UDP targeting TCP admin ports, ICMP with non-zero ports, or commonly abused ports)—recording human-readable evidence for each matched rule.
- **ML Integration (`app/ml/predict.py`):** Runs the local `IsolationForest` pipeline when available (`models/isolation_forest.joblib`) and falls back gracefully to rule-based evaluation if the local model file is missing.
- **Optional Threat Intel Input:** Accepts optional pre-fetched `threat_intel` metadata in memory without making external API calls.
- **Risk Score (0–100) & Severity Mapping:**
  - `0` – `24.9`: `low` (normal baseline; **no** `Alert` is persisted)
  - `25` – `49.9`: `medium` (suspicious; `Alert` persisted when `persist=True`)
  - `50` – `74.9`: `high` (suspicious; `Alert` persisted when `persist=True`)
  - `75` – `100`: `critical` (suspicious; `Alert` persisted when `persist=True`)
- **Explainable Output:** Every assessment returns `attack_type`, `severity`, `anomaly_score`, `threat_score`, `confidence`, `evidence` (including exact severity-assignment rationale), cautious `explanation` (using terms like *"possible"* and *"suspicious"*), and `recommended_action`.
- **False-Positive Guardrails:**
  - Established bidirectional TCP flows with `ACK`/`PA` flags on standard web ports (`80`, `443`, `8080`, `8443`) are not flagged as floods solely from short burst packet rates, and mild ML drift (`confidence < 0.85`) without corroborating rules or threat intel stays `low`.
  - `high_packet_rate` as the sole triggered indicator is capped at maximum `medium` severity (`< 50`).
  - `critical` severity (`>= 75`) requires at least **two independent corroborating indicators** (e.g., strong ML anomaly, heuristic rules, or provider threat-intel reports).

## Optional Threat-Intelligence Lookup

`app/services/threat_intel.py` provides `ThreatIntelService`, an optional AbuseIPDB integration exposed via `GET /api/threat-intel/<ip>` and supported by `DetectionEngine`:

- **Opt-In via `ABUSEIPDB_API_KEY`:** If `ABUSEIPDB_API_KEY` is missing or left as a placeholder, no external HTTP requests are made (`reputation: "unknown"`).
- **Private & Reserved IP Protection:** Private, loopback, and reserved IPs immediately return `reputation: "private"` without leaving the host.
- **Timeouts, Rate Limits & Secret Safety:** Uses a 5-second request timeout, handles HTTP `429`/errors/invalid JSON safely, and never exposes the API key in logs or API responses.
- **TTL Caching:** Caches successful lookups per IP in memory (`THREAT_INTEL_CACHE_TTL`, default `900` seconds) and uses cautious wording (*"reported by the provider"*).

## Optional LLM-Powered Threat Explanations

`app/services/llm_explainer.py` provides `LLMExplainer`, exposed on demand via `POST /api/alerts/<id>/explain`:

- **Setup:** Set `OPENAI_API_KEY` and optionally `OPENAI_MODEL` (defaults to `gpt-4o-mini`) in your local `.env` file.
- **Privacy & Sanitization Limitations:** Only allowlisted metadata (`attack_type`, `severity`, `threat_score`, `anomaly_score`, `rule_evidence`, `threat_intel_summary`, and numeric/protocol flow statistics) is sent to OpenAI, with secret-pattern redaction applied. Packet payloads, raw packet data, passwords, tokens, and API keys are never transmitted. Do not enable OpenAI enrichment if your policy prohibits sending aggregated alert metadata to an external LLM provider.
- **Score Integrity:** The LLM generates explanatory text only (`summary`, `why_it_matters`, `evidence`, `recommended_actions`, `confidence_note`) and never alters `anomaly_score`, `threat_score`, or `severity`.
- **Safe Fallback:** If `OPENAI_API_KEY` is missing, an API call fails, or the returned JSON fails schema validation, `LLMExplainer` automatically returns a deterministic rule-based fallback explanation.

## Live Security Dashboard Usage

Open `http://127.0.0.1:5000/` after running `.\.venv\Scripts\python.exe run.py`:

- **Live Monitoring & Status:** The dashboard automatically polls `/api/summary` and `/api/alerts` every 3 seconds, shows the last successful update time, and displays an `API Offline` status and error banner if requests fail. Use **Stop Monitoring / Start Monitoring** in the top bar to pause or resume polling.
- **Alert Filtering:** Filter alerts dynamically by **Severity**, **Status**, **Source IP**, or **Destination IP** (with **Clear Filters** to reset). Both the alert table and the severity bar chart update from real database data.
- **Alert Details & On-Demand AI Explanations:** Click any alert row (or **Inspect**) to open the details modal showing `explanation`, `anomaly_score`, `threat_score`, and source-IP threat-intelligence lookup (`GET /api/threat-intel/<ip>`). Click **Generate AI Explanation** to call `POST /api/alerts/<id>/explain` on demand—if `OPENAI_API_KEY` is not set, a structured rule-based fallback explanation is displayed cleanly.

## End-to-End Monitoring Pipeline (`scripts/run_monitor.py`)

`app/services/monitoring_service.py` connects the full pipeline (`packet metadata -> FlowAggregator -> completed flow -> DetectionEngine -> optional ThreatIntelService -> SQLite Alert`). Only completed flows are analyzed, packet payloads are never stored, and Flask startup never starts monitoring automatically.

1. **Run safe synthetic demo monitoring (populates realistic alerts for the dashboard without touching a network interface):**
   ```powershell
   .\.venv\Scripts\python.exe scripts/run_monitor.py --demo
   ```

2. **Run authorized live monitoring on an interface you own or are authorized to monitor:**
   ```powershell
   .\.venv\Scripts\python.exe scripts/run_monitor.py --live --interface "Wi-Fi" --limit 100 --timeout 30 --filter "tcp or udp"
   ```
   Press `Ctrl+C` to stop capture gracefully, flush remaining flows, evaluate them, and save any suspicious alerts to SQLite.

## Real Dataset Training (UNSW-NB15)

`scripts/train_unsw_model.py` trains an `IsolationForest` model on real benign (`label == 0`) flows from the UNSW-NB15 dataset (`data/raw/UNSW-NB15/UNSW_NB15_training-set.csv`) using chunked CSV loading and evaluates it against the full testing set (`UNSW_NB15_testing-set.csv`). Target columns (`label`, `attack_cat`, `id`) are never used as model features, and the synthetic model (`models/isolation_forest.joblib`) is never overwritten.

### UNSW-NB15 to `FLOW_FEATURES` Mapping

| `FLOW_FEATURES` | UNSW-NB15 Source & Handling |
| --- | --- |
| `duration` | `dur` (coerced to finite float `>= 0`; `-`/missing -> `0.0`) |
| `protocol` | `proto` (`TCP`, `UDP`, `ICMP`, `HTTP`, `HTTPS`, `DNS`, `SSH`; unknown/`-` -> `OTHER`) |
| `source_port` | `sport` (`0`–`65535` if column present; `0` when omitted or invalid) |
| `destination_port` | `dsport` (`0`–`65535` if present; otherwise inferred from `service` or `0`) |
| `flow_bytes` | `sbytes + dbytes` |
| `flow_packets` | `spkts + dpkts` |
| `forward_packets` | `spkts` |
| `backward_packets` | `dpkts` |
| `average_packet_size` | Derived: `flow_bytes / flow_packets` (`0.0` when `flow_packets == 0`) |
| `packet_rate` | `rate` field (fallback: `flow_packets / duration` when `duration > 0`) |
| `byte_rate` | Derived from load fields `(sload + dload) / 8.0` (fallback: `flow_bytes / duration`) |

### Training Command & Model Selection

1. **Train and evaluate on UNSW-NB15:**
   ```powershell
   .\.venv\Scripts\python.exe scripts/train_unsw_model.py
   ```
   Saves the trained bundle to `models/isolation_forest_unsw_nb15.joblib` (excluded from Git via `.gitignore`).

2. **Select the active model via `ML_MODEL_PATH` in `.env`:**
   ```dotenv
   ML_MODEL_PATH=models/isolation_forest_unsw_nb15.joblib
   ```
   If `ML_MODEL_PATH` is unset, `app/ml/predict.py` and `DetectionEngine` fall back to `models/isolation_forest.joblib`.

### Observed UNSW-NB15 Evaluation & Limitations

- **Latest Baseline Evaluation (`UNSW_NB15_testing-set.csv`):** 56,000 benign training rows, 82,332 test rows (37,000 Normal + 45,332 attacks across `Generic`, `Exploits`, `Fuzzers`, `DoS`, `Reconnaissance`, `Analysis`, `Backdoor`, `Shellcode`, `Worms`): Precision `0.8715`, Recall `0.2811`, F1-Score `0.4251` (`TN=35,121`, `FP=1,879`, `FN=32,588`, `TP=12,744`).
- **Limitations:** The official `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` files omit `sport` and `dsport` columns (so `source_port` defaults to `0` and `destination_port` is inferred from `service` where available). Additionally, an unsupervised `IsolationForest` trained solely on 11 benign flow-volume/rate features achieves high precision on statistical outliers while missing application-layer attacks whose packet/byte rates resemble normal traffic.

### Model Benchmarking & Improvement (`scripts/benchmark_unsw_models.py`)

Run the leak-free benchmark comparing the preserved `IsolationForest` baseline against a supervised `RandomForestClassifier(class_weight="balanced_subsample")`:

```powershell
.\.venv\Scripts\python.exe scripts/benchmark_unsw_models.py
```

- **Leak-Free Selection & Threshold Tuning:** Splits `UNSW_NB15_training-set.csv` into an 80% training split (`140,272` rows) and a 20% validation split (`35,069` rows). `RandomForestClassifier` uses `label` only as the target (never `label`, `attack_cat`, or `id` as features), tunes its probability threshold (`0.32`) and selects the winning model strictly on the validation split, and evaluates both models **once** on `UNSW_NB15_testing-set.csv` (`82,332` rows).
- **Saved Artifact:** Saves the best bundle (`model_type`, `features`, and `decision_threshold`) to `models/unsw_best_model.joblib` without altering `models/isolation_forest.joblib` or `models/isolation_forest_unsw_nb15.joblib`. `app/ml/predict.py` supports both `IsolationForest` and `RandomForest` bundles seamlessly via `ML_MODEL_PATH=models/unsw_best_model.joblib`.

| Metric | IsolationForest (Baseline) | RandomForest (`balanced_subsample`, thresh=`0.32`) |
| --- | --- | --- |
| Precision | `0.8715` | `0.7946` |
| Recall | `0.2811` | `0.9793` |
| F1-Score | `0.4251` | `0.8773` |
| ROC-AUC | `0.7613` | `0.9702` |
| PR-AUC | `0.7769` | `0.9737` |
| Confusion Matrix | `TN=35,121, FP=1,879, FN=32,588, TP=12,744` | `TN=25,525, FP=11,475, FN=939, TP=44,393` |

### UNSW-NB15 Citation

> Moustafa, N., & Slay, J. (2015). *UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set).* 2015 Military Communications and Information Systems Conference (MilCIS), IEEE, pp. 1–6.

## Running Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

## Current Status

- [x] Phase 1: Flask app factory, homepage (`/`), health endpoint (`/health`), and pytest setup
- [x] Phase 2: SQLite `Alert` model, validated `/api/alerts` and `/api/summary` endpoints, and live dashboard integration
- [x] Phase 3: ML flow schema, synthetic dataset generator, `IsolationForest` training/evaluation, and reusable prediction module
- [x] Phase 4: Bidirectional `FlowAggregator` service with inactivity expiration and ML-compatible flow output
- [x] Phase 5: Controlled Scapy metadata-only `PacketCaptureService` and `scripts/run_capture.py` CLI (`--demo` / `--live`)
- [x] Phase 6: Explainable `RuleEngine` and `DetectionEngine` combining ML, rules, and optional threat-intel metadata
- [x] Phase 7: Optional AbuseIPDB `ThreatIntelService`, TTL cache, `GET /api/threat-intel/<ip>`, and `DetectionEngine` integration
- [x] Phase 8: Optional sanitized `LLMExplainer`, structured JSON validation, fallback explanations, and `POST /api/alerts/<id>/explain`
- [x] Phase 9: Live security dashboard with 3-second polling, monitoring toggle, filters, alert modal, and on-demand explanation button
- [x] Phase 10: End-to-end `MonitoringService` pipeline and `scripts/run_monitor.py` (`--demo` / `--live`)
- [x] Phase 11: Real UNSW-NB15 training/evaluation (`scripts/train_unsw_model.py`) and `ML_MODEL_PATH` selection
- [x] Phase 12: Leak-free UNSW-NB15 benchmarking (`IsolationForest` vs `RandomForestClassifier`) and `models/unsw_best_model.joblib`
- [x] Phase 13: Live-traffic false-positive guardrails (bidirectional TCP/HTTPS awareness, multi-indicator `critical` requirement, severity rationale)
