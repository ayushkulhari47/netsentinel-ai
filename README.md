# NetSentinel AI

An AI-powered, explainable cybersecurity threat-detection dashboard built with Python 3.13, Flask, SQLite, Scapy, Scikit-learn, and Chart.js.

## Overview

NetSentinel AI inspects network flow metadata (never packet payloads), aggregates packets into bidirectional 5-tuple flows, evaluates completed flows with a hybrid detection engine (Machine Learning + heuristic rules + optional threat intelligence), persists suspicious alerts to SQLite, and presents real-time triage insights in a dark-themed security dashboard.

## Key Features

- **Metadata-Only Packet Capture (`Scapy`):** Captures header metadata with `store=False`, supports IPv4/IPv6/TCP/UDP/ICMP, requires explicit `--live` authorization, and never captures or stores packet payloads.
- **Bidirectional Flow Aggregation:** Groups packets into canonical 5-tuples with inactivity expiration, zero-duration safety, and 11 standardized ML features.
- **Dual ML Support (`IsolationForest` & `RandomForestClassifier`):** Supports unsupervised anomaly detection (`IsolationForest`) and supervised UNSW-NB15 classification (`RandomForestClassifier` with `class_weight="balanced_subsample"`) selectable via `ML_MODEL_PATH`.
- **Explainable Hybrid Scoring & False-Positive Guardrails:** Combines ML scores, 4 heuristic rule categories, and optional threat intelligence into a `0`–`100` risk score (`low`, `medium`, `high`, `critical`) with HTTPS/ACK dampening, single-rule `medium` caps, and multi-indicator `critical` requirements.
- **Optional Threat Intelligence & LLM Explanations:** Integrates optional AbuseIPDB IP lookups (with private-IP protection and TTL cache) and on-demand sanitized OpenAI explanations (with deterministic rule-based fallback when no API key is configured).
- **Live Security Dashboard:** Polls `/api/summary` and `/api/alerts` every 3 seconds, supports Start/Stop monitoring, filters by severity/status/source IP/destination IP, renders a Chart.js severity breakdown, and provides an alert inspection modal.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the complete system architecture, Mermaid data-flow diagrams, ML workflow, and alert lifecycle.

```text
netsentinel-ai/
├── .github/workflows/tests.yml   # GitHub Actions CI test pipeline
├── app/
│   ├── __init__.py               # Flask app factory, SQLite init & security headers
│   ├── extensions.py             # Shared SQLAlchemy db instance
│   ├── models.py                 # SQLAlchemy Alert model
│   ├── validators.py             # Alert API input validation
│   ├── routes.py                 # Dashboard, health, alert, threat-intel & explain routes
│   ├── ml/
│   │   ├── feature_schema.py     # Canonical 11-feature flow schema & validation
│   │   └── predict.py            # Unified IsolationForest & RandomForest inference
│   ├── services/
│   │   ├── detection_engine.py   # Hybrid ML + rules + threat-intel risk scoring
│   │   ├── flow_aggregator.py    # 5-tuple bidirectional flow aggregator
│   │   ├── llm_explainer.py      # Optional sanitized OpenAI + fallback explanations
│   │   ├── monitoring_service.py # Capture -> Flow -> Detection -> SQLite pipeline
│   │   ├── packet_capture.py     # Controlled Scapy metadata-only capture
│   │   ├── rule_engine.py        # Heuristic rules & bidirectional TCP guardrails
│   │   └── threat_intel.py       # Optional AbuseIPDB client with TTL cache
│   ├── static/
│   │   ├── css/style.css         # Responsive dark-theme stylesheet
│   │   └── js/dashboard.js       # 3s polling, filters, Chart.js & safe DOM modal
│   └── templates/dashboard.html  # Threat-detection dashboard template
├── docs/architecture.md          # Detailed architecture & Mermaid diagrams
├── scripts/
│   ├── benchmark_unsw_models.py  # Leak-free IsolationForest vs RandomForest benchmark
│   ├── generate_demo_data.py     # Synthetic benign & anomalous flow generator
│   ├── run_capture.py            # Controlled capture CLI (--demo / --live)
│   ├── run_monitor.py            # End-to-end monitor CLI (--demo / --live)
│   ├── train_model.py            # Synthetic IsolationForest training script
│   └── train_unsw_model.py       # UNSW-NB15 chunked IsolationForest training script
├── tests/                        # Pytest unit, API, ML, capture & integration tests
├── .env.example                  # Sample environment variables (no real keys)
├── .gitignore                    # Excludes .env, .venv, data/, models/, instance/, DBs
├── README.md                     # Project documentation
├── SECURITY.md                   # Security, privacy & responsible monitoring policy
├── requirements.txt              # Pinned Python dependencies
└── run.py                        # Flask server entry point (debug disabled by default)
```

## Setup Instructions

1. **Create or activate the Python 3.13 virtual environment:**
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
   *(If setting up a fresh environment: `python -m venv .venv && pip install -r requirements.txt`.)*

2. **Create a local `.env` file (optional; app works out of the box without external API keys):**
   ```powershell
   Copy-Item .env.example .env
   ```
   Key options in `.env.example`:
   - `FLASK_DEBUG=false` (disabled by default for safety)
   - `ML_MODEL_PATH=models/isolation_forest_unsw_nb15.joblib` (or `models/unsw_best_model.joblib` / `models/isolation_forest.joblib`)
   - `ABUSEIPDB_API_KEY` (optional)
   - `OPENAI_API_KEY` and `OPENAI_MODEL=gpt-4o-mini` (optional)

3. **Train a local model (if `models/` has not been populated yet):**
   - **Synthetic quick-start model:**
     ```powershell
     .\.venv\Scripts\python.exe scripts/generate_demo_data.py
     .\.venv\Scripts\python.exe scripts/train_model.py
     ```
   - **Real UNSW-NB15 baseline and benchmark (when `data/raw/UNSW-NB15/` CSVs are present):**
     ```powershell
     .\.venv\Scripts\python.exe scripts/train_unsw_model.py
     .\.venv\Scripts\python.exe scripts/benchmark_unsw_models.py
     ```

4. **Start the Flask web dashboard:**
   ```powershell
   .\.venv\Scripts\python.exe run.py
   ```
   Open `http://127.0.0.1:5000/` in your browser. Starting Flask never starts packet capture automatically.

## Running Demo Mode & Authorized Live Monitoring

- **Safe Demo Mode (synthetic metadata only; no packets sent or captured):**
  ```powershell
  .\.venv\Scripts\python.exe scripts/run_monitor.py --demo
  ```
  Processes benign baseline flows (which do not create alerts) and safe synthetic suspicious flow metadata (which persists realistic alerts to SQLite for viewing on the dashboard).

- **Authorized Live Monitoring (only on interfaces you own or are authorized to monitor):**
  ```powershell
  .\.venv\Scripts\python.exe scripts/run_monitor.py --live --interface "Wi-Fi" --limit 100 --timeout 30 --filter "tcp or udp"
  ```
  Press `Ctrl+C` to stop gracefully, flush remaining flows, evaluate completed flows, and persist any suspicious alerts.

## API Endpoints

| Method & Path | Description |
| --- | --- |
| `GET /` | Threat-detection dashboard HTML UI |
| `GET /health` | Service health status JSON (`status`, `app`, `version`, `packet_capture`) |
| `GET /api/alerts` | List stored alerts (supports `?severity=`, `?status=`, `?source_ip=`, `?destination_ip=`, `?limit=`) |
| `POST /api/alerts` | Validate and persist a security alert |
| `POST /api/alerts/<id>/explain` | Generate a structured explanation on demand (OpenAI if configured, else fallback; never alters scores) |
| `GET /api/summary` | Aggregated metrics (`total_alerts`, `critical_alerts`, `high_alerts`, `suspicious_ip_count`) |
| `GET /api/threat-intel/<ip>` | Optional AbuseIPDB lookup (skips private/reserved IPs and skips external API if key missing) |

## UNSW-NB15 Dataset Metrics & Model Selection

Both models were trained without target leakage using only the 11 normalized `FLOW_FEATURES` (`dur -> duration`, `proto -> protocol`, `sport -> source_port`, `dsport -> destination_port`, `sbytes + dbytes -> flow_bytes`, `spkts + dpkts -> flow_packets`, `spkts -> forward_packets`, `dpkts -> backward_packets`, derived `average_packet_size`, `rate -> packet_rate`, `(sload + dload)/8 -> byte_rate`). `label`, `attack_cat`, and `id` are never used as features.

- **Model Selection Method:** `UNSW_NB15_training-set.csv` (`175,341` rows) is split 80/20 (`140,272` train / `35,069` validation). `IsolationForest` trains only on benign rows (`label == 0`); `RandomForestClassifier(class_weight="balanced_subsample")` trains on the 80% split, tunes its probability threshold (`0.32`) and is compared on the validation split, and both models are evaluated **once** on the held-out `UNSW_NB15_testing-set.csv` (`82,332` rows across `Normal`, `Generic`, `Exploits`, `Fuzzers`, `DoS`, `Reconnaissance`, `Analysis`, `Backdoor`, `Shellcode`, and `Worms`).

| Metric (UNSW-NB15 Test Set: 82,332 rows) | IsolationForest (Baseline) | RandomForest (`balanced_subsample`, thresh=`0.32`) |
| --- | --- | --- |
| Precision | `0.8715` | `0.7946` |
| Recall | `0.2811` | `0.9793` |
| F1-Score | `0.4251` | `0.8773` |
| ROC-AUC | `0.7613` | `0.9702` |
| PR-AUC | `0.7769` | `0.9737` |
| Confusion Matrix | `TN=35,121, FP=1,879, FN=32,588, TP=12,744` | `TN=25,525, FP=11,475, FN=939, TP=44,393` |

**Citation:** Moustafa, N., & Slay, J. (2015). *UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set).* 2015 Military Communications and Information Systems Conference (MilCIS), IEEE, pp. 1–6.

## Limitations

- **UNSW-NB15 Split Schema:** `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` omit `sport` and `dsport`, so `source_port` defaults to `0` and `destination_port` is inferred from `service` where available (`0` otherwise).
- **Flow-Level Visibility:** Because NetSentinel AI deliberately avoids payload inspection, application-layer exploits with normal packet/byte rates are harder to detect solely from flow statistics.
- **Probabilistic Indicators:** ML anomalies and rule matches are triage indicators, not proof of compromise. Human verification against host/firewall logs is always recommended.
- **External Enrichment Privacy:** If `OPENAI_API_KEY` or `ABUSEIPDB_API_KEY` are configured, sanitized alert metadata or public IPs are sent to those third-party providers on demand; leave them unset for strictly offline operation.

## Screenshots

Once `run.py` and `scripts/run_monitor.py --demo` are running locally, the dashboard at `http://127.0.0.1:5000/` provides:
- **Live Overview & KPIs:** Topbar with 3-second polling status, Start/Stop Monitoring toggle, API health indicator, and summary cards (`Total Alerts`, `Critical Alerts`, `High Alerts`, `Suspicious IPs`).
- **Severity Chart & Filterable Alerts Table:** Interactive Chart.js bar chart paired with severity, status, source-IP, and destination-IP filters.
- **Alert Details & On-Demand Explanation Modal:** Modal displaying `anomaly_score`, `threat_score`, rule/severity rationale `evidence`, source-IP threat intelligence, and the **Generate AI Explanation** action.

*(Add local UI screenshots under `docs/screenshots/` before publishing to a public portfolio if desired.)*

## Ethical & Legal Notice

NetSentinel AI is intended strictly for defensive security monitoring, research, and authorized network administration. Never run `--live` capture on any network or interface without explicit authorization from the network owner. Review [SECURITY.md](SECURITY.md) for full privacy, API-key, and responsible-use guidelines.

## Running Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```
