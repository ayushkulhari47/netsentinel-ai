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
│   │   ├── packet_capture.py# Controlled Scapy metadata-only packet capture service
│   │   ├── rule_engine.py   # Explainable heuristic flow rules
│   │   └── threat_intel.py  # Optional AbuseIPDB lookup with TTL cache & safety guards
│   ├── static/
│   │   ├── css/style.css    # Dashboard stylesheet
│   │   └── js/dashboard.js  # Live API polling & Chart.js severity chart
│   └── templates/
│       └── dashboard.html   # Main dashboard HTML template
├── scripts/
│   ├── generate_demo_data.py# Synthetic benign & anomalous flow data generator
│   ├── run_capture.py       # Controlled packet capture CLI (--demo / --live)
│   └── train_model.py       # Train IsolationForest on benign flows & evaluate
├── tests/
│   ├── test_alerts.py       # Alert model and API endpoint tests
│   ├── test_detection_engine.py# RuleEngine and DetectionEngine tests
│   ├── test_flow_aggregator.py# FlowAggregator unit tests
│   ├── test_health.py       # Health and homepage route tests
│   ├── test_llm_explainer.py# Mocked LLM explainer & /explain endpoint tests
│   ├── test_ml.py           # Feature schema, training, evaluation & prediction tests
│   ├── test_packet_capture.py# Mocked Scapy packet capture & CLI safety tests
│   └── test_threat_intel.py # Mocked AbuseIPDB lookup, caching & API route tests
├── .env.example             # Sample environment configuration
├── .gitignore               # Git ignore rules for secrets, DBs, models, and caches
├── README.md                # Project documentation
├── requirements.txt         # Python dependencies
└── run.py                   # Application entry point
```

## API Endpoints

- `GET /` — Threat detection dashboard UI
- `GET /health` — Service health status JSON
- `GET /api/alerts` — List stored alerts (supports `?severity=`, `?status=`, `?limit=`)
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
- **Explainable Output:** Every assessment returns `attack_type`, `severity`, `anomaly_score`, `threat_score`, `confidence`, `evidence`, cautious `explanation` (using terms like *"possible"* and *"suspicious"*), and `recommended_action`.

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
