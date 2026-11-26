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
│   │   └── flow_aggregator.py# Deterministic 5-tuple bidirectional flow aggregator
│   ├── static/
│   │   ├── css/style.css    # Dashboard stylesheet
│   │   └── js/dashboard.js  # Live API polling & Chart.js severity chart
│   └── templates/
│       └── dashboard.html   # Main dashboard HTML template
├── scripts/
│   ├── generate_demo_data.py# Synthetic benign & anomalous flow data generator
│   └── train_model.py       # Train IsolationForest on benign flows & evaluate
├── tests/
│   ├── test_alerts.py       # Alert model and API endpoint tests
│   ├── test_flow_aggregator.py# FlowAggregator unit tests
│   ├── test_health.py       # Health and homepage route tests
│   └── test_ml.py           # Feature schema, training, evaluation & prediction tests
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
- `GET /api/summary` — Aggregated counts (`total_alerts`, `critical_alerts`, `high_alerts`, `suspicious_ip_count`)

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

## Running Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

## Current Status

- [x] Phase 1: Flask app factory, homepage (`/`), health endpoint (`/health`), and pytest setup
- [x] Phase 2: SQLite `Alert` model, validated `/api/alerts` and `/api/summary` endpoints, and live dashboard integration
- [x] Phase 3: ML flow schema, synthetic dataset generator, `IsolationForest` training/evaluation, and reusable prediction module
- [x] Phase 4: Bidirectional `FlowAggregator` service with inactivity expiration and ML-compatible flow output
- [ ] Phase 5+: Live packet capture (Scapy) integration (upcoming)
