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
│   ├── static/
│   │   ├── css/style.css    # Dashboard stylesheet
│   │   └── js/dashboard.js  # Live API polling & Chart.js severity chart
│   └── templates/
│       └── dashboard.html   # Main dashboard HTML template
├── tests/
│   ├── test_alerts.py       # Alert model and API endpoint tests
│   └── test_health.py       # Health and homepage route tests
├── .env.example             # Sample environment configuration
├── .gitignore               # Git ignore rules for secrets, DBs, and caches
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

## Running Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

## Current Status

- [x] Phase 1: Flask app factory, homepage (`/`), health endpoint (`/health`), and pytest setup
- [x] Phase 2: SQLite `Alert` model, validated `/api/alerts` and `/api/summary` endpoints, and live dashboard integration
- [ ] Phase 3+: Live packet capture (Scapy) and `IsolationForest` anomaly detection (upcoming)
