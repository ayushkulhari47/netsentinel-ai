# NetSentinel AI

An AI-powered cybersecurity threat detection dashboard built with Python, Flask, SQLite, Scapy, Scikit-learn, and Chart.js.

## Tech Stack

- **Backend:** Python 3.13, Flask, SQLite
- **Packet & Data Processing:** Scapy, Pandas, NumPy
- **Machine Learning:** Scikit-learn (`IsolationForest`), Joblib
- **Frontend:** HTML, CSS, JavaScript, Chart.js
- **Optional Integrations:** OpenAI API, AbuseIPDB API, VirusTotal API

## Project Structure

```text
netsentinel-ai/
├── app/
│   ├── __init__.py          # Flask application factory
│   ├── routes.py            # Web and health-check routes
│   ├── static/
│   │   ├── css/style.css    # Dashboard stylesheet
│   │   └── js/dashboard.js  # Frontend health check & Chart.js setup
│   └── templates/
│       └── dashboard.html   # Main dashboard HTML template
├── tests/
│   └── test_health.py       # Health and homepage route tests
├── .env.example             # Sample environment configuration
├── .gitignore               # Git ignore rules for secrets, DBs, and caches
├── README.md                # Project documentation
├── requirements.txt         # Python dependencies
└── run.py                   # Application entry point
```

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
   Then open `http://127.0.0.1:5000/` in your browser, or check `http://127.0.0.1:5000/health`.

## Running Tests

```powershell
.\.venv\Scripts\python.exe -m pytest
```

## Current Status

- [x] Flask app factory, homepage (`/`), and health endpoint (`/health`)
- [x] Dashboard UI skeleton and placeholder chart
- [x] Initial pytest suite
- [ ] Live packet capture (Scapy), SQLite persistence, and IsolationForest anomaly detection (upcoming)
