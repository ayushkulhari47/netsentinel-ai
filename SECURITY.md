# Security & Responsible Use Policy

NetSentinel AI is designed for defensive cybersecurity monitoring, education, and authorized network diagnostics.

## 1. Authorized Monitoring Only

- Live packet capture is **disabled by default** and never starts automatically when the Flask server launches.
- `scripts/run_capture.py` and `scripts/run_monitor.py` strictly refuse to sniff any network interface unless the operator explicitly passes `--live`.
- Only run `--live` capture on networks and interfaces you own or have explicit written authorization to monitor. Unauthorized packet capture or traffic interception may violate organizational policy and applicable laws.
- Demo modes (`--demo`) use synthetic metadata only and never transmit packets, port scans, or attack traffic.

## 2. No Packet Payload Storage

- `PacketCaptureService` configures Scapy with `store=False` and extracts **header metadata only** (`timestamp`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`, `packet_length`, `tcp_flags`).
- Application payloads (`Raw` packet bytes), credentials, cookies, and session tokens are never read, stored in SQLite, logged, or transmitted to external services.

## 3. API-Key & Secret Protection

- Secrets such as `SECRET_KEY`, `ABUSEIPDB_API_KEY`, and `OPENAI_API_KEY` belong strictly in a local `.env` file, which is excluded from Git by `.gitignore`.
- Placeholder values from `.env.example` are treated as unconfigured; no external API calls are made unless a real key is supplied.
- **AbuseIPDB (`app/services/threat_intel.py`):**
  - Never queries private, loopback, reserved, link-local, or multicast IP addresses externally.
  - Enforces a 5-second request timeout and caches results in memory.
  - Never includes `ABUSEIPDB_API_KEY` in logs, error strings, or JSON responses.
- **OpenAI (`app/services/llm_explainer.py`):**
  - Transmits only allowlisted, secret-redacted alert metadata (`attack_type`, `severity`, `threat_score`, `anomaly_score`, `rule_evidence`, `threat_intel_summary`, and numeric/protocol flow stats).
  - Never alters ML scores, `threat_score`, or `severity`.
  - Falls back to deterministic rule-based explanations when `OPENAI_API_KEY` is missing or an API call fails.
- **Web Application Hardening:**
  - Flask debug mode (`FLASK_DEBUG`) is disabled (`false`) by default.
  - `SESSION_COOKIE_HTTPONLY` and `SESSION_COOKIE_SAMESITE="Lax"` are enabled.
  - Defensive response headers (`Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`) are attached to all HTTP responses.
  - Dashboard JavaScript renders all dynamic values with `textContent` and DOM element creation (`createElement`/`replaceChildren`), never raw HTML injection.

## 4. False-Positive & Detection Limitations

- Machine learning anomaly scores (`IsolationForest` / `RandomForestClassifier`) and heuristic rules indicate **statistical or behavioral suspicion**, not proof of malicious activity.
- Explanations intentionally use cautious wording (*"possible"*, *"suspicious"*, *"reported by the provider"*).
- Built-in guardrails reduce noisy false positives on established bidirectional HTTPS (`ACK`/`PA`) traffic, cap single-indicator `high_packet_rate` alerts at `medium`, and require at least two independent indicators for `critical` severity.
- Always correlate alerts with host, firewall, and authentication logs before taking blocking or containment actions.
