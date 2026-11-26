"""Optional OpenAI-powered threat explanation service with strict sanitization."""

import json
import os
import re
from openai import OpenAI

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_LLM_TIMEOUT_SECONDS = 10.0

PLACEHOLDER_KEYS = {
    "",
    "your-openai-api-key-here",
    "changeme",
    "replace-me",
}

ALLOWED_FLOW_STAT_KEYS = (
    "protocol",
    "source_port",
    "destination_port",
    "duration",
    "flow_bytes",
    "flow_packets",
    "forward_packets",
    "backward_packets",
    "average_packet_size",
    "packet_rate",
    "byte_rate",
    "tcp_flags",
)

REQUIRED_EXPLANATION_KEYS = (
    "summary",
    "why_it_matters",
    "evidence",
    "recommended_actions",
    "confidence_note",
)

_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]+"),
    re.compile(r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*\S+"),
]


def _normalize_api_key(raw_key):
    """Return stripped API key if valid/configured, or None if missing/placeholder."""
    if not isinstance(raw_key, str):
        return None
    cleaned = raw_key.strip()
    if cleaned.lower() in PLACEHOLDER_KEYS:
        return None
    return cleaned


def _redact_secrets(text):
    """Redact accidental secret-like substrings from sanitized text fields."""
    if not isinstance(text, str):
        return ""
    cleaned = text.strip()
    for pattern in _SECRET_PATTERNS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    return cleaned


def sanitize_alert_metadata(alert_data, threat_intel=None, flow_stats=None):
    """Extract only safe, non-payload alert metadata for optional LLM explanation.

    Never includes packet payloads, raw packet bytes, passwords, tokens, API keys,
    or source/destination IP addresses unless explicitly present in redacted summary text.
    """
    if not isinstance(alert_data, dict):
        raise ValueError("alert_data must be a dictionary.")

    # Extract safe rule evidence list
    raw_evidence = alert_data.get("rule_evidence")
    if raw_evidence is None:
        raw_evidence = alert_data.get("evidence")

    rule_evidence = []
    if isinstance(raw_evidence, list):
        for item in raw_evidence:
            if isinstance(item, str) and item.strip():
                rule_evidence.append(_redact_secrets(item))
    elif isinstance(raw_evidence, str) and raw_evidence.strip():
        rule_evidence.append(_redact_secrets(raw_evidence))

    existing_explanation = alert_data.get("explanation")
    if not rule_evidence and isinstance(existing_explanation, str) and existing_explanation.strip():
        rule_evidence.append(_redact_secrets(existing_explanation))

    # Extract sanitized threat-intelligence summary
    intel_summary = None
    raw_intel_summary = alert_data.get("threat_intel_summary")
    if isinstance(raw_intel_summary, str) and raw_intel_summary.strip():
        intel_summary = _redact_secrets(raw_intel_summary)
    elif isinstance(threat_intel, dict):
        reputation = str(threat_intel.get("reputation", "unknown")).strip().lower()
        provider = str(threat_intel.get("provider", "provider")).strip()
        abuse_score = threat_intel.get("abuse_score")
        categories = threat_intel.get("categories") or []
        parts = [f"reputation={reputation}", f"provider={provider}"]
        if isinstance(abuse_score, (int, float)) and not isinstance(abuse_score, bool):
            parts.append(f"abuse_score={abuse_score}")
        if isinstance(categories, list) and categories:
            parts.append("categories=" + ", ".join(str(c) for c in categories[:5]))
        intel_summary = _redact_secrets("; ".join(parts))

    # Extract sanitized protocol and flow statistics via strict allowlist
    combined_stats = {}
    for source in (alert_data, flow_stats if isinstance(flow_stats, dict) else {}):
        for key in ALLOWED_FLOW_STAT_KEYS:
            if key in source and source[key] is not None:
                val = source[key]
                if key == "protocol":
                    combined_stats[key] = str(val).strip().upper()
                elif key == "tcp_flags" and isinstance(val, list):
                    combined_stats[key] = [str(f).strip().upper() for f in val if str(f).strip()]
                elif isinstance(val, (int, float)) and not isinstance(val, bool):
                    combined_stats[key] = val

    return {
        "attack_type": _redact_secrets(str(alert_data.get("attack_type", "Possible Suspicious Activity"))),
        "severity": str(alert_data.get("severity", "medium")).strip().lower(),
        "threat_score": float(alert_data.get("threat_score", 0.0) or 0.0),
        "anomaly_score": float(alert_data.get("anomaly_score", 0.0) or 0.0),
        "rule_evidence": rule_evidence,
        "threat_intel_summary": intel_summary or "No threat-intelligence enrichment available.",
        "protocol_and_flow_stats": combined_stats,
    }


def validate_structured_explanation(payload):
    """Validate structured JSON returned by the LLM against the required 5-key schema."""
    if not isinstance(payload, dict):
        raise ValueError("LLM explanation must be a JSON object.")

    for key in REQUIRED_EXPLANATION_KEYS:
        if key not in payload:
            raise ValueError(f"Missing required explanation key: {key}")

    for str_key in ("summary", "why_it_matters", "confidence_note"):
        val = payload[str_key]
        if not isinstance(val, str) or not val.strip():
            raise ValueError(f"{str_key} must be a non-empty string.")

    for list_key in ("evidence", "recommended_actions"):
        val = payload[list_key]
        if not isinstance(val, list) or not val:
            raise ValueError(f"{list_key} must be a non-empty list of strings.")
        if any(not isinstance(item, str) or not item.strip() for item in val):
            raise ValueError(f"All items in {list_key} must be non-empty strings.")

    return {
        "summary": _redact_secrets(payload["summary"]),
        "why_it_matters": _redact_secrets(payload["why_it_matters"]),
        "evidence": [_redact_secrets(item) for item in payload["evidence"]],
        "recommended_actions": [_redact_secrets(item) for item in payload["recommended_actions"]],
        "confidence_note": _redact_secrets(payload["confidence_note"]),
    }


def build_fallback_explanation(sanitized_metadata, reason=None):
    """Generate a deterministic, cautious rule-based explanation without external LLM calls."""
    attack_type = sanitized_metadata["attack_type"]
    severity = sanitized_metadata["severity"]
    threat_score = sanitized_metadata["threat_score"]
    anomaly_score = sanitized_metadata["anomaly_score"]
    stats = sanitized_metadata["protocol_and_flow_stats"]
    proto = stats.get("protocol", "network")
    dst_port = stats.get("destination_port")
    port_text = f" on destination port {dst_port}" if dst_port is not None else ""

    summary = (
        f"Possible {attack_type} ({severity} severity, risk score {threat_score:.1f}/100) "
        f"observed over {proto}{port_text}."
    )
    why_it_matters = (
        "Unusual traffic rates, large transfer volumes, or unexpected protocol/port patterns "
        "may indicate reconnaissance, flooding, or unauthorized data movement and warrant verification."
    )

    evidence = list(sanitized_metadata["rule_evidence"])
    if sanitized_metadata["threat_intel_summary"]:
        evidence.append(f"Threat-intel context: {sanitized_metadata['threat_intel_summary']}")
    if not evidence:
        evidence.append(
            f"Observed {proto} flow metadata with threat_score={threat_score:.1f} "
            f"and anomaly_score={anomaly_score:.4f}."
        )

    if severity in {"critical", "high"}:
        recommended_actions = [
            "Review host and firewall logs for the involved endpoints to confirm authorization.",
            "Check destination service health and consider temporary rate-limiting if unauthorized.",
            "Correlate this alert with other recent events from the same source.",
        ]
    else:
        recommended_actions = [
            "Monitor subsequent traffic for repeated or escalating anomalies.",
            "Verify whether the protocol, port, and transfer volume match expected activity.",
        ]

    confidence_note = (
        "Generated via deterministic fallback rules without external LLM enrichment; "
        "scores indicate statistical or heuristic suspicion rather than certainty."
    )
    if reason:
        confidence_note = f"{confidence_note} ({reason})"

    return {
        "summary": summary,
        "why_it_matters": why_it_matters,
        "evidence": evidence,
        "recommended_actions": recommended_actions,
        "confidence_note": confidence_note,
        "source": "fallback",
        "model": None,
    }


class LLMExplainer:
    """Generates optional OpenAI-powered structured explanations for sanitized alerts."""

    def __init__(
        self,
        api_key=None,
        model=None,
        timeout_seconds=DEFAULT_LLM_TIMEOUT_SECONDS,
        client_factory=None,
    ):
        """Configure optional OpenAI client settings without making external calls."""
        self._explicit_api_key = api_key
        self._explicit_model = model
        self.timeout_seconds = float(timeout_seconds)
        self._client_factory = client_factory

    def _get_api_key(self):
        raw = self._explicit_api_key if self._explicit_api_key is not None else os.environ.get("OPENAI_API_KEY")
        return _normalize_api_key(raw)

    def _get_model(self):
        raw = self._explicit_model if self._explicit_model is not None else os.environ.get("OPENAI_MODEL")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        return DEFAULT_OPENAI_MODEL

    def _build_client(self, api_key):
        if self._client_factory is not None:
            return self._client_factory(api_key=api_key, timeout=self.timeout_seconds)
        return OpenAI(api_key=api_key, timeout=self.timeout_seconds)

    def explain(self, alert_data, threat_intel=None, flow_stats=None):
        """Return structured explanation JSON using OpenAI if configured, else safe fallback.

        Never modifies ML scores, threat scores, or severity, and never transmits raw payloads
        or secrets.
        """
        sanitized = sanitize_alert_metadata(
            alert_data,
            threat_intel=threat_intel,
            flow_stats=flow_stats,
        )

        api_key = self._get_api_key()
        if api_key is None:
            return build_fallback_explanation(sanitized, reason="OpenAI API key not configured")

        model = self._get_model()
        system_prompt = (
            "You are a defensive cybersecurity analyst assistant for NetSentinel AI. "
            "Analyze only the provided sanitized alert metadata and return a JSON object with "
            "exactly these keys: summary (string), why_it_matters (string), evidence (array of "
            "strings), recommended_actions (array of strings), confidence_note (string). "
            "Use cautious language such as 'possible' or 'suspicious'; never claim certainty "
            "and never alter risk scores or severity."
        )
        user_prompt = json.dumps(sanitized, sort_keys=True)

        try:
            client = self._build_client(api_key)
            response = client.chat.completions.create(
                model=model,
                temperature=0.2,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            content = response.choices[0].message.content
            if not isinstance(content, str) or not content.strip():
                raise ValueError("Empty response content from OpenAI.")
            parsed = json.loads(content)
            validated = validate_structured_explanation(parsed)
        except Exception:
            return build_fallback_explanation(sanitized, reason="OpenAI request or validation failed")

        validated["source"] = "openai"
        validated["model"] = model
        return validated
