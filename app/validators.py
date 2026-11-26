"""Input validation helpers for NetSentinel AI alert APIs."""

from datetime import datetime, timezone
import ipaddress
import math

ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
ALLOWED_STATUSES = {"open", "investigating", "resolved", "false_positive"}


def _is_valid_number(value):
    """Return True if value is a finite int or float (excluding booleans)."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _validate_ip(value, field_name, errors):
    """Validate an IPv4 or IPv6 address string."""
    if not isinstance(value, str) or not value.strip():
        errors[field_name] = f"{field_name} is required and must be a valid IP address."
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        errors[field_name] = f"{field_name} must be a valid IPv4 or IPv6 address."
        return None


def _validate_port(value, field_name, errors):
    """Validate an optional TCP/UDP port number (0-65535)."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        errors[field_name] = f"{field_name} must be an integer between 0 and 65535."
        return None
    if value < 0 or value > 65535:
        errors[field_name] = f"{field_name} must be between 0 and 65535."
        return None
    return value


def _validate_score(value, field_name, errors, default=0.0, min_val=None, max_val=None):
    """Validate an optional numeric score within optional bounds."""
    if value is None:
        return default
    if not _is_valid_number(value):
        errors[field_name] = f"{field_name} must be a finite number."
        return None
    num = float(value)
    if min_val is not None and num < min_val:
        errors[field_name] = f"{field_name} must be >= {min_val}."
        return None
    if max_val is not None and num > max_val:
        errors[field_name] = f"{field_name} must be <= {max_val}."
        return None
    return num


def _validate_timestamp(value, errors):
    """Validate an optional ISO-8601 timestamp string."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        errors["timestamp"] = "timestamp must be a valid ISO-8601 datetime string."
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        errors["timestamp"] = "timestamp must be a valid ISO-8601 datetime string."
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def validate_alert_payload(payload):
    """Validate and normalize a POST /api/alerts JSON payload.

    Returns (cleaned_data, errors). If errors is non-empty, validation failed.
    """
    if not isinstance(payload, dict):
        return None, {"body": "Request body must be a JSON object."}

    errors = {}
    cleaned = {}

    cleaned["source_ip"] = _validate_ip(payload.get("source_ip"), "source_ip", errors)
    cleaned["destination_ip"] = _validate_ip(payload.get("destination_ip"), "destination_ip", errors)
    cleaned["source_port"] = _validate_port(payload.get("source_port"), "source_port", errors)
    cleaned["destination_port"] = _validate_port(
        payload.get("destination_port"), "destination_port", errors
    )

    protocol = payload.get("protocol")
    if not isinstance(protocol, str) or not protocol.strip():
        errors["protocol"] = "protocol is required and must be a non-empty string."
    else:
        normalized_protocol = protocol.strip().upper()
        if len(normalized_protocol) > 16 or not normalized_protocol.replace("-", "").isalnum():
            errors["protocol"] = "protocol must be 1-16 alphanumeric characters."
        else:
            cleaned["protocol"] = normalized_protocol

    attack_type = payload.get("attack_type")
    if not isinstance(attack_type, str) or not attack_type.strip():
        errors["attack_type"] = "attack_type is required and must be a non-empty string."
    elif len(attack_type.strip()) > 100:
        errors["attack_type"] = "attack_type must be at most 100 characters."
    else:
        cleaned["attack_type"] = attack_type.strip()

    severity = payload.get("severity")
    if not isinstance(severity, str) or severity.strip().lower() not in ALLOWED_SEVERITIES:
        allowed = ", ".join(sorted(ALLOWED_SEVERITIES))
        errors["severity"] = f"severity is required and must be one of: {allowed}."
    else:
        cleaned["severity"] = severity.strip().lower()

    status = payload.get("status", "open")
    if status is None:
        status = "open"
    if not isinstance(status, str) or status.strip().lower() not in ALLOWED_STATUSES:
        allowed = ", ".join(sorted(ALLOWED_STATUSES))
        errors["status"] = f"status must be one of: {allowed}."
    else:
        cleaned["status"] = status.strip().lower()

    cleaned["anomaly_score"] = _validate_score(payload.get("anomaly_score"), "anomaly_score", errors)
    cleaned["threat_score"] = _validate_score(
        payload.get("threat_score"), "threat_score", errors, min_val=0.0, max_val=100.0
    )
    cleaned["confidence"] = _validate_score(
        payload.get("confidence"), "confidence", errors, min_val=0.0, max_val=1.0
    )

    explanation = payload.get("explanation", "")
    if explanation is None:
        explanation = ""
    if not isinstance(explanation, str):
        errors["explanation"] = "explanation must be a string."
    elif len(explanation) > 2000:
        errors["explanation"] = "explanation must be at most 2000 characters."
    else:
        cleaned["explanation"] = explanation.strip()

    timestamp = _validate_timestamp(payload.get("timestamp"), errors)
    if timestamp is not None:
        cleaned["timestamp"] = timestamp

    if errors:
        return None, errors
    return cleaned, {}
