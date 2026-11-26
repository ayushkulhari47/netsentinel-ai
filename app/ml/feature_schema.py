"""Standard network flow feature schema and validation for NetSentinel AI."""

import math
import numbers
import numpy as np
import pandas as pd

FLOW_FEATURES = [
    "duration",
    "protocol",
    "source_port",
    "destination_port",
    "flow_bytes",
    "flow_packets",
    "forward_packets",
    "backward_packets",
    "average_packet_size",
    "packet_rate",
    "byte_rate",
]

CATEGORICAL_FEATURES = ["protocol"]
NUMERIC_FEATURES = [feature for feature in FLOW_FEATURES if feature not in CATEGORICAL_FEATURES]
PORT_FEATURES = {"source_port", "destination_port"}

PROTOCOL_NUMBER_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}
ALLOWED_PROTOCOLS = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "OTHER"}


def _is_finite_number(value):
    """Return True if value is a finite real number (excluding booleans)."""
    return (
        isinstance(value, numbers.Real)
        and not isinstance(value, (bool, np.bool_))
        and math.isfinite(float(value))
    )


def normalize_protocol(value):
    """Normalize a protocol string or IANA protocol number into an uppercase token."""
    if isinstance(value, (bool, np.bool_)):
        raise ValueError("protocol must be a valid protocol name or number, not boolean.")

    if isinstance(value, numbers.Integral):
        num = int(value)
        if num in PROTOCOL_NUMBER_MAP:
            return PROTOCOL_NUMBER_MAP[num]
        raise ValueError(f"Unsupported numeric protocol: {num}.")

    if not isinstance(value, str) or not value.strip():
        raise ValueError("protocol must be a non-empty string.")

    cleaned = value.strip().upper()
    if cleaned.isdigit():
        num = int(cleaned)
        if num in PROTOCOL_NUMBER_MAP:
            return PROTOCOL_NUMBER_MAP[num]
        raise ValueError(f"Unsupported numeric protocol: {cleaned}.")

    if cleaned not in ALLOWED_PROTOCOLS:
        allowed = ", ".join(sorted(ALLOWED_PROTOCOLS))
        raise ValueError(f"protocol '{cleaned}' is not supported. Allowed: {allowed}.")
    return cleaned


def validate_flow_record(record):
    """Validate and normalize a single network flow dictionary.

    Returns a dictionary containing all FLOW_FEATURES with normalized types.
    Raises ValueError with clear field details if validation fails.
    """
    if not isinstance(record, dict):
        raise ValueError("Flow record must be a dictionary.")

    missing = [feature for feature in FLOW_FEATURES if feature not in record]
    if missing:
        raise ValueError(f"Missing required flow features: {', '.join(missing)}.")

    errors = []
    cleaned = {}

    for feature in FLOW_FEATURES:
        value = record[feature]
        if feature == "protocol":
            try:
                cleaned["protocol"] = normalize_protocol(value)
            except ValueError as exc:
                errors.append(str(exc))
            continue

        if not _is_finite_number(value):
            errors.append(f"{feature} must be a finite number.")
            continue

        if feature in PORT_FEATURES:
            float_val = float(value)
            if not float_val.is_integer():
                errors.append(f"{feature} must be an integer between 0 and 65535.")
                continue
            port = int(float_val)
            if port < 0 or port > 65535:
                errors.append(f"{feature} must be between 0 and 65535.")
                continue
            cleaned[feature] = port
        else:
            num = float(value)
            if num < 0.0:
                errors.append(f"{feature} must be >= 0.")
                continue
            cleaned[feature] = num

    if errors:
        raise ValueError(" ".join(errors))

    return cleaned


def validate_flow_dataframe(df):
    """Validate and normalize a DataFrame of network flows against FLOW_FEATURES.

    Returns a copy of the DataFrame containing only FLOW_FEATURES in canonical order.
    Raises ValueError if the DataFrame is invalid.
    """
    if not isinstance(df, pd.DataFrame):
        raise ValueError("Input must be a pandas DataFrame.")
    if df.empty:
        raise ValueError("Flow DataFrame must not be empty.")

    missing = [feature for feature in FLOW_FEATURES if feature not in df.columns]
    if missing:
        raise ValueError(f"Missing required flow columns: {', '.join(missing)}.")

    records = df[FLOW_FEATURES].to_dict(orient="records")
    validated_rows = []
    for idx, row in enumerate(records):
        try:
            validated_rows.append(validate_flow_record(row))
        except ValueError as exc:
            raise ValueError(f"Row {idx}: {exc}") from exc

    return pd.DataFrame(validated_rows, columns=FLOW_FEATURES)
