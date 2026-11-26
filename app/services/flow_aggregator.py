"""Deterministic network-flow aggregation service for NetSentinel AI."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import math
import numbers
import time
import numpy as np

from app.ml.feature_schema import normalize_protocol


def _is_finite_number(value):
    """Return True if value is a finite real number (excluding booleans)."""
    return (
        isinstance(value, numbers.Real)
        and not isinstance(value, (bool, np.bool_))
        and math.isfinite(float(value))
    )


def _normalize_timestamp(value):
    """Normalize a packet timestamp (epoch number, datetime, or ISO string) to float seconds."""
    if _is_finite_number(value):
        ts = float(value)
        if ts < 0.0:
            raise ValueError("timestamp must be >= 0.")
        return ts

    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return dt.timestamp()

    if isinstance(value, str) and value.strip():
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ValueError("timestamp must be a valid epoch number or ISO-8601 string.") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()

    raise ValueError("timestamp is required and must be a finite number, datetime, or ISO string.")


def _normalize_ip(value, field_name):
    """Validate and normalize an IPv4 or IPv6 address string."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required and must be a valid IP address.")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid IPv4 or IPv6 address.") from exc


def _normalize_port(value, field_name):
    """Validate and normalize a port number (0-65535; None defaults to 0)."""
    if value is None:
        return 0
    if not _is_finite_number(value):
        raise ValueError(f"{field_name} must be an integer between 0 and 65535.")
    float_val = float(value)
    if not float_val.is_integer():
        raise ValueError(f"{field_name} must be an integer between 0 and 65535.")
    port = int(float_val)
    if port < 0 or port > 65535:
        raise ValueError(f"{field_name} must be between 0 and 65535.")
    return port


def _normalize_tcp_flags(value):
    """Normalize TCP flags from None, string, or iterable into uppercase tokens."""
    if value is None:
        return []
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if "," in stripped:
            tokens = [part.strip().upper() for part in stripped.split(",") if part.strip()]
            return tokens
        return [stripped.upper()]
    if isinstance(value, (list, tuple, set)):
        tokens = []
        for item in value:
            if isinstance(item, str) and item.strip():
                tokens.append(item.strip().upper())
        return tokens
    raise ValueError("tcp_flags must be None, a string, or an iterable of strings.")


def _canonical_flow_key(source_ip, source_port, destination_ip, destination_port, protocol):
    """Create a bidirectional 5-tuple lookup key independent of packet direction."""
    src_endpoint = (source_ip, source_port)
    dst_endpoint = (destination_ip, destination_port)
    if src_endpoint <= dst_endpoint:
        return (src_endpoint, dst_endpoint, protocol)
    return (dst_endpoint, src_endpoint, protocol)


@dataclass
class _FlowState:
    """Mutable accumulator for a single bidirectional network flow."""

    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    first_seen: float
    last_seen: float
    total_bytes: float = 0.0
    total_packets: int = 0
    forward_packets: int = 0
    backward_packets: int = 0
    tcp_flags: set[str] = field(default_factory=set)

    def update(self, timestamp, source_ip, source_port, packet_length, tcp_flags):
        """Update flow counters and timestamps with a normalized packet."""
        if timestamp < self.first_seen:
            self.first_seen = timestamp
        if timestamp > self.last_seen:
            self.last_seen = timestamp

        self.total_bytes += packet_length
        self.total_packets += 1

        if (source_ip, source_port) == (self.source_ip, self.source_port):
            self.forward_packets += 1
        else:
            self.backward_packets += 1

        self.tcp_flags.update(tcp_flags)

    def to_record(self):
        """Convert accumulated flow state into an ML-compatible flow dictionary."""
        duration = round(max(0.0, self.last_seen - self.first_seen), 6)
        flow_bytes = round(float(self.total_bytes), 4)
        flow_packets = int(self.total_packets)
        avg_packet_size = round(flow_bytes / flow_packets, 4) if flow_packets > 0 else 0.0

        if duration > 0.0:
            packet_rate = round(flow_packets / duration, 4)
            byte_rate = round(flow_bytes / duration, 4)
        else:
            packet_rate = 0.0
            byte_rate = 0.0

        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": duration,
            "flow_bytes": flow_bytes,
            "flow_packets": flow_packets,
            "forward_packets": int(self.forward_packets),
            "backward_packets": int(self.backward_packets),
            "average_packet_size": avg_packet_size,
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "tcp_flags": sorted(self.tcp_flags),
        }


class FlowAggregator:
    """Aggregates normalized packet metadata into bidirectional network flows."""

    def __init__(self, inactivity_timeout=30.0, time_fn=None):
        """Initialize the aggregator with a positive inactivity timeout in seconds."""
        if not _is_finite_number(inactivity_timeout) or float(inactivity_timeout) <= 0.0:
            raise ValueError("inactivity_timeout must be a positive number.")

        self.inactivity_timeout = float(inactivity_timeout)
        self._time_fn = time_fn if time_fn is not None else time.time
        self._active_flows = {}
        self._expired_buffer = []

    @property
    def active_flow_count(self):
        """Return the number of currently active flows."""
        return len(self._active_flows)

    def _validate_packet(self, packet):
        """Validate and normalize incoming packet metadata."""
        if not isinstance(packet, dict):
            raise ValueError("Packet metadata must be a dictionary.")

        timestamp = _normalize_timestamp(packet.get("timestamp"))
        source_ip = _normalize_ip(packet.get("source_ip"), "source_ip")
        destination_ip = _normalize_ip(packet.get("destination_ip"), "destination_ip")
        source_port = _normalize_port(packet.get("source_port"), "source_port")
        destination_port = _normalize_port(packet.get("destination_port"), "destination_port")
        protocol = normalize_protocol(packet.get("protocol"))

        packet_length = packet.get("packet_length")
        if not _is_finite_number(packet_length) or float(packet_length) < 0.0:
            raise ValueError("packet_length is required and must be a finite number >= 0.")

        tcp_flags = _normalize_tcp_flags(packet.get("tcp_flags"))

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "packet_length": float(packet_length),
            "tcp_flags": tcp_flags,
        }

    def add_packet(self, packet):
        """Add one normalized packet dictionary to its bidirectional flow."""
        pkt = self._validate_packet(packet)
        key = _canonical_flow_key(
            pkt["source_ip"],
            pkt["source_port"],
            pkt["destination_ip"],
            pkt["destination_port"],
            pkt["protocol"],
        )

        existing = self._active_flows.get(key)
        if existing is not None and (pkt["timestamp"] - existing.last_seen) >= self.inactivity_timeout:
            self._expired_buffer.append(existing.to_record())
            del self._active_flows[key]
            existing = None

        if existing is None:
            existing = _FlowState(
                source_ip=pkt["source_ip"],
                destination_ip=pkt["destination_ip"],
                source_port=pkt["source_port"],
                destination_port=pkt["destination_port"],
                protocol=pkt["protocol"],
                first_seen=pkt["timestamp"],
                last_seen=pkt["timestamp"],
            )
            self._active_flows[key] = existing

        existing.update(
            timestamp=pkt["timestamp"],
            source_ip=pkt["source_ip"],
            source_port=pkt["source_port"],
            packet_length=pkt["packet_length"],
            tcp_flags=pkt["tcp_flags"],
        )

    def flush_expired(self, current_time=None):
        """Expire and return flows inactive for at least inactivity_timeout seconds."""
        now = _normalize_timestamp(current_time) if current_time is not None else float(self._time_fn())

        flushed = list(self._expired_buffer)
        self._expired_buffer.clear()

        expired_keys = [
            key
            for key, flow in self._active_flows.items()
            if (now - flow.last_seen) >= self.inactivity_timeout
        ]
        flushed.extend(
            self._active_flows.pop(key).to_record()
            for key in expired_keys
        )
        return self._sort_records(flushed)

    def flush_all(self):
        """Flush and return all active and buffered flows."""
        flushed = list(self._expired_buffer)
        self._expired_buffer.clear()

        flushed.extend(flow.to_record() for flow in self._active_flows.values())
        self._active_flows.clear()
        return self._sort_records(flushed)

    @staticmethod
    def _sort_records(records):
        """Return flow records sorted deterministically by first_seen and 5-tuple."""
        return sorted(
            records,
            key=lambda r: (
                r["first_seen"],
                r["source_ip"],
                r["destination_ip"],
                r["source_port"],
                r["destination_port"],
                r["protocol"],
            ),
        )
