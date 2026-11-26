"""Unit tests for the FlowAggregator network-flow aggregation service."""

import math
import pytest

from app.ml.feature_schema import FLOW_FEATURES, validate_flow_record
from app.services.flow_aggregator import FlowAggregator


def test_one_direction_flow():
    """Packets in a single direction should aggregate metrics and pass ML schema validation."""
    aggregator = FlowAggregator(inactivity_timeout=30.0)

    aggregator.add_packet(
        {
            "timestamp": 100.0,
            "source_ip": "192.168.1.10",
            "destination_ip": "93.184.216.34",
            "source_port": 51000,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_length": 100,
            "tcp_flags": "S",
        }
    )
    aggregator.add_packet(
        {
            "timestamp": 102.0,
            "source_ip": "192.168.1.10",
            "destination_ip": "93.184.216.34",
            "source_port": 51000,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_length": 200,
            "tcp_flags": "PA",
        }
    )

    records = aggregator.flush_all()
    assert len(records) == 1
    flow = records[0]

    assert flow["source_ip"] == "192.168.1.10"
    assert flow["destination_ip"] == "93.184.216.34"
    assert flow["source_port"] == 51000
    assert flow["destination_port"] == 443
    assert flow["protocol"] == "TCP"
    assert flow["first_seen"] == 100.0
    assert flow["last_seen"] == 102.0
    assert flow["duration"] == 2.0
    assert flow["flow_bytes"] == 300.0
    assert flow["flow_packets"] == 2
    assert flow["forward_packets"] == 2
    assert flow["backward_packets"] == 0
    assert flow["average_packet_size"] == 150.0
    assert flow["packet_rate"] == 1.0
    assert flow["byte_rate"] == 150.0
    assert flow["tcp_flags"] == ["PA", "S"]

    validated = validate_flow_record(flow)
    assert list(validated.keys()) == FLOW_FEATURES


def test_bidirectional_flow():
    """Reverse-direction packets on the same 5-tuple should merge into one bidirectional flow."""
    aggregator = FlowAggregator(inactivity_timeout=30.0)

    # Initiator -> Server
    aggregator.add_packet(
        {
            "timestamp": 200.0,
            "source_ip": "10.0.0.5",
            "destination_ip": "172.16.0.10",
            "source_port": 54321,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_length": 64,
            "tcp_flags": "S",
        }
    )
    # Server -> Initiator (reverse 5-tuple)
    aggregator.add_packet(
        {
            "timestamp": 200.5,
            "source_ip": "172.16.0.10",
            "destination_ip": "10.0.0.5",
            "source_port": 443,
            "destination_port": 54321,
            "protocol": "TCP",
            "packet_length": 64,
            "tcp_flags": "SA",
        }
    )
    # Initiator -> Server
    aggregator.add_packet(
        {
            "timestamp": 202.0,
            "source_ip": "10.0.0.5",
            "destination_ip": "172.16.0.10",
            "source_port": 54321,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_length": 172,
            "tcp_flags": "PA",
        }
    )
    # Server -> Initiator
    aggregator.add_packet(
        {
            "timestamp": 204.0,
            "source_ip": "172.16.0.10",
            "destination_ip": "10.0.0.5",
            "source_port": 443,
            "destination_port": 54321,
            "protocol": "TCP",
            "packet_length": 500,
            "tcp_flags": "A",
        }
    )

    assert aggregator.active_flow_count == 1
    records = aggregator.flush_all()
    assert len(records) == 1
    flow = records[0]

    # Preserves original initiator endpoints
    assert flow["source_ip"] == "10.0.0.5"
    assert flow["destination_ip"] == "172.16.0.10"
    assert flow["source_port"] == 54321
    assert flow["destination_port"] == 443
    assert flow["duration"] == 4.0
    assert flow["flow_bytes"] == 800.0
    assert flow["flow_packets"] == 4
    assert flow["forward_packets"] == 2
    assert flow["backward_packets"] == 2
    assert flow["average_packet_size"] == 200.0
    assert flow["packet_rate"] == 1.0
    assert flow["byte_rate"] == 200.0
    assert flow["tcp_flags"] == ["A", "PA", "S", "SA"]
    validate_flow_record(flow)


def test_multiple_independent_flows():
    """Distinct 5-tuples (ports or protocols) should remain independent flows."""
    aggregator = FlowAggregator(inactivity_timeout=30.0)

    # Flow 1: HTTPS TCP
    aggregator.add_packet(
        {
            "timestamp": 10.0,
            "source_ip": "192.168.1.20",
            "destination_ip": "93.184.216.34",
            "source_port": 50001,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_length": 120,
            "tcp_flags": "S",
        }
    )
    # Flow 2: Different source port
    aggregator.add_packet(
        {
            "timestamp": 11.0,
            "source_ip": "192.168.1.20",
            "destination_ip": "93.184.216.34",
            "source_port": 50002,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_length": 240,
            "tcp_flags": "PA",
        }
    )
    # Flow 3: DNS UDP
    aggregator.add_packet(
        {
            "timestamp": 12.0,
            "source_ip": "192.168.1.20",
            "destination_ip": "8.8.8.8",
            "source_port": 55000,
            "destination_port": 53,
            "protocol": "UDP",
            "packet_length": 78,
            "tcp_flags": None,
        }
    )

    assert aggregator.active_flow_count == 3
    records = aggregator.flush_all()
    assert len(records) == 3
    assert [r["first_seen"] for r in records] == [10.0, 11.0, 12.0]
    assert [r["source_port"] for r in records] == [50001, 50002, 55000]
    assert records[2]["tcp_flags"] == []


def test_inactivity_expiration_with_injected_clock():
    """flush_expired should expire only flows inactive past inactivity_timeout."""
    fake_now = {"t": 100.0}
    aggregator = FlowAggregator(inactivity_timeout=15.0, time_fn=lambda: fake_now["t"])

    aggregator.add_packet(
        {
            "timestamp": 100.0,
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "source_port": 40000,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_length": 100,
            "tcp_flags": "S",
        }
    )
    aggregator.add_packet(
        {
            "timestamp": 110.0,
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.3",
            "source_port": 40001,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_length": 150,
            "tcp_flags": "S",
        }
    )

    # At t=114.0, neither flow has reached 15s inactivity
    fake_now["t"] = 114.0
    assert aggregator.flush_expired() == []
    assert aggregator.active_flow_count == 2

    # At t=115.0, first flow (last_seen=100.0) expires; second (last_seen=110.0) stays active
    fake_now["t"] = 115.0
    expired = aggregator.flush_expired()
    assert len(expired) == 1
    assert expired[0]["destination_ip"] == "10.0.0.2"
    assert aggregator.active_flow_count == 1

    # At explicit current_time=125.0, second flow expires
    expired_second = aggregator.flush_expired(current_time=125.0)
    assert len(expired_second) == 1
    assert expired_second[0]["destination_ip"] == "10.0.0.3"
    assert aggregator.active_flow_count == 0


def test_flow_flushing_and_same_key_rotation():
    """flush_all clears active flows, and same-key timeouts rotate cleanly."""
    aggregator = FlowAggregator(inactivity_timeout=10.0)

    aggregator.add_packet(
        {
            "timestamp": 50.0,
            "source_ip": "192.168.1.5",
            "destination_ip": "1.1.1.1",
            "source_port": 51111,
            "destination_port": 53,
            "protocol": "UDP",
            "packet_length": 60,
            "tcp_flags": None,
        }
    )
    # Same 5-tuple arrives after timeout -> rotates previous flow into expired buffer
    aggregator.add_packet(
        {
            "timestamp": 65.0,
            "source_ip": "192.168.1.5",
            "destination_ip": "1.1.1.1",
            "source_port": 51111,
            "destination_port": 53,
            "protocol": "UDP",
            "packet_length": 90,
            "tcp_flags": None,
        }
    )

    assert aggregator.active_flow_count == 1
    expired = aggregator.flush_expired(current_time=66.0)
    assert len(expired) == 1
    assert expired[0]["first_seen"] == 50.0
    assert expired[0]["flow_bytes"] == 60.0

    remaining = aggregator.flush_all()
    assert len(remaining) == 1
    assert remaining[0]["first_seen"] == 65.0
    assert remaining[0]["flow_bytes"] == 90.0
    assert aggregator.active_flow_count == 0
    assert aggregator.flush_all() == []


def test_zero_duration_handling():
    """Single-packet or identical-timestamp flows should produce finite zero rates."""
    aggregator = FlowAggregator(inactivity_timeout=30.0)

    aggregator.add_packet(
        {
            "timestamp": 500.0,
            "source_ip": "192.168.1.30",
            "destination_ip": "8.8.4.4",
            "source_port": 52000,
            "destination_port": 53,
            "protocol": "UDP",
            "packet_length": 84,
            "tcp_flags": None,
        }
    )

    records = aggregator.flush_all()
    assert len(records) == 1
    flow = records[0]

    assert flow["duration"] == 0.0
    assert flow["flow_packets"] == 1
    assert flow["flow_bytes"] == 84.0
    assert flow["average_packet_size"] == 84.0
    assert flow["packet_rate"] == 0.0
    assert flow["byte_rate"] == 0.0
    assert math.isfinite(flow["packet_rate"])
    assert math.isfinite(flow["byte_rate"])

    validated = validate_flow_record(flow)
    assert validated["duration"] == 0.0


def test_invalid_inputs_raise_value_error():
    """FlowAggregator should reject invalid timeout and malformed packet metadata."""
    with pytest.raises(ValueError):
        FlowAggregator(inactivity_timeout=0)

    aggregator = FlowAggregator(inactivity_timeout=30.0)
    with pytest.raises(ValueError):
        aggregator.add_packet({"timestamp": 1.0, "source_ip": "bad-ip"})
