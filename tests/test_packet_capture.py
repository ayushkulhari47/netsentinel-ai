"""Tests for controlled Scapy metadata-only packet capture using mocked packets."""

from types import SimpleNamespace
import pytest

from app import create_app
from app.services.flow_aggregator import FlowAggregator
from app.services.packet_capture import PacketCaptureService, extract_packet_metadata
from scripts import run_capture


class MockScapyPacket:
    """Lightweight mock mimicking Scapy's layer API without touching network interfaces."""

    def __init__(self, layers, timestamp=1000.0, wirelen=128):
        self._layers = layers
        self.time = timestamp
        self.wirelen = wirelen

    def haslayer(self, name):
        return name in self._layers

    def getlayer(self, name):
        return self._layers.get(name)

    def __len__(self):
        return self.wirelen


def test_extract_ipv4_tcp_metadata_ignores_payload():
    """extract_packet_metadata should return 8 metadata fields and ignore Raw payload."""
    pkt = MockScapyPacket(
        layers={
            "IP": SimpleNamespace(src="192.168.1.10", dst="93.184.216.34"),
            "TCP": SimpleNamespace(sport=54321, dport=443, flags="PA"),
            "Raw": SimpleNamespace(load=b"SECRET_PAYLOAD_DO_NOT_CAPTURE"),
        },
        timestamp=1234.5,
        wirelen=256,
    )

    meta = extract_packet_metadata(pkt)
    assert meta == {
        "timestamp": 1234.5,
        "source_ip": "192.168.1.10",
        "destination_ip": "93.184.216.34",
        "source_port": 54321,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_length": 256,
        "tcp_flags": "PA",
    }
    assert "payload" not in meta
    assert "SECRET_PAYLOAD_DO_NOT_CAPTURE" not in str(meta)


def test_extract_ipv4_udp_and_icmp_and_ipv6_metadata():
    """extract_packet_metadata should support UDP, ICMP, IPv6 TCP, and IPv6 ICMPv6."""
    udp_pkt = MockScapyPacket(
        layers={
            "IP": SimpleNamespace(src="10.0.0.2", dst="8.8.8.8"),
            "UDP": SimpleNamespace(sport=55000, dport=53),
        },
        timestamp=200.0,
        wirelen=72,
    )
    assert extract_packet_metadata(udp_pkt)["protocol"] == "UDP"
    assert extract_packet_metadata(udp_pkt)["tcp_flags"] is None

    icmp_pkt = MockScapyPacket(
        layers={
            "IP": SimpleNamespace(src="10.0.0.2", dst="10.0.0.1"),
            "ICMP": SimpleNamespace(type=8, code=0),
        },
        timestamp=201.0,
        wirelen=64,
    )
    icmp_meta = extract_packet_metadata(icmp_pkt)
    assert icmp_meta["protocol"] == "ICMP"
    assert icmp_meta["source_port"] == 0
    assert icmp_meta["destination_port"] == 0

    ipv6_tcp_pkt = MockScapyPacket(
        layers={
            "IPv6": SimpleNamespace(src="2001:db8::1", dst="2001:db8::2", nh=6),
            "TCP": SimpleNamespace(sport=50000, dport=443, flags="S"),
        },
        timestamp=202.0,
        wirelen=94,
    )
    v6_meta = extract_packet_metadata(ipv6_tcp_pkt)
    assert v6_meta["source_ip"] == "2001:db8::1"
    assert v6_meta["protocol"] == "TCP"

    ipv6_icmp_pkt = MockScapyPacket(
        layers={
            "IPv6": SimpleNamespace(src="2001:db8::1", dst="2001:db8::2", nh=58),
        },
        timestamp=203.0,
        wirelen=80,
    )
    v6_icmp_meta = extract_packet_metadata(ipv6_icmp_pkt)
    assert v6_icmp_meta["protocol"] == "ICMP"


def test_unsupported_packets_are_ignored_safely():
    """Unsupported or malformed packets should return None and increment packets_ignored."""
    arp_pkt = MockScapyPacket(layers={"ARP": SimpleNamespace(psrc="10.0.0.1")})
    gre_pkt = MockScapyPacket(layers={"IP": SimpleNamespace(src="10.0.0.1", dst="10.0.0.2")})
    bad_port_pkt = MockScapyPacket(
        layers={
            "IP": SimpleNamespace(src="10.0.0.1", dst="10.0.0.2"),
            "TCP": SimpleNamespace(sport=70000, dport=80, flags="S"),
        }
    )

    assert extract_packet_metadata(None) is None
    assert extract_packet_metadata(arp_pkt) is None
    assert extract_packet_metadata(gre_pkt) is None
    assert extract_packet_metadata(bad_port_pkt) is None

    service = PacketCaptureService()
    assert service.handle_packet(arp_pkt) is None
    assert service.handle_packet(gre_pkt) is None
    assert service.packets_seen == 2
    assert service.packets_processed == 0
    assert service.packets_ignored == 2


def test_live_capture_requires_explicit_live_flag():
    """PacketCaptureService.capture_live must refuse execution unless live=True."""
    called = {"sniff": False}

    def fake_sniff(**_kwargs):
        called["sniff"] = True

    service = PacketCaptureService(sniff_fn=fake_sniff)
    with pytest.raises(PermissionError):
        service.capture_live(live=False)

    assert called["sniff"] is False


def test_capture_live_uses_store_false_and_forwards_to_flow_aggregator():
    """capture_live(live=True) should invoke sniff with store=False and aggregate flows."""
    captured_kwargs = {}
    mock_packets = [
        MockScapyPacket(
            layers={
                "IP": SimpleNamespace(src="192.168.1.5", dst="93.184.216.34"),
                "TCP": SimpleNamespace(sport=51000, dport=443, flags="S"),
            },
            timestamp=500.0,
            wirelen=74,
        ),
        MockScapyPacket(
            layers={
                "IP": SimpleNamespace(src="93.184.216.34", dst="192.168.1.5"),
                "TCP": SimpleNamespace(sport=443, dport=51000, flags="SA"),
            },
            timestamp=500.5,
            wirelen=74,
        ),
        MockScapyPacket(
            layers={"ARP": SimpleNamespace(psrc="192.168.1.1")},
            timestamp=500.6,
            wirelen=42,
        ),
    ]

    def fake_sniff(**kwargs):
        captured_kwargs.update(kwargs)
        prn = kwargs["prn"]
        for pkt in mock_packets:
            if kwargs["stop_filter"](pkt):
                break
            prn(pkt)

    aggregator = FlowAggregator(inactivity_timeout=30.0)
    service = PacketCaptureService(
        flow_aggregator=aggregator,
        interface="eth0",
        bpf_filter="tcp or udp",
        packet_limit=10,
        timeout=5.0,
        sniff_fn=fake_sniff,
    )

    result = service.capture_live(live=True)

    assert captured_kwargs["store"] is False
    assert captured_kwargs["iface"] == "eth0"
    assert captured_kwargs["filter"] == "tcp or udp"
    assert captured_kwargs["count"] == 10
    assert captured_kwargs["timeout"] == 5.0
    assert result["packets_seen"] == 3
    assert result["packets_processed"] == 2
    assert result["packets_ignored"] == 1
    assert result["interrupted"] is False
    assert len(result["flows"]) == 1
    assert result["flows"][0]["forward_packets"] == 1
    assert result["flows"][0]["backward_packets"] == 1
    assert result["flows"][0]["tcp_flags"] == ["S", "SA"]


def test_capture_live_handles_ctrl_c_gracefully():
    """KeyboardInterrupt during sniff should stop cleanly and flush active flows."""
    pkt = MockScapyPacket(
        layers={
            "IP": SimpleNamespace(src="10.0.0.10", dst="1.1.1.1"),
            "UDP": SimpleNamespace(sport=53000, dport=53),
        },
        timestamp=700.0,
        wirelen=68,
    )

    def fake_sniff_with_ctrl_c(**kwargs):
        kwargs["prn"](pkt)
        raise KeyboardInterrupt

    service = PacketCaptureService(sniff_fn=fake_sniff_with_ctrl_c)
    result = service.capture_live(live=True)

    assert result["interrupted"] is True
    assert result["packets_processed"] == 1
    assert len(result["flows"]) == 1
    assert result["flows"][0]["protocol"] == "UDP"


def test_cli_refuses_live_without_flag_and_supports_demo_and_live(capsys):
    """scripts/run_capture.py should block live mode without --live and run --demo safely."""
    exit_code = run_capture.main(["--interface", "eth0"])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "--live" in captured.err

    demo_exit = run_capture.main(["--demo", "--limit", "3"])
    demo_out = capsys.readouterr()
    assert demo_exit == 0
    assert "[DEMO]" in demo_out.out
    assert "3 synthetic packets" in demo_out.out

    recorded_init = {}

    class FakeCaptureService:
        def __init__(self, **kwargs):
            recorded_init.update(kwargs)

        def request_stop(self):
            pass

        def capture_live(self, live=False):
            recorded_init["live"] = live
            return {
                "mode": "live",
                "packets_seen": 2,
                "packets_processed": 2,
                "packets_ignored": 0,
                "flows": [{"protocol": "TCP"}],
                "interrupted": False,
            }

    live_exit = run_capture.main(
        ["--live", "--interface", "lo", "--limit", "2", "--timeout", "4", "--filter", "tcp"],
        capture_service_cls=FakeCaptureService,
    )
    live_out = capsys.readouterr()
    assert live_exit == 0
    assert recorded_init == {
        "interface": "lo",
        "bpf_filter": "tcp",
        "packet_limit": 2,
        "timeout": 4.0,
        "live": True,
    }
    assert "[LIVE]" in live_out.out


def test_flask_startup_does_not_start_packet_capture(tmp_path):
    """Creating the Flask app must never start packet capture automatically."""
    db_file = tmp_path / "no_auto_capture.db"
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}"})
    with app.test_client() as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.get_json()["packet_capture"] == "not_configured"
