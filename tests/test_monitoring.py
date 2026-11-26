"""End-to-end tests for MonitoringService and scripts/run_monitor.py."""

from types import SimpleNamespace
import pytest
import requests

from app import create_app
from app.models import Alert
from app.services.detection_engine import DetectionEngine
from app.services.flow_aggregator import FlowAggregator
from app.services.llm_explainer import LLMExplainer
from app.services.monitoring_service import MonitoringService
from app.services.threat_intel import ThreatIntelService
from scripts import run_monitor
from scripts.generate_demo_data import generate_datasets
from scripts.train_model import train_and_save_model


class MockScapyPacket:
    """Mock Scapy packet exposing layer headers without touching network interfaces."""

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


@pytest.fixture()
def temp_app(tmp_path):
    """Create a Flask app with an isolated temporary SQLite database."""
    db_file = tmp_path / "test_monitoring.db"
    return create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
        }
    )


@pytest.fixture()
def trained_model_path(tmp_path):
    """Train a temporary IsolationForest model bundle in tmp_path."""
    data_dir = tmp_path / "data"
    model_dir = tmp_path / "models"
    generate_datasets(
        output_dir=data_dir,
        train_samples=300,
        eval_benign_samples=50,
        eval_anomaly_samples=50,
        random_state=42,
    )
    result = train_and_save_model(
        data_dir=data_dir,
        model_dir=model_dir,
        contamination=0.02,
        n_estimators=100,
        random_state=42,
    )
    return result["model_path"]


def test_only_completed_flows_are_analyzed(temp_app, trained_model_path):
    """Active flows must not be analyzed until inactivity expiration or explicit flush."""
    with temp_app.app_context():
        service = MonitoringService(
            flow_aggregator=FlowAggregator(inactivity_timeout=10.0),
            detection_engine=DetectionEngine(model_path=trained_model_path),
        )

        # Send suspicious-port packets inside active window (dt=1s < timeout=10s)
        service.ingest_packet(
            {
                "timestamp": 100.0,
                "source_ip": "198.51.100.10",
                "destination_ip": "10.0.0.5",
                "source_port": 40000,
                "destination_port": 4444,
                "protocol": "TCP",
                "packet_length": 120,
                "tcp_flags": "S",
            }
        )
        assert service.flows_analyzed == 0
        assert Alert.query.count() == 0

        # Flushing completes the flow and triggers detection + persistence
        assessments = service.flush_and_analyze()
        assert len(assessments) == 1
        assert service.flows_analyzed == 1
        assert Alert.query.count() == 1


def test_end_to_end_mocked_capture_persists_only_suspicious_alerts(
    temp_app, trained_model_path, monkeypatch
):
    """Normal flows must not create Alerts; suspicious flows must persist with fallback explanations."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    mock_packets = [
        # Normal HTTPS bidirectional flow
        MockScapyPacket(
            layers={
                "IP": SimpleNamespace(src="192.168.1.50", dst="93.184.216.34"),
                "TCP": SimpleNamespace(sport=54120, dport=443, flags="S"),
                "Raw": SimpleNamespace(load=b"DO_NOT_STORE_PAYLOAD"),
            },
            timestamp=500.0,
            wirelen=74,
        ),
        MockScapyPacket(
            layers={
                "IP": SimpleNamespace(src="93.184.216.34", dst="192.168.1.50"),
                "TCP": SimpleNamespace(sport=443, dport=54120, flags="SA"),
            },
            timestamp=501.0,
            wirelen=800,
        ),
    ]
    # Suspicious high-rate outbound flow on port 4444
    for idx in range(20):
        mock_packets.append(
            MockScapyPacket(
                layers={
                    "IP": SimpleNamespace(src="198.51.100.77", dst="10.0.0.15"),
                    "TCP": SimpleNamespace(sport=40123, dport=4444, flags="S"),
                },
                timestamp=600.0 + idx * 0.001,
                wirelen=1400,
            )
        )

    captured_kwargs = {}

    def fake_sniff(**kwargs):
        captured_kwargs.update(kwargs)
        for pkt in mock_packets:
            if kwargs["stop_filter"](pkt):
                break
            kwargs["prn"](pkt)

    with temp_app.app_context():
        service = MonitoringService(
            detection_engine=DetectionEngine(model_path=trained_model_path),
            threat_intel_service=ThreatIntelService(),
            llm_explainer=LLMExplainer(),
        )
        result = service.run_live(
            live=True,
            interface="lo",
            bpf_filter="tcp",
            packet_limit=50,
            timeout=5.0,
            sniff_fn=fake_sniff,
        )

        assert captured_kwargs["store"] is False
        assert result["packets_processed"] == 22
        assert result["flows_analyzed"] == 2
        assert result["alerts_created"] == 1
        assert result["interrupted"] is False

        alerts = Alert.query.all()
        assert len(alerts) == 1
        assert alerts[0].source_ip == "198.51.100.77"
        assert alerts[0].destination_port == 4444
        assert alerts[0].severity in {"high", "critical"}
        assert "Possible" in alerts[0].explanation
        assert "DO_NOT_STORE_PAYLOAD" not in alerts[0].explanation


def test_threat_intel_used_only_when_configured(temp_app, trained_model_path, monkeypatch):
    """MonitoringService should skip AbuseIPDB unless ABUSEIPDB_API_KEY is configured."""
    calls = {"count": 0}

    def fake_get(*_args, **_kwargs):
        calls["count"] += 1
        return SimpleNamespace(
            status_code=200,
            json=lambda: {"data": {"abuseConfidenceScore": 90, "categories": [14]}},
        )

    monkeypatch.setattr(requests, "get", fake_get)

    normal_packets = [
        {
            "timestamp": 100.0,
            "source_ip": "93.184.216.34",
            "destination_ip": "10.0.0.5",
            "source_port": 54000,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_length": 400,
            "tcp_flags": "S",
        },
        {
            "timestamp": 102.0,
            "source_ip": "10.0.0.5",
            "destination_ip": "93.184.216.34",
            "source_port": 443,
            "destination_port": 54000,
            "protocol": "TCP",
            "packet_length": 800,
            "tcp_flags": "SA",
        },
    ]

    with temp_app.app_context():
        # Unconfigured API key -> 0 external calls
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        unconfigured_service = MonitoringService(
            detection_engine=DetectionEngine(model_path=trained_model_path),
            threat_intel_service=ThreatIntelService(),
        )
        res_unconf = unconfigured_service.process_packets(normal_packets, flush=True)
        assert calls["count"] == 0
        assert res_unconf["alerts_created"] == 0

        # Configured API key -> external lookup enriches score and triggers alert
        configured_service = MonitoringService(
            detection_engine=DetectionEngine(model_path=trained_model_path),
            threat_intel_service=ThreatIntelService(api_key="test-abuse-key"),
        )
        res_conf = configured_service.process_packets(normal_packets, flush=True)
        assert calls["count"] == 1
        assert res_conf["alerts_created"] == 1
        assert res_conf["alerts"][0]["threat_score"] >= 25.0


def test_run_live_requires_flag_and_handles_ctrl_c(temp_app, trained_model_path):
    """MonitoringService.run_live must require live=True and flush captured flows on Ctrl+C."""
    with temp_app.app_context():
        service = MonitoringService(
            detection_engine=DetectionEngine(model_path=trained_model_path),
        )
        with pytest.raises(PermissionError):
            service.run_live(live=False)

        pkt = MockScapyPacket(
            layers={
                "IP": SimpleNamespace(src="198.51.100.88", dst="10.0.0.12"),
                "UDP": SimpleNamespace(sport=50000, dport=23),
            },
            timestamp=200.0,
            wirelen=120,
        )

        def ctrl_c_sniff(**kwargs):
            kwargs["prn"](pkt)
            raise KeyboardInterrupt

        res = service.run_live(live=True, sniff_fn=ctrl_c_sniff)
        assert res["interrupted"] is True
        assert res["flows_analyzed"] == 1
        assert res["alerts_created"] == 1


def test_cli_run_monitor_demo_and_live_and_refusal(temp_app, trained_model_path, capsys, monkeypatch):
    """scripts/run_monitor.py should refuse without --live/--demo and support both modes."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    # 1. Refusal without --demo or --live
    refuse_code = run_monitor.main(["--interface", "eth0"], app=temp_app)
    assert refuse_code == 2
    assert "--live" in capsys.readouterr().err

    # 2. Safe --demo mode creates normal + suspicious flows, persisting only suspicious alerts
    demo_service = MonitoringService(
        detection_engine=DetectionEngine(model_path=trained_model_path),
        threat_intel_service=ThreatIntelService(),
        llm_explainer=LLMExplainer(),
    )
    demo_code = run_monitor.main(["--demo"], app=temp_app, monitoring_service=demo_service)
    demo_out = capsys.readouterr().out
    assert demo_code == 0
    assert "[DEMO]" in demo_out

    with temp_app.test_client() as client:
        alerts_json = client.get("/api/alerts").get_json()
        summary_json = client.get("/api/summary").get_json()
        # 4 total demo flows (2 normal, 2 suspicious) -> only the 2 suspicious flows persist
        assert alerts_json["count"] == 2
        assert summary_json["total_alerts"] == 2

    # 3. Mocked --live mode
    live_pkt = MockScapyPacket(
        layers={
            "IP": SimpleNamespace(src="198.51.100.99", dst="10.0.0.20"),
            "UDP": SimpleNamespace(sport=51000, dport=23),
        },
        timestamp=900.0,
        wirelen=100,
    )

    def fake_live_sniff(**kwargs):
        kwargs["prn"](live_pkt)

    live_service = MonitoringService(
        detection_engine=DetectionEngine(model_path=trained_model_path),
        threat_intel_service=ThreatIntelService(),
        llm_explainer=LLMExplainer(),
    )
    live_code = run_monitor.main(
        ["--live", "--interface", "lo", "--limit", "5", "--timeout", "3", "--filter", "udp"],
        app=temp_app,
        monitoring_service=live_service,
        sniff_fn=fake_live_sniff,
    )
    live_out = capsys.readouterr().out
    assert live_code == 0
    assert "[LIVE]" in live_out
    assert "alerts_created=1" in live_out


def test_flask_startup_does_not_auto_start_monitoring(temp_app):
    """Starting Flask must never start background packet capture or create demo alerts."""
    with temp_app.test_client() as client:
        assert client.get("/health").get_json()["packet_capture"] == "not_configured"
        assert client.get("/api/alerts").get_json()["count"] == 0
