"""Tests for RuleEngine and DetectionEngine explainable threat detection."""

import pytest

from app import create_app
from app.models import Alert
from app.services.detection_engine import DetectionEngine, map_risk_to_severity
from app.services.flow_aggregator import FlowAggregator
from app.services.rule_engine import RuleEngine
from scripts.generate_demo_data import generate_datasets
from scripts.train_model import train_and_save_model


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app configured with an isolated temporary SQLite database."""
    db_file = tmp_path / "test_detection.db"
    application = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
        }
    )
    yield application


@pytest.fixture()
def trained_model_path(tmp_path):
    """Train a small IsolationForest bundle in tmp_path for deterministic ML tests."""
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


def _normal_flow():
    return {
        "source_ip": "192.168.1.25",
        "destination_ip": "93.184.216.34",
        "duration": 2.0,
        "protocol": "TCP",
        "source_port": 54000,
        "destination_port": 443,
        "flow_bytes": 12000.0,
        "flow_packets": 20,
        "forward_packets": 10,
        "backward_packets": 10,
        "average_packet_size": 600.0,
        "packet_rate": 10.0,
        "byte_rate": 6000.0,
        "tcp_flags": ["A", "PA", "S", "SA"],
    }


def _high_rate_anomalous_flow():
    return {
        "source_ip": "203.0.113.77",
        "destination_ip": "10.0.0.15",
        "duration": 0.25,
        "protocol": "TCP",
        "source_port": 33333,
        "destination_port": 4444,
        "flow_bytes": 600_000.0,
        "flow_packets": 2000,
        "forward_packets": 2000,
        "backward_packets": 0,
        "average_packet_size": 300.0,
        "packet_rate": 8000.0,
        "byte_rate": 2_400_000.0,
        "tcp_flags": ["S"],
    }


def test_map_risk_to_severity_boundaries():
    """Risk scores 0-100 should map cleanly to low, medium, high, and critical."""
    assert map_risk_to_severity(0) == "low"
    assert map_risk_to_severity(24.9) == "low"
    assert map_risk_to_severity(25.0) == "medium"
    assert map_risk_to_severity(49.9) == "medium"
    assert map_risk_to_severity(50.0) == "high"
    assert map_risk_to_severity(74.9) == "high"
    assert map_risk_to_severity(75.0) == "critical"
    assert map_risk_to_severity(100.0) == "critical"


def test_rule_engine_evaluates_all_four_categories():
    """RuleEngine should trigger packet rate, byte rate, flow size, and port rules."""
    engine = RuleEngine()
    result = engine.evaluate(_high_rate_anomalous_flow())
    matched_ids = {rule["rule_id"] for rule in result["matched_rules"]}

    assert matched_ids == {
        "high_packet_rate",
        "high_byte_rate",
        "large_flow_size",
        "suspicious_protocol_port",
    }
    assert result["rule_score"] == 100.0
    assert len(result["evidence"]) == 4

    # Normal flow triggers zero rules
    normal_result = engine.evaluate(_normal_flow())
    assert normal_result["rule_score"] == 0.0
    assert normal_result["matched_rules"] == []


def test_normal_flow_is_not_persisted_as_alert(app, trained_model_path):
    """Normal flows should score low, avoid false alerts, and return full output schema."""
    with app.app_context():
        engine = DetectionEngine(model_path=trained_model_path)
        result = engine.analyze_flow(_normal_flow(), persist=True)

        assert result["is_suspicious"] is False
        assert result["severity"] == "low"
        assert 0.0 <= result["threat_score"] < 25.0
        assert 0.0 <= result["confidence"] <= 1.0
        assert result["ml_available"] is True
        assert result["alert"] is None
        assert result["recommended_action"]
        assert "No suspicious indicators" in result["explanation"]
        assert Alert.query.count() == 0


def test_anomalous_and_high_rate_flows_persist_explainable_alerts(app, trained_model_path):
    """Suspicious and high-rate flows should produce cautious explanations and persist Alerts."""
    with app.app_context():
        engine = DetectionEngine(model_path=trained_model_path)

        # ML anomaly on unusual pattern below extreme rule thresholds
        ml_only_anomalous = {
            "source_ip": "198.51.100.20",
            "destination_ip": "10.0.0.8",
            "duration": 0.005,
            "protocol": "TCP",
            "source_port": 40001,
            "destination_port": 23,  # Telnet triggers suspicious port rule + ML outlier
            "flow_bytes": 2400.0,
            "flow_packets": 40,
            "forward_packets": 40,
            "backward_packets": 0,
            "average_packet_size": 60.0,
            "packet_rate": 8000.0,
            "byte_rate": 480_000.0,
            "tcp_flags": ["S"],
        }
        res_anom = engine.analyze_flow(ml_only_anomalous, persist=True)
        assert res_anom["is_suspicious"] is True
        assert res_anom["severity"] in {"high", "critical"}
        assert 25.0 <= res_anom["threat_score"] <= 100.0
        assert "possible" in res_anom["explanation"].lower() or "suspicious" in res_anom["explanation"].lower()
        assert len(res_anom["evidence"]) >= 2
        assert res_anom["recommended_action"]
        assert res_anom["alert"] is not None

        # High-rate multi-rule flow
        res_high = engine.analyze_flow(
            _high_rate_anomalous_flow(),
            threat_intel={"malicious": True, "reputation_score": 85, "source": "demo_cache"},
            persist=True,
        )
        assert res_high["is_suspicious"] is True
        assert res_high["severity"] == "critical"
        assert res_high["threat_score"] == 100.0
        assert res_high["alert"] is not None
        assert Alert.query.count() == 2


def test_missing_local_model_is_handled_gracefully(app, tmp_path):
    """DetectionEngine should fall back cleanly to rules when local ML model is absent."""
    missing_model = tmp_path / "missing_model.joblib"

    with app.app_context():
        engine = DetectionEngine(model_path=missing_model)

        normal_res = engine.analyze_flow(_normal_flow(), persist=True)
        assert normal_res["ml_available"] is False
        assert normal_res["is_suspicious"] is False
        assert normal_res["severity"] == "low"
        assert any("unavailable" in item.lower() for item in normal_res["evidence"])
        assert Alert.query.count() == 0

        high_res = engine.analyze_flow(_high_rate_anomalous_flow(), persist=True)
        assert high_res["ml_available"] is False
        assert high_res["is_suspicious"] is True
        assert high_res["severity"] == "critical"
        assert high_res["alert"] is not None
        assert Alert.query.count() == 1


def test_invalid_flows_raise_value_error_and_persist_nothing(app, trained_model_path):
    """Invalid flows or invalid threat_intel must raise ValueError without writing Alerts."""
    with app.app_context():
        engine = DetectionEngine(model_path=trained_model_path)

        with pytest.raises(ValueError):
            engine.analyze_flow({"source_ip": "10.0.0.1"}, persist=True)

        bad_ip_flow = _normal_flow()
        bad_ip_flow["source_ip"] = "not-an-ip"
        with pytest.raises(ValueError):
            engine.analyze_flow(bad_ip_flow, persist=True)

        bad_rate_flow = _normal_flow()
        bad_rate_flow["packet_rate"] = -5.0
        with pytest.raises(ValueError):
            engine.analyze_flow(bad_rate_flow, persist=True)

        with pytest.raises(ValueError):
            engine.analyze_flow(_normal_flow(), threat_intel="invalid", persist=True)

        assert Alert.query.count() == 0


def test_flow_aggregator_to_detection_engine_pipeline(app, trained_model_path):
    """Flows flushed from FlowAggregator should integrate cleanly with DetectionEngine."""
    aggregator = FlowAggregator(inactivity_timeout=30.0)
    aggregator.add_packet(
        {
            "timestamp": 100.0,
            "source_ip": "192.168.1.40",
            "destination_ip": "93.184.216.34",
            "source_port": 52100,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_length": 400,
            "tcp_flags": "S",
        }
    )
    aggregator.add_packet(
        {
            "timestamp": 101.0,
            "source_ip": "93.184.216.34",
            "destination_ip": "192.168.1.40",
            "source_port": 443,
            "destination_port": 52100,
            "protocol": "TCP",
            "packet_length": 800,
            "tcp_flags": "SA",
        }
    )
    flows = aggregator.flush_all()

    with app.app_context():
        engine = DetectionEngine(model_path=trained_model_path)
        result = engine.analyze_flow(flows[0], persist=True)
        assert result["severity"] == "low"
        assert result["is_suspicious"] is False
        assert Alert.query.count() == 0


def test_normal_bidirectional_https_burst_is_not_classified_as_flood(app, tmp_path):
    """Established bidirectional HTTPS traffic with ACK/PA flags must not trigger flood alerts."""
    missing_model = tmp_path / "no_model.joblib"

    https_burst_flow = {
        "source_ip": "192.168.1.50",
        "destination_ip": "93.184.216.34",
        "duration": 0.02,
        "protocol": "TCP",
        "source_port": 54120,
        "destination_port": 443,
        "flow_bytes": 24_000.0,
        "flow_packets": 24,
        "forward_packets": 10,
        "backward_packets": 14,
        "average_packet_size": 1000.0,
        "packet_rate": 1200.0,  # High short burst rate on 443
        "byte_rate": 600_000.0,
        "tcp_flags": ["A", "PA", "S", "SA"],
    }

    with app.app_context():
        engine = DetectionEngine(model_path=missing_model)
        result = engine.analyze_flow(https_burst_flow, persist=True)

        assert result["is_suspicious"] is False
        assert result["severity"] == "low"
        assert "flood" not in result["attack_type"].lower()
        assert result["alert"] is None
        assert any("Severity 'low' assigned" in item for item in result["evidence"])
        assert Alert.query.count() == 0


def test_mild_ml_outlier_dampened_on_https_while_strong_ml_remains_valid(app, monkeypatch):
    """Mild ML outliers on HTTPS stay low; strong ML anomalies (confidence >= 0.85) remain valid."""
    https_flow = _normal_flow()

    with app.app_context():
        engine = DetectionEngine(model_bundle={"pipeline": object()})

        # Mild ML outlier (confidence=0.72) on established HTTPS -> dampened to low
        monkeypatch.setattr(
            "app.services.detection_engine.predict_flow",
            lambda *_a, **_kw: {"anomaly_score": 0.08, "prediction": "anomaly", "confidence": 0.72},
        )
        mild_res = engine.analyze_flow(https_flow, persist=True)
        assert mild_res["severity"] == "low"
        assert mild_res["is_suspicious"] is False
        assert Alert.query.count() == 0

        # Strong ML anomaly (confidence=0.95) -> kept as valid evidence
        monkeypatch.setattr(
            "app.services.detection_engine.predict_flow",
            lambda *_a, **_kw: {"anomaly_score": 0.45, "prediction": "anomaly", "confidence": 0.95},
        )
        strong_res = engine.analyze_flow(https_flow, persist=True)
        assert strong_res["is_suspicious"] is True
        assert strong_res["severity"] in {"medium", "high"}
        assert strong_res["alert"] is not None
        assert Alert.query.count() == 1


def test_single_high_packet_rate_rule_capped_at_medium(app, tmp_path):
    """high_packet_rate as the sole indicator must never exceed medium severity."""
    missing_model = tmp_path / "no_model.joblib"

    udp_high_pps = {
        "source_ip": "198.51.100.30",
        "destination_ip": "10.0.0.10",
        "duration": 0.1,
        "protocol": "UDP",
        "source_port": 51000,
        "destination_port": 5300,
        "flow_bytes": 20_000.0,
        "flow_packets": 300,
        "forward_packets": 300,
        "backward_packets": 0,
        "average_packet_size": 66.67,
        "packet_rate": 3000.0,  # extreme packet_rate alone
        "byte_rate": 200_000.0,  # below high_byte_rate threshold
    }

    with app.app_context():
        engine = DetectionEngine(model_path=missing_model)
        result = engine.analyze_flow(udp_high_pps, persist=True)

        assert result["is_suspicious"] is True
        assert result["severity"] == "medium"
        assert result["threat_score"] < 50.0
        assert any("Severity 'medium' assigned" in item for item in result["evidence"])
        assert Alert.query.count() == 1


def test_critical_requires_two_independent_indicators(app, tmp_path):
    """Critical severity requires >= 2 independent indicators; 1 indicator is capped at high."""
    missing_model = tmp_path / "no_model.joblib"

    class SingleHighRuleEngine:
        def evaluate(self, _flow):
            return {
                "rule_score": 85.0,
                "matched_rules": [
                    {
                        "rule_id": "suspicious_protocol_port",
                        "title": "Single Strong Rule",
                        "points": 85.0,
                        "attack_hint": "Possible Suspicious Activity",
                        "detail": "Single synthetic high-weight indicator.",
                    }
                ],
                "evidence": ["Single synthetic high-weight indicator."],
                "attack_hints": ["Possible Suspicious Activity"],
                "context_notes": [],
                "established_bidirectional_tcp": False,
                "likely_normal_web_traffic": False,
            }

    with app.app_context():
        # Single indicator scoring 85 -> capped at high (74.0)
        single_engine = DetectionEngine(model_path=missing_model, rule_engine=SingleHighRuleEngine())
        single_res = single_engine.analyze_flow(_normal_flow(), persist=True)
        assert single_res["severity"] == "high"
        assert single_res["threat_score"] == 74.0
        assert any("fewer than two independent indicators" in item.lower() for item in single_res["evidence"])

        # Multiple corroborating indicators -> reaches critical
        multi_engine = DetectionEngine(model_path=missing_model)
        multi_res = multi_engine.analyze_flow(_high_rate_anomalous_flow(), persist=True)
        assert multi_res["severity"] == "critical"
        assert multi_res["threat_score"] >= 75.0
        assert any("independent_indicators=4" in item for item in multi_res["evidence"])


def test_confirmed_threat_intel_remains_valid_evidence(app, tmp_path):
    """A confirmed threat-intel report should persist an alert with clear rationale."""
    missing_model = tmp_path / "no_model.joblib"

    with app.app_context():
        engine = DetectionEngine(model_path=missing_model)
        result = engine.analyze_flow(
            _normal_flow(),
            threat_intel={
                "ip": "192.168.1.25",
                "reputation": "reported",
                "provider": "abuseipdb",
                "abuse_score": 92,
                "categories": ["Port Scan", "Brute-Force"],
            },
            persist=True,
        )

        assert result["is_suspicious"] is True
        assert result["severity"] == "medium"
        assert result["threat_score"] == 30.0
        assert any("reported by the provider" in item.lower() for item in result["evidence"])
        assert any("Severity 'medium' assigned" in item for item in result["evidence"])
        assert result["alert"] is not None
        assert Alert.query.count() == 1
