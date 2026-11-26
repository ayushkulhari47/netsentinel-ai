"""Tests for the Alert SQLAlchemy model and /api/alerts, /api/summary endpoints."""

import pytest
from sqlalchemy import inspect
from app import create_app
from app.extensions import db
from app.models import Alert


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app configured with a temporary SQLite database."""
    db_file = tmp_path / "test_alerts.db"
    application = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
        }
    )
    yield application


@pytest.fixture()
def client(app):
    """Create a Flask test client."""
    with app.test_client() as test_client:
        yield test_client


def test_database_and_alerts_table_created_on_startup(tmp_path):
    """create_app should automatically create the SQLite file and alerts table."""
    db_file = tmp_path / "auto_created.db"
    application = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
        }
    )

    assert db_file.exists()
    with application.app_context():
        inspector = inspect(db.engine)
        assert "alerts" in inspector.get_table_names()


def test_alert_model_persistence_and_serialization(app):
    """Alert model should persist to SQLite and serialize cleanly via to_dict()."""
    with app.app_context():
        alert = Alert(
            source_ip="192.168.1.50",
            destination_ip="10.0.0.5",
            source_port=54321,
            destination_port=22,
            protocol="TCP",
            attack_type="SSH Brute Force",
            severity="high",
            anomaly_score=-0.42,
            threat_score=84.5,
            confidence=0.91,
            explanation="Repeated failed SSH authentication attempts.",
        )
        db.session.add(alert)
        db.session.commit()

        saved = Alert.query.first()
        assert saved is not None
        assert saved.id == 1
        assert saved.status == "open"
        assert saved.timestamp is not None

        data = saved.to_dict()
        assert data["source_ip"] == "192.168.1.50"
        assert data["destination_port"] == 22
        assert data["severity"] == "high"
        assert data["status"] == "open"
        assert isinstance(data["timestamp"], str)


def test_get_alerts_and_summary_when_empty(client):
    """API endpoints should return empty collections and zero counts when DB is empty."""
    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.status_code == 200
    assert alerts_resp.get_json() == {"alerts": [], "count": 0}

    summary_resp = client.get("/api/summary")
    assert summary_resp.status_code == 200
    assert summary_resp.get_json() == {
        "total_alerts": 0,
        "critical_alerts": 0,
        "high_alerts": 0,
        "suspicious_ip_count": 0,
    }


def test_post_alert_and_fetch_alerts_and_summary(client):
    """POST /api/alerts should store alerts and update /api/alerts and /api/summary."""
    payload_1 = {
        "source_ip": "203.0.113.10",
        "destination_ip": "10.0.0.12",
        "source_port": 49152,
        "destination_port": 443,
        "protocol": "tcp",
        "attack_type": "Port Scan",
        "severity": "High",
        "anomaly_score": -0.25,
        "threat_score": 72.0,
        "confidence": 0.85,
        "explanation": "Sequential SYN probes across multiple ports.",
        "timestamp": "2026-11-26T09:00:00Z",
    }
    payload_2 = {
        "source_ip": "203.0.113.10",
        "destination_ip": "10.0.0.15",
        "protocol": "ICMP",
        "attack_type": "ICMP Flood",
        "severity": "critical",
        "threat_score": 95.0,
        "confidence": 0.96,
        "explanation": "Sustained high-rate ICMP echo traffic.",
        "status": "investigating",
        "timestamp": "2026-11-26T09:05:00Z",
    }
    payload_3 = {
        "source_ip": "2001:db8::1",
        "destination_ip": "2001:db8::2",
        "source_port": 5353,
        "destination_port": 53,
        "protocol": "UDP",
        "attack_type": "DNS Tunneling",
        "severity": "medium",
        "threat_score": 55.0,
        "confidence": 0.7,
        "timestamp": "2026-11-26T09:02:00Z",
    }

    for payload in (payload_1, payload_2, payload_3):
        resp = client.post("/api/alerts", json=payload)
        assert resp.status_code == 201
        assert "alert" in resp.get_json()

    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.status_code == 200
    body = alerts_resp.get_json()
    assert body["count"] == 3
    # Ordered newest timestamp first: 09:05 -> 09:02 -> 09:00
    assert [a["attack_type"] for a in body["alerts"]] == [
        "ICMP Flood",
        "DNS Tunneling",
        "Port Scan",
    ]
    assert body["alerts"][0]["source_port"] is None
    assert body["alerts"][2]["protocol"] == "TCP"
    assert body["alerts"][2]["severity"] == "high"

    summary_resp = client.get("/api/summary")
    assert summary_resp.status_code == 200
    assert summary_resp.get_json() == {
        "total_alerts": 3,
        "critical_alerts": 1,
        "high_alerts": 1,
        "suspicious_ip_count": 2,
    }


def test_get_alerts_filters_and_validation(client):
    """GET /api/alerts should support severity, status, and limit filters."""
    client.post(
        "/api/alerts",
        json={
            "source_ip": "198.51.100.4",
            "destination_ip": "10.0.0.1",
            "protocol": "TCP",
            "attack_type": "SQL Injection",
            "severity": "critical",
            "status": "open",
        },
    )
    client.post(
        "/api/alerts",
        json={
            "source_ip": "198.51.100.5",
            "destination_ip": "10.0.0.1",
            "protocol": "TCP",
            "attack_type": "Policy Violation",
            "severity": "low",
            "status": "resolved",
        },
    )

    crit_resp = client.get("/api/alerts?severity=critical")
    assert crit_resp.status_code == 200
    assert crit_resp.get_json()["count"] == 1

    resolved_resp = client.get("/api/alerts?status=resolved&limit=1")
    assert resolved_resp.status_code == 200
    assert resolved_resp.get_json()["count"] == 1
    assert resolved_resp.get_json()["alerts"][0]["attack_type"] == "Policy Violation"

    src_ip_resp = client.get("/api/alerts?source_ip=198.51.100.4")
    assert src_ip_resp.status_code == 200
    assert src_ip_resp.get_json()["count"] == 1
    assert src_ip_resp.get_json()["alerts"][0]["attack_type"] == "SQL Injection"

    dst_ip_resp = client.get("/api/alerts?destination_ip=10.0.0.1")
    assert dst_ip_resp.status_code == 200
    assert dst_ip_resp.get_json()["count"] == 2

    bad_src_ip = client.get(f"/api/alerts?source_ip={'1' * 50}")
    assert bad_src_ip.status_code == 400

    bad_severity = client.get("/api/alerts?severity=unknown")
    assert bad_severity.status_code == 400

    bad_limit = client.get("/api/alerts?limit=0")
    assert bad_limit.status_code == 400


@pytest.mark.parametrize(
    "bad_payload,expected_field",
    [
        ({}, "source_ip"),
        (
            {
                "source_ip": "not-an-ip",
                "destination_ip": "10.0.0.1",
                "protocol": "TCP",
                "attack_type": "Scan",
                "severity": "low",
            },
            "source_ip",
        ),
        (
            {
                "source_ip": "192.0.2.1",
                "destination_ip": "10.0.0.1",
                "source_port": 70000,
                "protocol": "TCP",
                "attack_type": "Scan",
                "severity": "low",
            },
            "source_port",
        ),
        (
            {
                "source_ip": "192.0.2.1",
                "destination_ip": "10.0.0.1",
                "destination_port": True,
                "protocol": "TCP",
                "attack_type": "Scan",
                "severity": "low",
            },
            "destination_port",
        ),
        (
            {
                "source_ip": "192.0.2.1",
                "destination_ip": "10.0.0.1",
                "protocol": "TCP",
                "attack_type": "Scan",
                "severity": "extreme",
            },
            "severity",
        ),
        (
            {
                "source_ip": "192.0.2.1",
                "destination_ip": "10.0.0.1",
                "protocol": "TCP",
                "attack_type": "Scan",
                "severity": "high",
                "status": "archived",
            },
            "status",
        ),
        (
            {
                "source_ip": "192.0.2.1",
                "destination_ip": "10.0.0.1",
                "protocol": "TCP",
                "attack_type": "Scan",
                "severity": "high",
                "threat_score": 150,
            },
            "threat_score",
        ),
        (
            {
                "source_ip": "192.0.2.1",
                "destination_ip": "10.0.0.1",
                "protocol": "TCP",
                "attack_type": "Scan",
                "severity": "high",
                "confidence": 1.5,
            },
            "confidence",
        ),
        (
            {
                "source_ip": "192.0.2.1",
                "destination_ip": "10.0.0.1",
                "protocol": "TCP",
                "attack_type": "Scan",
                "severity": "high",
                "timestamp": "not-a-date",
            },
            "timestamp",
        ),
    ],
)
def test_post_alert_validation_rejects_invalid_inputs(client, bad_payload, expected_field):
    """POST /api/alerts should return 400 with field error details on invalid data."""
    resp = client.post("/api/alerts", json=bad_payload)
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["error"] == "Validation failed"
    assert expected_field in data["details"]


def test_post_alert_rejects_missing_json(client):
    """POST /api/alerts should return 400 when body is not valid JSON."""
    resp = client.post("/api/alerts", data="plain text", content_type="text/plain")
    assert resp.status_code == 400
