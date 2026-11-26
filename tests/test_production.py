"""Tests for production configuration, security headers, missing keys, and model path."""

import pytest

from app import create_app
from app.extensions import db
from app.ml.predict import DEFAULT_MODEL_PATH, get_default_model_path
from app.models import Alert
from app.services.detection_engine import DetectionEngine


def test_production_defaults_disable_debug_and_harden_cookies(tmp_path, monkeypatch):
    """Flask debug mode must be disabled by default with secure cookie defaults."""
    monkeypatch.delenv("FLASK_DEBUG", raising=False)
    db_file = tmp_path / "prod_defaults.db"

    # Explicitly test create_app with only DATABASE_URL override (no TESTING=True)
    app = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}"})
    assert app.config["DEBUG"] is False
    assert app.debug is False
    assert app.config["TESTING"] is False
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

    # Explicit FLASK_DEBUG=true enables debug when requested
    monkeypatch.setenv("FLASK_DEBUG", "true")
    debug_app = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}"})
    assert debug_app.config["DEBUG"] is True


def test_security_headers_attached_to_responses(tmp_path):
    """All web and API responses should include defensive HTTP security headers."""
    db_file = tmp_path / "sec_headers.db"
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}"})

    with app.test_client() as client:
        for path in ("/", "/health", "/api/summary"):
            resp = client.get(path)
            assert resp.status_code == 200
            assert resp.headers.get("X-Content-Type-Options") == "nosniff"
            assert resp.headers.get("X-Frame-Options") == "DENY"
            assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
            assert "geolocation=()" in resp.headers.get("Permissions-Policy", "")
            csp = resp.headers.get("Content-Security-Policy", "")
            assert "default-src 'self'" in csp
            assert "frame-ancestors 'none'" in csp


def test_missing_api_keys_degrade_safely(tmp_path, monkeypatch):
    """App endpoints must operate cleanly when ABUSEIPDB_API_KEY and OPENAI_API_KEY are missing."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    db_file = tmp_path / "missing_keys.db"
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}"})

    with app.app_context():
        alert = Alert(
            source_ip="93.184.216.34",
            destination_ip="10.0.0.5",
            source_port=51000,
            destination_port=443,
            protocol="TCP",
            attack_type="Possible Suspicious Port or Protocol Activity",
            severity="medium",
            anomaly_score=0.1,
            threat_score=30.0,
            confidence=0.7,
            explanation="Rule trigger.",
        )
        db.session.add(alert)
        db.session.commit()
        alert_id = alert.id

    with app.test_client() as client:
        ti_resp = client.get("/api/threat-intel/8.8.8.8")
        assert ti_resp.status_code == 200
        assert ti_resp.get_json()["reputation"] == "unknown"

        explain_resp = client.post(f"/api/alerts/{alert_id}/explain")
        assert explain_resp.status_code == 200
        assert explain_resp.get_json()["explanation"]["source"] == "fallback"


def test_model_path_configuration_via_env_and_app_config(tmp_path, monkeypatch):
    """ML_MODEL_PATH should resolve relative/absolute paths and fall back to default."""
    monkeypatch.delenv("ML_MODEL_PATH", raising=False)
    assert get_default_model_path() == DEFAULT_MODEL_PATH

    monkeypatch.setenv("ML_MODEL_PATH", "models/unsw_best_model.joblib")
    resolved = get_default_model_path()
    assert resolved.is_absolute()
    assert resolved.name == "unsw_best_model.joblib"

    custom_path = tmp_path / "custom_model.joblib"
    db_file = tmp_path / "model_cfg.db"
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
            "ML_MODEL_PATH": str(custom_path),
        }
    )
    with app.app_context():
        assert DetectionEngine()._resolve_model_path() == str(custom_path)
