"""Mocked unit and API tests for optional OpenAI-powered threat explanations."""

import json
from types import SimpleNamespace
import pytest

from app import create_app
from app.extensions import db
from app.models import Alert
from app.services import llm_explainer
from app.services.llm_explainer import (
    DEFAULT_OPENAI_MODEL,
    LLMExplainer,
    sanitize_alert_metadata,
    validate_structured_explanation,
)


def _sample_alert_payload():
    return {
        "attack_type": "Possible High-Rate Packet Flood",
        "severity": "high",
        "threat_score": 68.5,
        "anomaly_score": 0.215,
        "protocol": "TCP",
        "source_port": 51234,
        "destination_port": 443,
        "packet_rate": 1800.0,
        "byte_rate": 450000.0,
        "rule_evidence": ["Suspiciously high packet rate observed (1800.0 pkt/s)."],
        "payload": b"SENSITIVE_PAYLOAD_BYTES",
        "raw_packet": "0xdeadbeef",
        "password": "super-secret-password",
        "token": "Bearer secret-jwt-token",
        "api_key": "sk-1234567890abcdef1234567890",
    }


def _valid_llm_json():
    return json.dumps(
        {
            "summary": "Possible high-rate TCP flood activity detected targeting port 443.",
            "why_it_matters": "Elevated packet rates may indicate resource exhaustion or probing.",
            "evidence": [
                "Packet rate reached 1800.0 pkt/s, exceeding baseline thresholds.",
                "IsolationForest anomaly_score was 0.215.",
            ],
            "recommended_actions": [
                "Inspect host and firewall logs to verify whether traffic is authorized.",
                "Monitor destination service latency and apply rate limiting if needed.",
            ],
            "confidence_note": "Assessment reflects statistical and heuristic signals, not certainty.",
        }
    )


def test_sanitize_alert_metadata_excludes_payloads_and_secrets():
    """Sanitizer should retain only allowlisted metadata and strip raw/secret fields."""
    sanitized = sanitize_alert_metadata(
        _sample_alert_payload(),
        threat_intel={"reputation": "reported", "provider": "abuseipdb", "abuse_score": 88},
        flow_stats={"flow_bytes": 90000.0, "flow_packets": 150, "payload": "DROP_ME"},
    )

    assert set(sanitized.keys()) == {
        "attack_type",
        "severity",
        "threat_score",
        "anomaly_score",
        "rule_evidence",
        "threat_intel_summary",
        "protocol_and_flow_stats",
    }
    serialized = json.dumps(sanitized)
    for forbidden in (
        "SENSITIVE_PAYLOAD_BYTES",
        "0xdeadbeef",
        "super-secret-password",
        "secret-jwt-token",
        "sk-1234567890abcdef1234567890",
        "DROP_ME",
    ):
        assert forbidden not in serialized

    assert sanitized["protocol_and_flow_stats"]["protocol"] == "TCP"
    assert sanitized["protocol_and_flow_stats"]["flow_bytes"] == 90000.0
    assert "abuse_score=88" in sanitized["threat_intel_summary"]


def test_missing_or_placeholder_api_key_uses_fallback_without_external_calls(monkeypatch):
    """Missing or placeholder OPENAI_API_KEY must skip OpenAI calls and return fallback."""
    called = {"count": 0}

    def fail_if_called(**_kwargs):
        called["count"] += 1
        raise AssertionError("OpenAI client should not be constructed when key is missing.")

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(llm_explainer, "OpenAI", fail_if_called)

    explainer = LLMExplainer()
    res = explainer.explain(_sample_alert_payload())
    assert called["count"] == 0
    assert res["source"] == "fallback"
    assert res["model"] is None
    assert set(res.keys()) >= {
        "summary",
        "why_it_matters",
        "evidence",
        "recommended_actions",
        "confidence_note",
    }
    assert isinstance(res["evidence"], list) and res["evidence"]
    assert isinstance(res["recommended_actions"], list) and res["recommended_actions"]

    placeholder_explainer = LLMExplainer(api_key="your-openai-api-key-here")
    res2 = placeholder_explainer.explain(_sample_alert_payload())
    assert called["count"] == 0
    assert res2["source"] == "fallback"


def test_configured_openai_reads_env_model_sends_sanitized_json_and_validates(monkeypatch):
    """LLMExplainer should read OPENAI_MODEL, send sanitized metadata, and return validated JSON."""
    captured = {}

    class FakeCompletions:
        def create(self, **kwargs):
            captured["create_kwargs"] = kwargs
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=_valid_llm_json()))]
            )

    class FakeOpenAI:
        def __init__(self, **kwargs):
            captured["init_kwargs"] = kwargs
            self.chat = SimpleNamespace(completions=FakeCompletions())

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-valid-key-00000000")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o-mini-custom")
    monkeypatch.setattr(llm_explainer, "OpenAI", FakeOpenAI)

    explainer = LLMExplainer()
    res = explainer.explain(_sample_alert_payload())

    assert captured["init_kwargs"]["api_key"] == "sk-test-valid-key-00000000"
    assert captured["create_kwargs"]["model"] == "gpt-4o-mini-custom"
    assert captured["create_kwargs"]["response_format"] == {"type": "json_object"}

    user_msg = captured["create_kwargs"]["messages"][1]["content"]
    assert "SENSITIVE_PAYLOAD_BYTES" not in user_msg
    assert "super-secret-password" not in user_msg
    assert "sk-1234567890abcdef1234567890" not in user_msg

    assert res["source"] == "openai"
    assert res["model"] == "gpt-4o-mini-custom"
    assert "Possible high-rate TCP flood" in res["summary"]
    assert len(res["evidence"]) == 2
    assert len(res["recommended_actions"]) == 2


@pytest.mark.parametrize(
    "response_content,raise_error",
    [
        (None, RuntimeError("API timeout")),
        ("not-valid-json", False),
        (json.dumps({"summary": "only summary"}), False),
        (json.dumps({"summary": "", "why_it_matters": "x", "evidence": ["e"], "recommended_actions": ["a"], "confidence_note": "n"}), False),
        (json.dumps({"summary": "ok", "why_it_matters": "x", "evidence": [], "recommended_actions": ["a"], "confidence_note": "n"}), False),
    ],
)
def test_api_failure_or_invalid_llm_output_falls_back_safely(monkeypatch, response_content, raise_error):
    """OpenAI errors or invalid structured JSON should safely fall back to rule-based output."""
    class FailingCompletions:
        def create(self, **_kwargs):
            if raise_error:
                raise raise_error
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=response_content))]
            )

    class FakeOpenAI:
        def __init__(self, **_kwargs):
            self.chat = SimpleNamespace(completions=FailingCompletions())

    monkeypatch.setattr(llm_explainer, "OpenAI", FakeOpenAI)
    explainer = LLMExplainer(api_key="sk-test-valid-key-00000000")

    res = explainer.explain(_sample_alert_payload())
    assert res["source"] == "fallback"
    assert res["summary"]
    assert res["why_it_matters"]
    assert res["evidence"]
    assert res["recommended_actions"]
    assert res["confidence_note"]


def test_validate_structured_explanation_rejects_bad_schema():
    """validate_structured_explanation should reject non-dict or malformed payloads."""
    with pytest.raises(ValueError):
        validate_structured_explanation(["not", "a", "dict"])


def test_post_explain_endpoint_on_demand_preserves_scores(tmp_path, monkeypatch):
    """POST /api/alerts/<id>/explain should return explanation without modifying scores/severity."""
    db_file = tmp_path / "test_explain.db"
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
        }
    )

    with app.app_context():
        alert = Alert(
            source_ip="93.184.216.34",
            destination_ip="10.0.0.5",
            source_port=51234,
            destination_port=443,
            protocol="TCP",
            attack_type="Possible High-Rate Packet Flood",
            severity="high",
            anomaly_score=0.25,
            threat_score=70.0,
            confidence=0.86,
            explanation="Initial rule explanation.",
            status="open",
        )
        db.session.add(alert)
        db.session.commit()
        alert_id = alert.id

    with app.test_client() as client:
        # 404 on unknown alert
        missing_resp = client.post("/api/alerts/9999/explain")
        assert missing_resp.status_code == 404

        # Fallback when API key is missing
        fallback_resp = client.post(f"/api/alerts/{alert_id}/explain")
        assert fallback_resp.status_code == 200
        fb_data = fallback_resp.get_json()
        assert fb_data["explanation"]["source"] == "fallback"
        assert fb_data["alert"]["anomaly_score"] == 0.25
        assert fb_data["alert"]["threat_score"] == 70.0
        assert fb_data["alert"]["severity"] == "high"

        # Invalid JSON body rejected
        bad_json_resp = client.post(
            f"/api/alerts/{alert_id}/explain",
            data="not json",
            content_type="text/plain",
        )
        assert bad_json_resp.status_code == 400

    # Mocked OpenAI response with OPENAI_API_KEY set
    class FakeCompletions:
        def create(self, **_kwargs):
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=_valid_llm_json()))]
            )

    class FakeOpenAI:
        def __init__(self, **_kwargs):
            self.chat = SimpleNamespace(completions=FakeCompletions())

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-endpoint-key-11111111")
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.setattr(llm_explainer, "OpenAI", FakeOpenAI)

    with app.test_client() as client:
        ok_resp = client.post(
            f"/api/alerts/{alert_id}/explain",
            json={"flow_stats": {"packet_rate": 1800.0, "payload": "IGNORE_THIS"}},
        )
        assert ok_resp.status_code == 200
        ok_data = ok_resp.get_json()
        assert ok_data["explanation"]["source"] == "openai"
        assert ok_data["explanation"]["model"] == DEFAULT_OPENAI_MODEL
        # Scores and severity must remain completely unchanged
        assert ok_data["alert"]["anomaly_score"] == 0.25
        assert ok_data["alert"]["threat_score"] == 70.0
        assert ok_data["alert"]["severity"] == "high"
        assert ok_data["alert"]["explanation"] == ok_data["explanation"]["summary"]
