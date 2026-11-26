"""Mocked unit and API tests for optional AbuseIPDB threat-intelligence lookup."""

from types import SimpleNamespace
import pytest
import requests

from app import create_app
from app.services.detection_engine import DetectionEngine
from app.services.threat_intel import REQUEST_TIMEOUT_SECONDS, ThreatIntelService


class MockResponse:
    """Simple mocked requests.Response object."""

    def __init__(self, status_code=200, json_data=None, json_error=False):
        self.status_code = status_code
        self._json_data = json_data
        self._json_error = json_error

    def json(self):
        if self._json_error:
            raise ValueError("Invalid JSON")
        return self._json_data


def _normal_flow(source_ip="203.0.113.55"):
    return {
        "source_ip": source_ip,
        "destination_ip": "10.0.0.5",
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
    }


def test_missing_and_placeholder_api_key_skips_external_calls(monkeypatch):
    """Missing or placeholder ABUSEIPDB_API_KEY must never trigger external HTTP requests."""
    called = {"count": 0}

    def fail_if_called(*_args, **_kwargs):
        called["count"] += 1
        raise AssertionError("External API should not be called when API key is missing.")

    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setattr(requests, "get", fail_if_called)

    service = ThreatIntelService(time_fn=lambda: 1000.0)
    res = service.lookup_ip("8.8.8.8")
    assert called["count"] == 0
    assert res["ip"] == "8.8.8.8"
    assert res["reputation"] == "unknown"
    assert res["confidence"] == 0.0
    assert res["provider"] == "abuseipdb"
    assert res["abuse_score"] == 0
    assert res["categories"] == []
    assert res["checked_at"]

    # Placeholder value from .env.example should also skip external calls
    placeholder_service = ThreatIntelService(
        api_key="your-abuseipdb-api-key-here",
        time_fn=lambda: 1000.0,
    )
    res2 = placeholder_service.lookup_ip("8.8.8.8")
    assert called["count"] == 0
    assert res2["reputation"] == "unknown"


@pytest.mark.parametrize(
    "non_public_ip",
    ["192.168.1.10", "10.0.0.1", "172.16.5.4", "127.0.0.1", "::1", "240.0.0.1"],
)
def test_private_loopback_and_reserved_ips_never_queried_externally(monkeypatch, non_public_ip):
    """Private, loopback, and reserved IPs must return reputation='private' without API calls."""
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("External API must never be called for non-public IPs.")

    monkeypatch.setattr(requests, "get", fail_if_called)
    service = ThreatIntelService(api_key="fake-secret-key", time_fn=lambda: 2000.0)

    res = service.lookup_ip(non_public_ip)
    assert res["reputation"] == "private"
    assert res["provider"] == "local"
    assert res["confidence"] == 0.0
    assert res["abuse_score"] == 0
    assert res["categories"] == []


def test_public_ip_lookup_reported_suspicious_and_clean_with_ttl_cache(monkeypatch):
    """Mocked AbuseIPDB lookups should classify reputations, enforce 5s timeout, and cache."""
    calls = []
    clock = {"now": 5000.0}
    secret_key = "super-secret-test-key-123"

    def fake_get(url, headers=None, params=None, timeout=None):
        calls.append({"url": url, "headers": headers, "params": params, "timeout": timeout})
        ip_param = params["ipAddress"]
        if ip_param == "93.184.216.34":
            return MockResponse(
                200,
                {
                    "data": {
                        "abuseConfidenceScore": 92,
                        "reports": [{"categories": [14, 18]}, {"categories": [18, 22]}],
                    }
                },
            )
        if ip_param == "9.9.9.9":
            return MockResponse(200, {"data": {"abuseConfidenceScore": 45, "categories": [14]}})
        return MockResponse(200, {"data": {"abuseConfidenceScore": 0, "categories": []}})

    monkeypatch.setattr(requests, "get", fake_get)
    service = ThreatIntelService(
        api_key=secret_key,
        cache_ttl_seconds=60.0,
        time_fn=lambda: clock["now"],
    )

    # 1. Reported IP
    rep = service.lookup_ip("93.184.216.34")
    assert len(calls) == 1
    assert calls[0]["timeout"] == REQUEST_TIMEOUT_SECONDS == 5
    assert calls[0]["headers"]["Key"] == secret_key
    assert rep["reputation"] == "reported"
    assert rep["abuse_score"] == 92
    assert rep["confidence"] == 0.92
    assert rep["categories"] == ["Port Scan", "Brute-Force", "SSH"]
    assert "reported by the provider" in rep["summary"].lower()
    assert rep["cached"] is False
    assert secret_key not in str(rep)

    # 2. Cached hit within TTL
    clock["now"] = 5030.0
    rep_cached = service.lookup_ip("93.184.216.34")
    assert len(calls) == 1
    assert rep_cached["cached"] is True
    assert rep_cached["reputation"] == "reported"

    # 3. Cache expiration after TTL
    clock["now"] = 5061.0
    rep_expired = service.lookup_ip("93.184.216.34")
    assert len(calls) == 2
    assert rep_expired["cached"] is False

    # 4. Suspicious & clean classifications
    susp = service.lookup_ip("9.9.9.9")
    assert susp["reputation"] == "suspicious"
    assert susp["abuse_score"] == 45
    assert susp["categories"] == ["Port Scan"]

    clean = service.lookup_ip("1.1.1.1")
    assert clean["reputation"] == "clean"
    assert clean["abuse_score"] == 0


@pytest.mark.parametrize(
    "mock_behavior",
    [
        lambda *_a, **_kw: (_ for _ in ()).throw(requests.Timeout("timed out")),
        lambda *_a, **_kw: MockResponse(status_code=429),
        lambda *_a, **_kw: MockResponse(status_code=401),
        lambda *_a, **_kw: MockResponse(status_code=200, json_error=True),
        lambda *_a, **_kw: MockResponse(status_code=200, json_data={"data": "bad"}),
        lambda *_a, **_kw: MockResponse(status_code=200, json_data={"data": {"abuseConfidenceScore": "NaN"}}),
    ],
)
def test_api_errors_rate_limits_and_invalid_responses_handled_safely(monkeypatch, mock_behavior):
    """Errors, rate limits, timeouts, and bad payloads should safely return reputation='unknown'."""
    secret_key = "leak-check-secret-key"
    monkeypatch.setattr(requests, "get", mock_behavior)

    service = ThreatIntelService(api_key=secret_key, time_fn=lambda: 1000.0)
    res = service.lookup_ip("8.8.4.4")

    assert res["reputation"] == "unknown"
    assert res["confidence"] == 0.0
    assert res["abuse_score"] == 0
    assert secret_key not in str(res)


def test_api_endpoint_get_threat_intel(tmp_path, monkeypatch):
    """GET /api/threat-intel/<ip> should handle missing keys, private IPs, mocked hits, and invalid IPs."""
    db_file = tmp_path / "test_ti.db"
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    # Case 1: No API key configured
    app_no_key = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
        }
    )
    with app_no_key.test_client() as client:
        resp_no_key = client.get("/api/threat-intel/8.8.8.8")
        assert resp_no_key.status_code == 200
        assert resp_no_key.get_json()["reputation"] == "unknown"

        resp_private = client.get("/api/threat-intel/127.0.0.1")
        assert resp_private.status_code == 200
        assert resp_private.get_json()["reputation"] == "private"

        resp_bad = client.get("/api/threat-intel/not-an-ip")
        assert resp_bad.status_code == 400

    # Case 2: Configured API key with mocked AbuseIPDB response
    secret_key = "api-route-secret-key"
    monkeypatch.setattr(
        requests,
        "get",
        lambda *_a, **_kw: MockResponse(
            200,
            {"data": {"abuseConfidenceScore": 85, "categories": [14, 21]}},
        ),
    )
    app_with_key = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
            "ABUSEIPDB_API_KEY": secret_key,
        }
    )
    with app_with_key.test_client() as client:
        resp = client.get("/api/threat-intel/93.184.216.34")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ip"] == "93.184.216.34"
        assert data["reputation"] == "reported"
        assert data["abuse_score"] == 85
        assert data["categories"] == ["Port Scan", "Web App Attack"]
        assert secret_key not in resp.get_data(as_text=True)


def test_detection_engine_integrates_threat_intel_results(tmp_path, monkeypatch):
    """DetectionEngine should factor ThreatIntelService scores into threat_score cautiously."""
    db_file = tmp_path / "test_ti_det.db"
    missing_model = tmp_path / "no_model.joblib"

    monkeypatch.setattr(
        requests,
        "get",
        lambda *_a, **_kw: MockResponse(
            200,
            {"data": {"abuseConfidenceScore": 90, "categories": [14]}},
        ),
    )
    ti_service = ThreatIntelService(api_key="test-key", time_fn=lambda: 100.0)

    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}"})
    with app.app_context():
        engine = DetectionEngine(
            model_path=missing_model,
            threat_intel_service=ti_service,
        )
        result = engine.analyze_flow(_normal_flow(source_ip="93.184.216.34"), persist=True)

        assert result["is_suspicious"] is True
        assert result["threat_score"] == 30.0
        assert result["severity"] == "medium"
        assert any("reported by the provider" in item.lower() for item in result["evidence"])
        assert result["alert"] is not None
        assert result["alert"]["threat_score"] == 30.0
