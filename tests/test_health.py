"""Tests for the NetSentinel AI health check and homepage routes."""

import pytest
from app import create_app


@pytest.fixture()
def client():
    """Create a Flask test client using testing configuration."""
    app = create_app({"TESTING": True})
    with app.test_client() as test_client:
        yield test_client


def test_health_endpoint_returns_ok(client):
    """GET /health should return HTTP 200 and expected JSON payload."""
    response = client.get("/health")

    assert response.status_code == 200
    assert response.is_json

    data = response.get_json()
    assert data["status"] == "ok"
    assert data["app"] == "NetSentinel AI"
    assert data["version"] == "0.1.0"
    assert data["packet_capture"] == "not_configured"


def test_homepage_renders_dashboard(client):
    """GET / should return HTTP 200 and render the dashboard HTML."""
    response = client.get("/")

    assert response.status_code == 200
    assert b"NetSentinel AI" in response.data
    assert b"trafficChart" in response.data
