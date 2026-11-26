"""Tests for the NetSentinel AI health check and homepage routes."""

import pytest
from app import create_app


@pytest.fixture()
def client(tmp_path):
    """Create a Flask test client using an isolated temporary SQLite database."""
    db_file = tmp_path / "test_health.db"
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
        }
    )
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
    assert b"alerts-table-body" in response.data
    assert b"trafficChart" in response.data
    assert b"monitoring-toggle-btn" in response.data
    assert b"filter-severity" in response.data
    assert b"filter-source-ip" in response.data
    assert b"alert-modal" in response.data
    assert b"generate-explanation-btn" in response.data
