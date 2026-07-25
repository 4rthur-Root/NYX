from __future__ import annotations

import json
from pathlib import Path

import pytest

from flask_app.app import create_app


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    app.config["MOCK_MODE"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


class TestMetricsRoute:
    def test_metrics_page_returns_200(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_page_contains_charts(self, client):
        resp = client.get("/metrics")
        html = resp.data.decode("utf-8")
        assert "severityChart" in html
        assert "latencyChart" in html
        assert "timelineChart" in html


class TestAlertsRoute:
    def test_alerts_page_returns_200(self, client):
        resp = client.get("/alerts")
        assert resp.status_code == 200

    def test_alerts_page_contains_mock_alerts(self, client):
        resp = client.get("/alerts")
        html = resp.data.decode("utf-8")
        assert "SSH_BRUTEFORCE_001" in html
        assert "SMB_EXFIL_001" in html
        assert "MALICIOUS_FILE_EXEC_001" in html

    def test_alert_detail_returns_200(self, client):
        resp = client.get("/alerts/550e8400-e29b-41d4-a716-446655440001")
        assert resp.status_code == 200

    def test_alert_detail_contains_ip(self, client):
        resp = client.get("/alerts/550e8400-e29b-41d4-a716-446655440001")
        html = resp.data.decode("utf-8")
        assert "185.220.101.99" in html


class TestResponsesRoute:
    def test_responses_page_returns_200(self, client):
        resp = client.get("/responses")
        assert resp.status_code == 200

    def test_responses_page_contains_block_ip(self, client):
        resp = client.get("/responses")
        html = resp.data.decode("utf-8")
        assert "block_ip" in html


class TestHealthRoute:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "ok"
