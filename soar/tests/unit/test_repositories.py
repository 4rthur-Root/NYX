import json
import sqlite3
import time
from pathlib import Path

import pytest

from soar.config.settings import settings
from soar.db.connection import close_connection, get_connection, initialize_db
from soar.models.alert import Alert, EventDetail
from soar.models.decision import EnrichmentResult
from soar.models.response import OpnsenseResult, Response
from soar.repositories.alert_repository import AlertRepository
from soar.repositories.audit_repository import AuditRepository
from soar.repositories.response_repository import ResponseRepository

SAMPLE_ALERT = Alert(
    alert_id="alert-uuid-001",
    timestamp=1750000000000,
    rule_id="SSH_BRUTEFORCE_001",
    severity="CRITICAL",
    attacker_ip="1.2.3.4",
    target_host="debian-server",
    target_ip="10.0.1.20",
    mitre_tactic="TA0006",
    mitre_technique="T1110",
    events_count=15,
    events_details=[
        EventDetail(
            timestamp=1749999940000,
            event_type="ssh_failure",
            source_host="debian-server",
            raw_log="Failed password from 1.2.3.4",
        )
    ],
)

SAMPLE_RESPONSE = Response(
    response_id="resp-alert-uuid-001",
    alert_id="alert-uuid-001",
    alert_timestamp=1750000000000,
    response_timestamp=1750000001000,
    latency_ms=1000,
    action="block_ip",
    status="success",
    enrichment=EnrichmentResult(
        source="abuseipdb",
        abuseipdb_score=85,
        country_code="US",
        isp="SomeISP",
        fallback_used=False,
    ),
    opnsense=OpnsenseResult(
        rule_id="soar_blocklist",
        blocked_ip="1.2.3.4",
        api_status_code=200,
        retry_count=1,
    ),
)


@pytest.fixture(autouse=True)
def _db(tmp_path):
    db_path = str(tmp_path / "test.db")
    original = settings._config["paths"]["database"]
    settings._config["paths"]["database"] = db_path
    close_connection()
    initialize_db()
    yield
    close_connection()
    settings._config["paths"]["database"] = original


def _save_alert(alert_id: str = "alert-uuid-001"):
    alert = Alert(
        alert_id=alert_id,
        timestamp=1,
        rule_id="SSH_BRUTEFORCE_001",
        severity="CRITICAL",
        attacker_ip="1.2.3.4",
        target_host="h", target_ip="10.0.1.1",
        mitre_tactic="TA0006", mitre_technique="T1110",
        events_count=1, events_details=[],
    )
    AlertRepository().save(alert)


class TestAlertRepository:
    def test_save_and_get_by_id(self):
        repo = AlertRepository()
        repo.save(SAMPLE_ALERT)

        loaded = repo.get_by_id("alert-uuid-001")
        assert loaded is not None
        assert loaded.alert_id == "alert-uuid-001"
        assert loaded.rule_id == "SSH_BRUTEFORCE_001"
        assert loaded.attacker_ip == "1.2.3.4"

    def test_exists_returns_true(self):
        repo = AlertRepository()
        repo.save(SAMPLE_ALERT)
        assert repo.exists("alert-uuid-001") is True

    def test_exists_returns_false(self):
        repo = AlertRepository()
        assert repo.exists("nonexistent") is False

    def test_list_recent(self):
        repo = AlertRepository()
        repo.save(SAMPLE_ALERT)
        results = repo.list_recent(limit=10)
        assert len(results) >= 1

    def test_save_duplicate_ignored(self):
        repo = AlertRepository()
        repo.save(SAMPLE_ALERT)
        repo.save(SAMPLE_ALERT)
        assert repo.exists("alert-uuid-001") is True


class TestResponseRepository:
    def test_save_and_get_by_alert_id(self):
        _save_alert()
        repo = ResponseRepository()
        repo.save(SAMPLE_RESPONSE)

        loaded = repo.get_by_alert_id("alert-uuid-001")
        assert loaded is not None
        assert loaded.response_id == "resp-alert-uuid-001"
        assert loaded.action == "block_ip"
        assert loaded.status == "success"

    def test_save_with_enrichment_and_opnsense(self):
        _save_alert()
        repo = ResponseRepository()
        repo.save(SAMPLE_RESPONSE)

        loaded = repo.get_by_alert_id("alert-uuid-001")
        assert loaded.enrichment is not None
        assert loaded.enrichment.abuseipdb_score == 85
        assert loaded.enrichment.source == "abuseipdb"
        assert loaded.opnsense is not None
        assert loaded.opnsense.blocked_ip == "1.2.3.4"
        assert loaded.opnsense.api_status_code == 200

    def test_save_without_enrichment(self):
        _save_alert("alert-no-enrich")
        resp = Response(
            response_id="resp-no-enrich",
            alert_id="alert-no-enrich",
            alert_timestamp=1,
            response_timestamp=2,
            latency_ms=1,
            action="none",
            status="skipped",
            skip_reason="whitelisted",
        )
        repo = ResponseRepository()
        repo.save(resp)

        loaded = repo.get_by_alert_id("alert-no-enrich")
        assert loaded.enrichment is None
        assert loaded.opnsense is None
        assert loaded.skip_reason == "whitelisted"

    def test_get_by_response_id(self):
        _save_alert()
        repo = ResponseRepository()
        repo.save(SAMPLE_RESPONSE)

        loaded = repo.get_by_response_id("resp-alert-uuid-001")
        assert loaded is not None
        assert loaded.alert_id == "alert-uuid-001"

    def test_list_failed(self):
        _save_alert()
        _save_alert("alert-fail")
        repo = ResponseRepository()
        repo.save(SAMPLE_RESPONSE)

        failed = Response(
            response_id="resp-fail",
            alert_id="alert-fail",
            alert_timestamp=1,
            response_timestamp=2,
            latency_ms=1,
            action="block_ip",
            status="error",
            error="API timeout",
        )
        repo.save(failed)

        results = repo.list_failed()
        assert len(results) == 1
        assert results[0].response_id == "resp-fail"

    def test_list_recent(self):
        _save_alert()
        repo = ResponseRepository()
        repo.save(SAMPLE_RESPONSE)
        results = repo.list_recent(limit=10)
        assert len(results) >= 1


class TestAuditRepository:
    def test_insert_event(self):
        repo = AuditRepository()
        repo.insert_event(
            {
                "event_type": "alert_received",
                "alert_id": "alert-uuid-001",
                "details": {"rule_id": "SSH_BRUTEFORCE_001"},
                "timestamp": 1750000000000,
            }
        )

        results = repo.list_recent()
        assert len(results) == 1
        assert results[0]["event_type"] == "alert_received"

    def test_insert_event_without_alert_id(self):
        repo = AuditRepository()
        repo.insert_event({"event_type": "system_start"})

        results = repo.list_recent()
        assert len(results) == 1
        assert results[0]["alert_id"] is None
