import json
import logging
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from soar.logging.audit_logger import AuditLogger
from soar.logging.response_writer import ResponseWriter
from soar.logging.soar_log import setup_soar_logging
from soar.models.alert import Alert, EventDetail
from soar.models.decision import Decision
from soar.models.response import OpnsenseResult, Response

SAMPLE_ALERT = Alert(
    alert_id="alert-001",
    timestamp=1750000000000,
    rule_id="SSH_BRUTEFORCE_001",
    severity="CRITICAL",
    attacker_ip="1.2.3.4",
    target_host="debian-server",
    target_ip="10.0.1.20",
    mitre_tactic="TA0006",
    mitre_technique="T1110",
    events_count=1,
    events_details=[],
)

SAMPLE_DECISION = Decision(
    alert=SAMPLE_ALERT,
    scenario_type="S1",
    action="block_ip",
)

SAMPLE_RESPONSE = Response(
    response_id="resp-alert-001",
    alert_id="alert-001",
    alert_timestamp=1750000000000,
    response_timestamp=1750000001000,
    latency_ms=1000,
    action="block_ip",
    status="success",
)


class TestSetupSoarLogging:
    def test_does_not_crash(self):
        logger = logging.getLogger("soar.test_setup")
        logger.handlers.clear()
        setup_soar_logging()
        assert len(logging.getLogger("soar").handlers) >= 1


class TestAuditLogger:
    def test_log_writes_jsonl_line(self, tmp_path):
        jsonl_path = tmp_path / "audit.log"
        with patch("soar.logging.audit_logger.settings") as s:
            s.audit_log_path = jsonl_path
            with patch(
                "soar.logging.audit_logger.AuditRepository"
            ) as MockRepo:
                repo = MockRepo.return_value
                al = AuditLogger()
                al.log(SAMPLE_ALERT, SAMPLE_DECISION, SAMPLE_RESPONSE)

                lines = jsonl_path.read_text().strip().split("\n")
                assert len(lines) == 1
                record = json.loads(lines[0])
                assert record["event_type"] == "alert_processed"
                assert record["alert_id"] == "alert-001"
                assert record["action"] == "block_ip"
                assert record["status"] == "success"
                repo.insert_event.assert_called_once()

    def test_log_event_writes_jsonl(self, tmp_path):
        jsonl_path = tmp_path / "audit.log"
        with patch("soar.logging.audit_logger.settings") as s:
            s.audit_log_path = jsonl_path
            with patch(
                "soar.logging.audit_logger.AuditRepository"
            ) as MockRepo:
                repo = MockRepo.return_value
                al = AuditLogger()
                al.log_event("system_start", {"version": "1.0"})

                lines = jsonl_path.read_text().strip().split("\n")
                assert len(lines) == 1
                record = json.loads(lines[0])
                assert record["event_type"] == "system_start"
                assert record["version"] == "1.0"
                repo.insert_event.assert_called_once()

    def test_log_without_response(self, tmp_path):
        jsonl_path = tmp_path / "audit.log"
        with patch("soar.logging.audit_logger.settings") as s:
            s.audit_log_path = jsonl_path
            with patch(
                "soar.logging.audit_logger.AuditRepository"
            ):
                al = AuditLogger()
                al.log(SAMPLE_ALERT, SAMPLE_DECISION)

                lines = jsonl_path.read_text().strip().split("\n")
                assert len(lines) == 1
                record = json.loads(lines[0])
                assert record["status"] == "decided"

    def test_jsonl_write_error_does_not_crash(self, caplog, tmp_path):
        jsonl_path = tmp_path / "readonly" / "audit.log"
        jsonl_path.parent.mkdir()
        jsonl_path.parent.chmod(0o444)  # read-only
        with patch("soar.logging.audit_logger.settings") as s:
            s.audit_log_path = jsonl_path
            with patch(
                "soar.logging.audit_logger.AuditRepository"
            ):
                al = AuditLogger()
                al.log(SAMPLE_ALERT, SAMPLE_DECISION)
                assert any("Impossible d'écrire" in r.message for r in caplog.records)
        jsonl_path.parent.chmod(0o755)


class TestResponseWriter:
    def test_write_calls_repo_save(self):
        with patch(
            "soar.logging.response_writer.ResponseRepository"
        ) as MockRepo:
            repo = MockRepo.return_value
            rw = ResponseWriter()
            rw.write(SAMPLE_RESPONSE)

            repo.save.assert_called_once_with(SAMPLE_RESPONSE)
