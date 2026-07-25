# tests/unit/test_alerter.py
"""Tests unitaires — Alerter et build_alert."""
import json
import logging
import os
import time
from pathlib import Path

import pytest

from alerter import Alerter, build_alert


@pytest.fixture
def alerts_dir(tmp_path):
    return tmp_path / "alerts"


@pytest.fixture
def alerts_log(alerts_dir):
    return alerts_dir / "alerts.log"


@pytest.fixture
def alerter(alerts_dir, alerts_log):
    logger = logging.getLogger("nyxsoc.alerts")
    logger.handlers.clear()
    return Alerter(str(alerts_dir), str(alerts_log))


@pytest.fixture
def sample_rule():
    return {
        "rule_id": "TEST_RULE_001",
        "severity": "CRITICAL",
        "mitre_tactic": "TA0006",
        "mitre_technique": "T1110",
    }


@pytest.fixture
def sample_events():
    return [
        {
            "timestamp": 1750329821000,
            "event_type": "ssh_failure",
            "source_host": "debian-server",
            "actor_user": "root",
            "raw_log": "Failed password for root from 10.0.1.50 port 52341 ssh2",
        }
    ]


# =====================================================================
# build_alert
# =====================================================================

class TestBuildAlert:
    def test_returns_dict_with_required_fields(self, sample_rule, sample_events):
        alert = build_alert(
            rule=sample_rule,
            events=sample_events,
            attacker_ip="10.0.1.50",
            target_host="debian-server",
        )
        assert "alert_id" in alert
        assert "timestamp" in alert
        assert alert["rule_id"] == "TEST_RULE_001"
        assert alert["severity"] == "CRITICAL"
        assert alert["attacker_ip"] == "10.0.1.50"
        assert alert["target_host"] == "debian-server"

    def test_events_count_matches(self, sample_rule, sample_events):
        alert = build_alert(rule=sample_rule, events=sample_events)
        assert alert["events"]["count"] == 1
        assert len(alert["events"]["details"]) == 1

    def test_truncate_more_than_5_events(self, sample_rule):
        events = [
            {
                "timestamp": 1750329821000 + i,
                "event_type": "ssh_failure",
                "source_host": "debian-server",
                "actor_user": f"user{i}",
                "raw_log": f"event {i}",
            }
            for i in range(10)
        ]
        alert = build_alert(rule=sample_rule, events=events)
        assert alert["events"]["count"] == 10
        assert len(alert["events"]["details"]) == 4  # 2 premiers + 2 derniers

    def test_truncate_keep_first_and_last(self, sample_rule):
        events = [
            {
                "timestamp": 1750329821000 + i,
                "event_type": "ssh_failure",
                "source_host": "debian-server",
                "actor_user": f"user{i}",
                "raw_log": f"event {i}",
            }
            for i in range(10)
        ]
        alert = build_alert(rule=sample_rule, events=events)
        details = alert["events"]["details"]
        assert details[0]["actor_user"] == "user0"
        assert details[-1]["actor_user"] == "user9"

    def test_mitre_technique_strips_subtechnique(self, sample_rule, sample_events):
        sample_rule["mitre_technique"] = "T1110.001"
        alert = build_alert(rule=sample_rule, events=sample_events)
        assert alert["mitre_technique"] == "T1110"

    def test_yara_match_included(self, sample_rule, sample_events):
        yara_match = {"rule_name": "MALWARE", "file_hash": "md5:abc123"}
        alert = build_alert(
            rule=sample_rule,
            events=sample_events,
            yara_match=yara_match,
        )
        assert alert["yara_match"] == yara_match

    def test_target_resource_is_none(self, sample_rule, sample_events):
        alert = build_alert(rule=sample_rule, events=sample_events)
        assert alert["target_resource"] is None


# =====================================================================
# Alerter — WARNING
# =====================================================================

class TestAlerterWarning:
    def test_warning_logs_to_file(self, alerter, alerts_log, sample_rule, sample_events):
        alert = build_alert(rule=sample_rule, events=sample_events)
        alert["severity"] = "WARNING"
        alerter.send(alert)

        assert alerts_log.exists()
        content = alerts_log.read_text()
        assert "WARNING" in content
        assert "TEST_RULE_001" in content

    def test_warning_no_json_file(self, alerter, alerts_dir, sample_rule, sample_events):
        alert = build_alert(rule=sample_rule, events=sample_events)
        alert["severity"] = "WARNING"
        alerter.send(alert)

        json_files = list(alerts_dir.glob("alert_*.json"))
        assert len(json_files) == 0


# =====================================================================
# Alerter — CRITICAL
# =====================================================================

class TestAlerterCritical:
    def test_critical_logs_to_file(self, alerter, alerts_log, sample_rule, sample_events):
        alert = build_alert(rule=sample_rule, events=sample_events)
        alert["severity"] = "CRITICAL"
        alerter.send(alert)

        assert alerts_log.exists()
        content = alerts_log.read_text()
        assert "CRITICAL" in content
        assert "TEST_RULE_001" in content

    def test_critical_writes_json(self, alerter, alerts_dir, sample_rule, sample_events):
        alert = build_alert(rule=sample_rule, events=sample_events)
        alert["severity"] = "CRITICAL"
        alerter.send(alert)

        json_files = list(alerts_dir.glob("alert_*.json"))
        assert len(json_files) == 1

        with open(json_files[0]) as f:
            saved = json.load(f)
        assert saved["rule_id"] == "TEST_RULE_001"
        assert saved["severity"] == "CRITICAL"

    def test_critical_json_is_valid(self, alerter, alerts_dir, sample_rule, sample_events):
        alert = build_alert(rule=sample_rule, events=sample_events)
        alert["severity"] = "CRITICAL"
        alerter.send(alert)

        json_files = list(alerts_dir.glob("alert_*.json"))
        with open(json_files[0]) as f:
            saved = json.load(f)
        assert saved["alert_id"] == alert["alert_id"]

    def test_multiple_critical_alerts(self, alerter, alerts_dir, sample_rule):
        for i in range(3):
            events = [{"timestamp": 1750329821000 + i, "event_type": "ssh_failure",
                       "source_host": "debian-server", "actor_user": f"user{i}",
                       "raw_log": f"event {i}"}]
            alert = build_alert(rule=sample_rule, events=events)
            alert["severity"] = "CRITICAL"
            alerter.send(alert)

        json_files = list(alerts_dir.glob("alert_*.json"))
        assert len(json_files) == 3


# =====================================================================
# Alerter — Atomic write
# =====================================================================

class TestAtomicWrite:
    def test_no_tmp_file_left_after_success(self, alerter, alerts_dir, sample_rule, sample_events):
        alert = build_alert(rule=sample_rule, events=sample_events)
        alert["severity"] = "CRITICAL"
        alerter.send(alert)

        tmp_files = list(alerts_dir.glob("*.tmp"))
        assert len(tmp_files) == 0

    def test_alert_id_used_in_filename(self, alerter, alerts_dir, sample_rule, sample_events):
        alert = build_alert(rule=sample_rule, events=sample_events)
        alert_id = alert["alert_id"]
        alert["severity"] = "CRITICAL"
        alerter.send(alert)

        expected = alerts_dir / f"alert_{alert_id}.json"
        assert expected.exists()


# =====================================================================
# Alerter — Unknown severity
# =====================================================================

class TestUnknownSeverity:
    def test_unknown_severity_logs_error(self, alerter, caplog, sample_rule, sample_events):
        alert = build_alert(rule=sample_rule, events=sample_events)
        alert["severity"] = "UNKNOWN"
        with caplog.at_level(logging.ERROR, logger="alerter"):
            alerter.send(alert)
        assert "Sévérité inconnue" in caplog.text


# =====================================================================
# Alerter — Directory creation
# =====================================================================

class TestDirectoryCreation:
    def test_creates_missing_directories(self, tmp_path):
        alerts_dir = tmp_path / "new" / "nested" / "alerts"
        alerts_log = alerts_dir / "alerts.log"
        assert not alerts_dir.exists()

        logging.getLogger("nyxsoc.alerts").handlers.clear()
        alerter = Alerter(str(alerts_dir), str(alerts_log))
        alerter.send(build_alert(
            rule={"rule_id": "T", "severity": "WARNING", "mitre_tactic": "TA", "mitre_technique": "T1"},
            events=[],
        ))

        assert alerts_dir.exists()
        assert alerts_log.exists()
