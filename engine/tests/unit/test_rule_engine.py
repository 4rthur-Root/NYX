# tests/unit/test_rule_engine.py
"""Tests unitaires — RuleEngine avec hosts_map."""
import time
import pytest
from rule_engine import RuleEngine
from state_manager import StateManager
from unittest.mock import MagicMock


@pytest.fixture
def state_manager():
    sm = StateManager(":memory:")
    yield sm
    sm.close()


@pytest.fixture
def yara_scanner():
    return MagicMock()


@pytest.fixture
def rule_engine(state_manager, yara_scanner, tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    return RuleEngine(state_manager, yara_scanner, str(rules_dir))


@pytest.fixture
def hosts_map():
    return {
        "debian-server": "10.0.1.20",
        "srv-pme": "10.0.1.10",
        "OPNsense.internal": "10.0.1.1",
    }


class TestResolveTargetIp:
    def test_resolve_known_host(self, rule_engine, hosts_map):
        rule_engine.hosts_map = hosts_map
        ip = rule_engine._resolve_target_ip("debian-server")
        assert ip == "10.0.1.20"

    def test_resolve_unknown_host_returns_none(self, rule_engine, hosts_map):
        rule_engine.hosts_map = hosts_map
        ip = rule_engine._resolve_target_ip("unknown-host")
        assert ip is None

    def test_empty_hosts_map_returns_none(self, rule_engine):
        rule_engine.hosts_map = {}
        ip = rule_engine._resolve_target_ip("debian-server")
        assert ip is None

    def test_none_hosts_map_returns_none(self, rule_engine):
        rule_engine.hosts_map = {}
        ip = rule_engine._resolve_target_ip("debian-server")
        assert ip is None


class TestEvalType1:
    def test_eval_type1_uses_resolved_target_ip(self, rule_engine, hosts_map):
        rule_engine.hosts_map = hosts_map
        rule = {
            "rule_id": "TEST_001",
            "type": 1,
            "severity": "WARNING",
            "trigger": {
                "event_type": "ssh_failure",
                "threshold": 1,
                "window_seconds": 60,
                "group_by": "actor_ip"
            }
        }
        rule_engine.rules.append(rule)

        event = {
            "timestamp": int(time.time() * 1000),
            "source_host": "debian-server",
            "event_type": "ssh_failure",
            "actor_ip": "1.2.3.4",
            "actor_user": "root",
            "raw_log": "test"
        }
        rule_engine.state.store_event(event)

        alerts = rule_engine.process_event(event)
        assert alerts is not None
        assert alerts[0]["target_ip"] == "10.0.1.20"

    def test_eval_type1_no_hosts_map_target_ip_none(self, rule_engine):
        rule = {
            "rule_id": "TEST_001",
            "type": 1,
            "severity": "WARNING",
            "trigger": {
                "event_type": "ssh_failure",
                "threshold": 1,
                "window_seconds": 60,
                "group_by": "actor_ip"
            }
        }
        rule_engine.rules.append(rule)

        event = {
            "timestamp": int(time.time() * 1000),
            "source_host": "debian-server",
            "event_type": "ssh_failure",
            "actor_ip": "1.2.3.4",
            "actor_user": "root",
            "raw_log": "test"
        }
        rule_engine.state.store_event(event)

        alerts = rule_engine.process_event(event)
        assert alerts is not None
        assert alerts[0]["target_ip"] is None


class TestEvalType4:
    def test_eval_type4_uses_resolved_target_ip(self, rule_engine, hosts_map):
        rule_engine.hosts_map = hosts_map
        rule = {
            "rule_id": "YARA_001",
            "type": 4,
            "severity": "CRITICAL",
            "yara_trigger": {
                "event_type": "samba_write",
                "source_host_pattern": "*"
            }
        }
        rule_engine.rules.append(rule)

        event = {
            "timestamp": 1000,
            "source_host": "srv-pme",
            "event_type": "samba_write",
            "actor_ip": "1.2.3.4",
            "raw_log": "test",
            "yara_match": {"rule_name": "MALWARE"}
        }

        alerts = rule_engine.process_event(event)
        assert alerts is not None
        assert alerts[0]["target_ip"] == "10.0.1.10"

    def test_eval_type4_no_hosts_map_target_ip_none(self, rule_engine):
        rule = {
            "rule_id": "YARA_001",
            "type": 4,
            "severity": "CRITICAL",
            "yara_trigger": {
                "event_type": "samba_write",
                "source_host_pattern": "*"
            }
        }
        rule_engine.rules.append(rule)

        event = {
            "timestamp": 1000,
            "source_host": "srv-pme",
            "event_type": "samba_write",
            "raw_log": "test",
            "yara_match": {"rule_name": "MALWARE"}
        }

        alerts = rule_engine.process_event(event)
        assert alerts is not None
        assert alerts[0]["target_ip"] is None
