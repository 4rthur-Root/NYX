# tests/unit/test_rule_engine.py
import pytest
import time
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
    # Créer un répertoire vide pour les règles
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    engine = RuleEngine(state_manager, yara_scanner, str(rules_dir))
    return engine

class TestEvalType1:
    def test_eval_type1_trigger(self, rule_engine):
        rule = {
            "rule_id": "TEST_001",
            "type": 1,
            "severity": "WARNING",
            "trigger": {
                "event_type": "ssh_failure",
                "threshold": 3,
                "window_seconds": 60,
                "group_by": "actor_ip"
            }
        }
        
        # Injecter manuellement la règle
        rule_engine.rules.append(rule)
        
        event = {
            "timestamp": int(time.time() * 1000),
            "source_host": "debian",
            "event_type": "ssh_failure",
            "actor_ip": "1.2.3.4",
            "actor_user": "root",
            "raw_log": "test"
        }
        
        # Insérer 2 événements dans SQLite
        rule_engine.state.store_event(event)
        rule_engine.state.store_event(event)
        
        # L'événement actuel est le 3ème, le count sera à 3
        rule_engine.state.store_event(event)
        
        alerts = rule_engine.process_event(event)
        
        assert alerts is not None
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "TEST_001"
        assert alerts[0]["events"]["count"] == 3

    def test_eval_type1_no_trigger_below_threshold(self, rule_engine):
        rule = {
            "rule_id": "TEST_001",
            "type": 1,
            "severity": "WARNING",
            "trigger": {
                "event_type": "ssh_failure",
                "threshold": 3,
                "window_seconds": 60,
                "group_by": "actor_ip"
            }
        }
        rule_engine.rules.append(rule)
        
        event = {
            "timestamp": int(time.time() * 1000),
            "source_host": "debian",
            "event_type": "ssh_failure",
            "actor_ip": "1.2.3.4",
            "raw_log": "test"
        }
        
        rule_engine.state.store_event(event)
        alerts = rule_engine.process_event(event)
        
        assert alerts is None

class TestEvalType4:
    def test_eval_type4_trigger_with_yara(self, rule_engine):
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
            "source_host": "debian",
            "event_type": "samba_write",
            "actor_ip": "1.2.3.4",
            "raw_log": "test",
            "yara_match": {
                "rule_name": "MALWARE"
            }
        }
        
        alerts = rule_engine.process_event(event)
        assert alerts is not None
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "YARA_001"
        assert alerts[0]["yara_match"]["rule_name"] == "MALWARE"

    def test_eval_type4_no_yara_no_trigger(self, rule_engine):
        rule = {
            "rule_id": "YARA_001",
            "type": 4,
            "severity": "CRITICAL",
            "yara_trigger": {
                "event_type": "samba_write"
            }
        }
        rule_engine.rules.append(rule)
        
        event = {
            "timestamp": 1000,
            "source_host": "debian",
            "event_type": "samba_write",
            "raw_log": "test",
            "yara_match": None
        }
        
        alerts = rule_engine.process_event(event)
        assert alerts is None
