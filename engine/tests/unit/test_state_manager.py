# tests/unit/test_state_manager.py
"""Tests unitaires — StateManager."""
import time
import pytest
from state_manager import StateManager


@pytest.fixture
def db():
    sm = StateManager(":memory:")
    yield sm
    sm.close()


@pytest.fixture
def sample_event():
    return {
        "timestamp":   int(time.time() * 1000),
        "source_host": "debian-server",
        "event_type":  "ssh_failure",
        "actor_ip":    "10.0.1.50",
        "actor_user":  "root",
        "target_host": None,
        "target_port": 22,
        "extra":       None,
        "yara_match":  None,
        "raw_log":     "Failed password for root from 10.0.1.50 port 52341 ssh2",
    }


class TestStoreEvent:
    def test_returns_integer_id(self, db, sample_event):
        row_id = db.store_event(sample_event)
        assert isinstance(row_id, int)
        assert row_id >= 1

    def test_store_increments_id(self, db, sample_event):
        id1 = db.store_event(sample_event)
        id2 = db.store_event(sample_event)
        assert id2 > id1

    def test_store_with_extra_dict(self, db, sample_event):
        sample_event["extra"] = {"method": "password", "port": 22}
        row_id = db.store_event(sample_event)
        assert row_id >= 1

    def test_store_with_yara_match(self, db, sample_event):
        sample_event["yara_match"] = {
            "rule_name": "Meterpreter",
            "file_path": "/mnt/samba/commun/payload.exe",
            "file_hash": "md5:abc123",
            "ruleset":   "neo23x0/signature-base",
        }
        row_id = db.store_event(sample_event)
        assert row_id >= 1


class TestCountEvents:
    def test_count_one_event(self, db, sample_event):
        db.store_event(sample_event)
        count = db.count_events("ssh_failure", "10.0.1.50", "actor_ip", 60)
        assert count == 1

    def test_count_multiple_events(self, db, sample_event):
        for _ in range(5):
            db.store_event(sample_event)
        count = db.count_events("ssh_failure", "10.0.1.50", "actor_ip", 60)
        assert count == 5

    def test_count_zero_for_different_ip(self, db, sample_event):
        db.store_event(sample_event)
        count = db.count_events("ssh_failure", "192.168.1.1", "actor_ip", 60)
        assert count == 0

    def test_count_zero_for_different_type(self, db, sample_event):
        db.store_event(sample_event)
        count = db.count_events("samba_write", "10.0.1.50", "actor_ip", 60)
        assert count == 0

    def test_count_outside_window_returns_zero(self, db):
        old_event = {
            "timestamp":   int((time.time() - 200) * 1000),  # 200s ago
            "source_host": "debian-server",
            "event_type":  "ssh_failure",
            "actor_ip":    "10.0.1.50",
            "actor_user":  "root",
            "target_host": None,
            "target_port": 22,
            "extra":       None,
            "yara_match":  None,
            "raw_log":     "old event",
        }
        db.store_event(old_event)
        count = db.count_events("ssh_failure", "10.0.1.50", "actor_ip", 60)
        assert count == 0


class TestGetEvents:
    def test_returns_list(self, db, sample_event):
        db.store_event(sample_event)
        events = db.get_events("ssh_failure", "10.0.1.50", "actor_ip", 60)
        assert isinstance(events, list)
        assert len(events) == 1

    def test_extra_deserialized(self, db, sample_event):
        sample_event["extra"] = {"key": "value"}
        db.store_event(sample_event)
        events = db.get_events("ssh_failure", "10.0.1.50", "actor_ip", 60)
        assert events[0]["extra"] == {"key": "value"}


class TestContexts:
    def test_set_and_get_context(self, db):
        db.set_context("SSH_BRUTEFORCE_001", "10.0.1.50", None, step=1)
        ctx = db.get_context("SSH_BRUTEFORCE_001", "10.0.1.50", None)
        assert ctx is not None
        assert ctx["step"] == 1
        assert ctx["state"] == "pending"

    def test_update_context(self, db):
        db.set_context("RULE_001", "10.0.1.50", None, step=1)
        db.set_context("RULE_001", "10.0.1.50", None, step=2)
        ctx = db.get_context("RULE_001", "10.0.1.50", None)
        assert ctx["step"] == 2

    def test_get_nonexistent_context_returns_none(self, db):
        ctx = db.get_context("NONEXISTENT", "10.0.1.50", None)
        assert ctx is None

    def test_delete_context(self, db):
        db.set_context("RULE_001", "10.0.1.50", None, step=1)
        db.delete_context("RULE_001", "10.0.1.50", None)
        ctx = db.get_context("RULE_001", "10.0.1.50", None)
        assert ctx is None

    def test_context_with_extra(self, db):
        extra = {"step1_event": {"event_type": "samba_write"}}
        db.set_context("RULE_001", None, "dir1", step=1, extra=extra)
        ctx = db.get_context("RULE_001", None, "dir1")
        assert ctx["extra"]["step1_event"]["event_type"] == "samba_write"


class TestPurge:
    def test_purge_old_events(self, db):
        old_event = {
            "timestamp":   int((time.time() - 200) * 1000),
            "source_host": "debian-server",
            "event_type":  "ssh_failure",
            "actor_ip":    "10.0.1.50",
            "actor_user":  None,
            "target_host": None,
            "target_port": None,
            "extra":       None,
            "yara_match":  None,
            "raw_log":     "old",
        }
        db.store_event(old_event)
        deleted = db.purge_old_events(older_than_s=60)
        assert deleted >= 1

    def test_purge_keeps_recent_events(self, db, sample_event):
        db.store_event(sample_event)
        deleted = db.purge_old_events(older_than_s=3600)
        assert deleted == 0
        count = db.count_events("ssh_failure", "10.0.1.50", "actor_ip", 60)
        assert count == 1
