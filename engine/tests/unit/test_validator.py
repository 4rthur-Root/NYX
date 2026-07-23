# tests/unit/test_validator.py
"""Tests unitaires — EventValidator."""
import pytest
from validator import EventValidator


@pytest.fixture
def v():
    return EventValidator()


@pytest.fixture
def valid_event():
    return {
        "timestamp":   1750329821000,
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


class TestValidation:
    def test_valid_event_passes(self, v, valid_event):
        assert v.validate(valid_event) is True

    def test_missing_timestamp_fails(self, v, valid_event):
        del valid_event["timestamp"]
        assert v.validate(valid_event) is False

    def test_missing_source_host_fails(self, v, valid_event):
        del valid_event["source_host"]
        assert v.validate(valid_event) is False

    def test_missing_event_type_fails(self, v, valid_event):
        del valid_event["event_type"]
        assert v.validate(valid_event) is False

    def test_missing_raw_log_fails(self, v, valid_event):
        del valid_event["raw_log"]
        assert v.validate(valid_event) is False

    def test_wrong_type_timestamp_fails(self, v, valid_event):
        valid_event["timestamp"] = "not_an_int"
        assert v.validate(valid_event) is False

    def test_extra_field_not_in_schema_fails(self, v, valid_event):
        valid_event["unexpected_field"] = "value"
        assert v.validate(valid_event) is False


class TestTaxonomy:
    def test_all_valid_event_types(self, v, valid_event):
        valid_types = [
            "ssh_failure", "logon_success", "logon_failure",
            "samba_read", "samba_write", "smb_failure",
            "http_request", "net_scan", "firewall_block",
            "file_create", "process_exec", "net_connect",
        ]
        for et in valid_types:
            valid_event["event_type"] = et
            assert v.validate(valid_event) is True, f"'{et}' devrait être valide"

    def test_invalid_event_type_fails(self, v, valid_event):
        valid_event["event_type"] = "unknown_event"
        assert v.validate(valid_event) is False

    def test_empty_event_type_fails(self, v, valid_event):
        valid_event["event_type"] = ""
        assert v.validate(valid_event) is False


class TestNullableFields:
    def test_null_optional_fields_pass(self, v, valid_event):
        valid_event["actor_ip"]    = None
        valid_event["actor_user"]  = None
        valid_event["target_host"] = None
        valid_event["target_port"] = None
        valid_event["extra"]       = None
        valid_event["yara_match"]  = None
        assert v.validate(valid_event) is True

    def test_extra_as_dict_passes(self, v, valid_event):
        valid_event["extra"] = {"key": "value", "count": 42}
        assert v.validate(valid_event) is True

    def test_yara_match_as_dict_passes(self, v, valid_event):
        valid_event["yara_match"] = {
            "rule_name": "Meterpreter",
            "file_path": "/mnt/samba/commun/payload.exe",
            "file_hash": "md5:abc123",
            "ruleset":   "neo23x0/signature-base",
        }
        assert v.validate(valid_event) is True
