import pytest
from soar.parser import AlertParser, AlertValidationError


S1_VALID = {
    "alert_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": 1750000000000,
    "rule_id": "SSH_BRUTEFORCE_001",
    "severity": "CRITICAL",
    "attacker_ip": "10.0.1.50",
    "target_host": "debian-server",
    "target_ip": "10.0.1.20",
    "mitre_tactic": "TA0006",
    "mitre_technique": "T1110",
    "events": {
        "count": 15,
        "details": [
            {
                "timestamp": 1749999940000,
                "event_type": "ssh_failure",
                "source_host": "debian-server",
                "raw_log": "Failed password for root from 10.0.1.50 port 22",
            }
        ],
    },
    "yara_match": None,
}


@pytest.fixture
def parser():
    return AlertParser()


class TestValidAlerts:
    def test_s1_returns_alert_object(self, parser):
        alert = parser.parse_dict(S1_VALID)
        assert alert.rule_id == "SSH_BRUTEFORCE_001"
        assert alert.severity == "CRITICAL"
        assert alert.attacker_ip == "10.0.1.50"

    def test_s1_events_are_parsed(self, parser):
        alert = parser.parse_dict(S1_VALID)
        assert alert.events_count == 15
        assert len(alert.events_details) == 1
        d = alert.events_details[0]
        assert d.event_type == "ssh_failure"
        assert d.actor_user is None

    def test_s3_attacker_ip_null(self, parser):
        s3 = dict(S1_VALID)
        s3.update(
            {
                "alert_id": "660e8400-e29b-41d4-a716-446655440001",
                "rule_id": "MALICIOUS_FILE_EXEC_001",
                "attacker_ip": None,
                "yara_match": {
                    "rule_name": "MAL_Meterpreter_Reverse_TCP",
                    "file_path": "/srv/samba/commun/payload.exe",
                    "file_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d",
                    "ruleset": "Neo23x0/signature-base",
                },
            }
        )
        alert = parser.parse_dict(s3)
        assert alert.attacker_ip is None
        assert alert.yara_match is not None
        assert alert.yara_match.rule_name == "MAL_Meterpreter_Reverse_TCP"

    def test_attacker_ip_none_no_exception(self, parser):
        payload = dict(S1_VALID)
        payload.update({"alert_id": "xxx", "attacker_ip": None})
        alert = parser.parse_dict(payload)
        assert alert.attacker_ip is None


class TestInvalidAlerts:
    def test_missing_field_raises_error(self, parser):
        bad = dict(S1_VALID)
        del bad["severity"]
        with pytest.raises(AlertValidationError):
            parser.parse_dict(bad)

    def test_wrong_severity_raises_error(self, parser):
        bad = dict(S1_VALID)
        bad["severity"] = "INVALID"
        with pytest.raises(AlertValidationError):
            parser.parse_dict(bad)

    def test_missing_events_raises_error(self, parser):
        bad = dict(S1_VALID)
        del bad["events"]
        with pytest.raises(AlertValidationError):
            parser.parse_dict(bad)

    def test_empty_dict_raises_error(self, parser):
        with pytest.raises(AlertValidationError):
            parser.parse_dict({})
