import dataclasses

import pytest

from soar.engine import DecisionEngine
from soar.engine import rules
from soar.models.alert import Alert, EventDetail


S1_CRITICAL = Alert(
    alert_id="a1",
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
            raw_log="Failed password for root from 1.2.3.4",
        )
    ],
)

S3_CRITICAL = Alert(
    alert_id="a2",
    timestamp=1750000000000,
    rule_id="MALICIOUS_FILE_EXEC_001",
    severity="CRITICAL",
    attacker_ip=None,
    target_host="DESKTOP-PME",
    target_ip="10.0.1.30",
    mitre_tactic="TA0002",
    mitre_technique="T1204",
    events_count=3,
    events_details=[
        EventDetail(
            timestamp=1749999940000,
            event_type="file_create",
            source_host="DESKTOP-PME",
            raw_log="File created: payload.exe",
        )
    ],
)


@pytest.fixture
def engine():
    return DecisionEngine()


class TestSeverityWarning:
    def test_skips_warning_without_enrichment(self, engine):
        alert = Alert(
            alert_id="w1",
            timestamp=1,
            rule_id="SSH_BRUTEFORCE_001",
            severity="WARNING",
            attacker_ip="10.0.1.50",
            target_host="h", target_ip="1.2.3.4",
            mitre_tactic="TA0006", mitre_technique="T1110",
            events_count=1, events_details=[],
        )

        d = engine.decide(alert)

        assert d.action == "none"
        assert d.skip_reason == "severity_warning"


class TestAttackerIpNull:
    def test_skips_s1_with_null_ip(self, engine):
        alert = Alert(
            alert_id="n1",
            timestamp=1,
            rule_id="SSH_BRUTEFORCE_001",
            severity="CRITICAL",
            attacker_ip=None,
            target_host="h", target_ip="1.2.3.4",
            mitre_tactic="TA0006", mitre_technique="T1110",
            events_count=1, events_details=[],
        )

        d = engine.decide(alert)

        assert d.action == "none"
        assert d.skip_reason == "attacker_ip_null"

    def test_does_not_skip_s3_with_null_ip(self, engine, mocker):
        mocker.patch.object(engine._abuseipdb, "get_reputation")

        d = engine.decide(S3_CRITICAL)

        assert d.action != "none"
        assert d.skip_reason is None


class TestWhitelist:
    def test_skips_private_ip(self, engine):
        alert = Alert(
            alert_id="w2",
            timestamp=1,
            rule_id="SSH_BRUTEFORCE_001",
            severity="CRITICAL",
            attacker_ip="192.168.1.1",
            target_host="h", target_ip="1.2.3.4",
            mitre_tactic="TA0006", mitre_technique="T1110",
            events_count=1, events_details=[],
        )

        d = engine.decide(alert)

        assert d.action == "none"
        assert d.skip_reason == "whitelisted"

    def test_does_not_skip_public_ip(self, engine, mocker):
        mocker.patch.object(engine._abuseipdb, "get_reputation",
                            return_value=engine._abuseipdb._fallback_or_default("1.2.3.4"))

        alert = Alert(
            alert_id="w3",
            timestamp=1,
            rule_id="SSH_BRUTEFORCE_001",
            severity="CRITICAL",
            attacker_ip="1.2.3.4",
            target_host="h", target_ip="1.2.3.4",
            mitre_tactic="TA0006", mitre_technique="T1110",
            events_count=1, events_details=[],
        )

        d = engine.decide(alert)

        assert d.action == "block_ip"
        assert d.skip_reason is None


class TestPlaybookActions:
    def test_s1_block_ip(self, engine, mocker):
        mocker.patch.object(engine._abuseipdb, "get_reputation",
                            return_value=engine._abuseipdb._fallback_or_default("10.0.1.50"))

        d = engine.decide(S1_CRITICAL)

        assert d.action == "block_ip"
        assert d.enrichment is not None

    def test_s3_notify(self, engine, mocker):
        mocker.patch.object(engine._abuseipdb, "get_reputation")

        d = engine.decide(S3_CRITICAL)

        assert d.action == "notify"
        assert d.enrichment is None


class TestAbuseIpdbOverride:
    def test_low_score_overrides_to_notify(self, engine, mocker):
        low_score = engine._abuseipdb._fallback_or_default("1.2.3.4")
        low_score = dataclasses.replace(low_score, abuseipdb_score=10)
        mocker.patch.object(engine._abuseipdb, "get_reputation",
                            return_value=low_score)

        d = engine.decide(S1_CRITICAL)

        assert d.action == "notify"


class TestUnknownRuleId:
    def test_skips_unknown_rule_id(self, engine):
        alert = Alert(
            alert_id="u1",
            timestamp=1,
            rule_id="UNKNOWN_RULE_999",
            severity="CRITICAL",
            attacker_ip="10.0.1.50",
            target_host="h", target_ip="1.2.3.4",
            mitre_tactic="TA0006", mitre_technique="T1110",
            events_count=1, events_details=[],
        )

        d = engine.decide(alert)

        assert d.action == "none"
        assert d.skip_reason == "whitelisted"
