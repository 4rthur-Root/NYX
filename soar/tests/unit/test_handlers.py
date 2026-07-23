from unittest.mock import patch

from soar.engine import rules
from soar.handlers.handler import (
    HANDLERS,
    handle_block_ip,
    handle_ignore,
    handle_notify,
)
from soar.models.alert import Alert, EventDetail
from soar.models.decision import Decision

S1_ALERT = Alert(
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
            raw_log="Failed password from 1.2.3.4",
        )
    ],
)

S1_DECISION = Decision(
    alert=S1_ALERT,
    scenario_type="S1",
    action="block_ip",
)

NOTIFY_DECISION = Decision(
    alert=S1_ALERT,
    scenario_type="S3",
    action="notify",
)

IGNORE_DECISION = Decision(
    alert=S1_ALERT,
    scenario_type="S1",
    action="none",
    skip_reason="whitelisted",
)


class TestBlockIpHandler:
    def test_block_ip_success(self):
        with patch("soar.handlers.handler.OPNsenseClient") as MockClient:
            client = MockClient.return_value
            client.block_ip.return_value.api_status_code = 200

            resp = handle_block_ip(S1_ALERT, S1_DECISION)

        assert resp.status == "success"
        assert resp.action == "block_ip"
        assert resp.alert_id == "a1"
        assert resp.opnsense is not None
        assert resp.error is None
        client.block_ip.assert_called_once_with("1.2.3.4")

    def test_block_ip_api_failure(self):
        with patch("soar.handlers.handler.OPNsenseClient") as MockClient:
            client = MockClient.return_value
            client.block_ip.return_value.api_status_code = 500
            client.block_ip.return_value.retry_count = 3

            resp = handle_block_ip(S1_ALERT, S1_DECISION)

        assert resp.status == "error"
        assert resp.opnsense is not None
        assert resp.opnsense.api_status_code == 500

    def test_block_ip_null_ip(self):
        alert_null_ip = Alert(
            alert_id="a2",
            timestamp=1,
            rule_id="SSH_BRUTEFORCE_001",
            severity="CRITICAL",
            attacker_ip=None,
            target_host="h", target_ip="10.0.1.20",
            mitre_tactic="TA0006", mitre_technique="T1110",
            events_count=1, events_details=[],
        )
        dec = Decision(alert=alert_null_ip, scenario_type="S1", action="block_ip")

        resp = handle_block_ip(alert_null_ip, dec)

        assert resp.status == "error"
        assert resp.error == "attacker_ip is None, cannot block"
        assert resp.opnsense is None


class TestNotifyHandler:
    def test_notify_returns_success(self):
        resp = handle_notify(S1_ALERT, NOTIFY_DECISION)

        assert resp.status == "success"
        assert resp.action == "notify"

    def test_notify_includes_enrichment(self):
        from soar.models.decision import EnrichmentResult

        dec = NOTIFY_DECISION
        dec = Decision(
            alert=S1_ALERT,
            scenario_type=dec.scenario_type,
            action=dec.action,
            skip_reason=dec.skip_reason,
            enrichment=EnrichmentResult(
                source="abuseipdb", abuseipdb_score=10, fallback_used=False
            ),
        )

        resp = handle_notify(S1_ALERT, dec)

        assert resp.status == "success"
        assert resp.enrichment is not None
        assert resp.enrichment.abuseipdb_score == 10


class TestIgnoreHandler:
    def test_ignore_returns_skipped(self):
        resp = handle_ignore(S1_ALERT, IGNORE_DECISION)

        assert resp.status == "skipped"
        assert resp.action == "none"
        assert resp.opnsense is None


class TestHandlerRegistry:
    def test_handlers_maps_block_ip(self):
        assert "block_ip" in HANDLERS
        assert HANDLERS["block_ip"] is handle_block_ip

    def test_handlers_maps_notify(self):
        assert "notify" in HANDLERS
        assert HANDLERS["notify"] is handle_notify

    def test_handlers_maps_none(self):
        assert "none" in HANDLERS
        assert HANDLERS["none"] is handle_ignore

    def test_all_playbook_actions_have_handlers(self):
        for action in rules.PLAYBOOK.values():
            assert action in HANDLERS, f"Missing handler for action: {action}"
