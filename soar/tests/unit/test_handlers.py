from unittest.mock import patch

from soar.engine import rules
from soar.handlers.handler import (
    HANDLERS,
    get_handler,
    handle_block_ip,
    handle_ignore,
    handle_notify,
)
from soar.handlers.s3_handler import S3Handler
from soar.handlers.smb_handler import SmbHandler
from soar.handlers.ssh_handler import SshHandler
from soar.models.alert import Alert, EventDetail
from soar.models.decision import Decision
from soar.models.response import OpnsenseResult, Response

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
        with patch("soar.handlers.core.OPNsenseClient") as MockClient:
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
        with patch("soar.handlers.core.OPNsenseClient") as MockClient:
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


class TestSshHandler:
    def test_can_handle_s1(self):
        handler = SshHandler()
        assert handler.can_handle("S1") is True

    def test_cannot_handle_other_scenarios(self):
        handler = SshHandler()
        assert handler.can_handle("S2") is False
        assert handler.can_handle("S3") is False

    def test_execute_calls_block_ip(self):
        handler = SshHandler()
        with patch("soar.handlers.ssh_handler.handle_block_ip") as mock_block:
            mock_block.return_value = Response(
                response_id="resp-a1",
                alert_id="a1",
                alert_timestamp=1,
                response_timestamp=2,
                latency_ms=1,
                action="block_ip",
                status="success",
            )
            resp = handler.execute(S1_ALERT, S1_DECISION)
            assert resp.action == "block_ip"
            assert mock_block.called


class TestSmbHandler:
    def test_can_handle_s2(self):
        handler = SmbHandler()
        assert handler.can_handle("S2") is True

    def test_cannot_handle_other_scenarios(self):
        handler = SmbHandler()
        assert handler.can_handle("S1") is False
        assert handler.can_handle("S3") is False

    def test_execute_calls_block_ip(self):
        handler = SmbHandler()
        with patch("soar.handlers.smb_handler.handle_block_ip") as mock_block:
            mock_block.return_value = Response(
                response_id="resp-a1",
                alert_id="a1",
                alert_timestamp=1,
                response_timestamp=2,
                latency_ms=1,
                action="block_ip",
                status="success",
            )
            dec = Decision(alert=S1_ALERT, scenario_type="S2", action="block_ip")
            resp = handler.execute(S1_ALERT, dec)
            assert resp.action == "block_ip"
            assert mock_block.called


class TestS3Handler:
    def test_can_handle_s3(self):
        handler = S3Handler()
        assert handler.can_handle("S3") is True

    def test_cannot_handle_other_scenarios(self):
        handler = S3Handler()
        assert handler.can_handle("S1") is False
        assert handler.can_handle("S2") is False

    def test_execute_notify_without_ip(self):
        handler = S3Handler()
        alert_no_ip = Alert(
            alert_id="a3",
            timestamp=1,
            rule_id="MALICIOUS_FILE_EXEC_001",
            severity="CRITICAL",
            attacker_ip=None,
            target_host="DESKTOP-PME",
            target_ip="10.0.1.30",
            mitre_tactic="TA0002",
            mitre_technique="T1204",
            events_count=3,
            events_details=[],
        )
        dec = Decision(alert=alert_no_ip, scenario_type="S3", action="notify")
        with patch("soar.handlers.s3_handler.handle_notify") as mock_notify:
            mock_notify.return_value = Response(
                response_id="resp-a3",
                alert_id="a3",
                alert_timestamp=1,
                response_timestamp=2,
                latency_ms=1,
                action="notify",
                status="success",
            )
            resp = handler.execute(alert_no_ip, dec)
            assert resp.action == "notify"
            assert resp.status == "success"
            assert resp.opnsense is None
            assert mock_notify.called

    def test_execute_notify_with_ip_also_blocks(self):
        handler = S3Handler()
        dec = Decision(alert=S1_ALERT, scenario_type="S3", action="notify")
        with patch("soar.handlers.s3_handler.handle_notify") as mock_notify:
            with patch("soar.handlers.s3_handler.handle_block_ip") as mock_block:
                mock_notify.return_value = Response(
                    response_id="resp-a1",
                    alert_id="a1",
                    alert_timestamp=1,
                    response_timestamp=2,
                    latency_ms=1,
                    action="notify",
                    status="success",
                )
                mock_block.return_value = Response(
                    response_id="resp-a1",
                    alert_id="a1",
                    alert_timestamp=1,
                    response_timestamp=2,
                    latency_ms=1,
                    action="block_ip",
                    status="success",
                    opnsense=OpnsenseResult(api_status_code=200, retry_count=1),
                )
                resp = handler.execute(S1_ALERT, dec)
                assert mock_notify.called
                assert mock_block.called
                assert resp.action == "notify"
                assert resp.opnsense is not None


class TestGetHandlerDispatcher:
    def test_returns_ssh_for_s1(self):
        dec = Decision(alert=S1_ALERT, scenario_type="S1", action="block_ip")
        fn = get_handler(dec)
        assert fn is not None
        assert fn.__name__ == "execute"
        assert fn.__self__.__class__.__name__ == "SshHandler"

    def test_returns_smb_for_s2(self):
        dec = Decision(alert=S1_ALERT, scenario_type="S2", action="block_ip")
        fn = get_handler(dec)
        assert fn is not None
        assert fn.__name__ == "execute"
        assert fn.__self__.__class__.__name__ == "SmbHandler"

    def test_returns_s3_for_s3(self):
        dec = Decision(alert=S1_ALERT, scenario_type="S3", action="notify")
        fn = get_handler(dec)
        assert fn is not None
        assert fn.__name__ == "execute"
        assert fn.__self__.__class__.__name__ == "S3Handler"

    def test_returns_ignore_for_none_action(self):
        dec = Decision(alert=S1_ALERT, scenario_type="S1", action="none")
        fn = get_handler(dec)
        assert fn is handle_ignore

    def test_returns_none_for_unknown_action(self):
        dec = Decision(alert=S1_ALERT, scenario_type="S1", action="unknown_action")
        fn = get_handler(dec)
        assert fn is None

    def test_falls_back_to_action_handler_for_unknown_scenario(self):
        dec = Decision(alert=S1_ALERT, scenario_type="UNKNOWN", action="block_ip")
        fn = get_handler(dec)
        assert fn is handle_block_ip
