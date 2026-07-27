import logging
from unittest.mock import MagicMock, patch

from soar.models.decision import EnrichmentResult
from soar.models.response import OpnsenseResult, Response
from soar.notifications import Notifier

SAMPLE_RESPONSE = Response(
    response_id="resp-001",
    alert_id="alert-001",
    alert_timestamp=1,
    response_timestamp=2,
    latency_ms=1000,
    action="block_ip",
    status="success",
)

FAILED_RESPONSE = Response(
    response_id="resp-fail",
    alert_id="alert-fail",
    alert_timestamp=1,
    response_timestamp=2,
    latency_ms=1000,
    action="block_ip",
    status="error",
    error="API timeout",
)

HIGH_SCORE_RESPONSE = Response(
    response_id="resp-high",
    alert_id="alert-high",
    alert_timestamp=1,
    response_timestamp=2,
    latency_ms=1000,
    action="notify",
    status="success",
    enrichment=EnrichmentResult(
        source="abuseipdb",
        abuseipdb_score=99,
        fallback_used=False,
    ),
)

LOW_SCORE_RESPONSE = Response(
    response_id="resp-low",
    alert_id="alert-low",
    alert_timestamp=1,
    response_timestamp=2,
    latency_ms=1000,
    action="notify",
    status="success",
    enrichment=EnrichmentResult(
        source="abuseipdb",
        abuseipdb_score=50,
        fallback_used=False,
    ),
)

OPNSENSE_RESPONSE = Response(
    response_id="resp-opn",
    alert_id="alert-opn",
    alert_timestamp=1,
    response_timestamp=2,
    latency_ms=1000,
    action="block_ip",
    status="success",
    opnsense=OpnsenseResult(
        rule_id="soar_blocklist",
        blocked_ip="1.2.3.4",
        api_status_code=200,
        retry_count=1,
    ),
)


class TestShouldNotify:
    def test_notifies_on_error(self):
        n = Notifier()
        assert n._should_notify(FAILED_RESPONSE) is True

    def test_notifies_on_high_score(self):
        n = Notifier()
        assert n._should_notify(HIGH_SCORE_RESPONSE) is True

    def test_does_not_notify_on_low_score(self):
        n = Notifier()
        assert n._should_notify(LOW_SCORE_RESPONSE) is False

    def test_does_not_notify_on_plain_success(self):
        n = Notifier()
        assert n._should_notify(SAMPLE_RESPONSE) is False


class TestFormatResponse:
    def test_basic_response(self):
        n = Notifier()
        text = n._format_response(SAMPLE_RESPONSE)
        assert "alert-001" in text
        assert "block_ip" in text

    def test_includes_error(self):
        n = Notifier()
        text = n._format_response(FAILED_RESPONSE)
        assert "API timeout" in text

    def test_includes_enrichment(self):
        n = Notifier()
        text = n._format_response(HIGH_SCORE_RESPONSE)
        assert "99" in text

    def test_includes_opnsense(self):
        n = Notifier()
        text = n._format_response(OPNSENSE_RESPONSE)
        assert "200" in text


class TestSendImmediateAlert:
    def test_skips_if_no_trigger(self):
        n = Notifier()
        with patch.object(n, "_try_telegram") as tel:
            with patch.object(n, "_try_smtp") as smtp:
                n.send_immediate_alert(SAMPLE_RESPONSE)
                tel.assert_not_called()
                smtp.assert_not_called()

    def test_calls_telegram_and_smtp_on_failure(self):
        n = Notifier()
        with patch.object(n, "_try_telegram") as tel:
            with patch.object(n, "_try_smtp") as smtp:
                n.send_immediate_alert(FAILED_RESPONSE)
                tel.assert_called_once()
                smtp.assert_called_once()

    def test_calls_on_high_score(self):
        n = Notifier()
        with patch.object(n, "_try_telegram") as tel:
            with patch.object(n, "_try_smtp") as smtp:
                n.send_immediate_alert(HIGH_SCORE_RESPONSE)
                tel.assert_called_once()
                smtp.assert_called_once()


class TestTryTelegram:
    def test_skips_if_not_configured(self):
        n = Notifier()
        with patch("soar.notifications.notifier.settings") as s:
            s.telegram_bot_token = None
            s.telegram_chat_id = None
            with patch("soar.notifications.notifier.requests.post") as req:
                n._try_telegram("s", "b")
                req.assert_not_called()

    def test_sends_message(self):
        n = Notifier()
        with patch("soar.notifications.notifier.settings") as s:
            s.telegram_bot_token = "token"
            s.telegram_chat_id = "chat"
            with patch("soar.notifications.notifier.requests.post") as req:
                req.return_value.status_code = 200
                n._try_telegram("Subject", "Body text")
                req.assert_called_once()

    def test_handles_http_error(self):
        n = Notifier()
        with patch("soar.notifications.notifier.settings") as s:
            s.telegram_bot_token = "token"
            s.telegram_chat_id = "chat"
            with patch("soar.notifications.notifier.requests.post") as req:
                req.return_value.status_code = 401
                req.return_value.text = '{"error": "unauthorized"}'
                n._try_telegram("s", "b")


class TestTrySmtp:
    def test_skips_if_not_configured(self):
        n = Notifier()
        with patch("soar.notifications.notifier.settings") as s:
            s.smtp_host = None
            with patch("soar.notifications.notifier.smtplib.SMTP") as smtp:
                n._try_smtp("s", "b")
                smtp.assert_not_called()

    def test_handles_smtp_error(self):
        n = Notifier()
        with patch("soar.notifications.notifier.settings") as s:
            s.smtp_host = "smtp.example.com"
            s.smtp_port = 587
            s.smtp_user = None
            s.smtp_password = None
            s.smtp_to = "admin@example.com"
            with patch("soar.notifications.notifier.smtplib.SMTP") as smtp:
                smtp.side_effect = Exception("Connection refused")
                n._try_smtp("s", "b")


class TestDailySummary:
    def test_sends_summary_with_recent(self):
        now_ms = int(__import__("time").time() * 1000)
        recent = Response(
            response_id="resp-recent",
            alert_id="alert-recent",
            alert_timestamp=now_ms - 1000,
            response_timestamp=now_ms - 500,
            latency_ms=500,
            action="block_ip",
            status="success",
        )
        n = Notifier()
        with patch.object(n, "_repo") as repo:
            repo.list_recent.return_value = [recent]
            with patch.object(n, "_try_telegram") as tel:
                with patch.object(n, "_try_smtp") as smtp:
                    n.send_daily_summary()
                    tel.assert_called_once()
                    smtp.assert_called_once()

    def test_no_activity_logs_info(self, caplog):
        caplog.set_level(logging.INFO)
        n = Notifier()
        with patch.object(n, "_repo") as repo:
            repo.list_recent.return_value = []
            with patch.object(n, "_try_telegram") as tel:
                n.send_daily_summary()
                tel.assert_not_called()
                assert any("Aucune activité" in r.message for r in caplog.records)
