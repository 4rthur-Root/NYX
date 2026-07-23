from pathlib import Path
from unittest.mock import MagicMock

from soar.engine import DecisionEngine
from soar.handlers.handler import HANDLERS
from soar.models.alert import Alert, EventDetail
from soar.models.decision import Decision
from soar.models.response import Response
from soar.orchestrator import AlertOrchestrator
from soar.parser import AlertParser

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
    events_count=1,
    events_details=[
        EventDetail(
            timestamp=1749999940000,
            event_type="ssh_failure",
            source_host="debian-server",
            raw_log="Failed password from 1.2.3.4",
        )
    ],
)


def make_decision(action: str, skip_reason: str | None = None) -> Decision:
    return Decision(
        alert=S1_ALERT,
        scenario_type="S1",
        action=action,
        skip_reason=skip_reason,
    )


class TestPipeline:
    def test_full_pipeline_with_block_ip(self):
        engine = MagicMock(spec=DecisionEngine)
        engine.decide.return_value = make_decision("block_ip")

        orch = AlertOrchestrator(
            parser=MagicMock(spec=AlertParser),
            decision_engine=engine,
            watch_dir=Path("/tmp/nyx_test"),
        )

        with MagicMock() as mock_handler:
            original = HANDLERS["block_ip"]
            HANDLERS["block_ip"] = mock_handler
            mock_handler.return_value = Response(
                response_id="resp-a1",
                alert_id="a1",
                alert_timestamp=1,
                response_timestamp=2,
                latency_ms=1,
                action="block_ip",
                status="success",
            )

            try:
                orch._on_alert(S1_ALERT)
                assert mock_handler.called
            finally:
                HANDLERS["block_ip"] = original

    def test_error_in_decision_does_not_crash(self, caplog):
        engine = MagicMock(spec=DecisionEngine)
        engine.decide.side_effect = ValueError("boom")

        orch = AlertOrchestrator(
            parser=MagicMock(spec=AlertParser),
            decision_engine=engine,
            watch_dir=Path("/tmp"),
        )

        orch._on_alert(S1_ALERT)

        assert any("Erreur décision" in r.message for r in caplog.records)

    def test_error_in_handler_does_not_crash(self, caplog):
        engine = MagicMock(spec=DecisionEngine)
        engine.decide.return_value = make_decision("block_ip")

        orch = AlertOrchestrator(
            parser=MagicMock(spec=AlertParser),
            decision_engine=engine,
            watch_dir=Path("/tmp"),
        )

        original = HANDLERS["block_ip"]
        HANDLERS["block_ip"] = MagicMock(side_effect=RuntimeError("handler fail"))
        try:
            orch._on_alert(S1_ALERT)
            assert any("Erreur exécution handler" in r.message for r in caplog.records)
        finally:
            HANDLERS["block_ip"] = original

    def test_unknown_action_logs_warning(self, caplog):
        engine = MagicMock(spec=DecisionEngine)
        engine.decide.return_value = make_decision("unknown_action")

        orch = AlertOrchestrator(
            parser=MagicMock(spec=AlertParser),
            decision_engine=engine,
            watch_dir=Path("/tmp"),
        )

        orch._on_alert(S1_ALERT)

        assert any("unknown_action" in r.message for r in caplog.records)


class TestStartStop:
    def test_start_creates_watcher(self):
        orch = AlertOrchestrator(
            parser=MagicMock(spec=AlertParser),
            decision_engine=MagicMock(spec=DecisionEngine),
            watch_dir=Path("/tmp"),
        )

        orch.start()
        assert orch._watcher is not None
        orch.stop()

    def test_double_stop_does_not_crash(self):
        orch = AlertOrchestrator(
            parser=MagicMock(spec=AlertParser),
            decision_engine=MagicMock(spec=DecisionEngine),
            watch_dir=Path("/tmp"),
        )

        orch.start()
        orch.stop()
        orch.stop()
