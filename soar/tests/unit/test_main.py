from unittest.mock import MagicMock, patch

import soar.main
from soar.main import _daily_loop, _shutdown, _signal_handler, main


class TestMainEntryPoint:
    def test_main_starts_orchestrator(self):
        with patch("soar.main.setup_soar_logging"):
            with patch("soar.main.initialize_db"):
                with patch("soar.main.AlertOrchestrator") as MockOrch:
                    with patch("soar.main.Notifier"):
                        with patch("soar.main._daily_loop"):
                            with patch("soar.main.signal.signal"):
                                with patch("soar.main._shutdown") as mock_event:
                                    mock_event.wait.side_effect = [None]
                                    orch = MockOrch.return_value
                                    main()
                                    orch.start.assert_called_once()
                                    orch.stop.assert_called_once()

    def test_main_exits_on_db_failure(self):
        with patch("soar.main.setup_soar_logging"):
            with patch("soar.main.initialize_db") as db:
                db.side_effect = Exception("DB error")
                try:
                    main()
                except SystemExit as e:
                    assert e.code == 1


class TestSignalHandler:
    def test_sets_shutdown_event(self):
        _shutdown.clear()
        _signal_handler(15, None)
        assert _shutdown.is_set()
        _shutdown.clear()


class TestDailyLoop:
    def test_sends_summary(self):
        soar.main._DAILY_INTERVAL_S = 0.01
        _shutdown.clear()
        notifier = MagicMock()

        def stop_after_one():
            _shutdown.set()

        notifier.send_daily_summary.side_effect = stop_after_one
        _daily_loop(notifier)
        notifier.send_daily_summary.assert_called_once()

    def test_handles_exception(self):
        soar.main._DAILY_INTERVAL_S = 0.01
        _shutdown.clear()
        notifier = MagicMock()

        def fail_then_stop():
            _shutdown.set()
            raise Exception("oups")

        notifier.send_daily_summary.side_effect = fail_then_stop
        _daily_loop(notifier)
        notifier.send_daily_summary.assert_called_once()
