# tests/unit/test_dispatcher.py
import pytest
from unittest.mock import MagicMock, patch
from dispatcher import Dispatcher

@pytest.fixture
def mocks():
    return {
        "parsers": {"test.log": MagicMock()},
        "validator": MagicMock(),
        "state": MagicMock(),
        "yara": MagicMock(),
        "rule_engine": MagicMock(),
        "alerter": MagicMock(),
        "samba_mounts": {"commun": "/mnt/test/commun"}
    }

@pytest.fixture
def dispatcher(mocks):
    return Dispatcher(**mocks)

class TestDispatcher:
    def test_dispatch_unknown_file(self, dispatcher, mocks):
        dispatcher.dispatch("some line", "unknown.log")
        mocks["parsers"]["test.log"].parse.assert_not_called()

    def test_dispatch_invalid_event(self, dispatcher, mocks):
        mocks["parsers"]["test.log"].parse.return_value = {"bad": "event"}
        mocks["validator"].validate.return_value = False
        
        dispatcher.dispatch("line", "test.log")
        
        mocks["state"].store_event.assert_not_called()

    def test_dispatch_valid_event(self, dispatcher, mocks):
        event = {"event_type": "ssh_failure", "source_host": "test"}
        mocks["parsers"]["test.log"].parse.return_value = event
        mocks["validator"].validate.return_value = True
        mocks["rule_engine"].process_event.return_value = None
        
        dispatcher.dispatch("line", "test.log")
        
        mocks["state"].store_event.assert_called_once_with(event)
        mocks["rule_engine"].process_event.assert_called_once_with(event)
        mocks["alerter"].send.assert_not_called()

    def test_dispatch_with_alerts(self, dispatcher, mocks):
        event = {"event_type": "ssh_failure", "source_host": "test"}
        alert = {"rule_id": "TEST"}
        
        mocks["parsers"]["test.log"].parse.return_value = event
        mocks["validator"].validate.return_value = True
        mocks["rule_engine"].process_event.return_value = [alert]
        
        dispatcher.dispatch("line", "test.log")
        
        mocks["alerter"].send.assert_called_once_with(alert)

    def test_samba_write_triggers_yara(self, dispatcher, mocks):
        event = {
            "event_type": "samba_write",
            "extra": {"filename": "test.exe", "share": "//commun"}
        }
        mocks["parsers"]["test.log"].parse.return_value = event
        mocks["validator"].validate.return_value = True
        
        yara_result = {"rule_name": "MALWARE"}
        mocks["yara"].scan.return_value = yara_result
        
        # Mock Path.exists pour le fallback
        with patch("dispatcher.Path.exists", return_value=True):
            dispatcher.dispatch("line", "test.log")
        
        mocks["yara"].scan.assert_called_once_with("/mnt/test/commun/test.exe")
        assert event["yara_match"] == yara_result
