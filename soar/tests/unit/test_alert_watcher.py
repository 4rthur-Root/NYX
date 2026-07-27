import json
import time
from pathlib import Path

import pytest
from watchdog.events import FileSystemEvent, FileSystemMovedEvent

from soar.parser import AlertParser
from soar.watcher import AlertFileHandler, AlertWatcher


S1_ALERT = {
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


@pytest.fixture
def tmp_alerts(tmp_path: Path) -> Path:
    d = tmp_path / "alerts"
    d.mkdir()
    return d


class TestAlertFileHandler:
    def test_processes_valid_alert(self, parser, tmp_alerts):
        received = []
        handler = AlertFileHandler(parser=parser, on_alert=received.append)

        alert_file = tmp_alerts / "alert_550e.json"
        alert_file.write_text(json.dumps(S1_ALERT))

        handler.on_created(
            FileSystemEvent(str(alert_file))
        )

        assert len(received) == 1
        assert received[0].alert_id == "550e8400-e29b-41d4-a716-446655440000"

    def test_dedup_same_alert_id(self, parser, tmp_alerts):
        received = []
        handler = AlertFileHandler(parser=parser, on_alert=received.append)

        alert_file = tmp_alerts / "alert_550e.json"
        alert_file.write_text(json.dumps(S1_ALERT))

        handler.on_created(FileSystemEvent(str(alert_file)))
        handler.on_created(FileSystemEvent(str(alert_file)))

        assert len(received) == 1

    def test_ignores_tmp_files(self, parser, tmp_alerts):
        received = []
        handler = AlertFileHandler(parser=parser, on_alert=received.append)

        tmp_file = tmp_alerts / "alert_550e.json.tmp"
        tmp_file.write_text(json.dumps(S1_ALERT))

        handler.on_created(FileSystemEvent(str(tmp_file)))

        assert len(received) == 0

    def test_invalid_json_does_not_crash(self, parser, tmp_alerts):
        received = []
        handler = AlertFileHandler(parser=parser, on_alert=received.append)

        bad_file = tmp_alerts / "bad.json"
        bad_file.write_text("not valid json")

        handler.on_created(FileSystemEvent(str(bad_file)))

        assert len(received) == 0

    def test_non_existent_file_ignored(self, parser, tmp_alerts):
        received = []
        handler = AlertFileHandler(parser=parser, on_alert=received.append)

        handler._process(str(tmp_alerts / "nonexistent.json"))

        assert len(received) == 0

    def test_on_moved_triggers_processing(self, parser, tmp_alerts):
        received = []
        handler = AlertFileHandler(parser=parser, on_alert=received.append)

        src = tmp_alerts / "temp.tmp"
        dst = tmp_alerts / "alert_final.json"
        src.write_text(json.dumps(S1_ALERT))
        src.rename(dst)

        event = FileSystemMovedEvent(src_path=str(src), dest_path=str(dst))
        handler.on_moved(event)

        assert len(received) == 1


class TestAlertWatcher:
    def test_preloads_existing_alerts(self, parser, tmp_alerts):
        (tmp_alerts / "alert_001.json").write_text(json.dumps(S1_ALERT))

        received = []
        watcher = AlertWatcher(
            watch_dir=tmp_alerts,
            parser=parser,
            on_alert=received.append,
        )
        watcher._preload_existing()

        assert len(watcher._seen_ids) == 1
        assert "550e8400-e29b-41d4-a716-446655440000" in watcher._seen_ids
        assert len(received) == 1

    def test_start_stop_does_not_crash(self, parser, tmp_alerts):
        watcher = AlertWatcher(
            watch_dir=tmp_alerts,
            parser=parser,
            on_alert=lambda a: None,
        )
        watcher.start()
        time.sleep(0.2)
        watcher.stop()
