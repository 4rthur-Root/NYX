# tests/unit/test_windows_parser.py
"""Tests unitaires — WindowsParser."""
import pytest
from parsers.windows_parser import WindowsParser


@pytest.fixture
def parser():
    return WindowsParser(debug=True)

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _wrap(event_id: str, extra_data: str = "") -> str:
    return (
        f"2026-06-19T10:24:20+00:00 DESKTOP-PME NXLog[999]: "
        f"<Event xmlns='{NS}'>"
        f"<System><EventID>{event_id}</EventID>"
        f"<TimeCreated SystemTime='2026-06-19T10:24:20'/>"
        f"<Computer>DESKTOP-PME</Computer></System>"
        f"<EventData>{extra_data}</EventData></Event>"
    )


class TestLogonFailure:
    """Tests EventID 4625 — logon_failure."""

    def test_event_type(self, parser):
        line = _wrap("4625",
                     "<Data Name='TargetUserName'>employe</Data>"
                     "<Data Name='IpAddress'>10.0.1.50</Data>")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "logon_failure"

    def test_extracts_user_and_ip(self, parser):
        line = _wrap("4625",
                     "<Data Name='TargetUserName'>employe</Data>"
                     "<Data Name='IpAddress'>10.0.1.50</Data>")
        event = parser.parse(line)
        assert event["actor_user"] == "employe"
        assert event["actor_ip"] == "10.0.1.50"


class TestLogonSuccess:
    """Tests EventID 4624 — logon_success."""

    def test_event_type(self, parser):
        line = _wrap("4624",
                     "<Data Name='TargetUserName'>employe</Data>"
                     "<Data Name='IpAddress'>10.0.1.50</Data>"
                     "<Data Name='LogonType'>3</Data>")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "logon_success"


class TestProcessExec:
    """Tests EventID 1 (Sysmon) — process_exec."""

    def test_event_type(self, parser):
        line = _wrap("1",
                     "<Data Name='Image'>C:\\Users\\employe\\payload.exe</Data>"
                     "<Data Name='User'>PME\\employe</Data>"
                     "<Data Name='Hashes'>MD5=abc123,SHA256=dead</Data>"
                     "<Data Name='CommandLine'>payload.exe</Data>")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "process_exec"

    def test_extracts_user(self, parser):
        line = _wrap("1",
                     "<Data Name='Image'>C:\\Windows\\cmd.exe</Data>"
                     "<Data Name='User'>PME\\employe</Data>"
                     "<Data Name='Hashes'>MD5=abc123</Data>")
        event = parser.parse(line)
        assert event["actor_user"] == "PME\\employe"

    def test_extracts_md5_hash(self, parser):
        line = _wrap("1",
                     "<Data Name='Image'>C:\\payload.exe</Data>"
                     "<Data Name='User'>PME\\employe</Data>"
                     "<Data Name='Hashes'>MD5=abc123def456,SHA256=dead</Data>")
        event = parser.parse(line)
        assert event["extra"]["process_hash"] == "md5:abc123def456"


class TestFileCreate:
    """Tests EventID 11 (Sysmon) — file_create."""

    def test_event_type(self, parser):
        line = _wrap("11",
                     "<Data Name='Image'>C:\\Users\\employe\\Downloads\\payload.exe</Data>"
                     "<Data Name='TargetFilename'>C:\\Users\\employe\\Downloads\\payload.exe</Data>"
                     "<Data Name='User'>PME\\employe</Data>")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "file_create"

    def test_extracts_target_filename(self, parser):
        line = _wrap("11",
                     "<Data Name='TargetFilename'>C:\\Users\\employe\\payload.exe</Data>"
                     "<Data Name='User'>PME\\employe</Data>")
        event = parser.parse(line)
        assert "target_filename" in event["extra"]


class TestNetConnect:
    """Tests EventID 3 (Sysmon) — net_connect."""

    def test_event_type(self, parser):
        line = _wrap("3",
                     "<Data Name='SourceIp'>10.0.1.30</Data>"
                     "<Data Name='DestinationIp'>10.0.1.50</Data>"
                     "<Data Name='DestinationPort'>4444</Data>"
                     "<Data Name='User'>PME\\employe</Data>")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "net_connect"
        assert event["target_port"] == 4444


class TestIgnored:
    """Tests pour les EventIDs non gérés et lignes invalides."""

    def test_unknown_event_id_returns_none(self, parser):
        line = _wrap("9999", "<Data Name='foo'>bar</Data>")
        event = parser.parse(line)
        assert event is None

    def test_non_nxlog_line_returns_none(self, parser):
        line = "2026-06-19T10:24:20+00:00 DESKTOP-PME sshd[123]: some message"
        event = parser.parse(line)
        assert event is None

    def test_empty_returns_none(self, parser):
        assert parser.parse("") is None


class TestOutput:
    """Tests sur le schéma de sortie."""

    def test_yara_match_always_none(self, parser):
        line = _wrap("4625",
                     "<Data Name='TargetUserName'>employe</Data>"
                     "<Data Name='IpAddress'>10.0.1.50</Data>")
        event = parser.parse(line)
        assert event["yara_match"] is None

    def test_process_exec_actor_ip_is_none(self, parser):
        """Sysmon EventID 1 n'a pas d'IP source."""
        line = _wrap("1",
                     "<Data Name='Image'>C:\\payload.exe</Data>"
                     "<Data Name='User'>PME\\employe</Data>"
                     "<Data Name='Hashes'>MD5=abc</Data>")
        event = parser.parse(line)
        assert event["actor_ip"] is None
