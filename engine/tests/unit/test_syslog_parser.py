# tests/unit/test_syslog_parser.py
"""Tests unitaires — SyslogParser."""
import pytest
from parsers.syslog_parser import SyslogParser


@pytest.fixture
def parser():
    return SyslogParser(debug=True)


class TestSSHFailure:
    """Tests pour les événements ssh_failure."""

    def test_extracts_event_type(self, parser):
        line = ("2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
                "Failed password for root from 10.0.1.50 port 52341 ssh2")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "ssh_failure"

    def test_extracts_actor_ip(self, parser):
        line = ("2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
                "Failed password for root from 10.0.1.50 port 52341 ssh2")
        event = parser.parse(line)
        assert event["actor_ip"] == "10.0.1.50"

    def test_extracts_actor_user(self, parser):
        line = ("2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
                "Failed password for root from 10.0.1.50 port 52341 ssh2")
        event = parser.parse(line)
        assert event["actor_user"] == "root"

    def test_invalid_user_returns_ssh_failure(self, parser):
        line = ("2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
                "Invalid user hacker from 10.0.1.50")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "ssh_failure"
        assert event["actor_user"] == "hacker"

    def test_missing_user_is_none_not_empty(self, parser):
        """Champs absents = None, jamais chaîne vide."""
        line = ("2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
                "Invalid user  from 10.0.1.50")
        event = parser.parse(line)
        # L'user vide doit donner None ou être ignoré
        if event is not None:
            assert event["actor_user"] != ""


class TestSSHSuccess:
    """Tests pour les événements logon_success."""

    def test_accepted_password(self, parser):
        line = ("2026-06-19T10:24:01+00:00 debian-server sshd[1250]: "
                "Accepted password for dir1 from 10.0.1.50 port 52400 ssh2")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "logon_success"
        assert event["actor_user"] == "dir1"
        assert event["actor_ip"] == "10.0.1.50"


class TestSamba:
    """Tests pour les événements samba_write / samba_read / smb_failure."""

    def test_samba_write_detected(self, parser):
        line = ("2026-06-19T10:24:10+00:00 debian-server smbd[1328]: "
                "dir1 wrote payload.exe on //commun from 10.0.1.50")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "samba_write"
        assert event["actor_user"] == "dir1"

    def test_smb_failure_on_wrong_password(self, parser):
        line = ("2026-06-19T10:24:05+00:00 debian-server smbd[1327]: "
                "NT_STATUS_WRONG_PASSWORD for dir2 from 10.0.1.50")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "smb_failure"


class TestApache:
    """Tests pour les événements http_request."""

    def test_apache_get_request(self, parser):
        line = ("2026-06-19T10:24:15+00:00 debian-server apache2[1400]: "
                "10.0.1.50 - - [19/Jun/2026:10:24:15 +0000] "
                '"GET /index.php HTTP/1.1" 200 4523')
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "http_request"
        assert event["actor_ip"] == "10.0.1.50"
        assert event["extra"]["http_status"] == 200

    def test_apache_post_401(self, parser):
        line = ("2026-06-19T10:24:16+00:00 debian-server apache2[1400]: "
                "10.0.1.50 - - [19/Jun/2026:10:24:16 +0000] "
                '"POST /login.php HTTP/1.1" 401 234')
        event = parser.parse(line)
        assert event is not None
        assert event["extra"]["http_status"] == 401


class TestIgnored:
    """Tests pour les lignes ignorées."""

    def test_nmbd_returns_none(self, parser):
        line = ("2026-06-19T10:24:17+00:00 debian-server nmbd[999]: "
                "Netbios name query ignored")
        event = parser.parse(line)
        assert event is None

    def test_empty_line_returns_none(self, parser):
        assert parser.parse("") is None
        assert parser.parse("   ") is None

    def test_unknown_program_returns_none(self, parser):
        line = ("2026-06-19T10:24:17+00:00 debian-server cron[999]: "
                "some cron job ran")
        event = parser.parse(line)
        assert event is None


class TestOutput:
    """Tests sur le schéma de sortie."""

    def test_yara_match_always_none(self, parser):
        """Les parsers ne renseignent jamais yara_match."""
        line = ("2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
                "Failed password for root from 10.0.1.50 port 52341 ssh2")
        event = parser.parse(line)
        assert event is not None
        assert event["yara_match"] is None

    def test_required_fields_present(self, parser):
        line = ("2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
                "Failed password for root from 10.0.1.50 port 52341 ssh2")
        event = parser.parse(line)
        assert event is not None
        for field in ["timestamp", "source_host", "event_type", "raw_log"]:
            assert field in event

    def test_timestamp_is_int_milliseconds(self, parser):
        line = ("2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
                "Failed password for root from 10.0.1.50 port 52341 ssh2")
        event = parser.parse(line)
        assert isinstance(event["timestamp"], int)
        assert event["timestamp"] > 1_000_000_000_000  # > Jan 2001 en ms
