# tests/unit/test_syslog_parser.py
"""Tests unitaires — SyslogParser (Debian/Linux logs)."""
import pytest
from parsers.syslog_parser import SyslogParser


@pytest.fixture
def parser():
    return SyslogParser(debug=True)


# =====================================================================
# SSH
# =====================================================================

class TestSSHFailure:
    """Événements ssh_failure."""

    def test_failed_password_extracts_all_fields(self, parser):
        line = (
            "2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
            "Failed password for root from 10.0.1.50 "
            "port 52341 ssh2"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "ssh_failure"
        assert event["actor_ip"] == "10.0.1.50"
        assert event["actor_user"] == "root"
        assert event["target_port"] == 22
        assert event["source_host"] == "debian-server"

    def test_invalid_user_returns_ssh_failure(self, parser):
        line = (
            "2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
            "Invalid user hacker from 10.0.1.50"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "ssh_failure"
        assert event["actor_user"] == "hacker"
        assert event["actor_ip"] == "10.0.1.50"

    def test_missing_user_becomes_none(self, parser):
        line = (
            "2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
            "Invalid user  from 10.0.1.50"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["actor_user"] is None

    def test_rfc3164_timestamp_accepted(self, parser):
        line = (
            "Jun 19 10:23:41 debian-server sshd[1234]: "
            "Failed password for root from 10.0.1.50 port 52341 ssh2"
        )
        event = parser.parse(line)
        assert event is not None
        assert isinstance(event["timestamp"], int)
        assert event["timestamp"] > 1_000_000_000_000


class TestSSHSuccess:
    """Événements logon_success."""

    def test_accepted_password(self, parser):
        line = (
            "2026-06-19T10:24:01+00:00 debian-server sshd[1250]: "
            "Accepted password for dir1 from 10.0.1.50 port 52400 ssh2"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "logon_success"
        assert event["actor_user"] == "dir1"
        assert event["actor_ip"] == "10.0.1.50"


class TestSSHNoise:
    """Lignes SSH sans intérêt."""

    def test_disconnect_returns_none(self, parser):
        for msg in [
            "Disconnected from 10.0.1.50 port 52341",
            "Connection closed by 10.0.1.50",
            "Connection reset by 10.0.1.50",
        ]:
            line = (
                f"2026-06-19T10:23:41+00:00 debian-server sshd[1234]: {msg}"
            )
            assert parser.parse(line) is None


# =====================================================================
# Samba (smbd)
# =====================================================================

class TestSambaWrite:
    """Événements samba_write."""

    def test_write_detected(self, parser):
        line = (
            "2026-06-19T10:24:10+00:00 debian-server smbd[1328]: "
            "dir1 wrote payload.exe on //commun from 10.0.1.50"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "samba_write"
        assert event["actor_user"] == "dir1"
        assert event["actor_ip"] == "10.0.1.50"
        assert event["extra"]["filename"] == "payload.exe"
        assert event["extra"]["share"] == "//commun"

    def test_alternative_write_pattern(self, parser):
        line = (
            "2026-06-19T10:24:10+00:00 debian-server smbd[1328]: "
            "open file /path/to/file for write"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "samba_write"


class TestSambaRead:
    """Événements samba_read."""

    def test_read_detected(self, parser):
        line = (
            "2026-06-19T10:24:12+00:00 debian-server smbd[1329]: "
            "dir1 read secret.txt from //direction"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "samba_read"
        assert event["extra"]["filename"] == "secret.txt"
        assert event["extra"]["share"] == "//direction"


class TestSambaFailure:
    """Événements smb_failure."""

    def test_auth_failure(self, parser):
        line = (
            "2026-06-19T10:24:05+00:00 debian-server smbd[1327]: "
            "NT_STATUS_WRONG_PASSWORD for dir2 from 10.0.1.50"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "smb_failure"
        assert event["actor_user"] == "dir2"
        assert event["actor_ip"] == "10.0.1.50"


# =====================================================================
# Samba Audit JSON (Kerberos)
# =====================================================================

class TestSambaAudit:
    """Audit JSON Samba — EventIDs 4768 et 4769."""

    def test_tgt_request_4768(self, parser):
        line = (
            '2026-06-19T10:25:00+00:00 srv-pme samba-audit[222]: '
            '{"Authentication": {"eventId": 4768, '
            '"remoteAddress": "ipv4:10.0.1.50:56100", '
            '"servicePrincipalName": "krbtgt/NYX.TG", '
            '"accountName": "employe"}}'
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "tgt_request"
        assert event["actor_ip"] == "10.0.1.50"
        assert event["actor_user"] == "employe"
        assert event["extra"]["spn"] == "krbtgt/NYX.TG"

    def test_tgs_request_4769(self, parser):
        line = (
            '2026-06-19T10:25:05+00:00 srv-pme samba-audit[222]: '
            '{"Authentication": {"eventId": 4769, '
            '"remoteAddress": "ipv6:[::1]:56101", '
            '"servicePrincipalName": "cifs/srv-pme.nyx.tg", '
            '"accountName": "employe"}}'
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "tgs_request"
        assert event["actor_ip"] == "[::1]:56101"
        assert event["extra"]["spn"] == "cifs/srv-pme.nyx.tg"


# =====================================================================
# Ignored / noise
# =====================================================================

class TestIgnored:
    """Lignes sans parser applicable."""

    def test_nmbd_returns_none(self, parser):
        line = (
            "2026-06-19T10:24:17+00:00 debian-server nmbd[999]: "
            "Netbios name query ignored"
        )
        assert parser.parse(line) is None

    def test_unknown_program_returns_none(self, parser):
        line = (
            "2026-06-19T10:24:17+00:00 debian-server cron[999]: "
            "some cron job ran"
        )
        assert parser.parse(line) is None

    def test_empty_line_returns_none(self, parser):
        assert parser.parse("") is None
        assert parser.parse("   ") is None


# =====================================================================
# Output contract
# =====================================================================

class TestOutput:
    """Contrat de sortie du parser."""

    def test_yara_match_always_none(self, parser):
        line = (
            "2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
            "Failed password for root from 10.0.1.50 port 52341 ssh2"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["yara_match"] is None

    def test_required_fields_present(self, parser):
        line = (
            "2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
            "Failed password for root from 10.0.1.50 port 52341 ssh2"
        )
        event = parser.parse(line)
        assert event is not None
        for field in ["timestamp", "source_host", "event_type", "raw_log"]:
            assert field in event

    def test_timestamp_is_int_milliseconds(self, parser):
        line = (
            "2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
            "Failed password for root from 10.0.1.50 port 52341 ssh2"
        )
        event = parser.parse(line)
        assert isinstance(event["timestamp"], int)
        assert event["timestamp"] > 1_000_000_000_000

    def test_raw_log_is_original_line(self, parser):
        line = (
            "2026-06-19T10:23:41+00:00 debian-server sshd[1234]: "
            "Failed password for root from 10.0.1.50 port 52341 ssh2"
        )
        event = parser.parse(line)
        assert event["raw_log"] == line

    def test_no_http_request_produced(self, parser):
        """SyslogParser ne produit plus d'événements http_request."""
        line = (
            "2026-06-19T10:24:15+00:00 debian-server apache2[1400]: "
            "10.0.1.50 - - [19/Jun/2026:10:24:15 +0000] "
            '"GET /index.php HTTP/1.1" 200 4523'
        )
        event = parser.parse(line)
        # Apache n'est plus parsé par SyslogParser
        assert event is None
