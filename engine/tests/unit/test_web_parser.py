# tests/unit/test_web_parser.py
"""Tests unitaires — WebParser (logs Dolibarr / Apache Combined Log)."""
import pytest
from parsers.web_parser import WebParser


@pytest.fixture
def parser():
    return WebParser(debug=True)


# =====================================================================
# Événements http_request
# =====================================================================

class TestHTTPRequest:
    """Parsing du Combined Log Format Dolibarr."""

    def test_basic_get_request(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] '
            '"GET /admin/modules.php?id=42 HTTP/1.1" 302 390 '
            '"http://10.0.1.20/" "Mozilla/5.0"'
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "http_request"
        assert event["actor_ip"] == "10.0.1.1"
        assert event["source_host"] == "localhost"
        assert event["target_port"] == 80

    def test_post_request_401(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.50 - - [02/Jul/2026:16:39:30 +0000] '
            '"POST /login.php HTTP/1.1" 401 234 '
            '"http://10.0.1.20/" "Mozilla/5.0"'
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "http_request"
        assert event["extra"]["http_method"] == "POST"
        assert event["extra"]["http_path"] == "/login.php"
        assert event["extra"]["http_status"] == 401

    def test_internal_dummy_connection(self, parser):
        line = (
            "2026-07-02T16:39:45+00:00 localhost dolibarr[794]: "
            '127.0.0.1 - - [02/Jul/2026:16:39:45 +0000] '
            '"OPTIONS * HTTP/1.0" 200 110 "-" '
            '"Apache/2.4.59 (Debian) PHP/8.2.7 (internal dummy connection)"'
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "http_request"
        assert event["actor_ip"] == "127.0.0.1"
        assert event["extra"]["http_method"] == "OPTIONS"


# =====================================================================
# Extraction des champs extra
# =====================================================================

class TestFieldExtraction:
    """Champs extra du Combined Log."""

    def test_extracts_http_method(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] '
            '"DELETE /api/endpoint HTTP/1.1" 200 0 '
            '"-" "curl/7.68.0"'
        )
        event = parser.parse(line)
        assert event["extra"]["http_method"] == "DELETE"

    def test_extracts_http_path(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] '
            '"GET /admin/modules.php?id=42 HTTP/1.1" 200 1234 '
            '"-" "Mozilla/5.0"'
        )
        event = parser.parse(line)
        assert event["extra"]["http_path"] == "/admin/modules.php?id=42"

    def test_extracts_http_status(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] '
            '"GET / HTTP/1.1" 403 123 '
            '"-" "Mozilla/5.0"'
        )
        event = parser.parse(line)
        assert event["extra"]["http_status"] == 403

    def test_extracts_user_agent(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] '
            '"GET / HTTP/1.1" 200 123 '
            '"-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"'
        )
        event = parser.parse(line)
        assert event["extra"]["user_agent"] == (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        )

    def test_extracts_referer(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] '
            '"GET /page HTTP/1.1" 200 123 '
            '"https://example.com/" "Mozilla/5.0"'
        )
        event = parser.parse(line)
        assert event["extra"]["referer"] == "https://example.com/"

    def test_response_size_dash_becomes_none(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] '
            '"HEAD / HTTP/1.1" 200 - '
            '"-" "Mozilla/5.0"'
        )
        event = parser.parse(line)
        assert event["extra"]["response_size"] is None

    def test_pid_injected_in_extra(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] '
            '"GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        )
        event = parser.parse(line)
        assert event["extra"]["pid"] == "794"


# =====================================================================
# Lignes ignorées
# =====================================================================

class TestIgnored:
    """Lignes non reconnues ou hors périmètre."""

    def test_empty_line_returns_none(self, parser):
        assert parser.parse("") is None
        assert parser.parse("   ") is None

    def test_non_syslog_line_returns_none(self, parser):
        assert parser.parse("not a syslog line") is None

    def test_non_web_program_returns_none(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost sshd[123]: "
            "some ssh message"
        )
        assert parser.parse(line) is None

    def test_non_combined_log_returns_none(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            "some random dolibarr message without combined log"
        )
        assert parser.parse(line) is None


# =====================================================================
# Output contract
# =====================================================================

class TestOutput:
    """Contrat de sortie du parser."""

    def test_yara_match_always_none(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] '
            '"GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        )
        event = parser.parse(line)
        assert event["yara_match"] is None

    def test_required_fields_present(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] '
            '"GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        )
        event = parser.parse(line)
        for field in ["timestamp", "source_host", "event_type", "raw_log"]:
            assert field in event

    def test_timestamp_is_int_milliseconds(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] '
            '"GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        )
        event = parser.parse(line)
        assert isinstance(event["timestamp"], int)
        assert event["timestamp"] > 1_000_000_000_000

    def test_raw_log_is_original_line(self, parser):
        line = (
            "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: "
            '10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] '
            '"GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        )
        event = parser.parse(line)
        assert event["raw_log"] == line
