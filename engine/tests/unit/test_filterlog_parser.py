# tests/unit/test_filterlog_parser.py
"""Tests unitaires — FilterlogParser."""
import pytest
from parsers.filterlog_parser import FilterlogParser


@pytest.fixture
def parser():
    return FilterlogParser(debug=True)


class TestNetScan:
    """Tests pour la classification net_scan (block in)."""

    def test_block_in_tcp_is_net_scan(self, parser):
        line = ("2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
                "76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,"
                "10.0.1.50,10.0.1.20,54321,22,0")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "net_scan"

    def test_extracts_actor_ip(self, parser):
        line = ("2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
                "76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,"
                "10.0.1.50,10.0.1.20,54321,22,0")
        event = parser.parse(line)
        assert event["actor_ip"] == "10.0.1.50"

    def test_extracts_target_port(self, parser):
        line = ("2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
                "76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,"
                "10.0.1.50,10.0.1.20,54321,22,0")
        event = parser.parse(line)
        assert event["target_port"] == 22


class TestFirewallBlock:
    """Tests pour la classification firewall_block (block out)."""

    def test_block_out_is_firewall_block(self, parser):
        line = ("2026-06-19T10:23:41+00:00 OPNsense.internal filterlog[56376]: "
                "76,,,uuid,vtnet1,match,block,out,4,0x0,,64,0,0,none,6,tcp,60,"
                "10.0.1.20,10.0.1.50,445,54321,0")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "firewall_block"


class TestUDP:
    """Tests pour le protocole UDP."""

    def test_udp_pass_is_net_connect(self, parser):
        line = ("2026-06-19T10:23:40+00:00 OPNsense.internal filterlog[56375]: "
                "76,,,uuid,vtnet1,match,pass,in,4,0x0,,64,0,0,none,17,udp,40,"
                "10.0.1.50,10.0.1.20,1234,53,0")
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "net_connect"


class TestIgnored:
    """Tests pour les lignes non filterlog."""

    def test_non_filterlog_line_returns_none(self, parser):
        line = "2026-06-19T10:23:38+00:00 OPNsense.internal sshd[123]: some message"
        event = parser.parse(line)
        assert event is None

    def test_empty_line_returns_none(self, parser):
        assert parser.parse("") is None


class TestOutput:
    """Tests sur le schéma de sortie."""

    def test_actor_user_is_none(self, parser):
        """filterlog ne contient jamais d'utilisateur."""
        line = ("2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
                "76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,"
                "10.0.1.50,10.0.1.20,54321,22,0")
        event = parser.parse(line)
        assert event["actor_user"] is None

    def test_yara_match_is_none(self, parser):
        line = ("2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
                "76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,"
                "10.0.1.50,10.0.1.20,54321,22,0")
        event = parser.parse(line)
        assert event["yara_match"] is None
