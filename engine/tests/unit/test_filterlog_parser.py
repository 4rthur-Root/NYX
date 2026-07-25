# tests/unit/test_filterlog_parser.py
"""Tests unitaires — FilterlogParser (OPNsense BSD CSV)."""
import pytest
from parsers.filterlog_parser import FilterlogParser


@pytest.fixture
def parser():
    return FilterlogParser(debug=True)


# =====================================================================
# Classification d'événements
# =====================================================================

class TestNetScan:
    """block in → net_scan (sondage de port entrant)."""

    def test_tcp_block_in_is_net_scan(self, parser):
        line = (
            "2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
            "76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,"
            "10.0.1.50,10.0.1.20,54321,22,0"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "net_scan"

    def test_udp_block_in_is_net_scan(self, parser):
        line = (
            "2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
            "76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,17,udp,40,"
            "10.0.1.50,10.0.1.20,1234,53,0"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "net_scan"


class TestFirewallBlock:
    """block out → firewall_block."""

    def test_block_out_is_firewall_block(self, parser):
        line = (
            "2026-06-19T10:23:41+00:00 OPNsense.internal filterlog[56376]: "
            "76,,,uuid,vtnet1,match,block,out,4,0x0,,64,0,0,none,6,tcp,60,"
            "10.0.1.20,10.0.1.50,445,54321,0"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "firewall_block"


class TestNetConnect:
    """pass in/out → net_connect."""

    def test_tcp_pass_in_is_net_connect(self, parser):
        line = (
            "2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56377]: "
            "76,,,uuid,vtnet1,match,pass,in,4,0x0,,64,0,0,none,6,tcp,60,"
            "10.0.1.50,10.0.1.20,54321,22,0"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "net_connect"

    def test_udp_pass_is_net_connect(self, parser):
        line = (
            "2026-06-19T10:23:40+00:00 OPNsense.internal filterlog[56375]: "
            "76,,,uuid,vtnet1,match,pass,in,4,0x0,,64,0,0,none,17,udp,40,"
            "10.0.1.50,10.0.1.20,1234,53,0"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "net_connect"


# =====================================================================
# Extraction des champs
# =====================================================================

class TestFieldExtraction:
    """Champs extraits du CSV filterlog."""

    def test_extracts_actor_ip(self, parser):
        line = (
            "2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
            "76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,"
            "10.0.1.50,10.0.1.20,54321,22,0"
        )
        event = parser.parse(line)
        assert event["actor_ip"] == "10.0.1.50"

    def test_extracts_target_port(self, parser):
        line = (
            "2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
            "76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,"
            "10.0.1.50,10.0.1.20,54321,22,0"
        )
        event = parser.parse(line)
        assert event["target_port"] == 22

    def test_extracts_protocol(self, parser):
        line = (
            "2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
            "76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,"
            "10.0.1.50,10.0.1.20,54321,22,0"
        )
        event = parser.parse(line)
        assert event["extra"]["protocol"] == "tcp"

    def test_actor_user_is_none(self, parser):
        """filterlog ne contient jamais d'utilisateur."""
        line = (
            "2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
            "76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,"
            "10.0.1.50,10.0.1.20,54321,22,0"
        )
        event = parser.parse(line)
        assert event["actor_user"] is None

    def test_yara_match_is_none(self, parser):
        line = (
            "2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
            "76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,"
            "10.0.1.50,10.0.1.20,54321,22,0"
        )
        event = parser.parse(line)
        assert event["yara_match"] is None


# =====================================================================
# IPv6
# =====================================================================

class TestIPv6:
    """Support IPv6 dans le CSV filterlog."""

    def test_ipv6_block_in(self, parser):
        line = (
            "2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
            "76,,,uuid,vtnet1,match,block,in,6,0x0,,64,6,tcp,60,"
            "2001:db8::1,2001:db8::2,54321,22,0"
        )
        event = parser.parse(line)
        assert event is not None
        assert event["event_type"] == "net_scan"
        assert event["actor_ip"] == "2001:db8::1"


# =====================================================================
# Lignes ignorées
# =====================================================================

class TestIgnored:
    """Lignes non filterlog ou malformées."""

    def test_non_filterlog_returns_none(self, parser):
        line = (
            "2026-06-19T10:23:38+00:00 OPNsense.internal "
            "sshd[123]: some message"
        )
        assert parser.parse(line) is None

    def test_empty_line_returns_none(self, parser):
        assert parser.parse("") is None

    def test_too_few_fields_returns_none(self, parser):
        line = (
            "2026-06-19T10:23:38+00:00 OPNsense.internal "
            "filterlog[56373]: short"
        )
        assert parser.parse(line) is None

    def test_invalid_ip_version_returns_none(self, parser):
        line = (
            "2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: "
            "76,,,uuid,vtnet1,match,block,in,5,0x0,,64,0,0,none,6,tcp,60,"
            "10.0.1.50,10.0.1.20,54321,22,0"
        )
        assert parser.parse(line) is None
