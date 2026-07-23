# tests/conftest.py
"""Fixtures pytest partagées entre tous les tests NyxSOC Engine."""
import sys
import os
import pytest

# Ajouter engine/ au sys.path pour les imports relatifs
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from state_manager import StateManager
from parsers.syslog_parser import SyslogParser
from parsers.filterlog_parser import FilterlogParser
from parsers.windows_parser import WindowsParser
from validator import EventValidator


@pytest.fixture
def db():
    """StateManager en mémoire — isolé, pas d'écriture disque.

    Yields:
        StateManager configuré avec ':memory:'.
    """
    sm = StateManager(":memory:")
    yield sm
    sm.close()


@pytest.fixture
def syslog_parser():
    """SyslogParser en mode debug pour faciliter le diagnostic des tests.

    Returns:
        SyslogParser(debug=True).
    """
    return SyslogParser(debug=True)


@pytest.fixture
def filterlog_parser():
    """FilterlogParser en mode debug.

    Returns:
        FilterlogParser(debug=True).
    """
    return FilterlogParser(debug=True)


@pytest.fixture
def windows_parser():
    """WindowsParser en mode debug.

    Returns:
        WindowsParser(debug=True).
    """
    return WindowsParser(debug=True)


@pytest.fixture
def validator():
    """EventValidator pour les tests de validation de schéma.

    Returns:
        EventValidator().
    """
    return EventValidator()


@pytest.fixture
def minimal_event():
    """Événement normalisé minimal valide pour les tests.

    Returns:
        Dict conforme au schéma EventNormalized.
    """
    return {
        "timestamp":   1750329821000,
        "source_host": "debian-server",
        "event_type":  "ssh_failure",
        "actor_ip":    "10.0.1.50",
        "actor_user":  "root",
        "target_host": None,
        "target_port": 22,
        "extra":       None,
        "yara_match":  None,
        "raw_log":     "Failed password for root from 10.0.1.50 port 52341 ssh2",
    }
