# tests/integration/test_engine_full.py
import pytest
import tempfile
import os
import json
import time
import datetime
from pathlib import Path
import threading
import queue

from state_manager import StateManager
from yara_scanner import YaraScanner
from rule_engine import RuleEngine
from alerter import Alerter
from validator import EventValidator
from dispatcher import Dispatcher
from parsers.syslog_parser import SyslogParser
from parsers.filterlog_parser import FilterlogParser
from parsers.windows_parser import WindowsParser

@pytest.fixture
def engine_env(tmp_path):
    """Fixture créant un environnement complet avec base SQLite en fichier temp et dossiers de logs."""
    alerts_dir = tmp_path / "alerts"
    alerts_dir.mkdir()
    alerts_log = alerts_dir / "alerts.log"
    db_path = tmp_path / "engine.db"
    rules_dir = Path(__file__).parent.parent.parent / "rules" / "attack"
    
    state = StateManager(str(db_path))
    yara = YaraScanner(str(tmp_path / "yara"))  # Pas de règles YARA
    rule_engine = RuleEngine(state, yara, str(rules_dir))
    alerter = Alerter(str(alerts_dir), str(alerts_log))
    validator = EventValidator()
    
    parsers = {
        "debian.log": SyslogParser(),
        "OPNsense.internal.log": FilterlogParser(),
        "DESKTOP-PME.log": WindowsParser()
    }
    
    dispatcher = Dispatcher(
        parsers=parsers,
        validator=validator,
        state=state,
        yara=yara,
        rule_engine=rule_engine,
        alerter=alerter
    )
    
    yield dispatcher, alerts_dir, state
    
    state.close()

def test_full_ssh_bruteforce(engine_env):
    dispatcher, alerts_dir, state = engine_env
    
    # 10 échecs SSH en moins d'une minute -> règle SSH_BRUTEFORCE_001
    for i in range(10):
        ts = int(time.time()) - (20 - i)
        # Format RFC 3164
        import datetime
        dt = datetime.datetime.fromtimestamp(ts)
        ts_str = dt.strftime("%b %d %H:%M:%S")
        
        line = f"{ts_str} debian-server sshd[123]: Failed password for root from 1.2.3.4 port 5555 ssh2"
        dispatcher.dispatch(line, "debian.log")
        
    # Vérifier que l'alerte a été générée
    alert_files = list(alerts_dir.glob("alert_*.json"))
    assert len(alert_files) == 1
    
    with open(alert_files[0]) as f:
        alert = json.load(f)
        
    assert alert["rule_id"] == "SSH_BRUTEFORCE_001"
    assert alert["severity"] == "CRITICAL"
    assert alert["attacker_ip"] == "1.2.3.4"
    assert alert["target_host"] == "debian-server"
    assert alert["events"]["count"] == 10

def test_full_smb_exfil(engine_env):
    dispatcher, alerts_dir, state = engine_env
    
    # Règle SMB_EXFIL_001 : net_scan + samba_read dans les 300s
    ts = int(time.time()) - 10
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    ts_str_iso = dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    
    # 1. net_scan (OPNsense)
    line1 = f"{ts_str_iso} OPNsense.internal filterlog[1]: 76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,10.0.1.60,10.0.1.20,54321,22,0"
    dispatcher.dispatch(line1, "OPNsense.internal.log")
    
    # 2. samba_read (debian)
    line2 = f"{ts_str_iso} debian-server smbd[2]: admin read secret.txt from //direction from 10.0.1.60"
    dispatcher.dispatch(line2, "debian.log")
    
    # Vérifier
    alert_files = list(alerts_dir.glob("alert_*.json"))
    assert len(alert_files) == 1
    
    with open(alert_files[0]) as f:
        alert = json.load(f)
        
    assert alert["rule_id"] == "SMB_EXFIL_001"
    assert alert["severity"] == "CRITICAL"
    assert alert["attacker_ip"] == "10.0.1.60"
