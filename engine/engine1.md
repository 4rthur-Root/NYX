# Engine — Moteur de corrélation NyxSOC

**Module** : Corrélation stateful multi-sources  
**Auteur** : KPODONOU Kossigan Gaël God-Love  
**Langage** : Python 3.12  
**Dépendances** : `pyyaml>=6.0`, `watchdog>=4.0`, `jsonschema>=4.0`, `yara-python>=4.3`, `pytest>=8.0`  
**Environnement cible** : Debian 12, SOC 10.0.1.10

---

## 1. Vue d'ensemble

Le moteur de corrélation est le composant central de NyxSOC. Il ingère des
événements de sécurité issus de trois sources hétérogènes, les normalise en
un schéma JSON unifié, maintient un état persistant dans SQLite, évalue des
règles de détection YAML, et publie des alertes structurées vers le module
SOAR via écriture atomique de fichiers JSON.

### Principe fondamental

Le moteur ne décide pas de la gravité d'un événement isolé. Il détecte des
**chaînes d'événements** — des séquences temporelles qui, prises ensemble,
constituent une attaque. Un seul échec SSH n'est pas une alerte. Quinze
échecs SSH depuis la même IP en 60 secondes suivis d'une connexion Samba
réussie — c'est une alerte.

La décision de réponse (bloquer une IP, isoler un poste) appartient
exclusivement au module SOAR. Le moteur produit des **faits classifiés**,
pas des ordres.

---

## 2. Architecture

![Architecture du module engine](engine.png)

### Flux de données

```
/var/log/remote/*.log
        │
        │  inotify (watchdog)
        ▼
    reader.py  ──────────────────────────────────────────────────────────┐
  (un handler par fichier, queue commune)                                │
        │                                                                │
        │  tuple (ligne, nom_fichier)                                    │
        ▼                                                                │
  dispatcher.py                                                          │
  (routing config.yaml → parser, validation EventValidator)             │
        │                                                                │
        ├──── syslog_parser.py     ← debian.log                         │
        ├──── filterlog_parser.py  ← OPNsense.internal.log              │
        └──── windows_parser.py    ← DESKTOP-PME.log                    │
        │                                                                │
        │  dict normalisé | None                                         │
        ▼                                                                │
  state_manager.py  ◄──────────────────────────────────────────────┐    │
  (SQLite WAL — events + contexts)                                  │    │
        │                                                           │    │
        │  store_event()                                            │    │
        ▼                                                           │    │
  rule_engine.py  ──── interroge et écrit ──────────────────────────┘    │
  (évalue règles YAML)                                                   │
        │                                                                │
        │  file_create + check_yara: true                                │
        ├──── yara_scanner.py                                            │
        │     (yara-python, règles rules/yara/)                          │
        │                                                                │
        │  alerte dict                                                   │
        ▼                                                                │
  alerter.py                                                             │
        │                                                                │
        ├── WARNING  → alerts.log                                        │
        └── CRITICAL → alert_<uuid>.json → /var/log/nyxsoc/alerts/      │
                                                                         │
  main.py ────────────────────────────────────────────────────────────────┘
  (orchestre, purge périodique, arrêt propre)
```

---

## 3. Structure des fichiers

```
engine/
  main.py                    # Initialisation, orchestration, purge périodique
  reader.py                  # Watchdog inotify, queue thread-safe commune
  dispatcher.py              # Routing parser, validation schéma JSON
  validator.py               # EventValidator — jsonschema sur événements normalisés
  parsers/
    base_parser.py           # Classe abstraite BaseParser (ABC)
    syslog_parser.py         # Logs Debian — SSH, Samba, Apache (RFC 5424)
    filterlog_parser.py      # Logs OPNsense — filterlog BSD
    windows_parser.py        # Logs Windows — XML EventLog + Sysmon via NXLog
  state_manager.py           # SQLite — stockage événements et contextes
  rule_engine.py             # Évaluation règles YAML, corrélation stateful
  yara_scanner.py            # Scan fichiers via yara-python
  alerter.py                 # Publication alertes WARNING et CRITICAL
  rules/
    ssh_bruteforce.yaml      # Règle Type 1 — seuil SSH
    smb_exfil.yaml           # Règle Type 1+2 — scan + exfiltration SMB
    malicious_file.yaml      # Règle Type 2 — BEC kill-chain
    yara/
      malware_generic.yar    # Règles YARA — neo23x0/signature-base (filtrées)
  tests/
    unit/
      test_syslog_parser.py
      test_filterlog_parser.py
      test_windows_parser.py
      test_state_manager.py
      test_rule_engine.py
      test_validator.py
    integration/
      test_dispatcher_to_state.py
      test_engine_full.py
    fixtures/
      sample_syslog.log      # Logs SSH, Samba, Apache synthétiques
      sample_filterlog.log   # Logs OPNsense filterlog synthétiques
      sample_windows.log     # Logs NXLog/Sysmon synthétiques
  config.yaml
  requirements.txt
  engine.db                  # Généré au runtime — NON versionné (.gitignore)
```

---

## 4. Modules

### 4.1 main.py

Point d'entrée du moteur. Responsabilités strictement limitées à
l'orchestration — aucune logique métier ici.

**Ordre d'instanciation obligatoire** (les dépendances vont dans ce sens) :

```
StateManager → RuleEngine(state_manager) → YaraScanner
→ Alerter → Dispatcher(parsers, validator, state_manager)
→ Reader(dispatcher, config)
```

**Responsabilités** :
- Charger `config.yaml` et valider son existence
- Vérifier l'existence de `/var/log/remote/` avant de démarrer
- Lancer les threads : watcher (Reader), consommateur de queue (Dispatcher),
  purge périodique
- Intercepter `SIGTERM` et `KeyboardInterrupt` pour un arrêt propre
  (vider la queue, fermer la connexion SQLite)
- Appeler `state_manager.purge_old_events()` et
  `state_manager.expire_contexts()` toutes les heures via un thread daemon

**Concept clé — Injection de dépendance** : `StateManager` est instancié
une seule fois dans `main.py` et passé en paramètre à `Dispatcher` et
`RuleEngine`. Aucun module n'instancie `StateManager` lui-même. Cela
permet de passer une base `:memory:` dans les tests sans modifier le code.

**Bibliothèques** : `threading`, `signal`, `logging`, `pathlib`, `yaml`

---

### 4.2 reader.py

Surveille `/var/log/remote/` via `watchdog` (inotify sous Linux). Produit
un flux d'événements vers la queue commune.

**Mécanisme** : un `FileSystemEventHandler` par fichier source surveille
les événements `on_modified`. À chaque modification, le handler lit les
nouvelles lignes depuis la dernière position connue (pointeur de fichier
maintenu par instance) et pousse chaque ligne dans la queue sous la forme
d'un tuple `(ligne: str, nom_fichier: str)`.

**Gestion du pointeur de fichier** : chaque handler maintient un `dict`
`{chemin: position}`. À chaque `on_modified`, il ouvre le fichier, se
positionne à la dernière position connue via `f.seek(position)`, lit les
nouvelles lignes, et met à jour la position. Cela évite de relire tout le
fichier à chaque modification.

**Politique de dépassement de queue** : la queue a une taille maximale
de `config.queue.maxsize` (défaut 10 000). Si la queue est pleine,
`put_nowait()` lève `queue.Full` — le handler loggue l'anomalie et rejette
la ligne. Cette politique est documentée comme limite explicite du système
(voir H-E3).

**Bibliothèques** : `watchdog`, `queue`, `threading`

---

### 4.3 dispatcher.py + validator.py

Le Dispatcher consomme la queue dans un thread dédié. Il est le
**gardien du contrat de données** — le StateManager ne reçoit jamais
un événement mal formé.

**Séquence de traitement pour chaque tuple** :

```
1. Extraire (ligne, nom_fichier)
2. Consulter config.sources[nom_fichier] → type de parser
3. Appeler parser.parse(ligne) → dict | None
4. Si None : ligne ignorée silencieusement (log debug si debug=True)
5. Si dict : appeler EventValidator.validate(event)
6. Si invalide : log WARNING + rejet
7. Si valide : state_manager.store_event(event)
8. Passer event au rule_engine.process_event(event)
9. Si alertes retournées : les passer à alerter.send()
```

**Concept clé — Principe de responsabilité unique (SRP)** : le Dispatcher
fait du routing et de la coordination. La validation est déléguée à
`EventValidator`. Le parsing est délégué aux parsers. Le Dispatcher ne
contient aucune logique de parsing ni de validation inline.

**EventValidator** (dans `validator.py`) : encapsule `jsonschema.validate()`
contre le schéma de l'événement normalisé défini dans `config.yaml`. Expose
une seule méthode publique `validate(event: dict) -> bool`.

**Bibliothèques** : `jsonschema`, `yaml`, `logging`

---

### 4.4 parsers/

#### BaseParser — contrat abstrait

```python
# parsers/base_parser.py
from abc import ABC, abstractmethod

class BaseParser(ABC):
    """
    Contrat commun à tous les parsers.
    Tout parser doit implémenter parse() et retourner
    un dict conforme au schéma normalisé, ou None.
    """

    @abstractmethod
    def parse(self, line: str) -> dict | None:
        """
        Parse une ligne de log brute.
        Retourne un dict normalisé ou None si la ligne
        ne correspond à aucun pattern connu.
        """
        ...
```

**Concept clé — Principe de substitution de Liskov (LSP)** : le Dispatcher
ne connaît que `BaseParser`. Il appelle `parser.parse(line)` sans savoir
quel parser concret est derrière. N'importe quel parser peut remplacer un
autre du point de vue du Dispatcher.

**Concept clé — Classe abstraite (ABC)** : si un parser hérite de
`BaseParser` sans implémenter `parse()`, Python lève `TypeError` à
l'instanciation. C'est un contrat enforced à l'exécution.

#### Schéma de sortie garanti (tous parsers)

```python
{
    "timestamp":   int,        # Unix millisecondes — OBLIGATOIRE
    "source_host": str,        # Hostname de la machine émettrice — OBLIGATOIRE
    "event_type":  str,        # Taxonomie fermée ci-dessous — OBLIGATOIRE
    "actor_ip":    str | None, # IP de l'entité qui agit
    "actor_user":  str | None, # Utilisateur qui agit
    "target_host": str | None, # Machine ciblée si différente de source_host
    "target_port": int | None, # Port ciblé — réseau uniquement
    "extra":       dict | None,# Champs spécifiques à la source (sérialisé JSON)
    "raw_log":     str,        # Ligne brute originale — OBLIGATOIRE
}
```

**Convention stricte** : les champs absents valent `None`, jamais `""`.
Une chaîne vide provoque des bugs silencieux dans les comparaisons du
RuleEngine (`if event["actor_user"]` est `True` pour `""` mais `False`
pour `None`).

#### Taxonomie fermée des event_type

| event_type | Source | Événement réel |
|---|---|---|
| `ssh_failure` | Debian | Échec authentification SSH (`sshd`) |
| `logon_success` | Debian / Windows | Connexion réussie |
| `samba_read` | Debian | Accès lecture partage SMB (`smbd`) |
| `smb_failure` | Debian | Échec authentification SMB (`smbd`) |
| `http_request` | Debian | Requête Apache/Dolibarr |
| `net_scan` | OPNsense | Scan réseau détecté dans filterlog |
| `firewall_block` | OPNsense | Paquet bloqué par règle pare-feu |
| `file_create` | Windows | Création fichier — Sysmon EventID 11 |
| `process_exec` | Windows | Exécution processus — Sysmon EventID 1 |
| `net_connect` | Windows | Connexion réseau sortante — Sysmon EventID 3 |
| `logon_failure` | Windows | Échec logon — Windows EventID 4625 |

#### Principes communs aux trois parsers

**Compilation des regex à l'initialisation** : toutes les regex sont
compilées dans `__init__()` via `re.compile()` et stockées comme attributs
d'instance. Elles ne sont jamais recompilées dans `parse()`. Sur des
milliers de lignes par minute, la différence de performance est mesurable.

```python
# CORRECT
class SyslogParser(BaseParser):
    def __init__(self):
        self.RE_SSH_FAIL = re.compile(
            r'Failed password for (\S+) from ([\d.]+) port (\d+)'
        )

    def parse(self, line: str) -> dict | None:
        m = self.RE_SSH_FAIL.search(line)  # regex déjà compilée
```

**Flag debug** : un paramètre `debug: bool = False` à l'init. Si `True`,
les lignes non reconnues sont loggées en DEBUG. En production, le silence
est le comportement correct — toutes les lignes non pertinentes (cron,
kernel, NTP) doivent être ignorées sans bruit.

**Fonction utilitaire partagée `parse_timestamp()`** : une seule implémentation
dans `parsers/base_parser.py` qui convertit n'importe quel format de
timestamp (ISO 8601, syslog BSD, format NXLog) en Unix millisecondes.
Les trois parsers l'appellent — zéro duplication.

#### syslog_parser.py

Traite les logs RFC 5424 depuis `debian.log`. Dispatch interne par champ
`program` extrait de l'enveloppe syslog.

Structure interne :
```
parse(line)
  → _parse_envelope(line) → (timestamp, host, program, message)
  → if program == "sshd"    : _parse_sshd(message)
  → if program == "smbd"    : _parse_smbd(message)
  → if program == "nmbd"    : return None  (ignoré)
  → if program == "apache2" : _parse_apache(message)
  → else                    : return None
```

#### filterlog_parser.py

Traite le format filterlog BSD d'OPNsense. Format CSV positionnel — les
positions des champs varient selon le protocole (TCP/UDP/ICMP) et la
version IP (v4/v6). Validation du nombre de champs avant extraction pour
éviter les `IndexError`.

Exemple de ligne filterlog :
```
filterlog[56373]: 76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,
60,10.0.1.50,10.0.1.20,54321,22,0
```

Champs extraits : interface, action (block/pass), protocole, IP source,
IP destination, port destination.

#### windows_parser.py

Deux couches de parsing :
1. Déshabillage de l'enveloppe syslog NXLog (identique à syslog_parser)
2. Parsing du contenu XML intérieur via `xml.etree.ElementTree`

Dispatch sur `EventID` :
```
EventID 4624 → logon_success
EventID 4625 → logon_failure
EventID 1    → process_exec  (Sysmon)
EventID 3    → net_connect   (Sysmon)
EventID 11   → file_create   (Sysmon)
autres       → return None
```

Les champs spécifiques Windows (hash de processus, chemin exécutable,
Logon Type, Logon ID) sont placés dans `extra` sous forme de dict.

**Bibliothèques parsers** : `re`, `datetime`, `xml.etree.ElementTree`

---

### 4.5 state_manager.py

Interface unique avec SQLite. Instancié une seule fois dans `main.py`
et passé par injection de dépendance.

**Initialisation** : `_init_db()` appelé dans `__init__()`. Crée le
fichier `.db` et les deux tables si elles n'existent pas
(`CREATE TABLE IF NOT EXISTS`). SQLite crée le fichier automatiquement
à la première connexion — aucune intervention manuelle nécessaire.

**Pragmas SQLite activés à l'init** :
```sql
PRAGMA journal_mode=WAL;      -- lectures concurrentes pendant les écritures
PRAGMA synchronous=NORMAL;    -- performance sans risque de corruption
PRAGMA busy_timeout=5000;     -- attend 5s si la base est verrouillée
```

**Concept clé — WAL (Write-Ahead Logging)** : sans WAL, une écriture
pose un verrou exclusif et bloque toutes les lectures simultanées.
Avec WAL, le Dispatcher peut écrire (store_event) pendant que le
RuleEngine lit (count_events) sans blocage mutuel.

**Concurrence** : `sqlite3.connect(db_path, check_same_thread=False)` +
`threading.Lock()` sur les méthodes d'écriture uniquement. Les lectures
sont libres — WAL garantit leur cohérence.

#### Table `events`

```sql
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,
    source_host TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    actor_ip    TEXT,
    actor_user  TEXT,
    target_host TEXT,
    target_port INTEGER,
    extra       TEXT,        -- dict Python sérialisé en JSON string
    raw_log     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts
    ON events(timestamp);

CREATE INDEX IF NOT EXISTS idx_events_type_ip
    ON events(event_type, actor_ip);
```

L'index composite `(event_type, actor_ip)` est critique — c'est la
requête la plus fréquente du RuleEngine :
`WHERE event_type = ? AND actor_ip = ? AND timestamp > ?`

#### Table `contexts`

```sql
CREATE TABLE IF NOT EXISTS contexts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id    TEXT    NOT NULL,
    actor_ip   TEXT    NOT NULL,
    state      TEXT    NOT NULL,  -- 'pending' | 'escalated' | 'expired'
    step       INTEGER DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    extra      TEXT               -- données accumulées par la règle (JSON)
);

CREATE INDEX IF NOT EXISTS idx_contexts_rule_ip
    ON contexts(rule_id, actor_ip);
```

Un contexte représente : "la règle `SSH_BRUTEFORCE_001` suit l'IP
`10.0.1.50` depuis `first_seen`, elle en est à l'étape `step`,
la fenêtre expire à `first_seen + window_seconds`."

#### Méthodes publiques

| Méthode | Signature | Retour | Appelé par |
|---|---|---|---|
| `store_event` | `(event: dict) → int` | id inséré | Dispatcher |
| `count_events` | `(type, ip, window_s) → int` | nombre | RuleEngine |
| `get_events` | `(type, ip, window_s) → list[dict]` | événements | RuleEngine (alert.json) |
| `get_context` | `(rule_id, ip) → dict\|None` | contexte actif | RuleEngine |
| `set_context` | `(rule_id, ip, step, extra) → None` | — | RuleEngine |
| `expire_contexts` | `() → None` | — | main.py (horaire) |
| `purge_old_events` | `(older_than_s: int) → None` | — | main.py (horaire) |

**Bibliothèques** : `sqlite3`, `json`, `time`, `threading`

---

### 4.6 rule_engine.py

Reçoit chaque événement normalisé du Dispatcher et l'évalue contre toutes
les règles YAML chargées en mémoire à l'initialisation.

**Méthode publique unique** :
```python
def process_event(self, event: dict) -> list[dict] | None:
    """
    Évalue l'événement contre toutes les règles.
    Retourne une liste d'alertes déclenchées, ou None.
    Une liste est retournée car un événement peut déclencher
    plusieurs règles simultanément.
    """
```

**Chargement des règles** : à l'init, le RuleEngine parcourt `rules/*.yaml`
et charge toutes les règles en mémoire. Les règles sont relues uniquement
au redémarrage du moteur — pas de hot-reload (documenté comme limite).

#### Type 1 — Règle à seuil simple

```yaml
rule_id: SSH_BRUTEFORCE_001
description: "Brute-force SSH détecté"
severity: CRITICAL
mitre_tactic: "TA0006"
mitre_technique: "T1110"
source_host_pattern: "debian*"

trigger:
  event_type: ssh_failure
  threshold: 10
  window_seconds: 60
  group_by: actor_ip

response:
  alert: true
```

**Logique d'évaluation** :
1. `event["event_type"] == trigger.event_type` ?
2. `fnmatch(event["source_host"], source_host_pattern)` ?
3. `state_manager.count_events(type, actor_ip, window_s) >= threshold` ?
4. Si tout vrai → générer alerte

#### Type 2 — Règle à étapes séquentielles

```yaml
rule_id: MALICIOUS_FILE_EXEC_001
description: "Fichier malveillant déposé et exécuté"
severity: CRITICAL
mitre_tactic: "TA0002"
mitre_technique: "T1204"

steps:
  - step: 1
    event_type: file_create
    source_host_pattern: "DESKTOP*"
    check_yara: true
    yara_match_required: false

  - step: 2
    event_type: process_exec
    source_host_pattern: "DESKTOP*"
    window_seconds: 14400    # 4 heures entre step 1 et step 2
    match_on: actor_user     # même utilisateur que step 1

response:
  alert: true
```

**Logique d'évaluation** :
1. Aucun contexte existant pour `(rule_id, actor_ip)` → attendre step 1
2. Contexte au step N → l'événement courant correspond au step N+1 ?
3. `last_seen + window_seconds > now` (dans la fenêtre) ?
4. `match_on` respecté (même actor_user, même actor_ip) ?
5. `check_yara: true` → appeler `yara_scanner.scan(file_path)`
6. Toutes les étapes franchies → générer alerte et marquer contexte
   `escalated`

**Bibliothèques** : `pyyaml`, `fnmatch`, `time`, `uuid`

---

### 4.7 yara_scanner.py

Appelé par le RuleEngine uniquement sur `event_type == file_create` quand
la règle YAML spécifie `check_yara: true`. N'est jamais dans le flux
principal — c'est une couche d'enrichissement conditionnelle.

**Méthode publique** :
```python
def scan(self, file_path: str) -> dict | None:
    """
    Scanne file_path contre les règles YARA chargées.
    Retourne un dict {rule_name, file_path, file_hash, ruleset}
    si match, None sinon.
    Si le fichier est inaccessible ou supprimé → return None silencieux.
    """
```

**Chargement des règles** : à l'init, compilation de toutes les règles
`rules/yara/*.yar` en un objet `yara.Rules` via `yara.compile()`. Les
règles compilées sont gardées en mémoire — pas de recompilation à chaque
scan.

**Calcul du hash** : `hashlib.md5(file_bytes).hexdigest()` calculé avant
le scan YARA, inclus dans le résultat pour enrichir `alert.json`.

**Si `yara_match_required: false`** : le RuleEngine génère l'alerte même
si YARA retourne `None` (fichier supprimé, accès refusé). YARA enrichit,
il ne bloque pas.

**Accès aux fichiers Windows** : les fichiers créés sur le poste Windows
(`C:\Users\...\payload.exe`) ne sont pas directement accessibles depuis
le SOC Linux. Le scan YARA sur fichiers Windows n'est réalisable que si
le partage Samba est monté sur le SOC. Documenté comme limite H-E4 —
en pratique YARA scanne les fichiers déposés sur les partages Debian.

**Bibliothèques** : `yara-python`, `hashlib`, `pathlib`

---

### 4.8 alerter.py

Reçoit les alertes confirmées du RuleEngine. Responsabilité unique :
publier selon la sévérité.

**WARNING** → écriture dans `alerts.log` via `logging`.

**CRITICAL** → écriture dans `alerts.log` + écriture atomique du fichier
`alert_<uuid>.json` dans `/var/log/nyxsoc/alerts/`.

**Écriture atomique — mécanisme** :
```python
import tempfile, os, pathlib, json

def _write_alert_file(self, alert: dict) -> None:
    target = self.alerts_dir / f"alert_{alert['alert_id']}.json"
    # 1. Écrire dans un fichier temporaire dans le même répertoire
    with tempfile.NamedTemporaryFile(
        mode='w', dir=self.alerts_dir,
        delete=False, suffix='.tmp'
    ) as f:
        json.dump(alert, f, indent=2, ensure_ascii=False)
        tmp_path = f.name
    # 2. Rename atomique — le SOAR ne voit jamais un fichier à moitié écrit
    os.rename(tmp_path, target)
```

`os.rename()` est atomique sur Linux (même système de fichiers). Le watcher
du SOAR ne voit jamais un fichier partiel — il voit soit le fichier complet,
soit rien.

**Création du répertoire** :
```python
pathlib.Path(alerts_dir).mkdir(parents=True, exist_ok=True)
```
Appelé à l'init — crée `/var/log/nyxsoc/alerts/` si absent.

**Bibliothèques** : `json`, `logging`, `tempfile`, `os`, `pathlib`, `uuid`

---

## 5. Format alert.json

Défini conjointement avec le module SOAR (GAHOUNZO Komlan Honoré).
Schéma JSON Schema versionné dans `docs/alert-schema.json`.

```json
{
  "alert_id":        "uuid-v4",
  "timestamp":       1750000000000,
  "rule_id":         "SSH_BRUTEFORCE_001",
  "severity":        "CRITICAL",
  "attacker_ip":     "10.0.1.50",
  "target_host":     "debian-server",
  "target_ip":       "10.0.1.20",
  "mitre_tactic":    "TA0006",
  "mitre_technique": "T1110",
  "events": {
    "count": 15,
    "details": [
      {
        "timestamp":   1749999940000,
        "event_type":  "ssh_failure",
        "source_host": "debian-server",
        "actor_user":  "root",
        "raw_log":     "Failed password for root from 10.0.1.50 port 51022..."
      }
    ]
  },
  "yara_match": null
}
```

**Règle de troncature des events.details** :
- `count <= 5` : tous les événements dans `details`
- `count > 5` : 2 premiers + 2 derniers (suffisant pour S1/S2 répétitifs,
  sans rien perdre pour S3 kill-chain à 3 étapes)

**Champ `soar_action` absent** : la décision de réponse appartient au
module SOAR via son `playbook.py`. Le moteur produit des faits, pas des
ordres.

---

## 6. config.yaml

```yaml
# Mapping nom de fichier source → type de parser
# Ajouter une source = ajouter une ligne ici, zéro modification du code
sources:
  "debian.log":              "syslog"
  "OPNsense.internal.log":   "filterlog"
  "DESKTOP-PME.log":         "windows"

# Rétention des données SQLite
retention:
  events_hours: 24
  context_cleanup_interval_seconds: 3600

# Queue en mémoire reader → dispatcher
queue:
  maxsize: 10000

# Chemins filesystem
log_dir:    "/var/log/remote"
db_path:    "engine/engine.db"
alerts_dir: "/var/log/nyxsoc/alerts"
alerts_log: "/var/log/nyxsoc/engine.log"

# Canal de communication vers le module SOAR
soar:
  channel: "file"               # écriture atomique fichier JSON
  alerts_dir: "/var/log/nyxsoc/alerts"
```

---

## 7. Tests

### Philosophie

Chaque classe est testable isolément grâce à l'injection de dépendance.
`StateManager` accepte `:memory:` comme `db_path` pour les tests unitaires
et d'intégration — aucune écriture disque, isolation totale entre tests.

### Unitaires — `tests/unit/`

Un fichier de test par module. Chaque test vérifie une seule responsabilité.

```python
# Exemple — test_syslog_parser.py
def test_ssh_failure_extracts_actor_ip():
    parser = SyslogParser()
    line = "2026-06-19T10:23:41+00:00 debian sshd[1234]: " \
           "Failed password for root from 10.0.1.50 port 52341 ssh2"
    event = parser.parse(line)
    assert event is not None
    assert event["event_type"] == "ssh_failure"
    assert event["actor_ip"]   == "10.0.1.50"
    assert event["actor_user"] == "root"
    assert event["raw_log"]    == line

def test_unknown_line_returns_none():
    parser = SyslogParser()
    assert parser.parse("Jun 19 10:23:41 debian cron[1234]: job started") is None

def test_actor_user_missing_is_none_not_empty():
    parser = SyslogParser()
    line = "2026-06-19T10:23:41+00:00 debian sshd[1234]: " \
           "Invalid user  from 10.0.1.50 port 52341"
    event = parser.parse(line)
    assert event["actor_user"] is None  # jamais ""
```

### Intégration — `tests/integration/`

`test_engine_full.py` : injecte des logs depuis `tests/fixtures/` dans le
pipeline complet (reader → dispatcher → state_manager → rule_engine) et
vérifie que les alertes produites correspondent aux alertes attendues.

Base SQLite `:memory:` utilisée pour l'isolation.

### Bout en bout — `datasets/eval/`

Le moteur complet tourne contre les 30% de logs réels isolés en semaine 3.
Les alertes produites sont comparées aux annotations du dataset labellisé.
Métriques calculées : TPR, FPR, latence de détection (timestamp alerte −
timestamp premier événement de la chaîne).

### Commandes

```bash
cd engine/

# Tests unitaires seuls
pytest tests/unit/ -v

# Tests d'intégration
pytest tests/integration/ -v

# Tout avec couverture
pytest --cov=. --cov-report=term-missing tests/

# Lint
flake8 . --max-line-length=100 --exclude=tests/
```

---

## 8. Permissions et accès filesystem

### `/var/log/remote/` (lecture)

Créé par rsyslog (tourne sous `syslog:adm`). Le moteur tourne sous
l'utilisateur `nyxsoc`. Solution :

```bash
sudo usermod -aG adm nyxsoc
sudo chmod 750 /var/log/remote/
sudo chown syslog:adm /var/log/remote/
```

### `/var/log/nyxsoc/alerts/` (écriture)

Créé par `alerter.py` à l'init via `pathlib.Path.mkdir()`. L'utilisateur
`nyxsoc` en est propriétaire — aucun problème d'écriture.

```bash
sudo mkdir -p /var/log/nyxsoc/
sudo chown nyxsoc:nyxsoc /var/log/nyxsoc/
```

---

## 9. Hypothèses et limites documentées

| Réf. | Hypothèse | Impact | Mitigation |
|---|---|---|---|
| H-E1 | Ordre temporel approximatif — traitement dans l'ordre d'arrivée queue, pas ordre timestamps | Décalage 1-2s possible entre sources | Fenêtres de corrélation ≥ 60s — négligeable |
| H-E2 | Pas de pivoting inter-IP — corrélation indexée par actor_ip | Attaquant changeant d'IP = deux contextes distincts | Documenté comme limite, perspective d'extension |
| H-E3 | Queue en mémoire — perte possible en cas de crash | Événements en queue non traités perdus | Événements déjà en SQLite préservés |
| H-E4 | YARA sur fichiers accessibles SOC uniquement | Fichiers Windows non directement accessibles | YARA scanne les fichiers sur partages Samba montés |
| H-E5 | Pas de hot-reload des règles YAML | Modification règle = redémarrage moteur | Acceptable pour un lab de 10 semaines |

---

## 10. Décisions architecturales

| Réf. | Décision | Alternative écartée | Justification |
|---|---|---|---|
| E-D1 | SQLite WAL | Redis | Local, sans serveur, un seul fichier, suffisant pour le volume du lab |
| E-D2 | Queue Python en mémoire | Kafka, RabbitMQ | Volume max ~centaines d'événements/min — middleware hors scope |
| E-D3 | Injection de dépendance | Singleton | Injection depuis main.py suffit — testabilité maximale (`:memory:`) |
| E-D4 | Règles YAML custom | Sigma complet | Sigma complet hors scope — format custom inspiré de Sigma |
| E-D5 | check_same_thread=False + Lock | Une connexion par thread | Simple et suffisant — lock uniquement sur les écritures |
| E-D6 | YARA uniquement sur SOC | Agent YARA sur chaque VM | Pas d'agent distant — accès via partage monté |
| E-D7 | Écriture atomique fichier JSON | HTTP POST, socket | Pas de dépendance réseau inter-modules — découplage total |
| E-D8 | BaseParser ABC | Duck typing | Contrat enforced à l'instanciation — erreur explicite si parse() absent |
| E-D9 | soar_action absent de alert.json | soar_action dicté par moteur | Décision de réponse = responsabilité SOAR, pas du moteur |

---

## 11. Ordre d'implémentation

```
Étape 1  — rules/*.yaml            Écrire les 3 règles finales AVANT de coder le RuleEngine
Étape 2  — parsers/base_parser.py  BaseParser ABC + parse_timestamp() utilitaire
Étape 3  — syslog_parser.py        + tests/unit/test_syslog_parser.py
Étape 4  — filterlog_parser.py     + tests/unit/test_filterlog_parser.py
Étape 5  — windows_parser.py       + tests/unit/test_windows_parser.py
Étape 6  — state_manager.py        + tests/unit/test_state_manager.py
Étape 7  — validator.py            + tests/unit/test_validator.py
Étape 8  — dispatcher.py           + tests/integration/test_dispatcher_to_state.py
Étape 9  — rule_engine.py          + tests/unit/test_rule_engine.py
Étape 10 — yara_scanner.py
Étape 11 — alerter.py
Étape 12 — main.py
Étape 13 — tests/integration/test_engine_full.py
```
