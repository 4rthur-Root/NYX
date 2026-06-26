# Engine — Moteur de corrélation NyxSOC

**Module** : Corrélation stateful multi-sources  
**Auteur** : KPODONOU Kossigan Gaël God-Love  
**Langage** : Python 3.12  
**Dépendances** : `pyyaml>=6.0`, `watchdog>=4.0`, `jsonschema>=4.0`, `pytest>=8.0`

---

## Vue d'ensemble

Le moteur de corrélation est le composant central de NyxSOC. Il ingère des
événements de sécurité issus de trois sources hétérogènes, les normalise en
un schéma JSON unifié, maintient un état persistant dans SQLite, évalue des
règles de détection YAML, et publie des alertes structurées vers le module
SOAR.

### Principe fondamental

Le moteur ne décide pas de la gravité d'un événement isolé. Il détecte des
**chaînes d'événements** — des séquences temporelles qui, prises ensemble,
constituent une attaque. Un seul échec SSH n'est pas une alerte. Quinze
échecs SSH depuis la même IP en 60 secondes suivis d'une connexion Samba
réussie — c'est une alerte.

---

## Architecture

![Architecture du module engine](engine.png)

---

## Structure des fichiers

```
engine/
  main.py              # Initialisation, orchestration, purge périodique
  reader.py            # Watchdog inotify, queue thread-safe commune
  dispatcher.py        # Routing parser, validation schéma JSON
  parsers/
    syslog_parser.py   # Logs Debian — SSH, Samba, Apache (RFC 5424)
    filterlog_parser.py# Logs OPNsense — filterlog BSD
    windows_parser.py  # Logs Windows — XML EventLog + Sysmon via NXLog
  state_manager.py     # SQLite — stockage événements et contextes
  rule_engine.py       # Évaluation règles YAML, corrélation stateful
  yara_scanner.py      # Scan fichiers via yara-python
  alerter.py           # Publication alertes WARNING et CRITICAL
  rules/
    ssh_bruteforce.yaml
    smb_exfil.yaml
    malicious_file.yaml
    yara/
      malware_generic.yar
  tests/
    unit/
      test_syslog_parser.py
      test_filterlog_parser.py
      test_windows_parser.py
      test_state_manager.py
      test_rule_engine.py
    integration/
      test_dispatcher_to_state.py
      test_engine_full.py
    fixtures/
      sample_syslog.log
      sample_filterlog.log
      sample_windows.log
  config.yaml
  requirements.txt
  engine.db            # Généré au runtime — non versionné
```

---

## Modules

### main.py

Point d'entrée du moteur. Responsabilités :

- Vérifier l'existence de `/var/log/remote/` et des fichiers sources
- Instancier les composants dans l'ordre : `StateManager` → `RuleEngine` →
  `Alerter` → `Dispatcher` → `Reader`
- Lancer les threads : watcher, consommateur de queue, purge périodique
- Gérer l'arrêt propre sur `SIGTERM` / `KeyboardInterrupt`

La purge périodique appelle `state_manager.purge_old_events()` et
`state_manager.expire_contexts()` toutes les heures.

**Bibliothèques** : `threading`, `signal`, `logging`, `pathlib`

---

### reader.py

Surveille `/var/log/remote/` via `watchdog` (inotify). Un handler par
fichier source. Chaque nouvelle ligne détectée est poussée dans une
`queue.Queue` commune sous la forme d'un tuple `(ligne, nom_fichier)`.

La queue a une taille maximale de 10 000 éléments. En cas de dépassement,
les nouvelles lignes sont rejetées et l'anomalie est loggée — politique
explicite documentée comme limite du système.

**Bibliothèques** : `watchdog`, `queue`, `threading`

---

### dispatcher.py

Reçoit les tuples `(ligne, nom_fichier)` de la queue. Responsabilités :

1. Consulte `config.yaml` pour router vers le parser correct selon le nom
   du fichier source
2. Appelle `parser.parse(ligne)` — reçoit `dict | None`
3. Si `None` : ligne ignorée silencieusement
4. Si `dict` : valide le schéma via `jsonschema` contre le schéma défini
   dans `config.yaml`
5. Si schéma invalide : log de l'anomalie, rejet
6. Si schéma valide : transmet à `StateManager.store_event()`

Le Dispatcher est le **gardien du contrat de données**. Le StateManager ne
reçoit jamais un dict mal formé.

**Bibliothèques** : `jsonschema`, `yaml`, `logging`

---

### parsers/

Trois parsers distincts. Contrat commun :

**Méthode publique unique** :
```python
def parse(self, line: str) -> dict | None
```

**Schéma de sortie garanti** :
```json
{
  "timestamp":   "int    — Unix ms, obligatoire",
  "source_host": "str    — hostname émetteur, obligatoire",
  "event_type":  "str    — taxonomie fermée, obligatoire",
  "actor_ip":    "str | null",
  "actor_user":  "str | null",
  "target_host": "str | null",
  "target_port": "int | null",
  "extra":       "dict | null — champs spécifiques à la source",
  "raw_log":     "str    — ligne brute originale, obligatoire"
}
```

**Taxonomie fermée des event_type** :

| event_type | Source | Description |
|---|---|---|
| `ssh_failure` | Debian | Échec authentification SSH |
| `logon_success` | Debian / Windows | Connexion réussie |
| `samba_read` | Debian | Accès lecture partage SMB |
| `smb_failure` | Debian | Échec authentification SMB |
| `http_request` | Debian | Requête Apache/Dolibarr |
| `net_scan` | OPNsense | Scan réseau détecté |
| `firewall_block` | OPNsense | Paquet bloqué par règle |
| `file_create` | Windows | Création fichier (Sysmon 11) |
| `process_exec` | Windows | Exécution processus (Sysmon 1) |
| `net_connect` | Windows | Connexion réseau (Sysmon 3) |
| `logon_failure` | Windows | Échec logon (EventID 4625) |

**Principes communs aux trois parsers** :

- Les regex sont compilées à l'initialisation, pas à chaque appel
- Les champs absents valent `None`, jamais une chaîne vide
- Un flag `debug=True` à l'init loggue les lignes non reconnues
- Aucune décision de criticité — extraction pure

**syslog_parser.py** — dispatch interne par champ `program` :
`_parse_sshd()`, `_parse_smbd()`, `_parse_apache()`

**filterlog_parser.py** — format CSV positionnel. Les positions des champs
varient selon le protocole (TCP/UDP/ICMP) et la version IP (v4/v6).
Validation du nombre de champs avant extraction.

**windows_parser.py** — deux couches : déshabillage enveloppe syslog NXLog,
puis parsing XML intérieur via `xml.etree.ElementTree`. Dispatch sur
`EventID`.

**Bibliothèques** : `re`, `datetime`, `xml.etree.ElementTree`

---

### state_manager.py

Interface unique avec SQLite. Instancié une fois dans `main.py` et passé
par injection de dépendance à `Dispatcher` et `RuleEngine`.

**Concurrence** : `check_same_thread=False` avec `threading.Lock` sur les
méthodes d'écriture. Les lectures sont libres. WAL activé à l'init.

**Pragmas SQLite à l'initialisation** :
```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;
```

#### Table `events`

```sql
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,
    source_host TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    actor_ip    TEXT,
    actor_user  TEXT,
    target_host TEXT,
    target_port INTEGER,
    extra       TEXT,
    raw_log     TEXT    NOT NULL
);

CREATE INDEX idx_events_ts      ON events(timestamp);
CREATE INDEX idx_events_type_ip ON events(event_type, actor_ip);
```

#### Table `contexts`

```sql
CREATE TABLE contexts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id    TEXT    NOT NULL,
    actor_ip   TEXT    NOT NULL,
    state      TEXT    NOT NULL,  -- 'pending' | 'escalated' | 'expired'
    step       INTEGER DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    extra      TEXT
);

CREATE INDEX idx_contexts_rule_ip ON contexts(rule_id, actor_ip);
```

#### Méthodes publiques

| Méthode | Entrée | Sortie | Usage |
|---|---|---|---|
| `store_event(event)` | dict normalisé | int (id) | Appelé par Dispatcher |
| `count_events(type, ip, window_s)` | str, str, int | int | RuleEngine — règles seuil |
| `get_events(type, ip, window_s)` | str, str, int | list[dict] | RuleEngine — contenu alert.json |
| `get_context(rule_id, ip)` | str, str | dict\|None | RuleEngine — règles séquentielles |
| `set_context(rule_id, ip, step, extra)` | str, str, int, dict | None | RuleEngine — mise à jour état |
| `expire_contexts()` | — | None | main.py — nettoyage périodique |
| `purge_old_events(older_than_s)` | int | None | main.py — rétention 24h |

**Rétention** : événements purgés après 24 heures. Contextes expirés selon
la fenêtre de leur règle.

**Bibliothèques** : `sqlite3`, `json`, `time`, `threading`

---

### rule_engine.py

Reçoit chaque événement normalisé du Dispatcher. Évalue toutes les règles
YAML chargées en mémoire.

**Méthode publique unique** :
```python
def process_event(self, event: dict) -> list[dict] | None
```

Retourne une liste d'alertes car un événement peut déclencher plusieurs
règles simultanément.

#### Deux types de règles

**Type 1 — Seuil simple** (comptage sur fenêtre temporelle) :

```yaml
rule_id: SSH_BRUTEFORCE_001
description: "Brute-force SSH détecté"
severity: CRITICAL
source_host_pattern: "debian*"

trigger:
  event_type: ssh_failure
  threshold: 10
  window_seconds: 60
  group_by: actor_ip

response:
  alert: true
  soar_action: block_ip
```

**Type 2 — Étapes séquentielles** (chaîne d'attaque) :

```yaml
rule_id: MALICIOUS_FILE_EXEC_001
description: "Fichier malveillant déposé et exécuté"
severity: CRITICAL

steps:
  - step: 1
    event_type: file_create
    source_host_pattern: "DESKTOP*"
    check_yara: true
    yara_match_required: false

  - step: 2
    event_type: process_exec
    source_host_pattern: "DESKTOP*"
    window_seconds: 14400
    match_on: actor_user

response:
  alert: true
  soar_action: block_ip_and_isolate
```

**Logique d'évaluation Type 1** :
1. L'événement courant correspond au `trigger.event_type` ?
2. `StateManager.count_events()` dépasse le seuil sur la fenêtre ?
3. Oui → génère alerte

**Logique d'évaluation Type 2** :
1. Aucun contexte existant → attendre step 1
2. Contexte au step N → l'événement courant correspond au step N+1 ?
3. Dans la fenêtre temporelle du step ?
4. `match_on` respecté (même utilisateur, même IP) ?
5. Toutes les étapes franchies → génère alerte

**Bibliothèques** : `pyyaml`, `fnmatch`, `time`

---

### yara_scanner.py

Appelé par `RuleEngine` uniquement sur `event_type == file_create` quand
la règle YAML spécifie `check_yara: true`.

**Méthode publique** :
```python
def scan(self, file_path: str) -> dict | None
```

Retourne un dict avec `rule_name`, `file_path`, `file_hash`, `ruleset` si
match. Retourne `None` si aucun match ou si le fichier est inaccessible.

Si le fichier a été supprimé avant le scan — `return None` silencieux.
L'alerte est quand même générée si `yara_match_required: false`.

**Règles YARA** stockées dans `rules/yara/`. Source communautaire :
`neo23x0/signature-base`.

**Bibliothèques** : `yara-python`, `hashlib`

---

### alerter.py

Reçoit les alertes confirmées du RuleEngine. Publie selon la sévérité.

**WARNING** → écriture dans `alerts.log` uniquement.

**CRITICAL** → écriture dans `alerts.log` + sérialisation `alert.json` +
envoi au module SOAR.

Le canal de transmission vers le SOAR (HTTP POST, socket, fichier partagé)
est défini dans `config.yaml` et finalisé avec le module SOAR.

**Bibliothèques** : `json`, `logging`, `requests` (conditionnel)

---

## config.yaml

```yaml
sources:
  "debian.log":              "syslog"
  "OPNsense.internal.log":   "filterlog"
  "DESKTOP-PME.log":         "windows"

retention:
  events_hours: 24
  context_cleanup_interval_seconds: 3600

queue:
  maxsize: 10000

log_dir: "/var/log/remote"
db_path: "engine.db"
alerts_log: "alerts.log"

soar:
  channel: "http"
  endpoint: "http://10.0.1.10:8080/alert"
  timeout_seconds: 5
```

---

## Contrat de données — alert.json

Format finalisé avec le module SOAR (GAHOUNZO Komlan Honoré).  
Référence : `docs/alert-schema.json`

Champs certains :

| Champ | Type | Description |
|---|---|---|
| `alert_id` | string (UUID) | Identifiant unique |
| `timestamp` | int (Unix ms) | Horodatage de l'alerte |
| `rule_id` | string | Règle déclenchée |
| `severity` | string | `WARNING` \| `CRITICAL` |
| `attacker_ip` | string | IP source de l'attaque |
| `target_host` | string | Machine ciblée |
| `events` | list[dict] | Événements constituant la preuve |
| `yara_match` | dict \| null | Résultat scan YARA si applicable |
| `soar_action` | string | Action proposée au SOAR |

---

## Tests

### Unitaires — `tests/unit/`

Chaque classe testée isolément avec données fictives.  
Base SQLite en mémoire (`:memory:`) pour `test_state_manager.py`.

### Intégration — `tests/integration/`

Deux modules ensemble. `test_engine_full.py` joue des logs pré-enregistrés
(`tests/fixtures/`) et vérifie les alertes produites.

### Bout en bout — `datasets/eval/`

Le moteur complet tourne contre les 30% de logs isolés en semaine 3.
Métriques calculées : TPR, FPR, latence de détection.

### Commande

```bash
cd engine/
pytest tests/unit/ -v
pytest tests/integration/ -v
pytest --cov=. tests/          # avec couverture
```

---

## Hypothèses et limites documentées

**H-E1 — Ordre temporel approximatif** : les événements sont traités dans
l'ordre d'arrivée dans la queue, pas strictement dans l'ordre des timestamps.
Un décalage de 1-2 secondes est possible entre sources. Négligeable pour des
fenêtres de corrélation ≥ 60 secondes.

**H-E2 — Pas de pivoting inter-IP** : la corrélation est indexée par
`actor_ip`. Un attaquant qui change d'IP en cours d'attaque génère deux
contextes distincts. Documenté comme limite, perspective d'extension.

**H-E3 — Queue en mémoire** : en cas de crash du processus, les événements
en queue non encore traités sont perdus. Les événements déjà écrits dans
SQLite sont préservés.

**H-E4 — YARA sur fichiers accessibles** : le scanner YARA nécessite un
accès au fichier sur le système de fichiers du SOC. Les fichiers sur les
partages Windows ou Samba doivent être montés ou accessibles via le réseau
au moment du scan.

---

## Décisions architecturales

| Réf. | Décision | Justification |
|---|---|---|
| E-D1 | SQLite WAL à la place de Redis | Local, sans serveur, un seul fichier, suffisant pour le volume du lab |
| E-D2 | Queue Python en mémoire | Volume max ~centaines d'événements/min — Kafka/RabbitMQ hors scope |
| E-D3 | Singleton écarté | Injection de dépendance depuis main.py suffit — pas de risque de double instanciation |
| E-D4 | Règles YAML custom (pas Sigma) | Sigma complet hors scope — format custom inspiré de Sigma, plus simple à implémenter |
| E-D5 | check_same_thread=False + Lock | Concurrence reader/RuleEngine sur SQLite — solution simple et suffisante |
| E-D6 | YARA uniquement sur SOC | yara-python installé uniquement sur le SOC — pas d'agent sur les VMs cibles |