# 🗂️ Planning de Développement — Module SOAR
**Branche : `soar`**
**Auteur : GAHOUNZO Komlan Honoré — Étudiant 2**
**Principe : je code, l'IA assiste**

---

## Philosophie du planning

Le développement suit la règle **"du noyau dur vers les couches externes"** :

```
Fondations (modèles + config)
      ↓
Entrée (watcher + parser)
      ↓
Cerveau (décision + règles)
      ↓
Bras (handlers + intégrations)
      ↓
Mémoire (DB + repositories)
      ↓
Visibilité (logs + notifications)
      ↓
Filet de sécurité (tests)
      ↓
Scripts utilitaires
```

Pourquoi cet ordre ? Chaque couche dépend de celle du dessous. Tu ne peux pas coder le `decision_engine` avant d'avoir le modèle `Alert` qui lui donne les données. Tu ne peux pas tester les handlers avant d'avoir `opnsense_client`. Chaque étape compile et tourne avant de passer à la suivante.

---

## Étape 0 — Mise en place de l'environnement (1 jour)

**Objectif :** avoir un environnement Python propre et reproductible.

### Tâches
- [ ] Créer le virtualenv Python 3.12
  ```bash
  python3.12 -m venv .venv
  source .venv/bin/activate
  ```
- [ ] Rédiger `requirements.txt` avec les dépendances minimales :
  ```
  watchdog>=4.0       # surveillance inotify du dossier d'alertes
  jsonschema>=4.0     # validation JSON contre le schéma de Gaël
  pyyaml>=6.0         # lecture config.yaml et whitelist
  requests>=2.31      # appels API AbuseIPDB + OPNsense
  python-dotenv>=1.0  # chargement .env
  pytest>=8.0         # tests unitaires
  pytest-mock>=3.0    # mocking des API externes
  ```
- [ ] Rédiger `.env.example` (jamais de vraies valeurs dedans)
- [ ] Vérifier que `data/`, `logs/`, `reports/` sont dans `.gitignore`
- [ ] Rédiger `config/config.yaml` squelette :
  ```yaml
  soar:
    severity_threshold: "CRITICAL"
    response_timeout_s: 5
    abuseipdb_score_threshold: 50
    rule_ttl_hours: 48
  paths:
    alerts_incoming: "../shared/alerts/incoming/"
    alert_schema: "../shared/schemas/alert_schema.json"
    fallback_list: "src/soar/cache/fallback_list.yaml"
  ```
- [ ] Commit : `chore: setup Python environment and base config`

---

## Étape 1 — Les modèles de données (1 jour)

**Objectif :** avoir des dataclasses typées pour `Alert`, `Decision`, `Response` — le vocabulaire commun de tout le module.

**Fichiers concernés :**
```
src/soar/models/
├── alert.py
├── decision.py
└── response.py
```

### Ordre dans les fichiers
1. `alert.py` en premier — tout le reste en dépend
2. `decision.py` — dépend d'`alert.py`
3. `response.py` — dépend de `decision.py`

### Ce à quoi penser
- Utiliser `@dataclass` ou `@dataclass(frozen=True)` pour `Alert` (immuable, elle vient de l'extérieur)
- `Decision` doit porter : `action`, `skip_reason` (si applicable), et l'`Alert` source
- `Response` doit porter tous les champs du `response-schema.json` qu'on a finalisé

### Commit attendu
```
feat(models): add Alert, Decision, Response dataclasses
```

---

## Étape 2 — Configuration et settings (0.5 jour)

**Objectif :** centraliser la lecture de toutes les variables d'environnement et de `config.yaml`.

**Fichiers concernés :**
```
config/settings.py
```

### Ce à quoi penser
- `settings.py` charge `.env` via `python-dotenv` au démarrage
- Toutes les clés API (`OPNSENSE_KEY`, `ABUSEIPDB_KEY`, etc.) sont lues depuis l'environnement, jamais hardcodées
- Ajouter une validation : si une variable obligatoire manque, lever une erreur explicite au démarrage (pas un `KeyError` mystérieux en cours d'exécution)
- Exposer un singleton `settings` importable depuis n'importe quel module

### Commit attendu
```
feat(config): add settings loader with env validation
```

---

## Étape 3 — Parser et validation du schéma (1 jour)

**Objectif :** valider chaque alerte entrante contre `alert_schema.json` et la désérialiser en dataclass `Alert`.

**Fichiers concernés :**
```
src/soar/parser/alert_parser.py
```

### Ce à quoi penser
- `jsonschema.validate()` contre le schéma de Gaël — si ça échoue, logguer l'erreur et ignorer l'alerte (ne jamais crasher le watcher)
- Si la validation passe, construire et retourner une dataclass `Alert`
- Cas particulier : `attacker_ip` peut être `null` → ton `Alert.attacker_ip` doit accepter `Optional[str]`
- Cas `events.details` tronqué (≤ 20 items) — vérifier que `count` ≥ `len(details)`

### Test immédiat à écrire
```
tests/unit/test_alert_parser.py
```
- Alerte valide S1 → retourne un objet `Alert`
- Alerte avec champ manquant → lève une erreur gérée
- Alerte avec `attacker_ip: null` → `Alert.attacker_ip == None` sans exception

### Commit attendu
```
feat(parser): add alert JSON validator and deserializer
```

---

## Étape 4 — Watcher (1 jour)

**Objectif :** surveiller le dossier `shared/alerts/incoming/` et déclencher le pipeline à chaque nouvelle alerte.

**Fichiers concernés :**
```
src/soar/watcher/alert_watcher.py
```

### Ce à quoi penser
- Utiliser `watchdog` avec un `FileSystemEventHandler` sur les événements `on_modified` et `on_created`
- Le fichier surveillé est en **JSONL** (une alerte par ligne) — lire seulement les **nouvelles lignes** depuis la dernière position lue (comme un `tail -f`)
- Maintenir un `Set[str]` des `alert_id` déjà traités pour éviter les doublons (si watchdog déclenche deux fois pour le même fichier)
- En cas d'erreur de parsing, **ne pas crasher** — logguer et continuer

### Ce à ne pas faire
- Ne pas lire le fichier entier à chaque événement watchdog
- Ne pas bloquer le thread watchdog avec des traitements longs — déléguer au pipeline

### Commit attendu
```
feat(watcher): add JSONL alert watcher with dedup
```

---

## Étape 5 — Cache AbuseIPDB (1 jour)

**Objectif :** avoir un cache TTL en mémoire avant de coder le client AbuseIPDB.

**Fichiers concernés :**
```
src/soar/cache/ip_cache.py
```

### Ce à quoi penser
- Structure : `dict[str, dict]` → `{ip: {"score": int, "expires_at": float}}`
- Méthode `get(ip)` → retourne le score si non expiré, `None` sinon
- Méthode `set(ip, score, ttl_seconds)` → stocke avec timestamp d'expiration
- Thread-safe avec `threading.Lock()` (le watcher et le pipeline peuvent tourner en parallèle)

### Test immédiat
```
tests/unit/test_ip_cache.py
```
- `set` puis `get` → retourne le bon score
- `get` après expiration TTL → retourne `None`
- Accès concurrent → pas de race condition

### Commit attendu
```
feat(cache): add thread-safe IP cache with TTL
```

---

## Étape 6 — Client AbuseIPDB (1 jour)

**Objectif :** interroger AbuseIPDB avec fallback sur le cache et sur la liste locale.

**Fichiers concernés :**
```
src/soar/integrations/abuseipdb_client.py
src/soar/cache/fallback_list.yaml
```

### Ce à quoi penser
- **Ordre de résolution :**
  1. Cache mémoire (Étape 5) → si hit, retourner directement
  2. API AbuseIPDB avec `timeout=2s` → si succès, stocker dans cache
  3. Circuit breaker → si 3 échecs consécutifs, basculer en mode dégradé 5 min
  4. Fallback list YAML → si API injoignable
  5. Score par défaut `50` si l'IP n'est dans aucune source
- Retourner un dict avec `source` (`"abuseipdb"`, `"cache"`, `"unavailable"`) pour alimenter le champ `enrichment.source` du schéma réponse
- Extraire `country_code` et `isp` depuis la réponse AbuseIPDB

### Commit attendu
```
feat(integrations): add AbuseIPDB client with cache and fallback
```

---

## Étape 7 — Client OPNsense (1 jour)

**Objectif :** injecter et supprimer des règles de blocage via l'API REST d'OPNsense.

**Fichiers concernés :**
```
src/soar/integrations/opnsense_client.py
```

### Ce à quoi penser
- **Prérequis OPNsense (à faire une seule fois manuellement) :**
  - Créer un alias `soar_blocklist` dans Firewall → Aliases
  - Créer une règle LAN bloquant le trafic dont la source est dans `soar_blocklist`
  - Générer une clé API dans System → Access → Users
- **Méthodes à implémenter :**
  - `block_ip(ip: str) -> dict` → ajoute l'IP à `soar_blocklist` + reconfigure
  - `unblock_ip(ip: str) -> dict` → retire l'IP de l'alias
  - `list_blocked() -> list[str]` → liste les IP actuellement bloquées
  - `is_already_blocked(ip: str) -> bool` → évite les doublons
- `verify=False` sur les requêtes HTTPS (certificat auto-signé en lab)
- Retry avec `retry_count` — 3 tentatives max avant `status: "failed"`

### Commit attendu
```
feat(integrations): add OPNsense API client with retry logic
```

---

## Étape 8 — Moteur de décision (1 jour)

**Objectif :** implémenter la logique qui transforme une `Alert` en `Decision`.

**Fichiers concernés :**
```
src/soar/engine/decision_engine.py
src/soar/engine/rules.py
```

### Ce à quoi penser

**`rules.py` — le playbook :**
```python
PLAYBOOK = {
    "SSH_BRUTEFORCE_001":      "block_ip",
    "SCAN_EXFIL_001":          "block_ip",
    "MALICIOUS_FILE_EXEC_001": "notify",
}

WHITELIST = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]
```

**`decision_engine.py` — la séquence de décision :**
1. `severity == "WARNING"` → `Decision(action="none", skip_reason="severity_warning")`
2. `attacker_ip is None` → `Decision(action="none", skip_reason="attacker_ip_null")`
3. `attacker_ip in WHITELIST` → `Decision(action="none", skip_reason="whitelisted")`
4. Appel `AbuseIPDB.get_score(attacker_ip)` → si score < seuil config → `notify`
5. `PLAYBOOK.get(rule_id)` → action finale

### Test immédiat
```
tests/unit/test_decision_engine.py
```
- Alert WARNING → skip, reason `severity_warning`
- Alert CRITICAL + IP whitelistée → skip, reason `whitelisted`
- Alert CRITICAL + `attacker_ip: null` → skip, reason `attacker_ip_null`
- Alert CRITICAL + IP non whitelistée → `block_ip`

### Commit attendu
```
feat(engine): add decision engine with whitelist and playbook
```

---

## Étape 9 — Handlers (2 jours)

**Objectif :** implémenter les actions concrètes pour S1, S2, S3.

**Fichiers concernés :**
```
src/soar/handlers/
├── base_handler.py
├── ssh_handler.py
├── smb_handler.py
└── s3_handler.py
```

### `base_handler.py` en premier
Définir le contrat commun (template method) :
```python
from abc import ABC, abstractmethod

class BaseHandler(ABC):
    @abstractmethod
    def can_handle(self, alert: Alert) -> bool:
        """Retourne True si ce handler gère ce rule_id"""

    @abstractmethod
    def execute(self, alert: Alert, decision: Decision) -> Response:
        """Exécute l'action et retourne la réponse"""
```

### Ordre d'implémentation
1. `ssh_handler.py` (S1) — le plus simple, `block_ip` via OPNsense
2. `smb_handler.py` (S2) — similaire à S1 mais port 445
3. `s3_handler.py` (S3) — `notify` + `block_ip` si `attacker_ip` présent (2 réponses atomiques)

### Commit attendu
```
feat(handlers): add base handler and SSH, SMB, S3 implementations
```

---

## Étape 10 — Orchestrateur (1 jour)

**Objectif :** assembler toutes les pièces dans un pipeline cohérent.

**Fichiers concernés :**
```
src/soar/orchestrator/response_orchestrator.py
```

### Ce à quoi penser
- Reçoit une `Alert` depuis le watcher
- Appelle `decision_engine.decide(alert)` → `Decision`
- Dispatche vers le bon handler via `can_handle()`
- Récupère la `Response`
- Passe la réponse aux repositories pour persistence

### Commit attendu
```
feat(orchestrator): add response orchestrator pipeline
```

---

## Étape 11 — Base de données SQLite (1 jour)

**Objectif :** persister les alertes, décisions et réponses pour l'audit et le rapport.

**Fichiers concernés :**
```
src/soar/db/
├── connection.py
├── schema.sql
└── migrations/001_initial_schema.sql

src/soar/repositories/
├── alert_repository.py
├── audit_repository.py
└── response_repository.py
```

### Tables à créer dans `schema.sql`
```sql
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    attacker_ip TEXT,
    target_ip TEXT NOT NULL,
    received_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS responses (
    response_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    skip_reason TEXT,
    latency_ms INTEGER NOT NULL,
    response_timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    response_id TEXT NOT NULL REFERENCES responses(response_id),
    blocked_ip TEXT,
    abuseipdb_score INTEGER,
    opnsense_rule_id TEXT,
    api_status_code INTEGER,
    error TEXT,
    created_at INTEGER NOT NULL
);
```

### Commit attendu
```
feat(db): add SQLite schema and repository layer
```

---

## Étape 12 — Logging et audit (0.5 jour)

**Objectif :** journaliser chaque action en JSONL et en SQLite.

**Fichiers concernés :**
```
src/soar/logging/
├── soar_log.py
├── audit_logger.py
└── response_writer.py
```

### Ce à quoi penser
- `soar_log.py` → logging standard Python (`logging.getLogger`) avec rotation automatique
- `audit_logger.py` → écriture en JSONL dans `logs/audit.log` + appel `audit_repository`
- `response_writer.py` → écriture de la `Response` en JSONL dans `logs/audit.log`

### Commit attendu
```
feat(logging): add structured audit logger and response writer
```

---

## Étape 13 — Notifications (1 jour)

**Objectif :** alerter l'administrateur en temps réel et en résumé quotidien.

**Fichiers concernés :**
```
src/soar/notifications/notifier.py
```

### Ce à quoi penser
- `send_immediate_alert(response)` → déclenché si `abuseipdb_score > 95`
- `send_daily_summary()` → résumé depuis SQLite des dernières 24h
- Telegram en priorité (gratuit, léger, adapté au contexte local)
- Email en option (SMTP Gmail ou relais local)
- Gérer le cas où les tokens ne sont pas configurés → logguer un warning sans crasher

### Commit attendu
```
feat(notifications): add Telegram and email notifier
```

---

## Étape 14 — Point d'entrée principal (0.5 jour)

**Objectif :** assembler tout dans `main.py` et démarrer le service.

**Fichiers concernés :**
```
src/soar/main.py
```

### Ce à quoi penser
- Initialiser la DB (migrations)
- Démarrer le watcher dans un thread
- Démarrer le cron de nettoyage des règles expirées
- Planifier le résumé quotidien (schedule ou cron système)
- Gestion propre de `SIGINT` / `SIGTERM` pour arrêt gracieux

### Commit attendu
```
feat(main): add main entry point with graceful shutdown
```

---

## Étape 15 — Tests complets (2 jours)

**Objectif :** valider chaque composant en isolation et end-to-end.

### Tests unitaires prioritaires
```
tests/unit/
├── test_alert_parser.py      ← Étape 3
├── test_ip_cache.py          ← Étape 5
├── test_decision_engine.py   ← Étape 8
├── test_ssh_handler.py       ← Étape 9
├── test_smb_handler.py       ← Étape 9
└── test_s3_handler.py        ← Étape 9
```

### Tests d'intégration (avec mocks)
```
tests/integration/
├── test_abuseipdb_client.py  ← mocker requests.get
└── test_opnsense_client.py   ← mocker requests.post
```

### Commit attendu
```
test: add full unit and integration test suite
```

---

## Étape 16 — Scripts utilitaires (1 jour)

**Objectif :** automatiser la maintenance du système.

**Fichiers concernés :**
```
scripts/
├── rotate_logs.sh             # rotation des logs (logrotate ou manuel)
├── generate_report.py         # rapport CSV/PDF depuis SQLite
└── cleanup_expired_rules.py   # suppression des règles OPNsense expirées
```

### Commit attendu
```
feat(scripts): add log rotation, report generation, rule cleanup
```

---

## Récapitulatif des étapes

| # | Étape | Durée | Commit type |
|---|-------|-------|-------------|
| 0 | Environnement + config | 1 jour | `chore` |
| 1 | Modèles (Alert, Decision, Response) | 1 jour | `feat(models)` |
| 2 | Settings + .env | 0.5 jour | `feat(config)` |
| 3 | Parser + validation schéma | 1 jour | `feat(parser)` |
| 4 | Watcher JSONL | 1 jour | `feat(watcher)` |
| 5 | Cache TTL AbuseIPDB | 1 jour | `feat(cache)` |
| 6 | Client AbuseIPDB | 1 jour | `feat(integrations)` |
| 7 | Client OPNsense | 1 jour | `feat(integrations)` |
| 8 | Moteur de décision | 1 jour | `feat(engine)` |
| 9 | Handlers S1, S2, S3 | 2 jours | `feat(handlers)` |
| 10 | Orchestrateur | 1 jour | `feat(orchestrator)` |
| 11 | SQLite + repositories | 1 jour | `feat(db)` |
| 12 | Logging + audit | 0.5 jour | `feat(logging)` |
| 13 | Notifications | 1 jour | `feat(notifications)` |
| 14 | main.py | 0.5 jour | `feat(main)` |
| 15 | Tests complets | 2 jours | `test` |
| 16 | Scripts utilitaires | 1 jour | `feat(scripts)` |
| **Total** | | **~17 jours** | |

---

## Règles de travail

1. **Une étape = un commit minimum** — jamais de `git commit -m "update"`
2. **Chaque étape doit tourner** avant de passer à la suivante — pas de code mort non testé qui s'accumule
3. **Les tests s'écrivent juste après le code**, pas à la fin — les étapes 3, 5, 8, 9 ont leurs tests indiqués
4. **Documenter dans `docs/semaineX.md`** chaque vendredi — ce qui a marché, ce qui a bloqué, les métriques si disponibles
5. **Toujours tirer la branche `soar` à jour** avant de commencer une session de travail

```bash
git checkout soar
git pull origin soar
```
