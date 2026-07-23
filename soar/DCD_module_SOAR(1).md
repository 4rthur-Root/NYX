# Dossier de Conception Détaillée — Module SOAR (NyxSOC)

**Auteur du module :** GAHOUNZO Komlan Honoré
**Statut :** en cours d'implémentation (Étape 0 terminée)
**Objectif de ce document :** permettre à n'importe quel développeur reprenant ce module de comprendre et coder chaque classe sans avoir à reconstituer le contexte du projet. Ce document décrit le *contrat* de chaque classe (responsabilité, entrées, sorties, cas limites) — pas son implémentation ligne à ligne, qui reste à écrire.

---

## 0. Comment lire ce document

Chaque classe est décrite selon le même gabarit :
- **Responsabilité** — en une phrase, ce que fait la classe et ce qu'elle ne fait pas
- **Dépend de** — les autres classes/fichiers qu'elle utilise
- **Entrée / Sortie** — ce qu'elle reçoit, ce qu'elle retourne
- **Cas limites** — les erreurs et cas particuliers à gérer explicitement
- **Ne doit jamais** — les pièges à éviter

Les classes sont présentées dans l'ordre du planning de développement (noyau → périphérie), pas dans l'ordre alphabétique des dossiers.

---

## 1. Vue d'ensemble du pipeline

```
/var/log/nyx/alert{uuid}.json   (écrit par le moteur de Gaël, .tmp + rename() atomique)
        │
        ▼
  AlertWatcher (watchdog)  ──lit──▶  AlertParser (valide contre alert-schema.json)
        │                                    │
        │                                    ▼
        │                              Alert (dataclass)
        │                                    │
        │                                    ▼
        │                          DecisionEngine (+ rules.py)
        │                                    │  appelle AbuseIPDBClient (+ IpCache, fallback_list.yaml)
        │                                    ▼
        │                              Decision (dataclass)
        │                                    │
        │                                    ▼
        │                       ResponseOrchestrator ──dispatch──▶ Handler (ssh/smb/s3)
        │                                                                 │  appelle OPNsenseClient si block_ip
        │                                                                 ▼
        │                                                          Response (dataclass, conforme response-scheme.json)
        │                                                                 │
        │                                                    ┌────────────┼────────────┐
        │                                                    ▼            ▼            ▼
        │                                             AuditLogger   ResponseWriter   Notifier
        │                                             (JSONL)       (SQLite via      (Telegram/
        │                                                            repositories)    Email si seuil)
        ▼
  déplacement du fichier alerte (à définir : processed/ ou suppression, cf. section 4.4)
```

---

## 2. Contrats externes (schémas figés — source de vérité absolue)

Ces deux fichiers sont **la référence**. En cas de doute entre ce document et le schéma réel, **le schéma JSON fait foi**.

- `docs/alert-schema.json` (v1.1.0) — ce que le moteur de Gaël écrit
- `docs/response-scheme.json` (v1.0.1) — ce que le SOAR doit produire en sortie
- `docs/rule-schema.json` (v1.0.0) — le format des règles YAML de détection, désormais fourni (voir 2.3)

### 2.1 Résumé du schéma `Alert`

| Champ | Type | Nullable | Notes |
|---|---|---|---|
| `alert_id` | string (UUID) | non | **Confirmé UUID, pas un entier auto-incrémenté** (cf. section 5) |
| `timestamp` | int (Unix ms) | non | |
| `rule_id` | string | non | Ex: `SSH_BRUTEFORCE_001` — clé pour retrouver le scénario |
| `severity` | enum | non | `WARNING` \| `CRITICAL` |
| `attacker_ip` | string (IPv4) | **oui** | Null pour S3 (attaque locale) — voir point critique section 5 |
| `target_host` | string | non | |
| `target_ip` | string (IPv4) | non | |
| `target_resource` | string | oui | |
| `mitre_tactic` | string (`^TA[0-9]{4}$`) | non | |
| `mitre_technique` | string (`^T[0-9]{4}$`) | non | |
| `events.count` | int (≥1) | non | Total réel même si `details` est tronqué |
| `events.details[]` | array (max 20) | non | Chaque item : `timestamp`, `event_type`, `source_host`, `actor_user?`, `actor_role?`, `target_resource?`, `raw_log` |
| `yara_match` | object \| null | oui | Non-null uniquement pour S3 : `rule_name`, `file_path`, `file_hash`, `ruleset` |

### 2.2 Résumé du schéma `Response`

| Champ | Type | Nullable | Notes |
|---|---|---|---|
| `response_id` | string (UUID) | non | Généré par le SOAR |
| `alert_id` | string (UUID) | non | Clé de liaison vers l'alerte source |
| `alert_timestamp` | int | non | Copié depuis l'alerte, pour calcul de latence sans relire le fichier |
| `response_timestamp` | int | non | Fin de traitement SOAR |
| `latency_ms` | int (≥0) | non | `response_timestamp - alert_timestamp` — **KPI H4, cible ≤ 5000 ms** |
| `action` | enum | non | `block_ip` \| `notify` \| `none` |
| `status` | enum | non | `success` \| `failed` \| `skipped` |
| `skip_reason` | enum \| null | oui | `severity_warning` \| `attacker_ip_null` \| `whitelisted` \| null. **Doit être null si status ≠ skipped — le schéma ne le vérifie pas, c'est à ton code de le garantir** |
| `enrichment` | object \| null | oui | Null si `attacker_ip` était null ou `action == none`. Sinon : `source`, `abuseipdb_score`, `country_code`, `isp`, `fallback_used` |
| `opnsense` | object \| null | oui | Null si `action != block_ip`. Sinon : `rule_id`, `blocked_ip`, `api_status_code`, `retry_count` |
| `error` | string \| null | oui | Renseigné uniquement si `status == failed` |

### 2.3 Résumé du schéma `Rule` (règles de détection du moteur)

**⚠️ Point de vigilance terminologique important :** ce schéma contient un champ `type` avec les valeurs `1`, `2`, `3` — **ce n'est PAS le numéro de scénario (S1/S2/S3/S4/S5)**. Il s'agit du **mécanisme de détection** :
- `type: 1` → seuil simple sur un `event_type` (ex: N échecs SSH en X secondes)
- `type: 2` → séquence d'étapes ordonnées (kill-chain, ex: scan puis lecture SMB puis exfiltration)
- `type: 3` → cooccurrence de plusieurs `event_types` sans ordre imposé dans une fenêtre donnée

Ne jamais utiliser `rule.type` pour router vers un handler — le routage se fait uniquement via `rule_id` (section 2.3.1).

**Autres points confirmés par ce schéma :**
- `rule_id` suit le pattern `^[A-Z][A-Z0-9_]+_[0-9]{3}$` (ex: `SSH_BRUTEFORCE_001`) — confirme le format déjà supposé dans `rules.py`.
- **Séparation des responsabilités confirmée noir sur blanc** : *"La décision de réponse (blocage, isolation) appartient exclusivement au module SOAR via son playbook. Le moteur ne dicte pas d'action."* Le moteur ne fait que décider s'il faut générer une alerte (`response.alert: true/false`) — jamais quelle action prendre. Ça valide l'architecture actuelle : `DecisionEngine` et `rules.py` (côté SOAR) sont bien les seuls dépositaires du `PLAYBOOK`.
- **Sémantique `severity` confirmée** : `WARNING` = *"pattern suspect, pas d'action SOAR automatique"* ; `CRITICAL` = *"chaîne confirmée, déclenche l'évaluation du playbook SOAR"*. Ça valide directement la règle 1 du `DecisionEngine` (skip si `severity == WARNING`).

#### 2.3.1 Mapping `rule_id → scénario` — état réel des connaissances

D'après les fichiers de règles visibles dans `engine/rules/attack/` (arborescence fournie précédemment), **seuls 3 fichiers de règles existent actuellement** :
```
ssh_bruteforce.yaml   → scénario S1
smb_exfil.yaml        → scénario S2
malicious_file.yaml   → scénario S3
```
Aucun fichier `.yaml` pour S4 ou S5 n'apparaît dans l'arborescence — alors que le schéma `alert-schema.json` mentionne bien "S1, S4" et "S4" dans certaines descriptions de champs (`actor_user`, `actor_role`). **Interprétation la plus probable : S4 (et peut-être S5) sont des scénarios prévus/documentés dans le mémoire mais pas encore implémentés comme règles actives côté moteur.** Ce n'est plus bloquant pour coder — tu as les 3 scénarios qui ont un handler prévu (S1/S2/S3) — mais à confirmer avec Gaël si S4/S5 sont à anticiper avant la soutenance.

---

## 3. Conventions transverses (valables pour toutes les classes)

1. **Aucune classe métier ne doit crasher le pipeline.** Toute exception attendue (fichier malformé, API injoignable, timeout) est capturée localement, journalisée via `SoarLog`, et transformée en un état explicite (`Response(status="failed", error=...)`) plutôt que de remonter une exception non gérée jusqu'au watcher.
2. **Les dataclasses de `models/` sont le seul vocabulaire échangé entre les couches.** Aucune couche ne doit manipuler un `dict` brut au-delà du point d'entrée (`AlertParser`) et du point de sortie (`repositories/`, `AuditLogger`).
3. **Aucun secret ou seuil en dur dans le code.** Tout ce qui est un secret vient de `.env` via `settings.py` ; tout ce qui est un seuil/paramètre métier vient de `config.yaml`.
4. **Chaque classe a une seule source d'I/O.** Ex: `AuditLogger` écrit uniquement en JSONL, `AuditRepository` uniquement en SQL — jamais les deux mélangés dans la même classe.

---

## 4. Spécification par classe

### 4.1 `models/alert.py`

**Responsabilité :** représenter une alerte confirmée, immuable, typée strictement selon `alert-schema.json`.

```python
@dataclass(frozen=True)
class EventDetail:
    timestamp: int
    event_type: str
    source_host: str
    raw_log: str
    actor_user: Optional[str] = None
    actor_role: Optional[str] = None   # "direction"|"comptabilite"|"technique"|"basique"|None
    target_resource: Optional[str] = None

@dataclass(frozen=True)
class YaraMatch:
    rule_name: str
    file_path: str
    file_hash: str
    ruleset: str

@dataclass(frozen=True)
class Alert:
    alert_id: str                      # UUID
    timestamp: int
    rule_id: str
    severity: str                      # "WARNING" | "CRITICAL"
    target_host: str
    target_ip: str
    mitre_tactic: str
    mitre_technique: str
    events_count: int
    events_details: list[EventDetail]
    attacker_ip: Optional[str] = None
    target_resource: Optional[str] = None
    yara_match: Optional[YaraMatch] = None
```

**Dépend de :** rien (c'est la fondation).
**Cas limites :** `attacker_ip` et `yara_match` sont normalement corrélés au scénario (S3 → `attacker_ip=None`, `yara_match` renseigné) mais **rien n'empêche techniquement une autre combinaison** — ne jamais supposer l'un à partir de l'autre dans le code, toujours lire les deux champs explicitement.
**Ne doit jamais :** contenir de logique métier (pas de méthode `is_critical()` ici — ça vit dans `DecisionEngine`).

### 4.2 `models/decision.py`

**Responsabilité :** représenter le résultat du `DecisionEngine`, avant exécution par un handler.

```python
@dataclass(frozen=True)
class EnrichmentResult:
    source: str                        # "abuseipdb" | "cache" | "unavailable"
    fallback_used: bool
    abuseipdb_score: Optional[int] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None

@dataclass(frozen=True)
class Decision:
    alert: Alert
    scenario_type: str                 # "S1".."S5" — voir section 5, mapping en attente
    action: str                        # "block_ip" | "notify" | "none"
    skip_reason: Optional[str] = None  # cf énumération response-scheme.json
    enrichment: Optional[EnrichmentResult] = None
```

**Dépend de :** `models/alert.py`.
**Cas limites :** si `action == "none"`, `skip_reason` DOIT être renseigné (invariant à valider en fin de `DecisionEngine.decide()`, potentiellement avec un `assert` ou une validation explicite).

### 4.3 `models/response.py`

**Responsabilité :** représenter le résultat final, conforme strictement à `response-scheme.json` — c'est cet objet qui est sérialisé/persisté.

```python
@dataclass(frozen=True)
class OpnsenseResult:
    api_status_code: int
    retry_count: int
    rule_id: Optional[str] = None
    blocked_ip: Optional[str] = None

@dataclass(frozen=True)
class Response:
    response_id: str                   # UUID généré ici, via uuid.uuid4()
    alert_id: str
    alert_timestamp: int
    response_timestamp: int
    latency_ms: int
    action: str
    status: str                        # "success" | "failed" | "skipped"
    skip_reason: Optional[str] = None
    enrichment: Optional[EnrichmentResult] = None
    opnsense: Optional[OpnsenseResult] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Sérialisation conforme au schéma, pour AuditLogger/ResponseWriter."""
```

**Dépend de :** `models/decision.py` (réutilise `EnrichmentResult`).
**Cas limites :** `latency_ms` doit être calculé (`response_timestamp - alert_timestamp`), jamais estimé ou laissé à 0 par défaut.
**Ne doit jamais :** être construit avec `enrichment` renseigné si `action == "none"` — violerait le schéma.

### 4.4 `config/settings.py`

**Responsabilité :** point d'entrée unique pour toute variable d'environnement ou paramètre de `config.yaml`.

**Entrée :** `.env` (via `python-dotenv`), `config/config.yaml` (via `pyyaml`).
**Sortie :** un singleton `settings` important par tous les autres modules (`from soar.config.settings import settings`).
**Cas limites :** si une variable obligatoire manque (ex: `OPNSENSE_API_KEY` absent), lever une erreur explicite et bloquante **au démarrage**, jamais un `KeyError` en pleine exécution du pipeline.
**Ne doit jamais :** avoir de valeur par défaut silencieuse pour un secret (une clé API vide ne doit jamais passer inaperçue).

### 4.5 `parser/alert_parser.py`

**Responsabilité :** valider un JSON brut contre `alert-schema.json` et le transformer en `Alert`.

**Dépend de :** `jsonschema`, `models/alert.py`, `config/settings.py` (chemin du schéma).
**Entrée :** `dict` (JSON déjà chargé) ou chemin de fichier.
**Sortie :** `Alert` si valide, sinon exception métier dédiée (`AlertValidationError`) capturée par l'appelant (`AlertWatcher`), jamais une exception `jsonschema` brute qui remonterait telle quelle.
**Cas limites :**
- `attacker_ip` peut être `null` (confirmé) → mapper vers `None` en Python, pas la chaîne `"null"`.
- `events.details` peut contenir moins d'items que `events.count` (troncature à 20 confirmée) → ne jamais supposer `len(details) == count`.
**Ne doit jamais :** modifier ou enrichir les données — le parser désérialise, il ne décide de rien.

### 4.6 `watcher/alert_watcher.py`

**Responsabilité :** détecter l'apparition d'un nouveau fichier d'alerte dans `/var/log/nyx/` et déclencher le pipeline.

**Dépend de :** `watchdog`, `parser/alert_parser.py`, `config/settings.py` (chemin `alerts_incoming`).
**Mécanisme confirmé par Gaël :** un fichier par alerte (`alert{uuid}.json`), écrit via `.tmp` + `rename()` atomique. **Ce n'est PAS un flux JSONL continu** — pas besoin de gestion d'offset ni de `tail -f`.
**Événement watchdog à écouter :** `on_moved` (déclenché par le `rename()` de Gaël) **et** `on_created` par sécurité (selon l'implémentation exacte de son `rename`, les deux peuvent se déclencher selon l'OS/filesystem — à tester empiriquement plutôt que supposer).
**Cas limites :**
- Ignorer tout fichier `.tmp` résiduel qui apparaîtrait dans le dossier surveillé (filtrer sur l'extension `.json` uniquement).
- Un fichier déjà vu (même `alert_id`) ne doit jamais être retraité — mais comme chaque fichier est unique et complet dès son apparition (garanti par l'écriture atomique), un simple traitement "à l'apparition" suffit, pas besoin du `Set[str]` de dédup prévu initialement pour le modèle JSONL.
**✅ TRANCHÉ — le SOAR est purement lecteur sur `/var/log/nyx/` :** ce dossier appartient à Gaël (son moteur y écrit, son `StateStore` gère sa propre rétention). Le `AlertWatcher` ne doit **jamais renommer, déplacer ou supprimer** un fichier d'alerte — ce n'est pas de sa responsabilité, et empiéter dessus créerait un couplage indésirable avec un espace qui ne lui appartient pas.

**Conséquence directe sur la dédup :** sans déplacement de fichier pour marquer "déjà traité", la dédup doit reposer sur une source que le SOAR contrôle lui-même. Solution recommandée : avant traitement, vérifier si `alert.alert_id` existe déjà dans la table `alerts` (SQLite, cf. 4.14) via `alert_repository.exists(alert_id)`. Si oui → ignorer silencieusement (déjà traité, watchdog a probablement déclenché deux fois pour le même événement). Si non → traiter normalement et insérer dans `alerts` dès le parsing réussi (avant même la décision), pour que toute alerte vue soit immédiatement marquée comme connue.
**Ne doit jamais :** bloquer le thread watchdog avec le traitement complet (parsing + décision + exécution) — déléguer à l'orchestrateur, potentiellement via une queue interne ou un thread pool si la latence de traitement s'avère non négligeable face à l'objectif de 5000ms.
**Ne doit jamais :** écrire, déplacer ou supprimer quoi que ce soit dans `/var/log/nyx/` — droits de lecture seule suffisent et doivent être demandés explicitement (cf. droits `soc` déjà en place côté Gaël).

### 4.7 `cache/ip_cache.py`

**Responsabilité :** cache mémoire TTL des scores AbuseIPDB, pour éviter des appels API redondants.

**Structure interne :** `dict[str, dict]` → `{ip: {"score": int, "expires_at": float}}`, protégé par `threading.Lock()`.
**Entrée/Sortie :** `get(ip) -> Optional[int]`, `set(ip, score, ttl_seconds) -> None`.
**Cas limites :** accès concurrent watcher/pipeline — le verrou doit englober la lecture ET l'éventuelle expiration/suppression, pas juste l'écriture.
**Ne doit jamais :** persister sur disque (c'est un cache mémoire volontairement volatile, pas un remplacement de `fallback_list.yaml`).

### 4.8 `integrations/base.py`, `abuseipdb_client.py`

**Responsabilité de `base.py` :** interface abstraite `ThreatIntelClient` avec une méthode `get_reputation(ip: str) -> EnrichmentResult`.

**Responsabilité d'`abuseipdb_client.py` :** implémenter cette interface avec la logique de résolution en cascade.

**Ordre de résolution (confirmé dans le planning, à respecter strictement) :**
1. `IpCache.get(ip)` → hit → retourne directement, `source="cache"`
2. Appel API AbuseIPDB (`timeout=2s`) → succès → stocke dans le cache, `source="abuseipdb"`
3. Circuit breaker : 3 échecs consécutifs → mode dégradé 5 min (durée pilotée par `config.yaml`, pas en dur)
4. `fallback_list.yaml` → `source="unavailable"`, `fallback_used=True`
5. Score par défaut `50` si l'IP n'apparaît nulle part

**Sortie :** toujours un `EnrichmentResult` complet, jamais un score brut isolé — c'est cet objet qui alimente directement `Decision.enrichment` puis `Response.enrichment`.
**Cas limites :** extraire `country_code` et `isp` uniquement si `source == "abuseipdb"` (les autres sources ne les fournissent pas — laisser `None`).

### 4.9 `integrations/opnsense_client.py`

**Responsabilité :** exécuter le blocage/déblocage réel via l'API REST OPNsense.

**Méthodes attendues :** `block_ip(ip) -> OpnsenseResult`, `unblock_ip(ip) -> OpnsenseResult`, `list_blocked() -> list[str]`, `is_already_blocked(ip) -> bool`.
**Cas limites :** retry jusqu'à `retry_count` max (config), `verify=False` sur les requêtes HTTPS (certificat auto-signé en lab — **commenter explicitement dans le code que ceci est un choix de lab, pas une pratique de production**), toujours retourner un `OpnsenseResult` même en cas d'échec final (`api_status_code` reflète le dernier code réellement reçu, ou un code interne dédié si aucune réponse réseau n'a été obtenue).
**Ne doit jamais :** lever une exception non gérée en cas d'échec réseau — c'est le handler appelant qui décide de la suite (`status="failed"`, `error=...`).

### 4.10 `engine/rules.py`

**Responsabilité :** centraliser toute donnée de règle statique — **playbook** (action par `rule_id`) et **whitelist**.

```python
PLAYBOOK: dict[str, str] = {
    "SSH_BRUTEFORCE_001":      "block_ip",
    "SCAN_EXFIL_001":          "block_ip",
    "MALICIOUS_FILE_EXEC_001": "notify",
    # ... à compléter avec la liste exhaustive des rule_id de Gaël (section 5)
}

RULE_TO_SCENARIO: dict[str, str] = {
    "SSH_BRUTEFORCE_001":      "S1",   # confirmé — engine/rules/attack/ssh_bruteforce.yaml
    "SMB_EXFIL_001":           "S2",   # confirmé — engine/rules/attack/smb_exfil.yaml
                                        # (⚠️ corrigé : ce n'est PAS "SCAN_EXFIL_001" comme
                                        #  précédemment supposé dans ce document)
    "MALICIOUS_FILE_EXEC_001": "S3",   # confirmé — engine/rules/attack/malicious_file.yaml
    # S4/S5 non implémentés côté moteur à ce jour — cf. 2.3.1, aucun fichier .yaml correspondant
}

# Scénarios où attacker_ip est structurellement attendu et non-null.
# Sert au DecisionEngine pour décider si un attacker_ip null doit provoquer
# un skip (S1/S2) ou non (S3, où c'est le cas normal). Cf. décision 5.1.
SCENARIOS_EXPECTING_IP: set[str] = {"S1", "S2"}

WHITELIST: list[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

PLAYBOOK: dict[str, str] = {
    "SSH_BRUTEFORCE_001":      "block_ip",
    "SMB_EXFIL_001":           "block_ip",
    "MALICIOUS_FILE_EXEC_001": "notify",   # + block_ip conditionnel géré dans s3_handler
}
```

**Ne doit jamais :** contenir de logique conditionnelle — uniquement des données statiques. Toute la logique vit dans `decision_engine.py`.
**Ne doit jamais :** lire un champ `response.soar_action` depuis le fichier de règle YAML de Gaël, même s'il y en a un dans certains fichiers (ex: `malicious_file.yaml`) — ce champ viole le principe de séparation confirmé par `rule-schema.json` lui-même ("le moteur ne dicte pas d'action") et n'est de toute façon pas garanti stable. Le `PLAYBOOK` ci-dessus reste l'unique source de vérité côté SOAR.
**Fichiers sources vérifiés :** les 3 `rule_id` ci-dessus sont désormais confirmés directement depuis les fichiers YAML réels (`ssh_bruteforce.yaml`, `smb_exfil.yaml`, `malicious_file.yaml`), plus aucune supposition.

### 4.11 `engine/decision_engine.py`

**Responsabilité :** transformer une `Alert` en `Decision`.

**Séquence (✅ TRANCHÉE — option (a) retenue pour la contradiction S3, cf. décision section 5.1) :**

```
0. scenario_type = RULE_TO_SCENARIO[alert.rule_id]   ← calculé EN PREMIER, condition tout le reste

1. severity == "WARNING"
       → Decision(action="none", skip_reason="severity_warning")

2. attacker_ip is None ET scenario_type in SCENARIOS_EXPECTING_IP (S1, S2)
       → Decision(action="none", skip_reason="attacker_ip_null")
   (Pour S3 : attacker_ip est structurellement null par design — cette règle ne
    s'applique PAS, le traitement continue normalement vers l'étape 5)

3. attacker_ip in WHITELIST (si attacker_ip non-null)
       → Decision(action="none", skip_reason="whitelisted")

4. Si attacker_ip non-null : appel AbuseIPDBClient.get_reputation(attacker_ip)
       → score < abuseipdb_score_threshold → action="notify" (override de l'étape 5)
   Si attacker_ip est null (cas S3 normal) : enrichment=None, cette étape est simplement sautée

5. action_finale = PLAYBOOK[alert.rule_id]   (sauf override de l'étape 4)
```

**Pourquoi cet ordre :** calculer `scenario_type` en premier (étape 0) permet à l'étape 2 de savoir si un `attacker_ip` null est normal (S3) ou anormal (S1/S2) — sans ça, l'ancienne séquence aurait fait sauter toutes les alertes S3 avant même d'atteindre le `s3_handler`, rendant sa logique ("notify + block_ip si IP présente") totalement inaccessible.

**Dépend de :** `engine/rules.py`, `integrations/abuseipdb_client.py`, `models/decision.py`.
**Ne doit jamais :** appeler `OPNsenseClient` directement — le `DecisionEngine` décide, il n'exécute rien.

### 4.12 `handlers/base_handler.py` + `ssh_handler.py`, `smb_handler.py`, `s3_handler.py`

**Responsabilité de `base_handler.py` :** contrat commun (déjà défini dans le planning) :

```python
class BaseHandler(ABC):
    @abstractmethod
    def can_handle(self, alert: Alert) -> bool: ...
    @abstractmethod
    def execute(self, alert: Alert, decision: Decision) -> Response: ...
```

**`can_handle` s'appuie sur `rule_id`** (via `RULE_TO_SCENARIO`), pas sur un champ `scenario` qui n'existe pas dans le schéma (confirmé en amont).

**`ssh_handler.py` (S1) :** `execute()` appelle `OPNsenseClient.block_ip()` si `decision.action == "block_ip"`, construit un `Response` avec `opnsense` renseigné et `enrichment` copié depuis `decision.enrichment`.

**`smb_handler.py` (S2) :** même logique que S1.

**`s3_handler.py` (S3) :** **cas particulier à bien gérer** — d'après le planning : *"notify + block_ip si attacker_ip présent (2 réponses atomiques)"*. Ça veut dire que ce handler peut produire **une notification systématique** (le fichier malveillant a été détecté, quoi qu'il arrive) **et optionnellement un blocage IP** si `attacker_ip` n'est pas null pour ce cas précis. Vérifier avec le schéma : rien n'interdit qu'un S3 ait un `attacker_ip` renseigné (le null est décrit comme le cas typique, pas absolu) — donc ce handler doit tester `alert.attacker_ip` explicitement, indépendamment de ce que `DecisionEngine` a décidé en amont sur la base de la règle 2 (point critique, section 5).

**Ne doit jamais :** appeler `AbuseIPDBClient` directement — l'enrichissement est déjà fait par `DecisionEngine`, le handler ne fait qu'exécuter et persister le résultat.

### 4.13 `orchestrator/response_orchestrator.py`

**Responsabilité :** pur routeur, aucune logique métier.

```python
def handle(self, alert: Alert) -> Response:
    decision = self.decision_engine.decide(alert)
    handler = next(h for h in self.handlers if h.can_handle(alert))
    response = handler.execute(alert, decision)
    self.audit_logger.log(alert, decision, response)
    self.response_repository.save(response)
    if response.status == "failed" or <seuil notification>:
        self.notifier.send_immediate_alert(response)
    return response
```

**Dépend de :** tout le reste — c'est le point d'assemblage.
**Cas limites :** aucun handler ne matche (`rule_id` inconnu) → logguer une erreur explicite via `SoarLog`, ne pas laisser une exception `StopIteration` remonter silencieusement.

### 4.14 `db/schema.sql` (mis à jour selon `response-scheme.json` réel)

```sql
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,          -- UUID, confirmé
    timestamp INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    attacker_ip TEXT,
    target_host TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    mitre_tactic TEXT NOT NULL,
    mitre_technique TEXT NOT NULL,
    received_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS responses (
    response_id TEXT PRIMARY KEY,       -- UUID
    alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
    alert_timestamp INTEGER NOT NULL,
    response_timestamp INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    skip_reason TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS enrichments (
    response_id TEXT PRIMARY KEY REFERENCES responses(response_id),
    source TEXT NOT NULL,
    abuseipdb_score INTEGER,
    country_code TEXT,
    isp TEXT,
    fallback_used INTEGER NOT NULL      -- 0/1, SQLite n'a pas de bool natif
);

CREATE TABLE IF NOT EXISTS opnsense_actions (
    response_id TEXT PRIMARY KEY REFERENCES responses(response_id),
    rule_id TEXT,
    blocked_ip TEXT,
    api_status_code INTEGER NOT NULL,
    retry_count INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_responses_status ON responses(status);
CREATE INDEX IF NOT EXISTS idx_responses_action ON responses(action);
CREATE INDEX IF NOT EXISTS idx_responses_timestamp ON responses(response_timestamp);
```

**Changement notable par rapport à la première ébauche :** `enrichment` et `opnsense` sont désormais des **tables séparées** (1-1 avec `responses`) plutôt que des colonnes JSON dans `audit_log` — plus propre pour le dashboard qui pourra faire des `JOIN` filtrés (ex: toutes les réponses avec `abuseipdb_score > 90`).

### 4.15 `repositories/*.py`

**`alert_repository.py` :** `save(alert)`, `get_by_id(alert_id)`, `list_recent(limit)`. Lecture/écriture de la table `alerts`.
**`response_repository.py` :** `save(response)` (doit écrire dans `responses` + `enrichments` + `opnsense_actions` en une transaction), `get_by_alert_id(alert_id)`, `list_failed()`, `list_recent(filters)`.
**`audit_repository.py` :** `insert_event(record: dict)` — SQL uniquement, aucune connaissance du format JSONL (c'est `AuditLogger` qui gère ça, cf. 4.16).
**Ne doit jamais :** contenir de logique de décision — un repository fait des `INSERT`/`SELECT`, point.

### 4.16 `logging/soar_log.py`, `audit_logger.py`, `response_writer.py`

**`soar_log.py` :** wrapper `logging` standard, rotation automatique — inchangé par rapport à nos échanges précédents.
**`audit_logger.py` :** écrit **uniquement en JSONL** dans `logs/audit.log` (trace temps réel lisible à l'œil). Délègue toute persistance structurée à `audit_repository.insert_event()` — ne fait jamais de SQL lui-même (acté avec toi précédemment).
**`response_writer.py` :** son rôle se réduit maintenant à appeler `response_repository.save(response)` — la persistance structurée de la `Response` va en SQLite (tables 4.14), pas en JSONL. Vérifie avec toi si tu veux qu'il écrive *aussi* une ligne JSONL de la réponse finale dans `audit.log` (résumé humain-lisible de l'issue), en plus de la SQLite — à trancher, les deux sont défendables.

### 4.17 `notifications/notifier.py`

**Responsabilité :** alerter un humain.
**Méthodes :** `send_immediate_alert(response: Response)` — déclenché si `response.enrichment.abuseipdb_score > 95` OU `response.status == "failed"`. `send_daily_summary()` — agrège depuis `response_repository` sur les dernières 24h.
**Cas limites :** tokens Telegram/SMTP absents → logguer un warning via `SoarLog`, ne jamais crasher le pipeline principal pour un échec de notification.

### 4.18 `main.py`

**Responsabilité :** câblage des dépendances (injection), démarrage du watcher, démarrage des tâches planifiées (nettoyage, résumé quotidien), arrêt propre sur `SIGINT`/`SIGTERM`.
**Ne doit jamais :** contenir de logique métier — uniquement de l'assemblage et du cycle de vie du process.

---

## 5. Points ouverts et décisions prises

### ✅ 5.1 RÉSOLU — Contradiction `DecisionEngine` / `s3_handler`

**Décision retenue : option (a).** Le `DecisionEngine` calcule `scenario_type` en premier (via `RULE_TO_SCENARIO[rule_id]`), puis ne skip sur `attacker_ip is None` que si `scenario_type in SCENARIOS_EXPECTING_IP` (S1, S2). Pour S3, `attacker_ip` null est traité comme le cas normal et le traitement continue jusqu'au `PLAYBOOK`. Implémentation détaillée en section 4.11.

### ✅ 5.2 RÉSOLU — Mapping `rule_id → scénario`

Les 3 fichiers YAML réels ont été fournis et analysés. Mapping définitif :
- `SSH_BRUTEFORCE_001` → S1
- `SMB_EXFIL_001` → S2 (⚠️ différent de `SCAN_EXFIL_001`, qui était une supposition erronée dans une version antérieure de ce document)
- `MALICIOUS_FILE_EXEC_001` → S3

S4/S5 n'ont pas de fichier `.yaml` correspondant dans le repo à ce jour — non implémentés côté moteur, pas bloquant pour la suite.

### ✅ 5.3 RÉSOLU — Devenir du fichier d'alerte : hors périmètre SOAR

`/var/log/nyx/` appartient à Gaël et à son moteur — **le SOAR n'a aucune action à y effectuer** (ni suppression, ni déplacement, ni renommage). Le `AlertWatcher` est un lecteur pur. La dédup se fait via la base SQLite du SOAR (vérification de `alert_id` déjà connu), pas via un mécanisme de fichiers. Détail en section 4.6.

### 🟡 5.6 Point de qualité à relayer à Gaël (sans impact sur le code SOAR)

En validant les 3 fichiers YAML contre `rule-schema.json`, plusieurs écarts de conformité ont été repérés — à signaler à Gaël pour son propre suivi qualité, sans impact sur ton code SOAR :
- **`smb_exfil.yaml`** : `mitre_tactic: TA001` invalide (le schéma exige 4 chiffres → `TA0001`) ; `event_type: smb_exfil` absent de la taxonomie fermée du schéma et placé à un niveau où ce champ n'est pas défini ; coquilles `treshold`/`windows_seconds` au lieu de `threshold`/`window_seconds` ; `type: 3` déclaré mais structure `trigger:` utilisée (propre au `type: 1`) au lieu de `condition:` ; `group_by` avec deux valeurs alors qu'une seule est autorisée par l'enum.
- **`malicious_file.yaml`** : champ `response.soar_action` non prévu par le schéma (`additionalProperties: false` sur `response`) et contraire au principe explicite du schéma ("le moteur ne dicte pas d'action").
- **`ssh_bruteforce.yaml`** : `type`, `mitre_tactic`, `mitre_technique` manquants, pourtant tous requis à la racine du schéma.

**Aucun impact côté SOAR** : `rules.py` n'a besoin que du `rule_id` (confirmé correct dans les 3 fichiers) et ignore délibérément tout le reste, y compris `soar_action`. Si le `RuleEngine` de Gaël applique réellement une validation stricte avant chargement, ces règles pourraient actuellement échouer à charger — à vérifier avec lui.

### 🟢 5.4 `alert_id` — résolu

Les deux schémas (`alert-schema.json` et `response-scheme.json`) confirment sans ambiguïté : `alert_id` est un **UUID string**. La réponse "auto-incrémenté" de Gaël concernait probablement une clé interne à son `StateStore`, sans rapport avec l'`alert_id` exposé. **Aucune action requise, ce point n'est plus ouvert.**

### 🟢 5.5 `response_writer.py` — écriture double JSONL + SQLite ?

Voir section 4.16 — à confirmer si tu veux un résumé JSONL de la réponse finale en plus de la persistance SQLite.

---

## 6. Glossaire rapide des énumérations

| Champ | Valeurs possibles |
|---|---|
| `severity` | `WARNING`, `CRITICAL` |
| `action` | `block_ip`, `notify`, `none` |
| `status` | `success`, `failed`, `skipped` |
| `skip_reason` | `severity_warning`, `attacker_ip_null`, `whitelisted`, `null` |
| `enrichment.source` | `abuseipdb`, `cache`, `unavailable` |
| `actor_role` | `direction`, `comptabilite`, `technique`, `basique`, `null` |
| `scenario_type` (interne, pas dans les schémas) | `S1`, `S2`, `S3` implémentés (mapping résolu, cf 5.2). S4/S5 non implémentés côté moteur à ce jour |
