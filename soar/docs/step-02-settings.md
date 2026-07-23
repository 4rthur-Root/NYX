# Étape 2 — Configuration et settings

**Date :** 23 juillet 2026
**Objectif :** centraliser la lecture de toutes les variables d'environnement et de `config.yaml`.

---

## Fichier créé

```
src/soar/config/
├── __init__.py       # Export du singleton settings
├── config.yaml       # Paramètres métier (seuils, chemins, logging)
└── settings.py       # Point d'entrée unique de configuration
```

**Note :** Le dossier `config/` a été déplacé de `soar/config/` vers `src/soar/config/` pour que l'import `from soar.config.settings import settings` fonctionne correctement dans le package Python.

---

## Architecture du module `settings.py`

### Principe

Deux sources de configuration, strictement séparées :

| Source | Contenu | Exemple |
|--------|---------|---------|
| `.env` (via `python-dotenv`) | **Secrets** (clés API, tokens) | `ABUSEIPDB_API_KEY`, `OPNSENSE_API_SECRET` |
| `config.yaml` (via `pyyaml`) | **Paramètres métier** (seuils, chemins) | `abuseipdb_score_threshold: 50` |

### Cycle de vie

```
settings.py est importé
    ↓
Charge .env depuis SOAR_ROOT/.env  (python-dotenv)
    ↓
Charge config.yaml depuis le même dossier  (pyyaml)
    ↓
Valide les 4 variables obligatoires
    ↓
Expose un singleton settings.*
```

### Singleton

Le module expose une instance unique de la classe `Settings` :
```python
from soar.config.settings import settings

# Usage :
threshold = settings.abuseipdb_score_threshold
api_url = settings.opnsense_api_url
```

### Propriétés exposées

#### Depuis `config.yaml` (paramètres métier)

| Propriété | Type | Valeur par défaut |
|-----------|------|-------------------|
| `severity_threshold` | `str` | `CRITICAL` |
| `response_timeout_s` | `int` | `5` |
| `abuseipdb_score_threshold` | `int` | `50` |
| `abuseipdb_circuit_breaker_cooldown_s` | `int` | `300` |
| `rule_ttl_hours` | `int` | `48` |
| `handler_mapping` | `dict` | `{S1: ssh_handler, S2: smb_handler, S3: s3_handler}` |
| `alerts_incoming` | `str` | `/var/log/nyx/` |
| `alert_schema_path` | `Path` | Résolu depuis `../docs/alert-schema.json` |
| `fallback_list_path` | `Path` | Résolu depuis `src/soar/cache/fallback_list.yaml` |
| `database_path` | `Path` | Résolu depuis `data/soar.db` |
| `soar_log_path` | `Path` | Résolu depuis `logs/soar.log` |
| `audit_log_path` | `Path` | Résolu depuis `logs/audit.log` |
| `rotation_max_bytes` | `int` | `5000000` |
| `rotation_backup_count` | `int` | `5` |

#### Depuis `.env` (secrets)

| Propriété | Obligatoire | Description |
|-----------|-------------|-------------|
| `abuseipdb_api_key` | Oui | Clé API AbuseIPDB |
| `opnsense_api_url` | Oui | URL de l'API OPNsense |
| `opnsense_api_key` | Oui | Clé API OPNsense |
| `opnsense_api_secret` | Oui | Secret API OPNsense |
| `opnsense_verify_ssl` | Non (défaut: `false`) | Vérification SSL (false en lab) |
| `log_level` | Non (défaut: `INFO`) | Niveau de logging |

#### Notifications (optionnelles, retournent `None` si absentes)

| Propriété | Description |
|-----------|-------------|
| `telegram_bot_token` | Token bot Telegram |
| `telegram_chat_id` | Chat ID Telegram |
| `smtp_host` | Serveur SMTP |
| `smtp_port` | Port SMTP (défaut: 587) |
| `smtp_user` | Utilisateur SMTP |
| `smtp_password` | Mot de passe SMTP |
| `smtp_to` | Destinataire email |

### Validation au démarrage

Si l'une des 4 variables obligatoires (`ABUSEIPDB_API_KEY`, `OPNSENSE_API_URL`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET`) est absente, `Settings.__init__()` lève une `EnvironmentError` explicite avec les instructions pour créer le `.env`.

**Exemple d'erreur :**
```
Variables d'environnement obligatoires manquantes.
Créez un fichier .env à la racine du module SOAR:
  cp .env.example .env
Et renseignez les valeurs suivantes:
  - ABUSEIPDB_API_KEY: Clé API AbuseIPDB (https://www.abuseipdb.com)
  - OPNSENSE_API_URL: URL de l'API OPNsense (ex: https://10.0.1.1/api)
```

### Résolution des chemins

Les chemins relatifs dans `config.yaml` sont résolus par rapport à la racine du projet SOAR (`soar/`). Les chemins absolus sont utilisés tels quels. Cela permet de :
- Fonctionner aussi bien en développement (chemins relatifs) qu'en production (chemins absolus)
- Ne pas casser les imports si le répertoire de lancement change

---

## Commit

```
feat(config): add settings loader with env validation
```
