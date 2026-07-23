# Étape 0 — Mise en place de l'environnement

**Date :** 23 juillet 2026
**Objectif :** environnement Python 3.12 propre et reproductible pour le module SOAR.

---

## Ce qui a été fait

### 1. Virtualenv Python 3.12
Création d'un environnement virtuel dédié au module SOAR :
```bash
python3.12 -m venv .venv
```
L'environnement est isolé du reste du projet — pas de conflit avec l'engine.

### 2. Dépendances installées
Fichier `requirements.txt` avec toutes les dépendances nécessaires :

| Package | Version | Utilité |
|---------|---------|---------|
| `watchdog` | ≥4.0 | Surveillance inotify du dossier d'alertes |
| `jsonschema` | ≥4.0 | Validation des alertes contre le schéma |
| `pyyaml` | ≥6.0 | Lecture config.yaml et whitelist |
| `requests` | ≥2.31 | Appels API AbuseIPDB + OPNsense |
| `python-dotenv` | ≥1.0 | Chargement des variables d'environnement |
| `pytest` | ≥8.0 | Tests unitaires |
| `pytest-mock` | ≥3.0 | Mocking des API externes |

Installation :
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Fichier `.env.example`
Modèle des variables d'environnement nécessaires (sans valeurs réelles) :
- Clé API AbuseIPDB
- URL + credentials API OPNsense
- Tokens Telegram (notifications)
- Configuration SMTP email (optionnel)
- Niveau de log

Le fichier `.env` réel (ignoré par git) est à créer par l'utilisateur.

### 4. Fichier `.gitignore` renforcé
Protection contre le commit de :
- Bases SQLite (`*.db`, `*.db-wal`, `*.db-shm`)
- Fichiers de logs (`*.log`)
- Rapports générés (`*.csv`, `*.pdf`, `*.json`)
- Caches Python (`__pycache__/`, `*.pyc`)
- Environnement virtuel (`.venv/`)
- Fichier `.env` (secrets)
- Caches pytest (`.pytest_cache/`, `.coverage`)
- Fichiers OS (`.DS_Store`, `Thumbs.db`)

### 5. Configuration `config/config.yaml`
Paramètres de base du module SOAR :
- **Seuils :** `severity_threshold: CRITICAL`, `abuseipdb_score_threshold: 50`
- **Timeouts :** `response_timeout_s: 5`, `rule_ttl_hours: 48`
- **Circuit breaker :** `abuseipdb_circuit_breaker_cooldown_s: 300` (5 min)
- **Mapping handlers :** S1 → ssh_handler, S2 → smb_handler, S3 → s3_handler
- **Chemins :** alertes entrantes, schéma, base de données, logs
- **Rotation logs :** 5 Mo max, 5 backups

### 6. Structure des répertoires
Création et suivi git des dossiers vides via `.gitkeep` :
- `data/` — bases SQLite (runtime)
- `logs/` — fichiers de log (runtime)
- `reports/` — rapports générés
- `src/soar/cache/` — cache mémoire + fallback list

### 7. Fichier de cache vide
`src/soar/cache/fallback_list.yaml` créé (sera alimenté à l'étape 6).

---

## Structure finale après l'étape 0

```
soar/
├── .gitignore              # Protections renforcées
├── .env.example            # Template des variables d'environnement
├── requirements.txt        # Dépendances Python
├── config/
│   └── config.yaml         # Configuration du module SOAR
├── data/.gitkeep           # Dossier pour SQLite
├── logs/.gitkeep           # Dossier pour logs
├── reports/.gitkeep        # Dossier pour rapports
├── src/soar/cache/
│   ├── __init__.py
│   └── fallback_list.yaml  # Liste de repli AbuseIPDB (vide pour l'instant)
├── .venv/                  # Virtualenv (ignoré par git)
└── docs/
    └── step-00-environment-setup.md  # Ce fichier
```

---

## Commit

```
chore: setup Python environment and base config
```
