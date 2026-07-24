# NyxSOC — Dashboard

Module de visualisation indépendant pour le projet NyxSOC.

## Stack technique

| Composant | Technologie | Rôle |
|-----------|-------------|------|
| **Flask** | Python 3.12 | Interface web narrative des alertes |
| **Grafana** | Container Docker | Visualisation des métriques et benchmark |
| **SQLite** | Fichier | Source de données (`soar.db`, `engine.db`) |
| **Chart.js** | JS | Graphiques dans l'interface Flask |
| **Docker Compose** | Orchestration | Déploiement unifié Flask + Grafana |
| **pytest** | Python | Tests unitaires des routes |

## Architecture

```
NyxSOC/
├── engine/                     # Moteur de corrélation (Gaël)
│   └── engine.db               # Événements et alertes
├── soar/                       # Module SOAR (Fiodor)
│   └── data/
│       └── soar.db             # Alertes, réponses, enrichissements, audit
└── dashboard/                  # Module visualisation (indépendant)
    ├── flask_app/              # Interface narrative
    │   ├── app.py              # Factory Flask
    │   ├── config.py           # Configuration centralisée
    │   ├── routes/
    │   │   ├── alerts.py       # Liste + détail des alertes
    │   │   ├── responses.py    # Réponses SOAR
    │   │   └── metrics.py      # KPIs et graphiques
    │   ├── templates/          # Jinja2
    │   └── static/             # CSS, JS
    ├── grafana/                # Provisioning
    │   └── provisioning/
    │       ├── datasources/
    │       │   └── sqlite.yaml
    │       └── dashboards/
    │           └── nyxsoc.json
    ├── mock_data/              # Données de démo standalone
    │   ├── alerts/
    │   │   ├── alert_s1.json
    │   │   ├── alert_s2.json
    │   │   └── alert_s3.json
    │   └── mock_engine.db
    ├── tests/                  # Tests unitaires
    ├── docker-compose.yml      # Stack Flask + Grafana
    ├── requirements.txt
    ├── .env.example
    └── README.md
```

## Double approche

- **Grafana** : métriques de benchmark, supervision temps réel, graphiques quantitatifs
- **Flask** : vue narrative des scénarios d'attaque, démo, portfolio

Les deux sont complémentaires et non redondants.

## Prérequis

- Docker & Docker Compose
- Python 3.12+ (pour développement Flask)
- Bases de données (optionnelles en mode mock) :
  - `../soar/data/soar.db` (SOAR)
  - `../engine/engine.db` (moteur de corrélation)

## Configuration

Copier `.env.example` vers `.env` et ajuster les chemins si nécessaire :

```bash
cp .env.example .env
```

| Variable | Défaut | Description |
|----------|--------|-------------|
| `FLASK_DEBUG` | `0` | Mode debug Flask (`1` pour activer) |
| `SECRET_KEY` | `nyxsoc-dashboard-dev` | Clé secrète Flask |
| `SOAR_DB_PATH` | `../soar/data/soar.db` | Chemin vers la base SOAR |
| `ENGINE_DB_PATH` | `../engine/engine.db` | Chemin vers la base engine |
| `MOCK_DATA_DIR` | `./mock_data` | Répertoire des données mockées |
| `MOCK_MODE` | `0` | Forcer le mode standalone (`1` pour activer) |

## Lancement

```bash
cd dashboard

# Mode standalone (données mockées)
MOCK_MODE=1 python -m flask_app.app

# Mode production (bases réelles)
python -m flask_app.app

# Avec Docker Compose (Flask + Grafana)
docker compose up -d
```

## Accès

| Service | URL | Identifiants |
|---------|-----|--------------|
| Flask | http://localhost:5000 | — |
| Grafana | http://localhost:3000 | admin / admin |

## API endpoints

| Méthode | Chemin | Description |
|---------|--------|-------------|
| GET | `/` | Redirection vers métriques |
| GET | `/metrics` | KPIs et graphiques |
| GET | `/alerts` | Liste des alertes avec filtres |
| GET | `/alerts/<id>` | Détail d'une alerte |
| GET | `/responses` | Liste des réponses SOAR |
| GET | `/health` | Santé de l'application + statut DB |

## Tests

```bash
cd dashboard
PYTHONPATH=. .venv/bin/python -m pytest tests/ -v
```

9 tests couvrent :
- Routes principales (200 OK)
- Présence des données mockées
- Détail d'alerte
- API health

## Métriques affichées

- Total alertes
- Taux de succès des blocages OPNsense
- Latence moyenne SOAR
- Alertes par sévérité (donut)
- Latence par scénario (bar)
- Timeline des alertes par heure (line)
- IPs bloquées

## Livrables

- Dépôt GitHub : module dashboard complet
- Docker Compose : déploiement unifié
- Jeu de données mockées : 3 scénarios d'attaque
- Tests unitaires : 9 tests passants
