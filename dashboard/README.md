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

## Architecture

```
dashboard/
├── flask_app/          # Interface narrative (alertes, réponses, métriques)
│   ├── app.py          # Factory Flask
│   ├── routes/         # Blueprints : alerts, responses, metrics
│   ├── templates/      # Jinja2 templates
│   └── static/         # CSS, JS, images
│
├── grafana/            # Provisioning Grafana (datasource + dashboard)
│   └── provisioning/
│       ├── datasources/
│       └── dashboards/
│
├── mock_data/          # Données de démo standalone
│   ├── alerts/         # alert_s1.json, alert_s2.json, alert_s3.json
│   └── mock_engine.db  # Base SQLite de test
│
├── docker-compose.yml  # Stack complète
├── requirements.txt    # Dépendances Python
└── README.md
```

## Double approche

- **Grafana** : métriques de benchmark, supervision temps réel, graphiques quantitatifs
- **Flask** : vue narrative des scénarios d'attaque, démo, portfolio

Les deux sont complémentaires et non redondants.

## Prérequis

- Docker & Docker Compose
- Python 3.12+ (pour développement Flask)
- Bases de données :
  - `data/soar.db` (SOAR)
  - `engine/engine.db` (moteur de corrélation)

## Lancement

```bash
cd dashboard

# Mode standalone (données mockées)
python -m flask_app.app --mock

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
