# Guide de test — Module Dashboard NyxSOC

## 1. Architecture du module

Le module dashboard est **totalement indépendant** des modules `engine/` et `soar/`. Il peut fonctionner en mode **standalone** avec des données mockées, puis être connecté aux bases de données réelles.

```
dashboard/
├── flask_app/          # Interface narrative (alertes, réponses, métriques)
│   ├── app.py          # Factory Flask + health endpoint
│   ├── config.py       # Configuration centralisée (Dev/Prod/Mock)
│   ├── routes/
│   │   ├── alerts.py       # Liste + détail des alertes
│   │   ├── responses.py    # Réponses SOAR
│   │   └── metrics.py      # KPIs et graphiques
│   ├── templates/      # Jinja2 templates
│   └── static/         # CSS, JS, Chart.js
├── grafana/            # Provisioning (datasource + dashboard JSON)
├── mock_data/          # Données de démo standalone
│   ├── alerts/
│   │   ├── alert_s1.json
│   │   ├── alert_s2.json
│   │   └── alert_s3.json
│   └── mock_engine.db
├── tests/              # Tests unitaires
├── docker-compose.yml  # Stack Flask + Grafana
├── requirements.txt
├── .env.example
└── README.md
```

## 2. Prérequis

- Python 3.12+
- Docker & Docker Compose (pour Grafana uniquement)
- Bases de données (optionnelles en mode mock) :
  - `../soar/data/soar.db`
  - `../engine/engine.db`

## 3. Tests unitaires

### Exécution

```bash
cd /home/fiodor/NYX/dashboard
PYTHONPATH=/home/fiodor/NYX/dashboard .venv/bin/python -m pytest tests/ -v
```

### Résultat attendu

```
tests/test_routes.py::TestMetricsRoute::test_metrics_page_returns_200 PASSED
tests/test_routes.py::TestMetricsRoute::test_metrics_page_contains_charts PASSED
tests/test_routes.py::TestAlertsRoute::test_alerts_page_returns_200 PASSED
tests/test_routes.py::TestAlertsRoute::test_alerts_page_contains_mock_alerts PASSED
tests/test_routes.py::TestAlertsRoute::test_alert_detail_returns_200 PASSED
tests/test_routes.py::TestAlertsRoute::test_alert_detail_contains_ip PASSED
tests/test_routes.py::TestResponsesRoute::test_responses_page_returns_200 PASSED
tests/test_routes.py::TestResponsesRoute::test_responses_page_contains_block_ip PASSED
tests/test_routes.py::TestHealthRoute::test_health_returns_ok PASSED

9 passed in 0.42s
```

### Couverture

| Route | Test | Vérifie |
|-------|------|---------|
| `GET /metrics` | `test_metrics_page_returns_200` | Page accessible |
| `GET /metrics` | `test_metrics_page_contains_charts` | Présence des 3 graphiques Chart.js |
| `GET /alerts` | `test_alerts_page_returns_200` | Page accessible |
| `GET /alerts` | `test_alerts_page_contains_mock_alerts` | 3 alertes mockées présentes |
| `GET /alerts/<id>` | `test_alert_detail_returns_200` | Détail accessible |
| `GET /alerts/<id>` | `test_alert_detail_contains_ip` | Détail contient l'IP attaquant |
| `GET /responses` | `test_responses_page_returns_200` | Page accessible |
| `GET /responses` | `test_responses_page_contains_block_ip` | Présence de l'action block_ip |
| `GET /health` | `test_health_returns_ok` | API health répond |

## 4. Tests fonctionnels — Mode Mock

### 4.1 Lancement de l'application

```bash
cd /home/fiodor/NYX/dashboard
MOCK_MODE=1 PYTHONPATH=/home/fiodor/NYX/dashboard .venv/bin/python -m flask_app.app
```

L'application démarre sur **http://localhost:5000**

### 4.2 Vérification de la page d'accueil

```bash
curl http://localhost:5000/health
```

Réponse attendue :
```json
{
  "status": "ok",
  "soar_db": "missing",
  "engine_db": "missing",
  "mock_mode": true
}
```

### 4.3 Page Alertes

**URL** : http://localhost:5000/alerts

**Vérifications** :
- [ ] 3 alertes affichées (S1, S2, S3)
- [ ] Filtres par sévérité, règle, IP fonctionnels
- [ ] Pagination présente (50 items/page)
- [ ] Clic sur une alerte → détail avec timeline
- [ ] Badges de sévérité colorés (rouge pour CRITICAL, jaune pour WARNING)

**Données mockées** :
- `alert_s1.json` — SSH_BRUTEFORCE_001 (CRITICAL)
- `alert_s2.json` — SMB_EXFIL_001 (CRITICAL)
- `alert_s3.json` — MALICIOUS_FILE_EXEC_001 (CRITICAL)

### 4.4 Page Réponses

**URL** : http://localhost:5000/responses

**Vérifications** :
- [ ] Tableau des réponses SOAR
- [ ] Colonnes : response_id, alert_id, action, status, score AbuseIPDB, OPNsense, latence
- [ ] Filtres par action et statut fonctionnels
- [ ] Badges de statut colorés (vert=success, rouge=error, jaune=skipped)

### 4.5 Page Métriques

**URL** : http://localhost:5000/metrics

**Vérifications** :
- [ ] 3 KPIs affichés : Total alertes, Taux de succès, Latence moyenne
- [ ] Graphique donut "Alertes par sévérité"
- [ ] Graphique bar "Latence par scénario"
- [ ] Graphique line "Alertes par heure"
- [ ] Liste des IPs bloquées
- [ ] Mode démo indiqué quand pas de données réelles

### 4.6 Navigation

**Vérifications** :
- [ ] Navbar avec onglets : Métriques, Alertes, Réponses
- [ ] Onglet actif mis en évidence
- [ ] Footer présent
- [ ] Navigation fluide sans rechargement complet

## 5. Tests fonctionnels — Mode Production

### 5.1 Préparation des bases de données

```bash
cd /home/fiodor/NYX/soar

# Vérifier que les bases existent
ls -la data/soar.db
ls -la /home/fiodor/NYX/engine/engine.db
```

### 5.2 Lancement en mode production

```bash
cd /home/fiodor/NYX/dashboard
PYTHONPATH=/home/fiodor/NYX/dashboard .venv/bin/python -m flask_app.app
```

L'application lit automatiquement :
- `../soar/data/soar.db`
- `../engine/engine.db`

### 5.3 Vérification de la connexion DB

```bash
curl http://localhost:5000/health
```

Réponse attendue :
```json
{
  "status": "ok",
  "soar_db": "/home/fiodor/NYX/soar/data/soar.db",
  "engine_db": "/home/fiodor/NYX/engine/engine.db",
  "mock_mode": false
}
```

### 5.4 Données attendues en production

| Page | Données source |
|------|----------------|
| `/alerts` | Table `alerts` de `soar.db` |
| `/responses` | JOIN `responses` + `enrichments` + `opnsense_actions` |
| `/metrics` | Agrégations sur `soar.db` (alertes, réponses, enrichissements) |

## 6. Tests avec Docker Compose

### 6.1 Prérequis

- Docker & Docker Compose installés
- Accès Internet pour le build Flask

### 6.2 Lancement

```bash
cd /home/fiodor/NYX/dashboard
docker compose up -d --build
```

### 6.3 Vérification des conteneurs

```bash
docker compose ps
```

Attendu :
```
NAME                  IMAGE                STATUS
dashboard-flask-1     dashboard-flask      Up (port 5000)
dashboard-grafana-1   grafana/grafana      Up (port 3000)
```

### 6.4 Accès aux services

| Service | URL | Identifiants |
|---------|-----|--------------|
| Flask | http://localhost:5000 | — |
| Grafana | http://localhost:3000 | admin / admin |

### 6.5 Grafana — Vérification du dashboard

1. Ouvrir http://localhost:3000
2. Login : `admin` / `admin`
3. Dashboard : **NyxSOC Dashboard**
4. Vérifier :
   - [ ] 5 panels présents
   - [ ] Datasource `NyxSOC-SQLite` sélectionnée
   - [ ] Données affichées (après peuplement de `soar.db`)

### 6.6 Nettoyage

```bash
docker compose down
docker volume rm dashboard_grafana-storage
```

## 7. Tests de données mock

### 7.1 Alertes mockées

Fichiers dans `mock_data/alerts/` :

| Fichier | Règle | Sévérité | IP attaquant |
|---------|-------|----------|--------------|
| `alert_s1.json` | SSH_BRUTEFORCE_001 | CRITICAL | 185.220.101.99 |
| `alert_s2.json` | SMB_EXFIL_001 | CRITICAL | 185.220.101.99 |
| `alert_s3.json` | MALICIOUS_FILE_EXEC_001 | CRITICAL | null |

### 7.2 Base mock_engine.db

```bash
sqlite3 mock_data/mock_engine.db "SELECT COUNT(*) FROM alerts;"
sqlite3 mock_data/mock_engine.db "SELECT COUNT(*) FROM events;"
```

Attendu : 3 alertes, 4 événements

## 8. Tests de l'API

### 8.1 Health endpoint

```bash
curl http://localhost:5000/health
```

### 8.2 Routes principales

```bash
curl -o /dev/null -s -w "%{http_code}" http://localhost:5000/
curl -o /dev/null -s -w "%{http_code}" http://localhost:5000/metrics
curl -o /dev/null -s -w "%{http_code}" http://localhost:5000/alerts
curl -o /dev/null -s -w "%{http_code}" http://localhost:5000/responses
curl -o /dev/null -s -w "%{http_code}" http://localhost:5000/alerts/550e8400-e29b-41d4-a716-446655440001
```

Attendu : `200` pour toutes les routes

## 9. Tests de filtres

### 9.1 Filtres alertes

```bash
curl "http://localhost:5000/alerts?severity=CRITICAL" | grep -c "CRITICAL"
curl "http://localhost:5000/alerts?rule_id=SSH_BRUTEFORCE_001" | grep -c "SSH_BRUTEFORCE_001"
curl "http://localhost:5000/alerts?attacker_ip=185.220.101.99" | grep -c "185.220.101.99"
```

### 9.2 Filtres réponses

```bash
curl "http://localhost:5000/responses?action=block_ip" | grep -c "block_ip"
curl "http://localhost:5000/responses?status=success" | grep -c "success"
```

## 10. Tests de peuplement de données

### 10.1 Peuplement rapide pour tests

```bash
cd /home/fiodor/NYX/soar
PYTHONPATH=src .venv/bin/python -c "
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

db_path = Path('data/soar.db')
conn = sqlite3.connect(db_path)
cur = conn.cursor()

now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

alerts = [
    ('alert-test-1', 'SSH_BRUTEFORCE_001', 'CRITICAL', '185.220.101.99', 'debian-server', '10.0.1.20', 'TA0006', 'T1110', 15, now_ms - 3600000),
    ('alert-test-2', 'SMB_EXFIL_001', 'CRITICAL', '185.220.101.99', 'debian-server', '10.0.1.20', 'TA0010', 'T1021.002', 8, now_ms - 3500000),
    ('alert-test-3', 'MALICIOUS_FILE_EXEC_001', 'CRITICAL', None, 'DESKTOP-PME', '10.0.1.30', 'TA0002', 'T1204.002', 3, now_ms - 3400000),
    ('alert-test-4', 'SSH_BRUTEFORCE_001', 'WARNING', '10.0.1.50', 'debian-server', '10.0.1.20', 'TA0006', 'T1110', 5, now_ms - 3300000),
    ('alert-test-5', 'WEB_BRUTEFORCE_001', 'WARNING', '192.168.1.100', 'debian-server', '10.0.1.20', 'TA0006', 'T1110.001', 25, now_ms - 3200000),
]

cur.executemany('''
    INSERT OR IGNORE INTO alerts (alert_id, rule_id, severity, attacker_ip, target_host, target_ip, mitre_tactic, mitre_technique, events_count, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''', alerts)

responses = [
    ('resp-test-1', 'alert-test-1', 'block_ip', 'success', None, None, now_ms - 3590000, now_ms - 3590000, 150),
    ('resp-test-2', 'alert-test-2', 'block_ip', 'success', None, None, now_ms - 3490000, now_ms - 3490000, 200),
    ('resp-test-3', 'alert-test-3', 'notify', 'success', None, None, now_ms - 3390000, now_ms - 3390000, 50),
    ('resp-test-4', 'alert-test-4', 'none', 'skipped', 'severity_warning', None, now_ms - 3290000, now_ms - 3290000, 10),
    ('resp-test-5', 'alert-test-5', 'block_ip', 'error', None, 'OPNsense timeout', now_ms - 3190000, now_ms - 3190000, 5000),
]

cur.executemany('''
    INSERT OR IGNORE INTO responses (response_id, alert_id, action, status, skip_reason, error, alert_timestamp, response_timestamp, latency_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
''', responses)

enrichments = [
    ('resp-test-1', 'abuseipdb', 85, 'RU', 'Hoster', False),
    ('resp-test-2', 'abuseipdb', 92, 'NG', 'Hoster', False),
    ('resp-test-3', 'cache', 45, 'TG', 'Unknown', True),
]

cur.executemany('''
    INSERT OR IGNORE INTO enrichments (response_id, source, abuseipdb_score, country_code, isp, fallback_used)
    VALUES (?, ?, ?, ?, ?, ?)
''', enrichments)

opnsense_actions = [
    ('resp-test-1', 'soar_blocklist', '185.220.101.99', 200, 1),
    ('resp-test-2', 'soar_blocklist', '185.220.101.99', 200, 1),
    ('resp-test-5', 'soar_blocklist', '192.168.1.100', 500, 3),
]

cur.executemany('''
    INSERT OR IGNORE INTO opnsense_actions (response_id, rule_id, blocked_ip, api_status_code, retry_count)
    VALUES (?, ?, ?, ?, ?)
''', opnsense_actions)

conn.commit()
conn.close()

print('Données insérées avec succès')
print('Alertes: 5')
print('Réponses: 5')
print('Enrichissements: 3')
print('Actions OPNsense: 3')
"
```

### 10.2 Vérification après peuplement

```bash
# Flask
curl http://localhost:5000/alerts | grep -c "alert-test"

# SQLite direct
sqlite3 /home/fiodor/NYX/soar/data/soar.db "SELECT COUNT(*) FROM alerts;"
```

Attendu : 13 alertes (8 initiales + 5 nouvelles)

## 11. Tests de la CLI

### 11.1 generate_report.py

```bash
cd /home/fiodor/NYX/soar
PYTHONPATH=src .venv/bin/python scripts/generate_report.py summary --since-hours 24
PYTHONPATH=src .venv/bin/python scripts/generate_report.py alerts --since-hours 24
PYTHONPATH=src .venv/bin/python scripts/generate_report.py responses --since-hours 24
```

Attendu : fichiers CSV générés dans `reports/`

### 11.2 cleanup_expired_rules.py

```bash
cd /home/fiodor/NYX/soar
PYTHONPATH=src .venv/bin/python scripts/cleanup_expired_rules.py
```

Attendu : log indiquant le nombre de règles expirées nettoyées

### 11.3 rotate_logs.sh

```bash
cd /home/fiodor/NYX/soar
bash scripts/rotate_logs.sh
```

Attendu : rotation des logs si seuil dépassé

## 12. Limitations connues

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Grafana provisioning automatique | Dashboard peut ne pas apparaître au démarrage | Importer manuellement `grafana/provisioning/dashboards/nyxsoc/nyxsoc.json` |
| Plugin SQLite nécessite Internet | Build Docker échoue sans DNS | Installer le plugin via `grafana-cli plugins install` |
| Time range restrictif | Panels vides si données anciennes | Utiliser `now-24h` ou `now-7d` |
| SQLite WAL files | Erreur "unable to open database file" si volume en `:ro` | Monter les volumes DB en écriture |

## 13. Checklist de validation avant commit

- [ ] `pytest tests/ -v` passe (9 tests)
- [ ] Flask démarre en mode mock (`MOCK_MODE=1`)
- [ ] Flask démarre en mode production (chemins DB valides)
- [ ] Les 3 pages (Alertes, Réponses, Métriques) s'affichent
- [ ] Les filtres fonctionnent
- [ ] Les données mockées sont présentes dans `mock_data/`
- [ ] `docker-compose.yml` valide (`docker compose config`)
- [ ] `requirements.txt` à jour
- [ ] `.env.example` présent et complet
