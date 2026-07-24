# Planning de développement — Dashboard NyxSOC

## Principe

Le module dashboard est **totalement indépendant** des modules `engine/` et `soar/`.
Il peut fonctionner en mode **standalone** avec des données mockées, puis être connecté
aux bases de données réelles une fois les deux modules opérationnels.

Chaque étape est atomique, testable manuellement, et fait l'objet d'un commit
avant de passer à la suivante.

---

## Étape 1 — Structure et fichiers de base

**Objectif :** Créer la structure du module et les fichiers de configuration.

**Fichiers concernés :**
- `dashboard/README.md`
- `dashboard/requirements.txt`
- `dashboard/.gitignore`
- `dashboard/docker-compose.yml`

**Actions :**
- README : présentation du module, stack technique, prérequis
- requirements.txt : Flask, requests, python-dotenv, gunicorn
- .gitignore : patterns Python, venv, __pycache__, .env, .DS_Store
- docker-compose.yml : services `flask` + `grafana`, réseaux, volumes

**Validation :**
```bash
cd dashboard
docker compose config   # valide la syntaxe
```

**Commit :**
```
feat(dashboard): initialize module structure, README, requirements, docker-compose
```

---

## Étape 2 — Squelette Flask

**Objectif :** Application Flask fonctionnelle avec routes de base.

**Fichiers concernés :**
- `dashboard/flask_app/app.py` (factory pattern)
- `dashboard/flask_app/routes/__init__.py`
- `dashboard/flask_app/templates/base.html` (layout commun)
- `dashboard/flask_app/static/css/style.css` (styles de base)

**Actions :**
- Factory `create_app()` avec blueprints
- Blueprint `alerts`, `responses`, `metrics`
- Template de base avec navigation (onglets)
- Styles CSS minimaux (dark theme inspiré SOC)
- Route `/health` pour vérifier que l'app tourne

**Validation :**
```bash
python -m flask_app.app
# Ouvrir http://localhost:5000
```

**Commit :**
```
feat(dashboard): add Flask app skeleton with blueprints and base template
```

---

## Étape 3 — Route Alertes

**Objectif :** Afficher la liste des alertes avec filtres.

**Fichiers concernés :**
- `dashboard/flask_app/routes/alerts.py`
- `dashboard/flask_app/templates/alerts/index.html`
- `dashboard/flask_app/static/js/alerts.js` (filtres dynamiques)

**Actions :**
- Route GET `/` et `/alerts`
- Lecture depuis `data/soar.db` (table `alerts`) si disponible, sinon mock
- Filtres : sévérité, règle, IP attaquant, plage de dates
- Pagination simple (50 items par page)
- Clic sur alerte → détail avec events_details

**Validation :**
- Lancer avec `mock_data/` : affiche 3 alertes S1/S2/S3
- Filtres fonctionnels

**Commit :**
```
feat(dashboard): add alerts list page with filters and pagination
```

---

## Étape 4 — Route Réponses

**Objectif :** Afficher les réponses SOAR avec enrichissement et actions OPNsense.

**Fichiers concernés :**
- `dashboard/flask_app/routes/responses.py`
- `dashboard/flask_app/templates/responses/index.html`
- `dashboard/flask_app/static/js/responses.js`

**Actions :**
- Route GET `/responses`
- JOIN responses + enrichments + opnsense_actions
- Colonnes : alert_id, action, status, abuseipdb_score, opnsense_status, latence_ms
- Filtres : action, status, plage de dates
- Lien vers l'alerte correspondante

**Validation :**
- Affichage correct des réponses avec enrichissement
- Filtres action/status fonctionnels

**Commit :**
```
feat(dashboard): add responses page with enrichment and OPNsense details
```

---

## Étape 5 — Route Métriques

**Objectif :** Dashboard de métriques agrégées.

**Fichiers concernés :**
- `dashboard/flask_app/routes/metrics.py`
- `dashboard/flask_app/templates/metrics/index.html`
- `dashboard/flask_app/static/js/metrics.js`

**Actions :**
- Route GET `/metrics`
- KPIs : total alertes, taux de succès block_ip, latence moyenne, top IPs
- Graphiques Chart.js :
  - Alertes par heure (timeline)
  - Répartition par sévérité (pie)
  - Latence par scénario (bar)
  - Taux de succès OPNsense (gauge)
- API JSON interne pour alimenter les graphiques

**Validation :**
- Graphiques s'affichent avec données mock
- KPIs corrects

**Commit :**
```
feat(dashboard): add metrics page with Chart.js visualizations
```

---

## Étape 6 — Assets statiques et polish

**Objectif :** Finaliser l'interface et l'expérience utilisateur.

**Fichiers concernés :**
- `dashboard/flask_app/static/css/style.css` (complet)
- `dashboard/flask_app/static/js/main.js` (navigation, thème)
- `dashboard/flask_app/templates/base.html` (navbar, footer)
- `dashboard/flask_app/templates/alerts/detail.html`
- `dashboard/flask_app/templates/errors/404.html`, `500.html`

**Actions :**
- Dark theme cohérent (inspiration SOC : bleu nuit, rouge alerte, vert succès)
- Responsive minimal (fonctionne sur laptop)
- Navigation entre onglets sans rechargement (SPA feel)
- Page détail alerte : vue narrative de la chaîne d'événements
- Gestion des erreurs (DB indisponible, pas de données)

**Validation :**
- Navigation fluide entre les 3 pages
- Responsive correct

**Commit :**
```
feat(dashboard): polish UI with dark theme, navigation and error pages
```

---

## Étape 7 — Grafana provisioning

**Objectif :** Configurer Grafana pour lire les bases SQLite.

**Fichiers concernés :**
- `dashboard/grafana/provisioning/datasources/sqlite.yaml`
- `dashboard/grafana/provisioning/dashboards/nyxsoc.json`
- `dashboard/docker-compose.yml` (ajout volume vers `data/`)

**Actions :**
- Datasource SQLite pointant vers `data/soar.db` (et `engine/engine.db` si dispo)
- Dashboard JSON avec panels :
  - Alertes par heure (chronologique)
  - Alertes par sévérité (donut)
  - Top 10 IPs attaquantes (bar)
  - Taux de succès OPNsense (stat)
  - Latence moyenne par scénario (bar)
  - Timeline des blocages (table)
- docker-compose.yml : volume `data/:/app/data:ro` pour Grafana

**Validation :**
```bash
docker compose up grafana -d
# Ouvrir http://localhost:3000 (admin/admin)
# Importer dashboard via provisioning
```

**Commit :**
```
feat(dashboard): add Grafana provisioning with SQLite datasource and dashboard
```

---

## Étape 8 — Mock data et mode standalone

**Objectif :** Permettre de lancer le dashboard sans SOAR ni engine.

**Fichiers concernés :**
- `dashboard/mock_data/alerts/alert_s1.json`
- `dashboard/mock_data/alerts/alert_s2.json`
- `dashboard/mock_data/alerts/alert_s3.json`
- `dashboard/mock_data/mock_engine.db` (SQLite avec données de test)
- `dashboard/flask_app/config.py` (config centralisée)

**Actions :**
- 3 alertes réalistes conformes au schéma (S1, S2, S3)
- mock_engine.db : tables events, alerts avec 50-100 événements
- config.py : chemins configurables (DEV vs PROD)
- Mode DEV : lit mock_data/
- Mode PROD : lit data/soar.db et engine/engine.db

**Validation :**
```bash
python -m flask_app.app --mock
# Dashboard fonctionne sans base SOAR réelle
```

**Commit :**
```
feat(dashboard): add mock data and standalone mode for demo
```

---

## Étape 9 — Intégration bases réelles

**Objectif :** Connecter le dashboard aux bases de données du SOAR et de l'engine.

**Fichiers concernés :**
- `dashboard/flask_app/config.py` (mise à jour)
- `dashboard/flask_app/routes/alerts.py` (lecture engine.db)
- `dashboard/flask_app/routes/metrics.py` (jointures cross-DB)

**Actions :**
- Détection automatique de la présence de `engine/engine.db` et `data/soar.db`
- Fallback gracieux sur mock_data si bases absentes
- Route `/api/health` : statut des connexions DB
- Page d'accueil adaptative selon les sources disponibles

**Validation :**
- Avec SOAR arrêté → mode mock automatique
- Avec SOAR démarré → données réelles affichées

**Commit :**
```
feat(dashboard): integrate with real SOAR and engine databases
```

---

## Étape 10 — Tests et documentation finale

**Objectif :** Finaliser le module pour la livraison.

**Fichiers concernés :**
- `dashboard/README.md` (complet)
- `dashboard/tests/` (tests unitaires Flask)
- `dashboard/.env.example`

**Actions :**
- README : installation, lancement, configuration, captures d'écran attendues
- Tests : pytest avec mock DB, test des routes, test des templates
- .env.example : FLASK_DEBUG, DB paths, SECRET_KEY
- Script `docker-compose.yml` final prêt pour démo

**Validation :**
```bash
pytest                    # tous les tests passent
docker compose up -d      # Flask + Grafana démarrent
```

**Commit :**
```
feat(dashboard): add tests, documentation and final docker-compose
```

---

## Récapitulatif

| Étape | Livrable | Durée estimée | Commit |
|-------|----------|---------------|--------|
| 1 | Structure + config | 30 min | `feat(dashboard): initialize module` |
| 2 | Squelette Flask | 1h | `feat(dashboard): add Flask skeleton` |
| 3 | Route Alertes | 1h | `feat(dashboard): add alerts page` |
| 4 | Route Réponses | 1h | `feat(dashboard): add responses page` |
| 5 | Route Métriques | 1h30 | `feat(dashboard): add metrics page` |
| 6 | Assets + polish | 1h30 | `feat(dashboard): polish UI` |
| 7 | Grafana provisioning | 1h | `feat(dashboard): add Grafana setup` |
| 8 | Mock data + standalone | 45 min | `feat(dashboard): add mock data` |
| 9 | Intégration DB réelles | 1h | `feat(dashboard): integrate real DBs` |
| 10 | Tests + docs finales | 1h | `feat(dashboard): finalize tests and docs` |

**Total estimé : 8-10 heures de développement.**
