# Étape 11 — Base de données SQLite + repositories

## Objectif

Persister les alertes, réponses, enrichissements et actions OPNsense dans une base SQLite, avec une couche d'accès par repository.

## Fichiers créés

- `src/soar/db/__init__.py` — export `get_connection`, `initialize_db`, `close_connection`
- `src/soar/db/connection.py` — gestionnaire de connexion (singleton, WAL, FK)
- `src/soar/db/migrations/001_initial_schema.sql` — schéma complet
- `src/soar/db/migrations/002_add_indexes.sql` — (réservé)
- `src/soar/repositories/__init__.py` — export des 3 repositories
- `src/soar/repositories/alert_repository.py` — CRUD alerts
- `src/soar/repositories/response_repository.py` — CRUD responses (transaction 3 tables)
- `src/soar/repositories/audit_repository.py` — audit events
- `tests/unit/test_repositories.py` — 13 tests

## Schéma SQLite

5 tables :

| Table | Rôle |
|---|---|
| `alerts` | Alertes parsées (PK = alert_id) |
| `responses` | Réponses SOAR (PK = response_id, FK → alerts) |
| `enrichments` | Résultats enrichissement (1-1 responses) |
| `opnsense_actions` | Résultats OPNsense (1-1 responses) |
| `audit_events` | Événements d'audit |

## Repositories

| Repository | Méthodes |
|---|---|
| `AlertRepository` | `save`, `get_by_id`, `exists`, `list_recent` |
| `ResponseRepository` | `save` (transaction), `get_by_alert_id`, `get_by_response_id`, `list_failed`, `list_recent` |
| `AuditRepository` | `insert_event`, `list_recent` |

## Tests

- 13 tests : alert CRUD, response avec/sans enrichissement/opnsense, audit events
- Base de données temporaire par test (fixture `_db`)
- Commit : `9b4f240`
