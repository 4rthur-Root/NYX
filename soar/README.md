# NyxSOC — Module SOAR

Security Orchestration, Automation and Response pour l'infrastructure NyxSOC.

## Architecture

```
Alert (JSON) → Watcher → AlertParser → DecisionEngine → Handler → OPNsense / Notifications
                                              ↘
                                         AlertRepository (SQLite)
```

## Quick Start

```bash
cp .env.example .env   # renseigner les clés OPNsense
pip install -r requirements.txt
PYTHONPATH=src python -m soar.main
```

Déposer une alerte dans `/tmp/nyx_alerts/` (format `docs/alert-schema.json`).

## Tests

```bash
pytest -v   # 111 tests
```

## Structure

| Couche | Dossier |
|--------|---------|
| Entry point | `src/soar/main.py` |
| Orchestrateur | `src/soar/orchestrator/` |
| Moteur de décision | `src/soar/engine/` |
| Parsing alerte | `src/soar/parser/` |
| Surveillant fichier | `src/soar/watcher/` |
| Intégrations | `src/soar/integrations/` (OPNsense, AbuseIPDB) |
| Handlers | `src/soar/handlers/` (block_ip, notify, ignore) |
| Persistance | `src/soar/db/` + `src/soar/repositories/` |
| Logging | `src/soar/logging/` |
| Notifications | `src/soar/notifications/` (Telegram, SMTP) |
| Config | `src/soar/config/` |

## OPNsense

Alias requis : `soar_blocklist` (type `Host(s)`) avec règle firewall bloquant → any.
