# Étape 13 — Notifications

## Objectif

Implémenter le système de notification pour alerter un humain en cas d'événement critique (échec d'exécution, score AbuseIPDB > 95) et fournir un résumé quotidien.

## Fichiers créés

- `src/soar/notifications/__init__.py` — export `Notifier`
- `src/soar/notifications/notifier.py` — `Notifier` avec canaux Telegram et SMTP
- `tests/unit/test_notifier.py` — 18 tests

## Architecture

```
Notifier.send_immediate_alert(response)
  ├─ _should_notify() : score > 95 OU status == "error"
  ├─ _try_telegram()  → API Telegram (optionnel)
  └─ _try_smtp()      → SMTP (optionnel)

Notifier.send_daily_summary()
  ├─ response_repository.list_recent() → filtre 24h
  ├─ aggrège succès/échecs/ignorées
  ├─ _try_telegram()
  └─ _try_smtp()
```

## Canaux de notification

| Canal | Configuration `.env` | Comportement si absent |
|---|---|---|
| Telegram | `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | Log debug, silencieux |
| SMTP | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_TO` | Log debug, silencieux |

Les deux canaux sont optionnels et indépendants. Si les deux sont absents, aucune notification n'est envoyée — le pipeline continue normalement.

## Conditions de déclenchement

`send_immediate_alert` ne fait rien sauf si :
- `response.status == "error"` (échec API OPNsense, timeout, etc.)
- `response.enrichment.abuseipdb_score > 95` (IP très malveillante)

## Tests

- 18 tests : should_notify, format_response, send_immediate_alert (4 cas), try_telegram (3 cas), try_smtp (2 cas), daily_summary (2 cas)
- Commit : `4cac6d4`
