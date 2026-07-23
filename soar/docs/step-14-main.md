# Étape 14 — Point d'entrée `main.py`

## Objectif

Créer le point d'entrée unique du module SOAR : câblage des dépendances, démarrage de l'orchestrateur, planification du résumé quotidien, arrêt propre sur signaux.

## Fichiers créés

- `src/soar/main.py` — fonction `main()` + helpers
- `tests/unit/test_main.py` — 5 tests

## Cycle de vie

```
1. setup_soar_logging()     ← configuration logging (fichier + console)
2. initialize_db()           ← création tables SQLite
3. AlertOrchestrator()       ← câblage watcher → parser → engine → handlers
4. Notifier()                ← notifications Telegram/SMTP
5. signal.signal(SIGINT/SIGTERM) ← handler d'arrêt
6. _daily_loop() (thread)    ← résumé quotidien toutes les 24h
7. orchestrator.start()      ← démarre le watchdog
8. _shutdown.wait()          ← bloquant jusqu'au signal
9. orchestrator.stop()       ← arrêt propre
```

## Gestion des signaux

```python
def _signal_handler(signum, frame):
    _shutdown.set()  # libère wait() → provoque l'arrêt
```

`SIGINT` (Ctrl+C) et `SIGTERM` (systemd/docker) sont capturés.

## Planificateur

Un thread daemon `daily-summary` appelle `Notifier.send_daily_summary()` toutes les 86400s. Les erreurs sont logguées sans crasher le thread principal.

## Tests

- 5 tests : démarrage/arrêt orchestrateur, échec DB, signal handler, daily loop (normal + erreur)
- Commit : `f05578f`
