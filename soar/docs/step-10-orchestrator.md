# Étape 10 — Orchestrateur

## Objectif

Coordonner le pipeline complet : watcher → parser → décision → handler.

## Fichiers créés

- `src/soar/orchestrator/__init__.py` — export `AlertOrchestrator`
- `src/soar/orchestrator/orchestrator.py` — pipeline coordonné
- `tests/unit/test_orchestrator.py` — 6 tests

## Architecture

```
AlertWatcher (watchdog)
  → AlertParser (validation + parsing)
    → on_alert callback
      → DecisionEngine.decide()
        → HANDLERS[decision.action]()
          → Response
```

## API

```python
orch = AlertOrchestrator()
orch.start()   # Démarre le watchdog
orch.stop()    # Arrête le watchdog
```

## Gestion d'erreurs

- Erreur de décision → log + continue
- Erreur handler → log + continue
- Action inconnue → log warning + continue

## Tests

- 6 tests : pipeline complet, erreur décision, erreur handler, action inconnue, start/stop, double stop
- Commit : `3e9e7a2`
