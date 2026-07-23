# Étape 8 — Moteur de décision

## Objectif

Implémenter la logique qui transforme une `Alert` en `Decision` : sévérité → IP nulle → whitelist → enrichissement AbuseIPDB → playbook.

## Fichiers créés

- `src/soar/engine/__init__.py` — export `DecisionEngine`
- `src/soar/engine/rules.py` — données statiques (PLAYBOOK, WHITELIST, RULE_TO_SCENARIO, SCENARIOS_EXPECTING_IP)
- `src/soar/engine/decision_engine.py` — `DecisionEngine.decide()` avec séquence DCD complète
- `tests/unit/test_decision_engine.py` — 9 tests

## Architecture

```
Alert → DecisionEngine.decide()
  ├─ severity == "WARNING"       → none (skip)
  ├─ attacker_ip is None (S1/S2) → none (skip)
  ├─ attacker_ip in WHITELIST    → none (skip)
  ├─ AbuseIPDB score < threshold → notify (override)
  └─ PLAYBOOK[rule_id]          → block_ip / notify
```

## Décisions DCD

- `WHITELIST` appliquée uniquement si `attacker_ip` non-null
- S3 (MALICIOUS_FILE_EXEC) a `attacker_ip=None` par design : ne déclenche pas le skip "null IP"
- Le score AbuseIPDB < threshold override l'action du playbook en "notify"

## Tests

- 9 tests unitaires : WARNING, null_ip S1/S3, whitelist, playbook S1/S3, override score, rule_id inconnu
- Commit : `cb24d1e`
