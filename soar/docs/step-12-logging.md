# Étape 12 — Logging et audit

## Objectif

Mettre en place le logging applicatif (rotation), la piste d'audit JSONL + SQLite, et la persistance des réponses.

## Fichiers créés

- `src/soar/logging/__init__.py` — export `setup_soar_logging`, `AuditLogger`, `ResponseWriter`
- `src/soar/logging/soar_log.py` — configuration logging (RotatingFileHandler + StreamHandler)
- `src/soar/logging/audit_logger.py` — écriture JSONL + délégation à `audit_repository.insert_event()`
- `src/soar/logging/response_writer.py` — appel à `response_repository.save(response)`
- `tests/unit/test_logging.py` — 6 tests

## Architecture

```
AuditLogger.log(alert, decision, response)
  ├─ _write_jsonl() → logs/audit.log (JSONL)
  └─ audit_repository.insert_event() → SQLite

ResponseWriter.write(response)
  └─ response_repository.save(response) → SQLite
```

## Tests

- 6 tests : setup logging, JSONL écrit + lu, log sans response, erreur I/O, ResponseWriter
- Commit : `9be54c3`
