# Étape 9 — Handlers

## Objectif

Implémenter les 3 actions possibles du playbook : `block_ip`, `notify`, `ignore`.

## Fichiers créés

- `src/soar/handlers/__init__.py`
- `src/soar/handlers/handler.py` — 3 handlers + registre `HANDLERS`
- `tests/unit/test_handlers.py` — 10 tests

## Handlers

| Handler | Action | Description |
|---|---|---|
| `handle_block_ip` | `block_ip` | Appelle `OPNsenseClient.block_ip(ip)` |
| `handle_notify` | `notify` | Log l'alerte + enrichissement |
| `handle_ignore` | `none` | No-op, status "skipped" |

## Registre

```python
HANDLERS = {
    "block_ip": handle_block_ip,
    "notify": handle_notify,
    "none": handle_ignore,
}
```

## Tests

- 10 tests : block success/échec/null_ip, notify avec/sans enrichissement, ignore, registry mapping, couverture playbook
- Commit : `0a1da36`
