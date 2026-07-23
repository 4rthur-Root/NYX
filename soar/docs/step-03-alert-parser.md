# Étape 3 — Parser et validation du schéma

**Date :** 23 juillet 2026
**Objectif :** valider chaque alerte entrante contre `alert-schema.json` et la désérialiser en dataclass `Alert`.

---

## Fichiers créés

```
src/soar/parser/
├── __init__.py          # Export de AlertParser + AlertValidationError
└── alert_parser.py      # Parseur JSON → Alert avec validation jsonschema

tests/
├── conftest.py          # Configuration pytest (PATH, env vars de test)
├── __init__.py
├── unit/
│   ├── __init__.py
│   └── test_alert_parser.py    # 8 tests
└── integration/
    └── __init__.py
```

---

## Classe `AlertParser`

### Responsabilité
Transformer un JSON brut d'alerte (provenant du fichier écrit par le moteur de corrélation) en objet `Alert` typé. Valide rigoureusement contre `alert-schema.json` avant toute désérialisation.

### Dépendances
- `jsonschema` — validation du JSON contre le schéma
- `models/alert.py` — dataclasses `Alert`, `EventDetail`, `YaraMatch`
- `config/settings.py` — chemin du fichier `alert-schema.json`

### Méthodes publiques

| Méthode | Entrée | Sortie | Erreur |
|---------|--------|--------|--------|
| `parse_dict(data)` | `dict` | `Alert` | `AlertValidationError` si invalide |
| `parse_file(file_path)` | `str \| Path` | `Alert` | `AlertValidationError` si lecture ou validation échoue |

### Flux interne

```
parse_file(path)
    ↓
lit le fichier JSON
    ↓
parse_dict(data)
    ↓
jsonschema.validate(data, schema)  ← validation stricte
    ↓
_build_alert(data)                  ← construction des dataclasses
    ↓
Alert
```

### Gestion des erreurs
- **Ne crashe jamais** le pipeline : toute erreur de validation ou de lecture est convertie en `AlertValidationError` (exception métier) qui doit être capturée par l'appelant (`AlertWatcher`)
- Le message d'erreur `jsonschema` est conservé dans l'exception pour faciliter le débogage

### Cas limites gérés
- `attacker_ip: null` → `Alert.attacker_ip = None` (pas la chaîne `"null"`)
- `yara_match: null` → `Alert.yara_match = None`
- `events.details` tronqué (≤ 20 items) → pas de supposition `len(details) == count`
- Champs optionnels absents → `None` par défaut

---

## Tests unitaires (8 tests)

| Test | Scénario |
|------|----------|
| `test_s1_returns_alert_object` | Alerte S1 valide → objet Alert avec les bons champs |
| `test_s1_events_are_parsed` | Les events sont correctement transformés en EventDetail |
| `test_s3_attacker_ip_null` | S3 avec `attacker_ip: null` + `yara_match` renseigné |
| `test_attacker_ip_none_no_exception` | `attacker_ip: null` ne lève pas d'exception |
| `test_missing_field_raises_error` | Champ `severity` manquant → `AlertValidationError` |
| `test_wrong_severity_raises_error` | `severity: "INVALID"` → `AlertValidationError` |
| `test_missing_events_raises_error` | `events` absent → `AlertValidationError` |
| `test_empty_dict_raises_error` | `{}` → `AlertValidationError` |

Exécution :
```bash
cd soar
source .venv/bin/activate
python -m pytest tests/unit/test_alert_parser.py -v
```

---

## Commit

```
feat(parser): add alert JSON validator and deserializer
```
