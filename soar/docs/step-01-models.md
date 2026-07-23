# Étape 1 — Modèles de données (dataclasses)

**Date :** 23 juillet 2026
**Objectif :** dataclasses typées pour `Alert`, `Decision`, `Response` — le vocabulaire commun de tout le module SOAR.

---

## Fichiers créés

```
src/soar/models/
├── __init__.py       # Exports publics
├── alert.py          # Alert + EventDetail + YaraMatch
├── decision.py       # Decision + EnrichmentResult
└── response.py       # Response + OpnsenseResult
```

---

## Détail des classes

### `alert.py` — Fondation du module

**`EventDetail`** — détail d'un événement ayant contribué à l'alerte :
| Champ | Type | Nullable |
|-------|------|----------|
| `timestamp` | `int` (Unix ms) | non |
| `event_type` | `str` (taxonomie fermée) | non |
| `source_host` | `str` | non |
| `raw_log` | `str` | non |
| `actor_user` | `Optional[str]` | oui |
| `actor_role` | `Optional[str]` | oui |
| `target_resource` | `Optional[str]` | oui |

**`YaraMatch`** — résultat du scan YARA (S3 uniquement) :
| Champ | Type | Nullable |
|-------|------|----------|
| `rule_name` | `str` | non |
| `file_path` | `str` | non |
| `file_hash` | `str` | non |
| `ruleset` | `str` | non |

**`Alert`** — alerte confirmée provenant du moteur de corrélation :
- **Immuable** (`frozen=True`) : l'alerte vient de l'extérieur, ne doit pas être modifiée
- Correspond exactement au schéma `alert-schema.json` v1.1.0
- `attacker_ip` nullable (cas normal pour S3, attaque locale)
- `yara_match` nullable (uniquement présent pour S3)

### `decision.py` — Résultat du moteur de décision

**`EnrichmentResult`** — résultat de l'enrichissement AbuseIPDB :
| Champ | Type | Notes |
|-------|------|-------|
| `source` | `str` | `"abuseipdb"` \| `"cache"` \| `"unavailable"` |
| `fallback_used` | `bool` | True si fallback local utilisé |
| `abuseipdb_score` | `Optional[int]` | 0-100, null si unavailable |
| `country_code` | `Optional[str]` | Code ISO pays |
| `isp` | `Optional[strt]` | Fournisseur |

**`Decision`** — décision du `DecisionEngine` avant exécution :
- Porte l'`Alert` source, le `scenario_type` (S1-S5), l'`action` et le `skip_reason`
- `skip_reason` DOIT être renseigné si `action == "none"` (invariant à valider)

### `response.py` — Résultat final persistant

**`OpnsenseResult`** — détail de l'action OPNsense :
| Champ | Type | Notes |
|-------|------|-------|
| `api_status_code` | `int` | 200 = succès |
| `retry_count` | `int` | Tentatives avant succès/abandon |
| `rule_id` | `Optional[str]` | ID règle injectée |
| `blocked_ip` | `Optional[str]` | IP bloquée |

**`Response`** — réponse finale conforme à `response-scheme.json` v1.0.1 :
- **Immuable** (frozen=True)
- `latency_ms` = `response_timestamp - alert_timestamp` (calculé, jamais 0 par défaut)
- `skip_reason` DOIT être null si `status != "skipped"`
- `enrichment` DOIT être null si `action == "none"` ou `attacker_ip` était null
- `opnsense` DOIT être null si `action != "block_ip"`
- Méthode `to_dict()` : sérialisation vers dict via `dataclasses.asdict()` pour persistance

---

## Ordre d'implémentation respecté

1. `alert.py` en premier — tout le reste en dépend
2. `decision.py` — dépend de `alert.py` (importe `Alert`)
3. `response.py` — dépend de `decision.py` (réutilise `EnrichmentResult`)

---

## Commit

```
feat(models): add Alert, Decision, Response dataclasses
```
