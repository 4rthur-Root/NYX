# Étape 5 — Cache AbuseIPDB (cache mémoire TTL)

**Date :** 23 juillet 2026
**Objectif :** cache mémoire TTL des scores AbuseIPDB pour éviter des appels API redondants.

---

## Fichiers

```
src/soar/cache/
├── __init__.py          # Export IpCache
├── ip_cache.py          # Cache thread-safe avec TTL
└── fallback_list.yaml   # Liste de repli (alimentée à l'étape 6)
```

---

## Classe `IpCache`

### Responsabilité
Stocke temporairement les scores de réputation AbuseIPDB pour éviter de rappeler l'API pour une même IP dans un intervalle court.

### Structure interne
```
dict[str, dict]
  clé : IP (str)
  valeur : { score: int, expires_at: float }
```

Protégé par `threading.Lock()` pour les accès concurrents watcher/pipeline.

### API publique

| Méthode | Entrée | Sortie | Description |
|---------|--------|--------|-------------|
| `get(ip)` | `str` | `Optional[int]` | Retourne le score si non expiré, `None` sinon |
| `set(ip, score, ttl_seconds)` | `str, int, int` | `None` | Stocke avec expiration |
| `clear()` | — | `None` | Vide tout le cache |
| `size` | — | `int` | Nombre d'entrées non expirées |

### Thread safety
- Le verrou (`threading.Lock()`) englobe lecture ET expiration dans `get()`
- Conforme au DCD : "le verrou doit englober la lecture ET l'éventuelle expiration/suppression, pas juste l'écriture"

### Cas limites
- IP inconnue → `get()` retourne `None`
- Entrée expirée → supprimée au prochain `get()` ou `size`
- TTL = 0 → expire immédiatement (utile pour les tests)

---

## Tests (9 tests)

| Test | Scénario |
|------|----------|
| `test_set_and_get` | set puis get → retourne le bon score |
| `test_get_unknown_ip` | IP jamais vue → `None` |
| `test_get_after_expiry` | TTL expiré → `None` |
| `test_multiple_ips` | Plusieurs IPs → chaque IP retourne son score |
| `test_overwrite_existing` | Même IP, nouveau score → dernier score |
| `test_clear` | clear() → cache vide |
| `test_size` | Nombre d'entrées correct |
| `test_size_after_expiry` | Expirées → pas comptées dans `size` |
| `test_concurrent_access` | 3 threads × 100 accès → pas de race condition |

---

## Commit

```
feat(cache): add thread-safe IP cache with TTL
```
