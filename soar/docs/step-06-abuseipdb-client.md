# Étape 6 — Client AbuseIPDB

**Date :** 23 juillet 2026
**Objectif :** interroger AbuseIPDB avec fallback sur le cache, circuit breaker et liste locale.

---

## Fichiers créés

```
src/soar/integrations/
├── __init__.py              # Export public
├── base.py                  # ThreatIntelClient (classe abstraite)
└── abuseipdb_client.py      # AbuseIPDBClient

src/soar/cache/
└── fallback_list.yaml       # Liste de repli (IPs connues)
```

---

## Architecture du client

### Ordre de résolution (strict)

```
1. Cache mémoire (IpCache)
     ↓ hit → EnrichmentResult(source="cache")
     ↓ miss
2. API AbuseIPDB (timeout=2s)
     ↓ succès → stocke dans cache + EnrichmentResult(source="abuseipdb")
     ↓ échec
3. Circuit breaker (3 échecs consécutifs → mode dégradé 5 min)
     ↓ si circuit ouvert
4. Fallback list YAML
     ↓ si IP inconnue dans fallback
5. Score par défaut 50
```

### Classe `AbuseIPDBClient`

| Méthode | Entrée | Sortie |
|---------|--------|--------|
| `get_reputation(ip)` | `str` | `EnrichmentResult` |

### Circuit breaker
- **Seuil :** 3 échecs consécutifs (`requests.RequestException`)
- **Cooldown :** `abuseipdb_circuit_breaker_cooldown_s` (config.yaml, défaut 300s)
- **Reset automatique :** après le cooldown, le circuit se referme
- **Pendant le mode dégradé :** pas d'appel API, utilisation directe du fallback

### Cache
- Résultat API stocké dans `IpCache` avec TTL de 300s (5 min)
- Les appels suivants pour la même IP retournent depuis le cache sans appeler l'API

### Fallback list
Fichier YAML `src/soar/cache/fallback_list.yaml` :
```yaml
known_ips:
  - ip: "10.0.1.50"
    score: 100
    reason: "Kali Linux — machine d'attaque du lab"
```

### Interface abstraite
`ThreatIntelClient` (base.py) permet d'ajouter d'autres fournisseurs de Threat Intelligence à l'avenir.

---

## Tests (7 tests)

| Test | Scénario |
|------|----------|
| `test_returns_from_cache_if_present` | IP en cache → source="cache" |
| `test_returns_from_api_on_cache_miss` | API répond → source="abuseipdb" + country/isp |
| `test_api_result_is_cached` | 2e appel → source="cache", 1 seul appel API |
| `test_opens_after_3_failures` | 3 timeouts → circuit breaker ouvert |
| `test_returns_fallback_while_circuit_open` | Circuit ouvert → pas d'appel API |
| `test_uses_fallback_for_known_ip` | IP dans fallback list → score fallback |
| `test_default_score_50_for_unknown_ip` | IP inconnue partout → score 50 par défaut |

---

## Ce que tu dois faire

Pour que le client fonctionne avec la vraie API AbuseIPDB, tu dois :

1. Créer un compte sur https://www.abuseipdb.com
2. Générer une clé API
3. Éditer `soar/.env` :
```env
ABUSEIPDB_API_KEY=ta_cle_ici
```

---

## Commit

```
feat(integrations): add AbuseIPDB client with cache, circuit breaker and fallback
```
