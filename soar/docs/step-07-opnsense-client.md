# Étape 7 — Client OPNsense

**Date :** 23 juillet 2026
**Objectif :** injecter et supprimer des règles de blocage via l'API REST d'OPNsense.

---

## Fichier créé

```
src/soar/integrations/
├── __init__.py              # Export OPNsenseClient
├── base.py                  # ThreatIntelClient (abstrait)
├── abuseipdb_client.py      # (étape 6)
└── opnsense_client.py       # Client API OPNsense
```

---

## Classe `OPNsenseClient`

### Responsabilité
Exécuter le blocage/déblocage d'IPs via l'API REST du firewall OPNsense, en gérant un alias nommé `soar_blocklist`.

### Authentification
- HTTP Basic Auth avec `OPNSENSE_API_KEY`:`OPNSENSE_API_SECRET`
- `verify=False` (certificat auto-signé en lab) — **paramétrable via `OPNSENSE_VERIFY_SSL`**

### Méthodes publiques

| Méthode | Entrée | Sortie | Description |
|---------|--------|--------|-------------|
| `block_ip(ip)` | `str` | `OpnsenseResult` | Ajoute l'IP à `soar_blocklist` + applique |
| `unblock_ip(ip)` | `str` | `OpnsenseResult` | Retire l'IP de l'alias + applique |
| `list_blocked()` | — | `list[str]` | Liste les IPs actuellement bloquées |
| `is_already_blocked(ip)` | `str` | `bool` | Vérifie si une IP est déjà bloquée |

### Retry logic (3 tentatives)
En cas d'échec (HTTP 500, timeout, erreur réseau) :
1. Log un warning avec le numéro de tentative
2. Attend la tentative suivante (pas de délai explicite — immédiat)
3. Après 3 échecs, retourne `OpnsenseResult(api_status_code=dernier_code, retry_count=3)`

### Gestion des erreurs
- **Ne lève jamais d'exception** — retourne toujours un `OpnsenseResult`
- `api_status_code = 0` si aucune réponse réseau n'a été obtenue
- C'est l'appelant (handler) qui décide de la suite via `status="failed"`

---

## API OPNsense utilisée

| Endpoint | Méthode | Usage |
|----------|---------|-------|
| `/api/firewall/alias/addItem` | POST | Ajouter une IP à `soar_blocklist` |
| `/api/firewall/alias/delItem` | POST | Retirer une IP de l'alias |
| `/api/firewall/alias/getAlias` | GET | Lire le contenu de l'alias |
| `/api/firewall/alias/reconfigure` | POST | Appliquer les modifications |

---

## ⚠️ Configuration manuelle OPNsense requise

Avant que le client puisse fonctionner, tu dois configurer OPNsense :

1. **Générer une clé API :**
   - System → Access → Users → (ton utilisateur) → Edit
   - Onglet "API keys" → "+" pour générer une clé
   - Copier la clé et le secret

2. **Créer l'alias `soar_blocklist` :**
   - Firewall → Aliases → "+"
   - Name: `soar_blocklist`
   - Type: `Network(s)`
   - Content: laisser vide (sera rempli par le SOAR)

3. **Créer la règle de blocage :**
   - Firewall → Rules → LAN → "+"
   - Action: `Block`
   - Source: `soar_blocklist`
   - Destination: `any`
   - Description: "SOAR blocklist"

4. **Renseigner le `.env` :**
```env
OPNSENSE_API_URL=https://10.0.1.1/api
OPNSENSE_API_KEY=ta_cle_generee
OPNSENSE_API_SECRET=ton_secret_genere
OPNSENSE_VERIFY_SSL=false
```

---

## Tests (9 tests)

| Test | Scénario |
|------|----------|
| `test_block_success` | block_ip OK → api_status_code=200, retry=1 |
| `test_block_retries_on_failure` | HTTP 500 ×3 → retry=3, last code=500 |
| `test_block_retries_on_network_error` | Timeout ×3 → retry=3, code=0 |
| `test_unblock_success` | unblock_ip OK → api_status_code=200 |
| `test_list_returns_ips` | Alias avec IPs → list |
| `test_list_empty_when_no_content` | Alias vide → [] |
| `test_list_returns_empty_on_error` | API injoignable → [] |
| `test_returns_true_when_blocked` | IP dans la liste → True |
| `test_returns_false_when_not_blocked` | IP absente → False |

---

## Commit

```
feat(integrations): add OPNsense API client with retry logic
```
