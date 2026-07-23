# Guide d'intégration Moteur → SOAR

## Contexte

- **Moteur de corrélation** (Gaël) : produit des alertes → les écrit dans `/var/log/nyx/`
- **Module SOAR** (Fiodor) : lit les alertes, décide d'une action, exécute (blocage OPNsense, notification)

Les deux modules sont **indépendants** : pas de code partagé, pas de base commune, pas d'appel direct. La communication se fait uniquement par fichiers JSON.

---

## Contrat : dossier + format

### 1. Écriture des alertes (par le moteur)

| Règle | Détail |
|-------|--------|
| Dossier | `/var/log/nyx/` |
| Format | JSON strict conforme à `docs/alert-schema.json` |
| Extension | `.json` |
| Écriture atomique | Écrire dans `alert-xxx.json.tmp` → **`rename()`** → `alert-xxx.json` |
| Fréquence | Pas de limite — le SOAR utilise `watchdog` (polling inotify) |
| Cycle de vie | Le moteur écrit, le SOAR lit. **Le SOAR ne supprime ni ne déplace jamais les fichiers.** |

**Fichier exemple :**
```json
{
  "alert_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1750000000000,
  "rule_id": "SSH_BRUTEFORCE_001",
  "severity": "CRITICAL",
  "attacker_ip": "1.2.3.4",
  "target_host": "debian-server",
  "target_ip": "10.0.1.20",
  "mitre_tactic": "TA0006",
  "mitre_technique": "T1110",
  "events_count": 5,
  "events": {
    "count": 5,
    "details": [
      {
        "timestamp": 1749999940000,
        "event_type": "ssh_failure",
        "source_host": "debian-server",
        "raw_log": "Failed password for root from 1.2.3.4 port 22 ssh2"
      }
    ]
  }
}
```

### 2. Lecture et réponse (par le SOAR)

Le SOAR :
1. Surveille `/var/log/nyx/` avec `watchdog`
2. Valide chaque nouveau `.json` contre `alert-schema.json`
3. Passe l'alerte dans le moteur de décision (sévérité, whitelist, playbook, enrichissement AbuseIPDB)
4. Exécute l'action (blocage OPNsense via API, notification)
5. Persiste tout dans sa propre base SQLite locale (`data/soar.db`)

Ce que le SOAR produit n'a pas besoin d'être lu par le moteur (mais le schéma de réponse est dans `docs/response-scheme.json` si besoin).

---

## Scénarios supportés

| ID | Règle | Attaquant | Action SOAR |
|----|-------|-----------|-------------|
| S1 | `SSH_BRUTEFORCE_001` | SSH brute-force | `block_ip` (OPNsense) |
| S2 | `SMB_EXFIL_001` | Scan → exfiltration Samba | `block_ip` (OPNsense) |
| S3 | `MALICIOUS_FILE_EXEC_001` | Fichier malveillant via partage | `notify` (log + potentiel Telegram/SMTP) |

---

## Setup pour le développeur moteur

```bash
# 1. Cloner
git clone https://github.com/4rthur-Root/NYX.git
cd NYX/soar

# 2. Environnement Python
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Config (demander les clés à Fiodor)
cp .env.example .env
# → Remplir avec les vraies clés fournies

# 4. Dossier d'alertes
sudo mkdir -p /var/log/nyx/
sudo chown $(whoami): /var/log/nyx/

# 5. Lancer les tests
pytest

# 6. Démarrer le SOAR
python -m soar.main
```

---

## Règles d'or

1. **Écriture atomique obligatoire** : `.tmp` → `rename()` → `.json`. Si le SOAR voit un `.tmp`, il l'ignore.
2. **Jamais de suppression** : le moteur ne doit pas nettoyer les fichiers dans `/var/log/nyx/`. Le SOAR non plus.
3. **Schéma strict** : une alerte non conforme au schéma est rejetée silencieusement (log warning).
4. **`alert_id` unique** : un UUID string. Le SOAR déduplique par `alert_id`.
5. **Le moteur n'a pas besoin de connaître le SOAR** : pas d'appel API, pas de callback. C'est une architecture orientée fichiers.

---

## Architecture

```
/var/log/nyx/
├── alert-001.json  ← écrit par le moteur (rename atomique)
├── alert-002.json
└── ...

Moteur (Gaël)                    SOAR (Fiodor)
    │                                 │
    ├── écrit alert.json              ├── watchdog détecte le fichier
    │   (rename atomique)             ├── parse + valide (jsonschema)
    │                                 ├── décide (playbook + enrichissement)
    │                                 ├── exécute (block / notify)
    │                                 └── persist (SQLite + JSONL audit)
    │
    └── /var/log/nyx/  ←─── lecture seule ───┘
```

---

## Questions fréquentes

**Q : Le SOAR a besoin d'OPNsense pour fonctionner ?**  
Non. Le code est testé avec des mocks. OPNsense est nécessaire seulement pour le blocage réel. Sans clés, les actions `block_ip` échouent proprement (statut "error").

**Q : Puis-je lancer le SOAR sans `.env` ?**  
Non. Les 4 variables obligatoires (AbuseIPDB + OPNsense) sont vérifiées au démarrage. Demande les clés à Fiodor.

**Q : Comment vérifier que le SOAR tourne ?**  
Regarde `logs/soar.log` et `logs/audit.log` après lancement de `python -m soar.main`.
