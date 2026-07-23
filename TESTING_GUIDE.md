# Guide de test local NyxSOC SOAR

## Prérequis

- Python 3.12+
- OPNsense VM avec API activée
- Alias `soar_blocklist` de type `Host(s)` créé sur OPNsense
- Règle firewall bloquant `soar_blocklist` → any

## 1. Configuration

Copier `.env.template` vers `.env` et renseigner :

```bash
OPNSENSE_API_URL=https://<ip-opnsense>
OPNSENSE_API_KEY=<votre-api-key>
OPNSENSE_API_SECRET=<votre-api-secret>
OPNSENSE_VERIFY_SSL=false
```

## 2. Lancer le SOAR

```bash
cd /home/fiodor/NYX/soar
PYTHONPATH=src .venv/bin/python -m soar.main
```

Le SOAR écoute les fichiers JSON déposés dans `/tmp/nyx_alerts/`.

## 3. Envoyer une alerte factice

Créer un fichier JSON valide dans `/tmp/nyx_alerts/` :

```bash
cat > /tmp/nyx_alerts/test.json.tmp << 'EOF'
{
  "alert_id": "550e8400-e29b-41d4-a716-446655440001",
  "timestamp": 1721746800000,
  "rule_id": "SSH_BRUTEFORCE_001",
  "severity": "CRITICAL",
  "attacker_ip": "185.220.101.99",
  "target_host": "debian-server",
  "target_ip": "10.0.1.10",
  "mitre_tactic": "TA0006",
  "mitre_technique": "T1110",
  "events": {
    "count": 1,
    "details": [
      {
        "timestamp": 1721746800000,
        "event_type": "ssh_failure",
        "source_host": "OPNsense",
        "raw_log": "sshd[1234]: Failed password for root from 185.220.101.99 port 22"
      }
    ]
  }
}
EOF

# Atomique : renommer .tmp → .json pour que le watcher le voie
mv /tmp/nyx_alerts/test.json.tmp /tmp/nyx_alerts/test.json
```

## 4. Vérifier le blocage

```bash
cd /home/fiodor/NYX/soar
PYTHONPATH=src .venv/bin/python -c "
from soar.integrations import OPNsenseClient
c = OPNsenseClient()
print('Blocked IPs:', c.list_blocked())
"
```

## 5. Nettoyer

```bash
rm -f /tmp/nyx_alerts/*.json
cd /home/fiodor/NYX/soar
PYTHONPATH=src .venv/bin/python -c "
from soar.integrations import OPNsenseClient
c = OPNsenseClient()
c.unblock_ip('185.220.101.99')
"
```

## Format de l'alerte

Le schéma complet est dans `docs/alert-schema.json`. Points clés :

- `alert_id`: UUID v4
- `severity`: `"WARNING"` ou `"CRITICAL"`
- `events`: objet avec `count` (int) et `details` (tableau d'événements)
- Chaque événement nécessite `timestamp` (Unix ms), `event_type`, `source_host`, `raw_log`

## Test unitaire

```bash
cd /home/fiodor/NYX/soar
.venv/bin/python -m pytest -v
```
