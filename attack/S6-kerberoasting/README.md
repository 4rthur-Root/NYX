# S6 - Kerberoasting / AS-REP Roasting

## Contexte — pourquoi ce scénario ?

Un attaquant disposant de credentials AD (via phishing, Kerberoasting préalable,
ou rejeu) peut demander des tickets de service Kerberos (TGS) pour des SPN
enregistrés dans l'AD — c'est le **Kerberoasting** (T1558.003). Les TGS sont
chiffrés avec le hash NTLM du compte de service, craquable hors-ligne.

Variante **AS-REP Roasting** (T1558.004) : si la pré-authentification Kerberos
est désactivée sur un compte, l'attaquant peut demander un TGT pour ce compte
sans fournir de mot de passe — le TGT est chiffré avec le hash du compte.

Le SOC doit détecter ces rafales de requêtes TGS/TGT - un comportement qui
n'a pas d'équivalent légitime à ce volume (5+ requêtes en 30 secondes).

**MITRE ATT&CK** : TA0006 / T1558.003 (Kerberoasting), T1558.004 (AS-REP)

## Topologie et flux réseau

```
Kali (10.0.1.50)  ───Kerberos──→  Samba AD DC (10.0.1.20)
                                      │
                                      │ JSON audit syslog (EventID 4768/4769)
                                      ▼
                                 SOC Engine
                                      │
                             ┌────────┴────────┐
                             │  RuleEngine      │
                             │  Type 1 (seuil)  │
                             └────────┬────────┘
                                      │ count >= 5 en 30s ?
                             ┌────────┴────────┐
                             │ KERBEROASTING_001│
                             │ ASREP_ROASTING_001│
                             └─────────────────┘
                                      │
                                      ▼
                                 SOAR → block_ip
```

## Chaîne d'attaque complète

### Kerberoasting

1. L'attaquant (Kali, 10.0.1.50) utilise `impacket-GetUserSPNs` avec des
   credentials AD valides (`dir1:Nyx2026!`).
2. Le script énumère tous les SPN de l'AD et demande un TGS pour chacun.
3. Le Samba AD DC (`srv-pme.nyx.tg`, 10.0.1.20) logue chaque TGS request
   sous forme d'un événement JSON (EventID 4769) dans syslog.
4. Le parseur `syslog_parser._parse_samba_json()` produit `event_type:
   tgs_request`.
5. `KERBEROASTING_001` (Type 1, seuil 5 en 30s) détecte la rafale → alerte.
6. SOAR déclenche `block_ip` sur 10.0.1.50.

### AS-REP Roasting

1. L'attaquant utilise `impacket-GetNPUsers` pour demander des TGT pour
   les comptes sans pré-authentification Kerberos.
2. Le Samba AD DC logue chaque TGT request (EventID 4768).
3. `ASREP_ROASTING_001` détecte la rafale de `tgt_request` → alerte.

## Règles déclenchées

### KERBEROASTING_001

| Champ | Valeur |
|-------|--------|
| **ID** | `KERBEROASTING_001` |
| **Type** | 1 — seuil simple |
| **Sévérité** | CRITICAL |
| **Fichier YAML** | `engine/rules/attack/kerberoasting.yaml` |
| **Trigger** | `event_type: tgs_request`, threshold: 5, window: 30s, group_by: actor_ip |
| **Action SOAR** | `block_ip` |

### ASREP_ROASTING_001

| Champ | Valeur |
|-------|--------|
| **ID** | `ASREP_ROASTING_001` |
| **Type** | 1 — seuil simple |
| **Sévérité** | CRITICAL |
| **Fichier YAML** | `engine/rules/attack/asrep_roasting.yaml` |
| **Trigger** | `event_type: tgt_request`, threshold: 5, window: 30s, group_by: actor_ip |
| **Action SOAR** | `block_ip` |

## Fichiers du scénario

| Fichier | Rôle |
|---------|------|
| `kerberoast.sh` | Wrapper `impacket-GetUserSPNs` pour Kerberoasting |
| `asrep_roast.sh` | Wrapper `impacket-GetNPUsers` pour AS-REP Roasting |
| `gen_events.py` | Générateur d'événements synthétiques JSON Samba audit |
| `verify.py` | Validation complète : pipeline, SOAR, règles, format |
| `proof.txt` | Preuve de détention |
| `README.md` | Ce fichier |

## Usage

### Attaque réelle (depuis Kali)

```bash
# Kerberoasting
cd attack/S6-kerberoasting
./kerberoast.sh

# AS-REP Roasting
./asrep_roast.sh
```

### Événements synthétiques

```bash
# Générer des événements TGS + TGT (stdout)
python3 gen_events.py

# Écrire dans un fichier ingérable par l'engine
python3 gen_events.py -o /var/log/remote/srv-pme.log
```

### Vérification

```bash
# Test intégration + SOAR + règles + format
cd attack/S6-kerberoasting
python3 verify.py

# Résultat attendu :
#   PASS  test_full_kerberoasting ✓
#   PASS  PLAYBOOK KERBEROASTING_001
#   PASS  RULE_TO_SCENARIO KERBEROASTING_001
#   ...
#   RÉSULTAT : TOUS LES TESTS PASSENT ✓
```

## Détection — format d'alerte attendu

```json
{
  "rule_id": "KERBEROASTING_001",
  "severity": "CRITICAL",
  "attacker_ip": "10.0.1.50",
  "target_host": "debian-server",
  "events": {
    "count": 8,
    "event_type": "tgs_request"
  }
}
```

## Logs Samba AD — format JSON attendu par le parser

```
2026-07-28T10:00:00+00:00 debian-server samba-audit[2]:
  {"Authentication": {"eventId": 4769, "remoteAddress": "ipv4:10.0.1.50:56100",
   "servicePrincipalName": "cifs/srv-pme.nyx.tg", "accountName": "employe"}}
```

Le parseur `syslog_parser._parse_samba_json()` extrait :
- `eventId` 4768 → `event_type: tgt_request`
- `eventId` 4769 → `event_type: tgs_request`
- `remoteAddress` → `actor_ip` (préfixe `ipv4:` supprimé)
- `accountName` → `actor_user`
- `servicePrincipalName` → stocké dans `extra.spn`

## Prérequis

- **Côté attaquant (Kali)** : `impacket` (`GetUserSPNs.py`, `GetNPUsers.py`)
- **Côté SOC** : Samba AD ≥ 4.12 avec JSON audit activé
- **Credentials** : compte AD valide (`dir1:Nyx2026!` par défaut)
