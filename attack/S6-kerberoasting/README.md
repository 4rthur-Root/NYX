# S6 — Kerberoasting / AS-REP Roasting : Détection sur NyxSOC

## Contexte

Un attaquant disposant de credentials AD légitimes (phishing, rejeu, etc.)
peut demander des tickets de service Kerberos (TGS) pour des SPN enregistrés
dans l'AD — c'est le **Kerberoasting** (MITRE T1558.003). Les TGS sont chiffrés
avec le hash NTLM du compte de service, craquable hors-ligne.

Variante **AS-REP Roasting** (T1558.004) : si la pré-authentification Kerberos
est désactivée sur un compte (`UF_DONT_REQUIRE_PREAUTH`), un TGT peut être
demandé sans connaître le mot de passe.

Le SOC doit détecter les rafales de requêtes TGS/TGT — comportement sans
équivalent légitime à ce volume (seuil : 5 requêtes en 30 secondes).

---

## État des lieux

### ✅ Ce qui fonctionne

- Création des comptes AD cibles sur le DC Samba (`svc_backup` avec SPNs,
  `user_nopreauth` sans pré-auth)
- Énumération SPN depuis Kali (`impacket-GetUserSPNs` liste les SPNs)
- Pipeline de détection complet validé avec logs synthétiques :
  `gen_events.py` → `syslog_parser._parse_samba_json()` → `RuleEngine._eval_type1()`
  → alerte CRITICAL → SOAR `block_ip`

### ❌ Ce qui est bloqué

| Problème | Cause | État |
|----------|-------|------|
| **Kerberoasting** : `KRB_AP_ERR_INAPP_CKSUM` | Samba 4.22 KDC refuse le checksum RC4 de l'AP-REQ dans le TGS-REQ. Problème connu des libs Kerberos Python (Impacket, minikerberos) avec Samba ≥ 4.19. | Bloqué |
| **AS-REP** : `ERR_PREAUTH_REQUIRED` | KDC Samba ignore le flag `UF_DONT_REQUIRE_PREAUTH` (0x400000) positionné dans l'UAC. Retourne PREAUTH_REQUIRED malgré le flag. | Bloqué |
| **Logs JSON Samba non forwardés** | Les JSON d'audit Samba (`/var/log/samba/log.samba`) ne sont pas envoyés au SOC via rsyslog. `daemon.*` ne capture que les logs syslog classiques, pas les lignes JSON. | Bloqué |

---

## Topologie

```
┌─────────────────────────────────────────────────────────┐
│ Kali (10.0.1.50)                                        │
│  impacket-GetUserSPNs / GetNPUsers                      │
│  → SPN enumeration OK                                   │
│  → TGS / AS-REP: BLOQUÉ (Samba 4.22 incompatibility)    │
└────────────────────┬────────────────────────────────────┘
                     │ Kerberos (TCP/88)
                     ▼
┌─────────────────────────────────────────────────────────┐
│ Samba AD DC — srv-pme.nyx.tg (10.0.1.20)                │
│  Comptes créés : svc_backup (3 SPNs), user_nopreauth    │
│  Logs JSON : /var/log/samba/log.samba (non forwardé)     │
│  rsyslog : daemon.* → SOC (mais pas les JSON audit)     │
└────────────────────┬────────────────────────────────────┘
                     │ syslog (UDP/514)
                     ▼
┌─────────────────────────────────────────────────────────┐
│ SOC Engine — nyx (10.0.1.10)                             │
│  Lecture logs → syslog_parser → RuleEngine → Alerter     │
│  Détection validée avec logs synthétiques de gen_events  │
└─────────────────────────────────────────────────────────┘
```

---

## Pipeline de détection

```
gen_events.py (logs synthétiques si attaque réelle impossible)
  → syslog_parser._parse_samba_json()
    → event_type: tgs_request (4769) / tgt_request (4768)
    → actor_ip, actor_user, extra.spn extraits
  → RuleEngine._eval_type1()
    → group_by: actor_ip
    → threshold: 5 events in 30 seconds
    → KERBEROASTING_001 / ASREP_ROASTING_001
  → Alerter → alerte CRITICAL
    → {rule_id, severity, attacker_ip, target_ip, events[], mitre}
  → SOAR → block_ip sur l'IP attaquante
```

---

## Usage

### 1. Générer des logs synthétiques (contournement Samba 4.22)

```bash
# Rafale simple — 8 TGS en 30s (seuil dépassé → alerte)
python3 gen_events.py --scenario burst --count 8 --window 30 -o /tmp/attack.log

# Scénario réaliste — bruit de fond + rafale
python3 gen_events.py --scenario mixed -o /tmp/realistic.log

# Attaque multi-sources
python3 gen_events.py --scenario multi-ip \
  --ips 10.0.1.50,10.0.1.60 --count 10

# Attaque lente (ne déclenche pas le seuil)
python3 gen_events.py --scenario slow --count 8 --window 30

# Injecter dans le répertoire de l'engine
python3 gen_events.py -o /var/log/remote/srv-pme.log
```

### 2. Lancer le pipeline de détection

```bash
cd engine
# Modifier config.yaml : sources: {"test.log": "syslog"}, log_dir: /tmp/logs
python3 main.py
# Vérifier les alertes :
cat /tmp/nyx_test/alerts/*.json
```

### 3. Validation automatique

```bash
cd attack/S6-kerberoasting
python3 verify.py   # Tests pipeline + SOAR + règles + format
```

---

## Comptes AD créés pour S6

| Compte | Mot de passe | Rôle | UAC | SPN |
|--------|-------------|------|-----|-----|
| `svc_backup` | `P@ssw0rd` | Service (Kerberoasting) | 512 (normal) | `cifs/srv-pme.nyx.tg`, `svc_backup/srv-pme.nyx.tg`, `svc_backup/srv-pme` |
| `user_nopreauth` | `P@ssw0rd` | Sans pré-auth (AS-REP) | 4260352 (inclut `UF_DONT_REQUIRE_PREAUTH`) | — |

---

## Difficultés rencontrées et analyse

### 1. Incompatibilité Samba 4.22 KDC ↔ Impacket/minikerberos

**Kerberoasting** : `GetUserSPNs.py` énumère correctement les SPN via LDAP mais
échoue au moment de la requête TGS avec `KRB_AP_ERR_INAPP_CKSUM`.

Racine : l'authenticator AP-REQ dans le TGS-REQ utilise un checksum RC4 que le
KDC Samba 4.22 rejette. Les bibliothèques Python (Impacket, minikerberos) ne
gèrent pas le checksum attendu (cf. `impacket/krb5/kerberosv5.py:430-456`).

Solutions possibles :
- Patcher Impacket pour ajouter un `cksum` conforme dans l'authenticator
- Utiliser un client Kerberos natif (MIT krb5) avec une GSSAPI adaptée
- Remplacer Samba AD par un Windows Server AD (compatible Impacket)

**AS-REP Roasting** : le flag `UF_DONT_REQUIRE_PREAUTH` (0x400000) est bien
présent dans `userAccountControl` (4260352 = 0x410200) mais le KDC Samba 4.22
retourne `ERR_PREAUTH_REQUIRED`. Le comportement diffère de Microsoft AD.

### 2. Logs JSON Samba non forwardés au SOC

Samba AD écrit ses logs d'audit JSON dans `/var/log/samba/log.samba` mais ces
lignes passent par le canal syslog standard (facility `daemon`). Le fichier
`50-forward.conf` forwarde `daemon.*` au SOC, mais les lignes JSON sont émises
en interne par Samba et ne transitent pas par syslog.

Pour corriger : configurer rsyslog `imfile` sur le DC pour surveiller
`/var/log/samba/log.samba` et forwarder les lignes JSON vers le SOC :

```
# /etc/rsyslog.d/55-samba-audit.conf
module(load="imfile" PollingInterval="2")
input(type="imfile"
      File="/var/log/samba/log.samba"
      Tag="samba-audit:"
      Severity="info"
      Facility="local6"
      ruleset="forwardSOC")
ruleset(name="forwardSOC") {
    action(type="omfwd" Target="10.0.1.10" Port="514" Protocol="udp")
}
```

### 3. Fiabilité de la détection sur logs synthétiques

Les logs générés par `gen_events.py` respectent le format attendu par le parser
(RFC 5424, program name `samba-audit`, JSON 4768/4769). Le pipeline complet
(parser → règle → alerte) a été validé. Cependant, les logs réels de Samba
pourraient avoir des variations de format non anticipées (timestamp, champs
optionnels). Une validation avec des logs réels reste souhaitable.

---

## Recommandations

1. **Remplacer Samba AD par Windows Server** — la solution la plus propre pour
   la compatibilité avec Impacket, Kerberoasting, AS-REP, et l'ensemble des
   outils d'audit AD.
2. **Configurer imfile sur le DC** — quelques minutes pour débloquer le flux
   de logs JSON vers le SOC.
3. **Tester avec un vrai AD** — rejouer les scripts `kerberoast.sh` et
   `asrep_roast.sh` contre un Windows Server pour confirmer la chaîne
   complète : attaque → log SOC → alerte engine → SOAR.

---

## Fichiers du scénario

| Fichier | Rôle |
|---------|------|
| `kerberoast.sh` | Wrapper `impacket-GetUserSPNs` pour Kerberoasting |
| `asrep_roast.sh` | Wrapper `impacket-GetNPUsers` pour AS-REP Roasting |
| `gen_events.py` | Générateur d'événements synthétiques (4 scénarios) |
| `verify.py` | Validation pipeline + SOAR + règles + format |
| `proof.txt` | Preuve de détection : résultats réels et synthétiques |

## Fichiers liés

- `engine/rules/attack/kerberoasting.yaml` — Règle KERBEROASTING_001
- `engine/rules/attack/asrep_roasting.yaml` — Règle ASREP_ROASTING_001
- `engine/tests/integration/test_engine_full.py` — Test intégration
- `soar/src/soar/engine/rules.py` — Mappings SOAR
- `infrastructure/Server/samba-ad_installation.sh` — Script provisionning AD
- `infrastructure/Server/smb.conf` — Config Samba avec log level
- `infrastructure/Server/50-forward.conf` — Forward rsyslog
