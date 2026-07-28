# NyxSOC — Scénarios d'attaque

Six scénarios de détection d'intrusion couvrant la matrice MITRE ATT&CK,
exécutés contre l'infrastructure PME de NyxSOC (DC Samba, ERP Dolibarr,
serveur de fichiers). Chaque scénario comprend :
- des scripts d'attaque reproductibles depuis Kali
- des règles de détection moteur (engine rules YAML)
- un pipeline de parsing/détection/alerte/SOAR complet
- une preuve de validation (`proof.txt`, `verify.py`)

## Topologie de test

```
Kali (attaquant)   192.168.122.112 / 10.0.1.50
SOC (engine)       192.168.122.128
DC/srv-pme         10.0.1.20 (Debian Server + Samba AD + Dolibarr)
```

Les logs sont forwardés de srv-pme vers le SOC via rsyslog (TCP 514).

## Tableau récapitulatif

| # | Scénario | MITRE ATT&CK | Attaque | Alerte SOC | Sévérité | Statut |
|---|----------|-------------|---------|------------|----------|--------|
| S1 | Brute-force SSH | T1110 (Brute Force) | Hydra → SSH srv-pme | `SSH_BRUTEFORCE_001` (>10 échecs en 60s) | CRITICAL | ✅ Scripté |
| S2 | Exfiltration SMB | T1048 (Exfil over Alt Protocol) | NetExec → smbclient → CSV | `SMB_EXFIL_001` (net_scan + samba_read en 300s) | CRITICAL | ✅ Scripté |
| S3 | Kill-chain BEC | T1566, T1204.002 | Phishing → dépôt SMB → exécution EICAR | `SMB_MALICIOUS_FILE_001` + alerte exécution | CRITICAL | ✅ Scripté |
| S4 | Brute-force Dolibarr | T1110 (Brute Force) | GET+CSRF → POST login → wordlist | `WEB_BRUTEFORCE_001` (>20 HTTP 401 en 120s) | WARNING | ✅ Validé |
| S5 | Upload malveillant Samba | T1080, T1204.002 | smbclient → 4 PE déguisés → signature YARA | `SMB_MALICIOUS_FILE_001` (yara_match) | CRITICAL | ✅ 4/4 PASS |
| S6 | Kerberoasting / AS-REP Roasting | T1558.003/.004 | getUserSPNs / GetNPUsers → TGS/TGT | `KERBEROASTING_001` / `ASREP_ROASTING_001` (>5 req en 30s) | CRITICAL | ⚠️ Pipeline OK, infra partielle |

## Détail par scénario

### S1 — Brute-force SSH

**Principe** : Hydra depuis Kali force le mot de passe SSH du compte `server` sur
`srv-pme`. Les `Failed password` sont parsés par le moteur SOC via rsyslog.

**Détection** : règle de type 1 (seuil) — 10 échecs en 60s depuis une même IP →
`SSH_BRUTEFORCE_001` CRITICAL → SOAR `block_ip`.

**Fichiers** : `S1-ssh-brute-force/gen_wordlist.py`, `ssh_bruteforce.sh`,
`logs/`

---

### S2 — Exfiltration de données financières via SMB

**Principe** : L'attaquant scanne le réseau (nmap), brute-force SMB (NetExec),
découvre le compte `dir1:Nyx2026!` et télécharge `releves_test.csv` (faux relevés
Mobile Money) depuis le partage `direction/`.

**Détection** : règle de type 2 (cooccurrence) — `net_scan` + `samba_read` depuis
la même IP en 300s → `SMB_EXFIL_001` CRITICAL → SOAR `block_ip`.

**Fichiers** : `S2-smb-exfiltration/gen_fake_data.py`, `gen_smb_wordlists.py`,
`smb_exfil.sh`, `deploy_bait_file.sh`

---

### S3 — Kill-chain BEC

**Principe** : Kill-chain complète : dépôt de fichier malveillant sur partage
`commun/` → copie poste employé → exécution. Utilise EICAR comme payload de
validation (innofensif, signatures YARA universelles).

**Détection** : double détection — YARA sur `samba_write` + alerte d'exécution
poste Windows. `SMB_MALICIOUS_FILE_001` CRITICAL.

**Fichiers** : `S3-kill-chain/gen_eicar.py`, `deploy_payload.sh`

---

### S4 — Brute-force interface web Dolibarr

**Principe** : Script Python automatisé : GET → extraction token CSRF → POST
login avec wordlist de 20 mots de passe. Compte `admin:admin` trouvé après 10
échecs.

**Particularité** : token CSRF dynamique obligatoire pour chaque tentative.

**Détection** : règle de type 1 (seuil) — >20 HTTP 401 en 120s →
`WEB_BRUTEFORCE_001` WARNING (pas de block SOAR, simple notification).

**Fichiers** : `S4-web-brute-force/gen_wordlist.py`, `web_bruteforce.py`,
`proof.txt`

---

### S5 — Upload de fichier malveillant sur partage Samba

**Principe** : 4 fichiers PE déguisés (`.pdf`, `.docm`, `.xls`, `.exe`) sont
générés avec des signatures extraites de vraies règles YARA
(Neo23x0/signature-base), puis uploadés via smbclient sur le partage `commun/`.

**Fichiers générés** :

| Fichier | Cible YARA | Patterns clés |
|---------|-----------|--------------|
| `facture_2026-07.pdf` | `MAL_Sindoor_Decryptor_Aug25` | `main.rc4EncryptDecrypt`, `main.processFile` |
| `note_interne.docm` | `SUSP_NET_Msil_Suspicious_Use_StrReverse` | `Microsoft.CSharp`, `StrReverse`, `.NETFramework,Version=` |
| `rapport_financier.xls` | `MAL_DNSPIONAGE_Malware_Nov18` | `.0ffice36o.com`, `/Client/Login?id=` |
| `mise_a_jour_critique.exe` | `MAL_RANSOM_DarkBit_Feb23_1` | `You will receive decrypting key after the payment.` |

**Détection** : YARA scan systématique sur écriture Samba → `yara_match` →
`SMB_MALICIOUS_FILE_001` CRITICAL → SOAR `block_ip`. 236 règles SUSP_*/MAL_*
PE filtrées depuis Neo23x0/signature-base.

**Validation** : `verify.py` — **4/4 PASS** ✅

**Fichiers** : `S5-file-upload/gen_test_files.py`, `smb_upload_malicious.sh`,
`verify.py`, `proof.txt`

---

### S6 — Kerberoasting / AS-REP Roasting

**Principe** : Un attaquant avec des credentials AD légitimes demande des
tickets TGS pour les SPN du compte `svc_backup` (Kerberoasting) ou des TGT sans
pré-authentification pour `user_nopreauth` (AS-REP Roasting).

**Infrastructure AD** :
- `svc_backup` : 3 SPN (cifs/srv-pme, svc_backup/srv-pme.nyx.tg, svc_backup/srv-pme)
- `user_nopreauth` : UAC 4260352 (DONT_REQUIRE_PREAUTH activé)

**Détection** : règles type 1 (seuil 5 requêtes en 30s) → alertes CRITICAL →
SOAR `block_ip`.

**Pipeline validé** ✅ :
- Parsing JSON Samba audit (RFC 5424, msg IDs 4768/4769)
- `KERBEROASTING_001` → 2 alertes CRITICAL
- `ASREP_ROASTING_001` → 2 alertes CRITICAL
- Enrichissement MITRE ATT&CK (TA0006/T1558.003/.004)

**Limitations connues** :
- KDC Samba 4.22 incompatible avec Impacket/minikerberos
  (`KRB_AP_ERR_INAPP_CKSUM` sur TGS, `ERR_PREAUTH_REQUIRED` sur TGT sans pré-auth)
- Logs JSON Samba audit non forwardés vers le SOC (pas d'imfile configuré)

**Recommandation** : remplacer Samba AD par un vrai AD Windows Server.

**Fichiers** : `S6-kerberoasting/gen_events.py`, `verify.py`, `proof.txt`

## Bilan global

| Métrique | Valeur |
|----------|--------|
| Scénarios d'attaque | 6 |
| Règles engine YAML | 6 (1 par scénario, S3/S5 partagent la même) |
| Règles YARA embarquées | 236 (SUSP_*/MAL_* PE) |
| Alertes CRITICAL | 5 (S1, S2, S3, S5, S6) |
| Alerte WARNING | 1 (S4) |
| Actions SOAR | `block_ip` sur toutes les alertes CRITICAL |
| Pipeline validation | ✅ S5 (4/4 YARA), ✅ S6 (4/4 engine) |
| Infrastructure réelle | ⚠️ S6 partielle (incompatibilité Samba 4.22 / Impacket) |
