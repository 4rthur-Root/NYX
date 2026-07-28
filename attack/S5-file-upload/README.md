# S5 — Upload de fichier malveillant sur partage Samba

## Contexte — pourquoi ce scénario ?

Un attaquant qui a compromis des credentials AD (via phishing, brute-force,
ou rejeu) — ou un employé malveillant interne — peut déposer un fichier
exécutable piégé sur un partage Samba. Le but : convaincre un collègue
d'ouvrir ce fichier pour exécuter un payload (ransomware, stealer, backdoor).

Le SOC doit détecter ce fichier **dès l'écriture**, avant toute exécution,
via une analyse YARA systématique de tous les fichiers déposés sur les
partages.

**MITRE ATT&CK** : T1080 (Taint Shared Content) / T1204.002 (Malicious File)

## Topologie et flux réseau

```
Kali (10.0.1.50)  ───SMB──→  Debian Server (10.0.1.20)
                                   │
                                   │ samba_write event (syslog)
                                   ▼
                              SOC Engine
                                   │
                          ┌────────┴────────┐
                          │ YARA enrichment  │
                           │ (236 règles PE)  │
                          └────────┬────────┘
                                   │ match ?
                          ┌────────┴────────┐
                          │  SMB_MALICIOUS_ │
                          │  FILE_001 (CRIT) │
                          └─────────────────┘
                                   │
                                   ▼
                              SOAR → block_ip
```

## Chaîne d'attaque complète

1. **Connexion** : l'attaquant se connecte au partage Samba via `smbclient`
   avec des credentials AD valides (`dir1:Nyx2026!` par défaut). Aucun
   brute-force — le postulat est que les credentials sont déjà compromis.
2. **Upload** : dépôt de fichiers aux extensions anodines mais contenant
   des signatures YARA détectables (patterns extraits de vrais malwares).
3. **Détection** : Samba (Debian Server) écrit l'événement dans syslog.
   Rsyslog forwarde vers le SOC. Le parsing produit `event_type: samba_write`.
4. **YARA** : le Dispatcher appelle `YaraScanner.scan()` sur le fichier
      (monté en read-only via CIFS sous `/mnt/samba/<partage>/`). 236 règles
   SUSP_*/MAL_* PE issues de Neo23x0/signature-base sont compilées.
5. **Alerte** : match YARA → alerte `SMB_MALICIOUS_FILE_001` (CRITICAL,
   Type 4). Le SOAR bloque l'IP source via `block_ip`.

## Règle déclenchée

| Champ | Valeur |
|-------|--------|
| **ID** | `SMB_MALICIOUS_FILE_001` |
| **Type** | 4 — alerte immédiate sur `samba_write` + `yara_match` |
| **Sévérité** | CRITICAL |
| **Fichier YAML** | `engine/rules/attack/smb_malicious_file.yaml` |
| **Filtre** | `event_type: samba_write`, `yara_match: required`, `source_host_pattern: "debian*"` |
| **Action SOAR** | `block_ip` (mapping dans `soar/src/soar/engine/rules.py`) |

## Règles YARA embarquées

Les 236 règles `SUSP_*` et `MAL_*` ciblant les PE Windows sont filtrées depuis
[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
via `engine/scripts/filter_yara_rules.py` et consolidées dans
`engine/rules/yara/susp_mal_pe.yar`.

Le filtre conserve uniquement les règles dont le nom commence par `SUSP_`
ou `MAL_` et qui ciblent les exécutables PE (présence de `uint16(0) == 0x5a4d`
dans la condition, ou tags PE/WIN/DLL/EXE, ou nom contenant WIN/PE/DLL/EXE).

## Fichiers du scénario

| Fichier | Rôle |
|---------|------|
| `gen_test_files.py` | Génère 4 fichiers test avec patterns YARA détectables |
| `payloads/` | Contient les fichiers générés (`.pdf`, `.docm`, `.xls`, `.exe`) |
| `smb_upload_malicious.sh` | Script principal : upload via `smbclient` |
| `logs/` | Logs et métadonnées de la run (créé à l'exécution) |

### Exemple de fichiers générés

| Fichier | Extension | Patterns YARA intégrés | Règle ciblée |
|---------|-----------|----------------------|--------------|
| `facture_2026-07.pdf` | .pdf | `main.rc4EncryptDecrypt`, `main.processFile` | MAL_Sindoor_Decryptor_Aug25 |
| `note_interne.docm` | .docm | `, PublicKeyToken=`, `.NETFramework,Version=`, `Microsoft.CSharp`, `Microsoft.VisualBasic`, `StrReverse` | SUSP_NET_Msil_Suspicious_Use_StrReverse |
| `rapport_financier.xls` | .xls | `.0ffice36o.com`, `/Client/Login?id=` | MAL_DNSPIONAGE_Malware_Nov18 |
| `mise_a_jour_critique.exe` | .exe | `You will receive decrypting key after the payment.` | MAL_RANSOM_DarkBit_Feb23_1 |

## Prérequis

- **Côté SOC** : montages CIFS read-only actifs sur `/mnt/samba/commun/`
  (configurés dans `engine/config.yaml`)
- **Côté attaquant (Kali)** : `smbclient`, `python3`
- **Credentials** : compte AD valide (`dir1:Nyx2026!` par défaut)

## Usage

```bash
# 0. Builder l'image engine (une fois)
cd engine && podman build -t nyxsoc-engine -f Dockerfile .

# 1. Générer les fichiers test
cd attack/S5-file-upload
python3 gen_test_files.py

# 2. Uploader sur le partage
./smb_upload_malicious.sh
#   Paramètres par défaut : target=10.0.1.20, share=commun, user=dir1, pass=Nyx2026!
```

## Vérification

### Validation YARA locale (hors moteur)

```bash
# Avec Podman (recommandé) :
podman run --rm \
  -v /home/adrien/My_codes_and_Projects/NYX:/nyx:Z \
  nyxsoc-engine \
  python3 /nyx/attack/S5-file-upload/verify.py

# Résultat attendu :
#   PASS  facture_2026-07.pdf           → MAL_Sindoor_Decryptor_Aug25
#   PASS  mise_a_jour_critique.exe      → MAL_RANSOM_DarkBit_Feb23_1
#   PASS  note_interne.docm             → SUSP_NET_Msil_Suspicious_Use_StrReverse
#   PASS  rapport_financier.xls         → MAL_DNSPIONAGE_Malware_Nov18
#   RÉSULTAT : 4/4 OK — Tous les fichiers détectés ✓
```

### Côté SOC (moteur en production)

```bash
tail -f /var/log/nyxsoc/alerts/*.log
# Chercher : SMB_MALICIOUS_FILE_001

# Vérifier le scan YARA dans les logs moteur :
grep yara /var/log/nyxsoc/engine.log
```

## Détection YARA — pour le rapport

Le champ `yara_match` dans l'alerte contient :

```json
{
  "rule_name": "MAL_Sindoor_Decryptor_Aug25",
  "file_path": "/mnt/samba/commun/facture_2026-07.pdf",
  "file_hash": "md5:<hash>",
  "ruleset": "susp_mal_pe"
}
```

- `rule_name` : nom exact de la règle YARA qui a matché
- `file_hash` : hash MD5 calculé par le YARA scanner avant le scan
- `ruleset` : namespace du fichier `.yar` source (`susp_mal_pe` depuis v1.2.0,
  plus de hardcode `neo23x0/signature-base`)

## Fichiers générés et règles YARA ciblées

| Fichier | Pattern testé | Règle YARA ciblée | Condition de la règle |
|---------|--------------|-------------------|----------------------|
| `facture_2026-07.pdf` | `Go build`, `main.rc4EncryptDecrypt`, `main.processFile`, `main.deriveKeyAES`, `use RC4 instead of AES` | `MAL_Sindoor_Decryptor_Aug25` | `uint16(0) == 0x5a4d AND filesize < 100MB AND all of them` |
| `note_interne.docm` | `, PublicKeyToken=`, `.NETFramework,Version=`, `Microsoft.CSharp`, `Microsoft.VisualBasic`, `StrReverse` | `SUSP_NET_Msil_Suspicious_Use_StrReverse` | `uint16(0) == 0x5a4d AND filesize < 50MB AND all of ($a*) AND $csharp AND $vbnet AND $strreverse` |
| `rapport_financier.xls` | `.0ffice36o.com`, `/Client/Login?id=` | `MAL_DNSPIONAGE_Malware_Nov18` | `uint16(0) == 0x5a4d AND filesize < 1000KB AND (1 of ($x*) or 2 of them)` |
| `mise_a_jour_critique.exe` | `You will receive decrypting key after the payment.`, `Go build`, `C:/updatescheck/main.go` | `MAL_RANSOM_DarkBit_Feb23_1` | `uint16(0) == 0x5a4d AND filesize < 10MB AND (1 of ($x*) or 2 of them) OR 4 of them OR (filesize < 10MB AND $xn1)` |
