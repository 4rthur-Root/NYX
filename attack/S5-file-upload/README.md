# S5 — Upload de fichier malveillant sur partage Samba

## Contexte

Un attaquant (ou un employé compromis) dépose un fichier malveillant sur un partage Samba.
Le SOC détecte le fichier via YARA dès l'écriture.

## Chaîne d'attaque

1. Attaquant se connecte au partage Samba (credentials connus, pas de brute-force)
2. Upload d'un fichier contenant des signatures YARA détectables
3. Le SOC (Debian Server) forwarde l'événement `samba_write`
4. Le moteur YARA scanne le fichier sur le montage CIFS read-only
5. Match YARA → alerte `SMB_MALICIOUS_FILE_001` (CRITICAL, Type 4)

## Règle déclenchée

- **ID** : `SMB_MALICIOUS_FILE_001`
- **Type** : 4 (alerte immédiate, pas de cooccurrence)
- **Severité** : CRITICAL
- **Filtre** : `event_type: samba_write` + `yara_match: required`
- **MITRE** : T1080 / T1204.002

## Fichiers

| Fichier | Rôle |
|---------|------|
| `gen_test_files.py` | Génère 4 fichiers test avec patterns YARA |
| `payloads/` | Fichiers générés (extensions .pdf, .docm, .xls, .exe) |
| `smb_upload_malicious.sh` | Upload les fichiers via smbclient |
| `logs/` | Logs et métadonnées de la run |

## Règles YARA

Les 249 règles `SUSP_*` et `MAL_*` ciblant les PE Windows sont filtrées depuis
[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
dans `engine/rules/yara/susp_mal_pe.yar`.

## Usage

```bash
# 1. Générer les fichiers test
python3 gen_test_files.py

# 2. Uploader sur le partage (par défaut : //10.0.1.20/commun)
./smb_upload_malicious.sh
```

## Vérification

```bash
# Côté SOC :
tail -f /var/log/nyxsoc/alerts/*.log
# Chercher : SMB_MALICIOUS_FILE_001
```
