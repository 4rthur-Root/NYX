# S2 - Exfiltration de données financières via SMB

Scénario d'attaque documenté dans [Topologie.pdf](../../docs/PDFs/Topologie.pdf) §6.2. Simule un attaquant
compromettant un partage Samba et exfiltrant des relevés financiers (Mobile Money) depuis le serveur de
fichiers de la PME.

## Contexte PME

Un attaquant externe sur le réseau (`10.0.1.50`) procède en 3 étapes : reconnaissance réseau,
brute-force SMB pour compromettre un compte de la direction (`dir1`), puis exfiltration d'un fichier
financier sensible (`releves_test.csv`) depuis le partage `direction/`.

## Chaîne d'attaque

1. Kali (`10.0.1.50`) lance **nmap** contre `10.0.1.20` → `filterlog` (OPNsense) → `net_scan`.
2. Kali lance **NetExec** (nxc) en brute-force SMB contre le serveur cible → `daemon/Samba` → `smb_failure`.
3. NXC trouve une paire valide (`dir1:Nyx2026!`).
4. Kali utilise **smbclient** pour télécharger `releves_test.csv` depuis `//10.0.1.20/direction/` → `daemon/Samba` → `samba_read`.
5. Règle attendue côté moteur : **`SMB_EXFIL_001`** — cooccurrence `net_scan` + `samba_read` depuis la même `actor_ip` en 300 secondes → alerte `CRITICAL`.

**Sources corrélées** : `filterlog` (OPNsense) + `daemon/Samba` (Debian Server).
**MITRE ATT&CK** : TA0010 (Exfiltration) / T1048 (Exfiltration Over Alternative Protocol), T1021.002 (SMB/Windows Admin Shares).

---

## Fichiers

```
S2-smb-exfiltration/
├── gen_fake_data.py      # génère un CSV factice de relevés Mobile Money
├── gen_smb_wordlists.py  # génère users.txt + passwords.txt pour le brute-force SMB
├── deploy_bait_file.sh   # dépose le fichier dans le partage direction/ (exécuté depuis Debian Server)
├── smb_exfil.sh           # lance l'attaque en 3 étapes + journalise le timing
├── README.md
└── logs/                  # sorties produites par smb_exfil.sh
```

---

## 1. `gen_fake_data.py`

Génère un fichier CSV factice mais réaliste de relevés Mobile Money (Flooz/TMoney, contexte PME togolais).
Toutes les données sont synthétiques.

### Options

| Option | Défaut | Rôle |
|--------|--------|------|
| `--rows` | `150` | Nombre de transactions à générer |
| `--out` | `releves_mm.csv` | Fichier de sortie |
| `--seed` | *(aucun)* | Seed aléatoire pour reproductibilité |

### Exemple

```bash
python3 gen_fake_data.py --rows 200 --out releves_test.csv
```

---

## 2. `gen_smb_wordlists.py`

Génère `users.txt` et `passwords.txt` pour le brute-force SMB. Même logique que `gen_wordlist.py` (S1) :
le vrai mot de passe du compte cible est injecté à une position connue.

NXC teste par défaut chaque `user` contre chaque `password` (produit cartésien).

### Options

| Option | Défaut | Rôle |
|--------|--------|------|
| `--users` | *(requis)* | Comptes AD ciblés, séparés par des virgules (ex: `dir1,compta1,tech1`) |
| `--target-user` | *(requis)* | Compte pour lequel le vrai mot de passe doit réussir |
| `--real-password` | *(requis)* | Le vrai mot de passe du target-user |
| `--position` | `8` | Position (1-indexed) du vrai mot de passe dans `passwords.txt` |
| `--total-len` | `20` | Longueur totale de `passwords.txt` |
| `--users-out` | `users.txt` | Fichier de sortie des comptes |
| `--passwords-out` | `passwords.txt` | Fichier de sortie des mots de passe |

### Exemple

```bash
python3 gen_smb_wordlists.py \
    --users dir1,compta1,tech1 \
    --target-user dir1 \
    --real-password 'Nyx2026!' \
    --position 8
```

---

## 3. `deploy_bait_file.sh`

**À exécuter depuis un poste légitime** (Debian Server ou poste avec accès autorisé), **pas depuis Kali**.
Simule le dépôt normal du fichier financier par l'employé de la direction — pas une action de l'attaquant.

### Usage

```bash
./deploy_bait_file.sh <target_ip> <dir1_password> [csv_file]
```

### Exemple

```bash
./deploy_bait_file.sh 10.0.1.20 'Nyx2026!' releves_test.csv
```

---

## 4. `smb_exfil.sh`

Wrapper bash qui orchestre les 3 étapes de l'attaque : nmap → NXC → smbclient. Journalise la sortie
brute et produit un fichier de métadonnées JSON exploitable pour le calcul de latence de détection.

### Usage

```bash
./smb_exfil.sh <target_ip> <target_share> <remote_file>
```

Valeurs par défaut : `10.0.1.20`, `direction`, `releves_test.csv`.

### Étapes internes

1. **Vérification de connectivité** — `ping` la cible avant de commencer.
2. **Étape 1 : Reconnaissance** — `nmap -sV` contre la cible → log dans `logs/<run_id>_1_nmap.log`.
3. **Étape 2 : Brute-force SMB** — `nxc smb` avec `users.txt` x `passwords.txt` → log dans `logs/<run_id>_2_cme.log`.
   Extraction robuste du compte compromis par `sed` + `cut` (pas de regex fragile, pas de `xargs` qui
   mangerait les backslashes).
4. **Étape 3 : Exfiltration** — `smbclient get` avec le compte compromis → log dans `logs/<run_id>_3_smbclient.log`.

### Sorties produites

```
logs/
├── s2_<timestamp>_1_nmap.log       # sortie brute nmap
├── s2_<timestamp>_2_cme.log        # sortie brute NXC
├── s2_<timestamp>_3_smbclient.log # sortie brute smbclient
└── s2_<timestamp>.meta.json        # métadonnées structurées de la run
```

Exemple de `.meta.json` :
```json
{
  "scenario": "S2_SMB_EXFIL",
  "run_id": "s2_20260727_145053",
  "target_ip": "10.0.1.20",
  "actor_ip": "10.0.1.50",
  "share": "direction",
  "remote_file": "releves_test.csv",
  "compromised_user": "dir1",
  "ts_start_utc": "2026-07-27T18:50:53.467Z",
  "ts_end_utc": "2026-07-27T18:51:59.034Z",
  "duration_seconds": 65.563,
  "steps": {
    "1_nmap_scan": { "start": "...", "end": "...", "log": "..." },
    "2_smb_bruteforce": { "start": "...", "end": "...", "log": "..." },
    "3_smb_exfiltration": { "start": "...", "end": "...", "log": "..." }
  },
  "expected_rule": "SMB_EXFIL_001",
  "mitre": ["T1041", "T1048", "T1021.002"]
}
```

### Rôle attendu par machine

| Machine | Rôle dans ce scénario |
|---------|-----------------------|
| Kali (`10.0.1.50`) | Exécute nmap + NXC + smbclient, génère le trafic d'attaque. |
| Debian Server (`10.0.1.20`) | Cible SMB, journalise les accès (`daemon.log`), héberge le partage `direction/`. |
| OPNsense (`10.0.1.1`) | Journalise le scan nmap dans `filterlog`. |
| SOC (`10.0.1.10`) | Reçoit les logs (filterlog + samba), le moteur corrèle `net_scan` + `samba_read`. |

---

## Procédure de test complète (depuis Kali)

```bash
# 1. Sur Kali : générer les wordlists
python3 gen_smb_wordlists.py \
    --users dir1,compta1,tech1 \
    --target-user dir1 \
    --real-password 'Nyx2026!' \
    --position 8

# 2. Sur Debian Server (ssh) : déposer le fichier bait
# scp le script + CSV, puis :
./deploy_bait_file.sh 10.0.1.20 'Nyx2026!' releves_test.csv

# 3. Sur Kali : lancer l'attaque
./smb_exfil.sh 10.0.1.20 direction releves_test.csv

# 4. Sur SOC : vérifier les logs
tail -f /var/log/remote/OPNsense.internal.log   # net_scan
tail -f /var/log/remote/srv-pme.log             # smb_failure + samba_read
```

## Vérification manuelle post-attaque

Côté SOC, après lancement du moteur (`engine/main.py`), l'alerte `SMB_EXFIL_001` doit apparaître
dans `/var/log/nyxsoc/alerts/` sous forme de fichier `alert_<uuid>.json`.

---

## Limites connues

- NXC teste le produit cartésien complet (3 users × 20 passwords = 60 combinaisons), ce qui peut
  prendre quelques secondes — acceptable pour un lab.
- Le compte `dir1` doit avoir accès en lecture au partage `direction/`. Vérifier les permissions
  Samba si l'exfiltration échoue alors que le brute-force réussit.
- La règle engine `SMB_EXFIL_001` attend une cooccurrence `net_scan` + `samba_read` en 300s.
  Si le scan nmap est trop long (> 5 min), la fenêtre de corrélation peut expirer.
