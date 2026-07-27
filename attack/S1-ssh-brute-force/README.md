# S1 - Brute-force SSH

Scénario d'attaque documenté dans [Topologie.pdf](../../docs/PDFs/Topologie.pdf) §6.1. Simule un attaquant
tentant de compromettre le serveur de fichiers de la PME via une attaque par
force brute sur SSH.

## Contexte PME

Un attaquant externe ou un poste compromis sur le réseau tente d'obtenir un
accès SSH au serveur de fichiers (`srv-pme`, `10.0.1.20`) par force brute sur
le seul compte disponible (`server`), `root` étant désactivé par défaut sur
Debian 13 (`PermitRootLogin no`).

## Chaîne d'attaque

1. Kali (`10.0.1.50`) lance Hydra contre `10.0.1.20:22`.
2. Hydra teste séquentiellement les mots de passe de la wordlist, à un débit
   modéré (~10-50 tentatives/minute visées, cohérent avec le §6.1 de la doc).
3. Chaque échec produit une entrée `Failed password` dans `/var/log/auth.log`
   sur `srv-pme` (facility `auth`).
4. `rsyslog` forwarde ces entrées vers le SOC (`10.0.1.10`), qui les écrit
   dans `/var/log/remote/srv-pme.log`.
5. Règle attendue côté moteur : **`SSH_BRUTEFORCE_001`** — 10 `ssh_failure`
   depuis la même `actor_ip` en 60 secondes → alerte `CRITICAL`.

**Sources corrélées** : `auth`/`authpriv` depuis Debian Server.
**MITRE ATT&CK** : TA0006 (Credential Access) / T1110 (Brute Force).

---

## Fichiers

```
S1-ssh-brute-force/
├── gen_wordlist.py     # génère la wordlist contrôlée
├── ssh_bruteforce.sh   # lance Hydra + journalise le timing
└── README.md
```

---

## 1. `gen_wordlist.py`

Génère une wordlist courte et déterministe où le **vrai mot de passe** du
compte cible est injecté à une **position connue**, entouré de mots de passe
génériques plausibles (`DECOY_PASSWORDS`). L'objectif n'est pas de simuler
une découverte aléatoire du mot de passe (non reproductible), mais de
contrôler précisément :

- le nombre de tentatives échouées avant le succès,
- donc la durée de l'attaque,
- donc la capacité à comparer plusieurs runs entre eux et à calculer une
  latence de détection reproductible (métrique H4 du protocole d'évaluation).

### Options

| Option | Défaut | Rôle |
|---|---|---|
| `--real-password` | *(requis)* | Le vrai mot de passe du compte SSH cible (`server`). |
| `--position` | `12` | Position (1-indexed) du vrai mot de passe dans la liste finale. Détermine le nombre de tentatives échouées avant succès (`position - 1`). |
| `--total-len` | `20` | Longueur totale de la wordlist générée. |
| `--out` | `wordlist_s1.txt` | Fichier de sortie. |

### Fonctionnement interne

- `DECOY_PASSWORDS` contient 20 mots de passe génériques plausibles
  (`123456`, `P@ssw0rd`, `Nyx@2026`, etc.) — jamais le vrai.
- Si `--total-len` dépasse 20, le script complète avec des entrées
  `fillerN` génériques (peu réalistes — voir "Variantes" ci-dessous si tu
  veux enrichir cette liste).
- Le vrai mot de passe est inséré à `--position`, les decoys se répartissent
  autour.
- Le fichier est écrit en clair, une entrée par ligne (format attendu par
  Hydra `-P`).

### Exemple d'exécution (sur Kali)

```bash
python3 gen_wordlist.py --real-password 'server1' --position 17 --out wordlist_s1.txt
```

Sortie attendue :
```
[+] Wordlist générée : wordlist_s1.txt (20 entrées)
[+] Mot de passe réel en position 17/20
[!] Ne pas committer ce fichier — vérifier .gitignore
```

### Faire varier la wordlist

Pour produire plusieurs variantes du scénario (utile pour le dataset —
plusieurs runs avec des latences différentes plutôt qu'un seul pattern
répété à l'identique) :

```bash
# Succès rapide (peu de tentatives avant détection)
python3 gen_wordlist.py --real-password 'server1' --position 3 --out wordlist_s1_fast.txt

# Succès tardif, wordlist plus longue
python3 gen_wordlist.py --real-password 'server1' --position 35 --total-len 50 --out wordlist_s1_slow.txt
```

⚠️ **Ne jamais committer un fichier `wordlist_s1*.txt`** généré avec le vrai
mot de passe — il est en clair. Garder ces fichiers locaux à Kali.

---

## 2. `ssh_bruteforce.sh`

Wrapper bash autour d'Hydra : lance l'attaque, vérifie la connectivité au
préalable, journalise la sortie brute et produit un fichier de métadonnées
JSON exploitable pour le dataset et le calcul de latence.

### Usage

```bash
./ssh_bruteforce.sh <target_ip> <ssh_user> <wordlist_file>
```

Valeurs par défaut si omis : `10.0.1.20`, `server`, `wordlist_s1.txt`.

### Étapes internes

1. **Vérification de connectivité** — `ping` la cible avant de lancer Hydra ;
   échoue proprement si `10.0.1.20` est injoignable (évite de lancer une
   attaque dans le vide si le réseau `nyx` n'est pas correctement routé
   depuis Kali).
2. **Lancement Hydra** :
   ```
   hydra -l <user> -P <wordlist> -t 4 -f -o <logfile> ssh://<target>
   ```
   - `-t 4` : 4 tâches parallèles — débit modéré choisi pour rester dans la
     fourchette documentée (10-50 tentatives/min) sans saturer la VM cible
     (1,5 Go RAM / 2 vCPU) ni produire un pattern trop artificiel.
   - `-f` : arrête Hydra dès qu'une paire valide est trouvée.
   - `-o` : écrit aussi la sortie Hydra dans le fichier de log.
3. **Calcul de durée** via `awk` (pas de dépendance à `bc`, absent par
   défaut sur Kali).
4. **Génération du fichier de métadonnées** `logs/<run_id>.meta.json`.

### Sorties produites

```
logs/
├── s1_<timestamp>.log         # sortie brute Hydra (tentatives, résultat)
└── s1_<timestamp>.meta.json   # métadonnées structurées de la run
```

Exemple de `.meta.json` :
```json
{
  "scenario": "S1_SSH_BRUTEFORCE",
  "run_id": "s1_20260727_094035",
  "target_ip": "10.0.1.20",
  "actor_ip": "10.0.1.50",
  "ssh_user": "server",
  "threads": 4,
  "wordlist_size": 20,
  "ts_start_utc": "2026-07-27T13:40:35.677Z",
  "ts_end_utc": "2026-07-27T13:40:59.112Z",
  "duration_seconds": 23.435,
  "expected_rule": "SSH_BRUTEFORCE_001",
  "mitre": "T1110"
}
```

Ce fichier sert de **vérité terrain** (ground truth) pour :
- labelliser les logs correspondants dans `datasets/labeled/` (protocole
  §8.3 de `Topologie.pdf`),
- calculer la latence de détection : `timestamp(alerte moteur) -
  ts_start_utc`.

### Rôle attendu par machine

| Machine | Rôle dans ce scénario |
|---|---|
| Kali (`10.0.1.50`) | Exécute Hydra, génère le trafic d'attaque. |
| Debian Server (`10.0.1.20`) | Cible SSH, journalise les échecs (`auth.log`), forwarde via `rsyslog`. |
| SOC (`10.0.1.10`) | Reçoit et stocke les logs dans `/var/log/remote/srv-pme.log`. Le moteur (non lancé lors du test initial) surveille ce fichier. |

### Vérification manuelle post-attaque

Côté serveur cible :
```bash
sudo tail -f /var/log/auth.log | grep -i "server"
```

Côté SOC :
```bash
tail -f /var/log/remote/srv-pme.log
```

Entrée attendue par tentative échouée :
```
<timestamp> srv-pme sshd-session[PID]: Failed password for server from 10.0.1.50 port <port> ssh2
```

---

## Limites connues de ce scénario

- Le débit est piloté uniquement via `-t` (threads Hydra), pas de contrôle
  fin du timing entre tentatives — acceptable pour rester dans la fourchette
  documentée, mais pas un contrôle seconde par seconde.
- Un brute-force **lent** (sous le seuil de détection, ex. 1 tentative/min)
  est un vecteur réel mais **hors scope** : l'objectif du test est de
  produire un signal qui dépasse le seuil de `SSH_BRUTEFORCE_001`, pas de le
  contourner.
- La wordlist reste petite (défaut 20 entrées) par choix — le but n'est pas
  un brute-force réaliste à grande échelle mais un signal contrôlé et
  reproductible pour valider la règle de détection.