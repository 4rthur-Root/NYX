# S4 — Brute-force interface web Dolibarr

Scénario d'attaque documenté dans [Topologie.pdf](../../docs/PDFs/Topologie.pdf) §6.4. Simule un attaquant
tentant de compromettre l'ERP de la PME via une attaque par force brute sur l'interface web de Dolibarr.

## Contexte PME

Un attaquant externe sur le réseau (`10.0.1.50`) tente de s'authentifier sur l'ERP Dolibarr
(`http://10.0.1.20`) en énumérant les mots de passe du compte `admin` via le formulaire de login.

## Chaîne d'attaque

1. Kali (`10.0.1.50`) boucle sur la wordlist : GET `/index.php?mainmenu=home` → extrait le token CSRF →
   POST avec `username=admin&password=...&actionlogin=login`.
2. Apache (via Docker syslog) journalise chaque requête HTTP — les échecs (auth failed) en 401/403,
   le succès en 302 (redirect).
3. Docker syslog → rsyslog local → forward UDP 514 → SOC → `/var/log/remote/localhost.log`.
4. Règle attendue côté moteur : **`WEB_BRUTEFORCE_001`** — 20 `http_request` avec `http_status` 401/403
   depuis la même `actor_ip` en 120 secondes → alerte `WARNING`.

**Sources corrélées** : `daemon/Apache` via Docker syslog (Debian Server) → `localhost.log` → `WebParser`.
**MITRE ATT&CK** : TA0006 (Credential Access) / T1110.001 (Password Guessing).

---

## Particularité technique : token CSRF

Contrairement à S1 (SSH) et S2 (SMB), Dolibarr protège son formulaire de login avec un **token CSRF
dynamique** (présent dans `<meta name="anti-csrf-newtoken" content="...">`). Ce token change à chaque
requête GET et doit être soumis avec le POST.

Le script Python `web_bruteforce.py` gère cette particularité :
1. **GET** la page de login → extrait le token CSRF (regex sur le `meta` ou l'`input hidden`).
2. **POST** avec `username`, `password`, `token`, `actionlogin=login`.
3. Si la réponse est **302** → succès (redirect post-connexion).
4. Si la réponse est **200** avec message d'erreur → échec, on passe au mot de passe suivant.

---

## Fichiers

```
S4-web-brute-force/
├── gen_wordlist.py       # génère la wordlist contrôlée
├── web_bruteforce.py     # script Python : GET+token → POST → détection succès
├── README.md
└── logs/                 # sorties produites par web_bruteforce.py
```

---

## 1. `gen_wordlist.py`

Identique à S1 : génère une wordlist courte et déterministe où le vrai mot de passe
(`admin`) est injecté à une position connue.

### Options

| Option | Défaut | Rôle |
|--------|--------|------|
| `--real-password` | *(requis)* | Le vrai mot de passe du compte Dolibarr (`admin`). |
| `--position` | `6` | Position (1-indexed) du vrai mot de passe. Position basse car le mdp est simple. |
| `--total-len` | `20` | Longueur totale de la wordlist. |
| `--out` | `wordlist_s4.txt` | Fichier de sortie. |

### Exemple

```bash
python3 gen_wordlist.py --real-password 'admin' --position 6 --out wordlist_s4.txt
```

---

## 2. `web_bruteforce.py`

Script Python qui orchestre l'attaque : GET → extraire token → POST → détecter succès 302.
Journalise chaque tentative et produit un fichier de métadonnées JSON.

### Dépendances

```bash
pip3 install requests
```

### Usage

```bash
python3 web_bruteforce.py [--target http://10.0.1.20] [--username admin]
                          [--wordlist wordlist_s4.txt] [--delay 0.5]
```

### Options

| Option | Défaut | Rôle |
|--------|--------|------|
| `--target` | `http://10.0.1.20` | URL de base du serveur Dolibarr |
| `--login-url` | `/index.php?mainmenu=home` | Chemin de la page de login |
| `--username` | `admin` | Compte Dolibarr ciblé |
| `--wordlist` | `wordlist_s4.txt` | Fichier de mots de passe |
| `--delay` | `0.5` | Délai entre tentatives (secondes) |
| `--timeout` | `10` | Timeout HTTP |
| `--verbose` / `-v` | — | Log chaque tentative (pas seulement le succès) |

### Fonctionnement interne

1. **GET initial** : récupère la page de login et le token CSRF.
2. **POST** : envoie le formulaire avec les identifiants.
3. **Détection** :
   - Code HTTP **302** → authentification réussie (redirect vers le dashboard).
   - Code HTTP **200** + message `"login or password failed"` dans le HTML → échec.
4. **Répète** jusqu'au mot de passe correct ou épuisement de la wordlist.

### Sorties produites

```
logs/
├── s4_<timestamp>.log       # liste chronologique des tentatives
└── s4_<timestamp>.meta.json  # métadonnées structurées de la run
```

Exemple de `.meta.json` :
```json
{
  "scenario": "S4_WEB_BRUTEFORCE",
  "run_id": "s4_20260727_160000",
  "target": "http://10.0.1.20",
  "username": "admin",
  "attempts": 6,
  "failures": 5,
  "found": true,
  "result_password": "admin",
  "duration_seconds": 8.234,
  "expected_rule": "WEB_BRUTEFORCE_001",
  "mitre": "T1110.001"
}
```

---

## Procédure de test (depuis Kali)

```bash
# 1. Générer la wordlist
python3 gen_wordlist.py --real-password 'admin' --position 6 --out wordlist_s4.txt

# 2. Lancer l'attaque
python3 web_bruteforce.py --wordlist wordlist_s4.txt --verbose

# 3. Sur SOC : vérifier les logs
tail -f /var/log/remote/localhost.log | grep dolibarr
```

## Vérification manuelle post-attaque

Côté SOC, les logs Apache doivent montrer les tentatives :

```
2026-07-27T16:00:00+00:00 localhost dolibarr[794]: 10.0.1.50 - - [27/Jul/2026:16:00:00 +0000] "POST /index.php?mainmenu=home HTTP/1.1" 401 234 "http://10.0.1.20/" "Mozilla/5.0"
2026-07-27T16:00:00+00:00 localhost dolibarr[794]: 10.0.1.50 - - [27/Jul/2026:16:00:00 +0000] "POST /index.php?mainmenu=home HTTP/1.1" 302 - "http://10.0.1.20/" "Mozilla/5.0"
```

Sur le SOC, les logs Apache/Dolibarr atterrissent dans **`/var/log/remote/localhost.log`**
(pas `srv-pme.log`). Vérifie :

```bash
tail -f /var/log/remote/localhost.log | grep dolibarr
```

Après lancement du moteur (`engine/main.py`), l'alerte `WEB_BRUTEFORCE_001` doit apparaître
(seuil : 15 requêtes POST avec code 200 vers `/index.php` en 120s).

---

## Différences avec S1 (SSH brute-force)

| Aspect | S1 | S4 |
|--------|----|----|
| Cible | SSH (port 22) | HTTP Dolibarr (port 80) |
| Outil | Hydra | Python + requests |
| Protection | Aucune | Token CSRF dynamique |
| Détection échec | Code retour Hydra | Code HTTP 302 vs 200 |
| Règle | `SSH_BRUTEFORCE_001` (CRITICAL) | `WEB_BRUTEFORCE_001` (CRITICAL) |
| Seuil | 10 en 60s | 15 en 120s |

---

## Limites connues

- Le token CSRF change à chaque GET, ce qui rend Hydra inutilisable (d'où le script Python).
- Chaque tentative = 2 requêtes HTTP (GET + POST), doublant le volume de logs.
- Le délai (`--delay`) évite de surcharger le serveur mais allonge la durée totale.
- La règle engine est en `WARNING`, pas `CRITICAL` — les alertes ne sont pas forwardées au SOAR
  par défaut. À monter en `CRITICAL` si un blocage automatique est souhaité.
