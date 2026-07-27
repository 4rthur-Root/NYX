#!/usr/bin/env python3
"""
gen_wordlist.py — Génère une wordlist SSH contrôlée pour le scénario S1
(Brute-force SSH — NyxSOC).

Objectif : produire une liste courte et déterministe où le vrai mot de passe
est injecté à une position connue, entouré de mots de passe génériques
plausibles. Permet de contrôler précisément le nombre de tentatives avant
succès, donc de calculer une latence de détection reproductible.

Usage :
    python3 gen_wordlist.py --real-password 'VraiMotDePasse' --position 'nombre(entier)' --out wordlist_s1.txt

⚠️ Ne jamais committer wordlist_s1.txt dans le repo (contient un vrai mdp).
   Ajouter au .gitignore : nyx-s1/wordlist_s1.txt
"""

import argparse
import sys

# Mots de passe génériques plausibles (bruit), jamais le vrai
DECOY_PASSWORDS = [
    "123456", "password", "admin123", "letmein", "qwerty123",
    "P@ssw0rd", "welcome1", "Password1", "root1234", "changeme",
    "server123", "azerty123", "motdepasse", "administrateur", "toto1234",
    "Debian123", "SambaAD2026", "Nyx@2026", "employe123", "compta2026",
]


def build_wordlist(real_password: str, position: int, total_len: int = 20) -> list[str]:
    if position < 1:
        raise ValueError("La position doit être >= 1 (1-indexed).")
    if position > total_len:
        raise ValueError("La position dépasse la longueur totale demandée.")

    decoys = DECOY_PASSWORDS.copy()
    # Complète si total_len > len(DECOY_PASSWORDS)
    i = 0
    while len(decoys) < total_len - 1:
        i += 1
        decoys.append(f"filler{i}")

    decoys = decoys[: total_len - 1]

    wordlist = decoys[: position - 1] + [real_password] + decoys[position - 1 :]
    return wordlist[:total_len]


def main():
    parser = argparse.ArgumentParser(description="Génère une wordlist SSH contrôlée pour S1.")
    parser.add_argument("--real-password", required=True, help="Le vrai mot de passe du compte cible.")
    parser.add_argument("--position", type=int, default=12, help="Position (1-indexed) du vrai mdp dans la liste.")
    parser.add_argument("--total-len", type=int, default=20, help="Longueur totale de la wordlist.")
    parser.add_argument("--out", default="wordlist_s1.txt", help="Fichier de sortie.")
    args = parser.parse_args()

    wordlist = build_wordlist(args.real_password, args.position, args.total_len)

    with open(args.out, "w") as f:
        f.write("\n".join(wordlist) + "\n")

    print(f"[+] Wordlist générée : {args.out} ({len(wordlist)} entrées)")
    print(f"[+] Mot de passe réel en position {args.position}/{len(wordlist)}")
    print(f"[!] Ne pas committer ce fichier — vérifier .gitignore")


if __name__ == "__main__":
    sys.exit(main())
