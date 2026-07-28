#!/usr/bin/env python3
"""
gen_wordlist.py — Génère une wordlist contrôlée pour S4
(Brute-force Dolibarr — NyxSOC).

Même logique que S1 : le vrai mot de passe du compte cible est injecté
à une position connue, entouré de mots de passe génériques plausibles.

Usage :
    python3 gen_wordlist.py --real-password 'admin' --position 6 --out wordlist_s4.txt

⚠️ Ne jamais committer wordlist_s4.txt dans le repo.
"""

import argparse
import sys

DECOY_PASSWORDS = [
    "123456", "password", "admin123", "letmein", "qwerty123",
    "P@ssw0rd", "welcome1", "Password1", "root1234", "changeme",
    "dolibarr2026", "erpadmin", "Doli@2026", "Nyx@2026",
    "server123", "azerty123", "motdepasse", "admin2026", "toto1234",
    "administrateur",
]


def build_wordlist(real_password: str, position: int, total_len: int = 20) -> list[str]:
    if position < 1:
        raise ValueError("La position doit être >= 1 (1-indexed).")
    if position > total_len:
        raise ValueError("La position dépasse la longueur totale demandée.")

    decoys = DECOY_PASSWORDS.copy()
    i = 0
    while len(decoys) < total_len - 1:
        i += 1
        decoys.append(f"filler{i}")

    decoys = decoys[: total_len - 1]

    wordlist = decoys[: position - 1] + [real_password] + decoys[position - 1 :]
    return wordlist[:total_len]


def main():
    parser = argparse.ArgumentParser(description="Génère une wordlist contrôlée pour S4.")
    parser.add_argument("--real-password", required=True, help="Le vrai mot de passe du compte Dolibarr.")
    parser.add_argument("--position", type=int, default=6, help="Position (1-indexed) du vrai mdp dans la liste.")
    parser.add_argument("--total-len", type=int, default=20, help="Longueur totale de la wordlist.")
    parser.add_argument("--out", default="wordlist_s4.txt", help="Fichier de sortie.")
    args = parser.parse_args()

    wordlist = build_wordlist(args.real_password, args.position, args.total_len)

    with open(args.out, "w") as f:
        f.write("\n".join(wordlist) + "\n")

    print(f"[+] Wordlist générée : {args.out} ({len(wordlist)} entrées)")
    print(f"[+] Mot de passe réel en position {args.position}/{len(wordlist)}")
    print(f"[!] Ne pas committer ce fichier — vérifier .gitignore")


if __name__ == "__main__":
    sys.exit(main())
