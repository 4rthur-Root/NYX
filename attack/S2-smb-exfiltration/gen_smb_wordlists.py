#!/usr/bin/env python3
"""
gen_smb_wordlists.py — Génère users.txt et passwords.txt pour le brute-force
SMB du scénario S2 (Exfiltration de données financières via SMB — NyxSOC).

Même logique que gen_wordlist.py (S1) : le vrai mot de passe d'un compte
cible est injecté à une position connue dans passwords.txt, pour contrôler
le nombre de tentatives échouées avant succès.

CrackMapExec teste par défaut CHAQUE user contre CHAQUE password (produit
cartésien). Pour rester cohérent avec la doc (§6.2 — succès sur dir1), il
faut positionner le bon mot de passe de dir1 de façon à ce que le succès
survienne pour le bon compte, tout en générant des échecs sur les autres
comptes du fichier users.txt.

Usage :
    python3 gen_smb_wordlists.py \\
        --users dir1,compta1,tech1 \\
        --target-user dir1 \\
        --real-password 'MotDePasseDir1' \\
        --position 8
"""

import argparse
import sys

DECOY_PASSWORDS = [
    "123456", "password", "admin123", "letmein", "qwerty123",
    "P@ssw0rd", "welcome1", "Password1", "root1234", "changeme",
    "Direction2026", "Comptabilite2026", "Technique2026", "Nyx@2026",
    "SambaAD2026", "employe123", "azerty123", "motdepasse", "toto1234",
    "administrateur",
]


def build_password_list(real_password: str, position: int, total_len: int = 20) -> list[str]:
    if position < 1 or position > total_len:
        raise ValueError("Position invalide par rapport à total_len.")

    decoys = DECOY_PASSWORDS.copy()
    i = 0
    while len(decoys) < total_len - 1:
        i += 1
        decoys.append(f"filler{i}")
    decoys = decoys[: total_len - 1]

    return decoys[: position - 1] + [real_password] + decoys[position - 1 :]


def main():
    parser = argparse.ArgumentParser(description="Génère users.txt et passwords.txt pour le brute-force SMB (S2).")
    parser.add_argument("--users", required=True, help="Comptes AD ciblés, séparés par des virgules (ex: dir1,compta1,tech1).")
    parser.add_argument("--target-user", required=True, help="Compte pour lequel le vrai mot de passe doit réussir (ex: dir1).")
    parser.add_argument("--real-password", required=True, help="Le vrai mot de passe du target-user.")
    parser.add_argument("--position", type=int, default=8, help="Position (1-indexed) du vrai mot de passe.")
    parser.add_argument("--total-len", type=int, default=20, help="Longueur totale de passwords.txt.")
    parser.add_argument("--users-out", default="users.txt", help="Fichier de sortie pour les comptes.")
    parser.add_argument("--passwords-out", default="passwords.txt", help="Fichier de sortie pour les mots de passe.")
    args = parser.parse_args()

    users = [u.strip() for u in args.users.split(",") if u.strip()]
    if args.target_user not in users:
        print(f"[!] Attention : {args.target_user} n'est pas dans la liste users ({users}).", file=sys.stderr)

    passwords = build_password_list(args.real_password, args.position, args.total_len)

    with open(args.users_out, "w") as f:
        f.write("\n".join(users) + "\n")

    with open(args.passwords_out, "w") as f:
        f.write("\n".join(passwords) + "\n")

    print(f"[+] users.txt généré : {len(users)} comptes ({', '.join(users)})")
    print(f"[+] passwords.txt généré : {len(passwords)} mots de passe")
    print(f"[+] Mot de passe réel de '{args.target_user}' en position {args.position}/{len(passwords)}")
    print(f"[!] CrackMapExec testera {len(users)} x {len(passwords)} = {len(users)*len(passwords)} combinaisons.")
    print(f"[!] Ne pas committer ces fichiers — vérifier .gitignore")


if __name__ == "__main__":
    sys.exit(main())
