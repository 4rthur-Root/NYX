#!/usr/bin/env python3
"""
gen_fake_data.py - Génère un fichier releves_mm.csv factice mais réaliste
pour le scénario S2 (Exfiltration de données financières via SMB - Nyx).

Ce fichier simule un export de relevés Mobile Money (Flooz/TMoney, cohérent
avec le contexte PME togolais documenté dans Topologie.pdf) tel qu'il
pourrait être stocké dans le partage Samba `direction/`.

⚠️ Toutes les données sont synthétiques (noms, numéros, montants générés
   aléatoirement) - aucune donnée réelle n'est utilisée ou nécessaire.

Usage :
    python3 gen_fake_data.py --rows 150 --out releves_mm.csv
"""

import argparse
import csv
import random
import sys
from datetime import datetime, timedelta

OPERATORS = ["Flooz", "TMoney"]
TRANSACTION_TYPES = ["Dépôt", "Retrait", "Transfert", "Paiement marchand", "Recharge"]
FIRST_NAMES = [
    "Kossi", "Ama", "Kokou", "Afi", "Yao", "Akosua", "Komla", "Abra",
    "Edem", "Delali", "Mensah", "Ablavi", "Fiifi", "Sena", "Kudzo",
]
LAST_NAMES = [
    "Agbodan", "Kponton", "Ametepe", "Lawson", "Adjovi", "Tetteh",
    "Amouzou", "Gangondoin", "Kokouvi", "Amegah",
]


def random_phone() -> str:
    # Format Togo Mobile Money : +228 9X XX XX XX
    return f"+228 9{random.randint(0,9)} {random.randint(10,99)} {random.randint(10,99)} {random.randint(10,99)}"


def random_name() -> str:
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"


def random_date(days_back: int = 90) -> str:
    base = datetime(2026, 7, 27)
    delta = timedelta(days=random.randint(0, days_back), hours=random.randint(7, 19), minutes=random.randint(0, 59))
    return (base - delta).strftime("%Y-%m-%d %H:%M")


def build_rows(n: int) -> list[dict]:
    rows = []
    for i in range(1, n + 1):
        amount = round(random.uniform(1000, 500000), 0)  # FCFA
        rows.append(
            {
                "id_transaction": f"MM-2026-{i:05d}",
                "date": random_date(),
                "operateur": random.choice(OPERATORS),
                "type": random.choice(TRANSACTION_TYPES),
                "client": random_name(),
                "telephone": random_phone(),
                "montant_fcfa": f"{amount:,.0f}".replace(",", " "),
                "frais_fcfa": f"{round(amount * 0.01):,.0f}".replace(",", " "),
                "statut": random.choices(["Validé", "En attente", "Échoué"], weights=[90, 7, 3])[0],
            }
        )
    return rows


def main():
    parser = argparse.ArgumentParser(description="Génère un CSV factice de relevés Mobile Money pour S2.")
    parser.add_argument("--rows", type=int, default=150, help="Nombre de lignes/transactions à générer.")
    parser.add_argument("--out", default="releves_mm.csv", help="Fichier de sortie.")
    parser.add_argument("--seed", type=int, default=None, help="Seed aléatoire pour reproductibilité.")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    rows = build_rows(args.rows)

    fieldnames = [
        "id_transaction", "date", "operateur", "type", "client",
        "telephone", "montant_fcfa", "frais_fcfa", "statut",
    ]

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Fichier généré : {args.out} ({len(rows)} transactions)")
    print(f"[+] Toutes les données sont synthétiques (aucune donnée réelle).")
    print(f"[!] À déposer manuellement dans le partage Samba direction/ avant le test S2.")


if __name__ == "__main__":
    sys.exit(main())
