#!/usr/bin/env python3
"""
gen_eicar.py — Génère le fichier de test EICAR pour valider le pipeline S3
(Compromission de poste employé — NyxSOC) avant de passer au vrai payload
Meterpreter.

EICAR est une chaîne de test standard reconnue par TOUS les antivirus/EDR
(y compris YARA si une règle le couvre) sans être un malware réel — elle ne
contient aucun code exécutable dangereux. C'est l'usage documenté dans
Topologie.pdf §6.7 : "Validation pipeline YARA sans payload réel".

Usage :
    python3 gen_eicar.py --out eicar_test.txt
"""

import argparse
import sys

# Chaîne EICAR standard (68 octets) — reconnue par toute solution antivirus
# et par des règles YARA de test. Totalement inoffensive.
EICAR_STRING = (
    r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
)


def main():
    parser = argparse.ArgumentParser(description="Génère le fichier de test EICAR pour S3.")
    parser.add_argument("--out", default="eicar_test.txt", help="Fichier de sortie.")
    args = parser.parse_args()

    with open(args.out, "w") as f:
        f.write(EICAR_STRING)

    print(f"[+] Fichier EICAR généré : {args.out}")
    print(f"[+] Chaîne de test standard, inoffensive, reconnue par les AV/EDR.")
    print(f"[!] Étape 1 de S3 (validation pipeline). Basculer vers Meterpreter une fois validé.")


if __name__ == "__main__":
    sys.exit(main())
