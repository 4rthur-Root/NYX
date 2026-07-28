#!/usr/bin/env python3
"""
verify.py - Validation du scénario S5 : scan YARA des fichiers test.

Compile les règles SUSP_*/MAL_* (susp_mal_pe.yar) et vérifie que
chaque fichier dans payloads/ déclenche bien un match YARA.

Usage :
    python3 verify.py                          # lancement direct
    podman run --rm -v $PWD:/nyx nyxsoc-engine python3 /nyx/verify.py

Exit code : 0 si tous les fichiers matchent, 1 sinon.
"""

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PAYLOADS_DIR = SCRIPT_DIR / "payloads"
RULES_FILE = SCRIPT_DIR.parent.parent / "engine" / "rules" / "yara" / "susp_mal_pe.yar"

try:
    import yara
except ImportError:
    print("FAIL  yara-python non installé. Exécute dans le conteneur Docker.")
    sys.exit(1)


def main():
    if not PAYLOADS_DIR.is_dir():
        print(f"FAIL  Répertoire introuvable : {PAYLOADS_DIR}")
        print("      Lance d'abord : python3 gen_test_files.py")
        sys.exit(1)

    if not RULES_FILE.is_file():
        print(f"FAIL  Fichier de règles introuvable : {RULES_FILE}")
        sys.exit(1)

    payloads = sorted(PAYLOADS_DIR.iterdir())
    if not payloads:
        print(f"FAIL  Aucun fichier dans {PAYLOADS_DIR}/")
        print("      Lance d'abord : python3 gen_test_files.py")
        sys.exit(1)

    print("=" * 60)
    print("  NyxSOC — S5 : Vérification YARA")
    print("=" * 60)
    print(f"  Règles : {RULES_FILE}")
    print(f"  Cibles : {len(payloads)} fichiers dans {PAYLOADS_DIR}/")
    print()

    try:
        rules = yara.compile(filepaths={"susp_mal_pe": str(RULES_FILE)})
    except yara.SyntaxError as e:
        print(f"FAIL  Erreur de compilation YARA : {e}")
        sys.exit(1)
    except yara.Error as e:
        print(f"FAIL  Erreur YARA : {e}")
        sys.exit(1)

    n_rules = len(rules) if hasattr(rules, "__len__") else "?"
    print(f"  Règles compilées : {n_rules}")
    print()

    total = 0
    ok = 0

    for fpath in payloads:
        if not fpath.is_file():
            continue
        total += 1
        data = fpath.read_bytes()
        matches = rules.match(data=data, timeout=30)
        name = fpath.name

        if matches:
            matched_rules = [m.rule for m in matches]
            ruleset = matches[0].namespace if hasattr(matches[0], "namespace") else "?"
            print(f"  PASS  {name:45s} → {matched_rules[0]:45s}  [{ruleset}]")
            ok += 1
        else:
            print(f"  FAIL  {name:45s} → aucun match YARA")

    print()
    print("=" * 60)
    if total == 0:
        print("  RÉSULTAT : AUCUN FICHIER TESTÉ")
        sys.exit(1)
    if ok == total:
        print(f"  RÉSULTAT : {ok}/{total} OK — Tous les fichiers détectés ✓")
        sys.exit(0)
    else:
        print(f"  RÉSULTAT : {ok}/{total} OK — {total - ok} fichier(s) non détecté(s) ✗")
        sys.exit(1)


if __name__ == "__main__":
    main()
