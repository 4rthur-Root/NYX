#!/usr/bin/env python3
"""
verify.py — Validation du scénario S6 : Kerberoasting / AS-REP Roasting.

Teste 4 aspects :
  1. Test d'intégration existant (pipeline : JSON Samba audit → alerte)
  2. Génération d'événements synthétiques (format compatible parser)
  3. SOAR mappings (PLAYBOOK + RULE_TO_SCENARIO)
  4. Compilation des règles YAML

Usage :
    python3 verify.py                          # tout (recommandé)
    python3 verify.py --pytest-only             # seulement le test intégration
    python3 verify.py --gen-only                # seulement génération + format
    python3 verify.py --soar-only               # seulement validation SOAR

Exit code : 0 si tout OK, 1 sinon.
"""

import argparse
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent.parent
ENGINE_DIR = PROJECT_DIR / "engine"
SOAR_DIR = PROJECT_DIR / "soar"


def run_pytest() -> bool:
    """Lance le test d'intégration existant pour KERBEROASTING."""
    print("=" * 60)
    print("  1) Test d'intégration — pipeline complète")
    print("=" * 60)

    test_file = ENGINE_DIR / "tests" / "integration" / "test_engine_full.py"
    if not test_file.is_file():
        print(f"  FAIL  Test introuvable : {test_file}")
        return False

    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(test_file), "-v", "-k", "kerberoasting", "-x"],
        capture_output=True, text=True, cwd=ENGINE_DIR,
    )

    if result.returncode == 0:
        print("  PASS  test_full_kerberoasting ✓")
        # Extraire les lignes pertinentes
        for line in result.stdout.splitlines():
            if "PASSED" in line or "FAILED" in line or "test_full_kerberoasting" in line:
                print(f"    {line.strip()}")
        print()
        return True
    else:
        print(f"  FAIL  code retour : {result.returncode}")
        print(result.stdout[-500:])
        print(result.stderr[-500:])
        return False


def validate_soar() -> bool:
    """Vérifie que les mappings SOAR contiennent les règles S6."""
    print("=" * 60)
    print("  2) SOAR mappings")
    print("=" * 60)

    rules_file = SOAR_DIR / "src" / "soar" / "engine" / "rules.py"
    if not rules_file.is_file():
        print(f"  FAIL  Fichier SOAR introuvable : {rules_file}")
        return False

    content = rules_file.read_text()

    checks = [
        ("PLAYBOOK KERBEROASTING_001", '"KERBEROASTING_001": "block_ip"' in content),
        ("PLAYBOOK ASREP_ROASTING_001", '"ASREP_ROASTING_001": "block_ip"' in content),
        ("RULE_TO_SCENARIO KERBEROASTING_001", '"KERBEROASTING_001": "S6"' in content),
        ("RULE_TO_SCENARIO ASREP_ROASTING_001", '"ASREP_ROASTING_001": "S6"' in content),
        ("SCENARIOS_EXPECTING_IP S6", '"S6"' in content),
    ]

    all_ok = True
    for label, ok in checks:
        status = "PASS" if ok else "FAIL"
        print(f"  {status}  {label}")
        all_ok = all_ok and ok

    print()
    return all_ok


def validate_rules_yaml() -> bool:
    """Valide que les fichiers YAML des règles S6 se chargent sans erreur."""
    print("=" * 60)
    print("  3) Règles YAML — compilation")
    print("=" * 60)

    try:
        import yaml
    except ImportError:
        print("  SKIP  PyYAML non installé")
        print()

        import json
        return True

    rules_files = [
        ENGINE_DIR / "rules" / "attack" / "kerberoasting.yaml",
        ENGINE_DIR / "rules" / "attack" / "asrep_roasting.yaml",
    ]

    all_ok = True
    for rf in rules_files:
        if not rf.is_file():
            print(f"  FAIL  Fichier introuvable : {rf}")
            all_ok = False
            continue
        try:
            with open(rf) as f:
                rule = yaml.safe_load(f)
            rule_id = rule.get("rule_id", "?")
            rtype = rule.get("type", "?")
            print(f"  PASS  {rf.name:30s} → {rule_id:25s} type {rtype}")
        except Exception as e:
            print(f"  FAIL  {rf.name:30s} → {e}")
            all_ok = False

    print()
    return all_ok


def gen_and_validate() -> bool:
    """Génère des événements synthétiques et valide le format."""
    print("=" * 60)
    print("  4) Événements synthétiques — format")
    print("=" * 60)

    gen_script = SCRIPT_DIR / "gen_events.py"
    if not gen_script.is_file():
        print(f"  FAIL  gen_events.py introuvable")
        return False

    # Valider que les événements générés ont le bon format
    result = subprocess.run(
        [sys.executable, str(gen_script), "--count", "2", "--event-type", "both"],
        capture_output=True, text=True, timeout=10,
    )

    if result.returncode != 0:
        print(f"  FAIL  gen_events.py exit {result.returncode}")
        print(result.stderr[-300:])
        return False

    lines = result.stdout.strip().splitlines()

    checks = [
        ("TGS events present (4769)", any('"eventId": 4769' in l for l in lines)),
        ("TGT events present (4768)", any('"eventId": 4768' in l for l in lines)),
        ("Format syslog RFC 5424", all('T' in l.split()[0] for l in lines if l.strip())),
        ("samba-audit[2]: present", all("samba-audit[2]:" in l for l in lines if l.strip())),
        ("remoteAddress ipv4:", all("ipv4:" in l for l in lines if l.strip())),
    ]

    all_ok = True
    for label, ok in checks:
        status = "PASS" if ok else "FAIL"
        print(f"  {status}  {label}")
        all_ok = all_ok and ok

    if lines:
        print(f"\n  Aperçu (1ère ligne) :")
        print(f"    {lines[0][:120]}...")

    print()
    return all_ok


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pytest-only", action="store_true")
    parser.add_argument("--gen-only", action="store_true")
    parser.add_argument("--soar-only", action="store_true")
    parser.add_argument("--yaml-only", action="store_true")
    args = parser.parse_args()

    run_all = not (args.pytest_only or args.gen_only or args.soar_only or args.yaml_only)

    results = []

    if run_all or args.pytest_only:
        results.append(("Pipeline intégration", run_pytest()))
    if run_all or args.gen_only:
        results.append(("Événements synthétiques", gen_and_validate()))
    if run_all or args.soar_only:
        results.append(("SOAR mappings", validate_soar()))
    if run_all or args.yaml_only:
        results.append(("Règles YAML", validate_rules_yaml()))

    print("=" * 60)
    print("  BILAN S6")
    print("=" * 60)
    for label, ok in results:
        status = "✓" if ok else "✗"
        print(f"  {status}  {label}")

    all_ok = all(ok for _, ok in results)
    print()
    if all_ok:
        print("  RÉSULTAT : TOUS LES TESTS PASSENT ✓")
    else:
        print("  RÉSULTAT : CERTAINS TESTS ÉCHOUENT ✗")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
