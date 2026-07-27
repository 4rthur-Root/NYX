#!/usr/bin/env bash
#
# deploy_bait_file.sh — Dépose le fichier releves_mm.csv dans le partage
# Samba direction/ AVANT de lancer S2. Étape de préparation, pas d'attaque.
#
# Ce script s'exécute avec des credentials LÉGITIMES (dir1), simulant le
# dépôt normal du fichier par l'employé de la direction — pas une action
# de l'attaquant. L'attaquant (Kali) le récupérera ensuite via smb_exfil.sh
# une fois l'accès compromis.
#
# Usage :
#   ./deploy_bait_file.sh <target_ip> <dir1_password> [csv_file]

set -euo pipefail

TARGET="${1:?Usage: ./deploy_bait_file.sh <target_ip> <dir1_password> [csv_file]}"
DIR1_PASSWORD="${2:?Mot de passe dir1 requis}"
CSV_FILE="${3:-releves_mm.csv}"

if [ ! -f "$CSV_FILE" ]; then
    echo "[!] Fichier introuvable : $CSV_FILE"
    echo "    Génère-le d'abord avec gen_fake_data.py"
    exit 1
fi

echo "[*] Dépôt de ${CSV_FILE} dans //${TARGET}/direction (utilisateur dir1)..."

smbclient "//${TARGET}/direction" -U "dir1%${DIR1_PASSWORD}" -c "put ${CSV_FILE}"

echo "[+] Fichier déposé avec succès. Prêt pour le scénario S2."
