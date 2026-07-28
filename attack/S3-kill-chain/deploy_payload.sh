#!/usr/bin/env bash
#
# deploy_payload.sh — Scénario S3, étape 1 : Dépôt du payload sur le
# partage commun (NyxSOC)
#
# Simule l'attaquant (ou l'employé piégé par phishing) qui dépose le
# fichier malveillant sur le partage Samba commun/, point d'entrée
# documenté pour S3/S4 dans Topologie.pdf §4.4.2.
#
# Ce dépôt déclenche samba_write côté Debian Server → le Dispatcher
# appelle YARA sur ce fichier AVANT que la séquence ne progresse vers
# les étapes suivantes (§6.7).
#
# Prérequis :
#   - payload local (eicar_test.txt en phase de validation, .exe ensuite)
#   - accès au partage commun/ (n'importe quel compte AD avec droits d'écriture)
#
# Usage :
#   ./deploy_payload.sh <target_ip> <ad_user> <ad_password> <payload_file>
#
# Exemple :
#   ./deploy_payload.sh 10.0.1.20 dir1 'Nyx2026!' eicar_test.txt

set -euo pipefail

TARGET="${1:?Usage: ./deploy_payload.sh <target_ip> <ad_user> <ad_password> <payload_file>}"
AD_USER="${2:?Compte AD requis}"
AD_PASSWORD="${3:?Mot de passe requis}"
PAYLOAD="${4:-eicar_test.txt}"

if [ ! -f "$PAYLOAD" ]; then
    echo "[!] Payload introuvable : $PAYLOAD"
    echo "    Génère-le d'abord avec gen_eicar.py (ou fournis un .exe pour la phase Meterpreter)."
    exit 1
fi

echo "[*] Dépôt de ${PAYLOAD} dans //${TARGET}/commun (utilisateur ${AD_USER})..."

TS_DEPLOY=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")

smbclient "//${TARGET}/commun" -U "${AD_USER}%${AD_PASSWORD}" -c "put ${PAYLOAD}"

echo "[+] Payload déposé avec succès à ${TS_DEPLOY}."
echo "[+] Ceci doit déclencher samba_write côté Debian Server, puis un scan YARA."
echo "[!] Note ce timestamp — il sert de départ à la fenêtre de 4h de MALICIOUS_FILE_EXEC_001."
