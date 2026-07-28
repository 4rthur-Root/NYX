#!/usr/bin/env bash
#
# smb_upload_malicious.sh - Scénario S5 : Upload de fichier malveillant
# (NyxSOC)
#
# Chaîne d'attaque :
#   1. Génération des fichiers test (gen_test_files.py)
#   2. Upload via smbclient sur un partage Samba
#   3. Déclenchement YARA côte SOC → alerte SMB_MALICIOUS_FILE_001
#
# Règle attendue : SMB_MALICIOUS_FILE_001 (Type 4, CRITICAL)
#
# Usage :
#   ./smb_upload_malicious.sh <target_ip> <share> <directory>
#
# Exemple :
#   ./smb_upload_malicious.sh 10.0.1.20 commun payloads

set -euo pipefail

TARGET="${1:-10.0.1.20}"
SHARE="${2:-commun}"
PAYLOAD_DIR="${3:-payloads}"

USER="${4:-dir1}"
PASS="${5:-Nyx2026!}"

LOGDIR="./logs"
mkdir -p "$LOGDIR"

RUN_ID="s5_$(date +%Y%m%d_%H%M%S)"
TS_START=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
TS_START_EPOCH=$(date +%s.%N)

echo "=================================================="
echo " NyxSOC — Scénario S5 : Upload fichier malveillant"
echo "=================================================="
echo " Cible       : ${TARGET}"
echo " Partage     : ${SHARE}"
echo " Répertoire  : ${PAYLOAD_DIR}"
echo " Utilisateur : ${USER}"
echo "=================================================="

if ! ping -c 1 -W 2 "$TARGET" > /dev/null 2>&1; then
    echo "[!] Cible ${TARGET} injoignable."
    exit 1
fi

if [ ! -d "$PAYLOAD_DIR" ]; then
    echo "[!] Répertoire ${PAYLOAD_DIR} introuvable."
    echo "    Génère les fichiers d'abord : python3 gen_test_files.py"
    exit 1
fi

UPLOAD_LOG="${LOGDIR}/${RUN_ID}_smbclient.log"
METAFILE="${LOGDIR}/${RUN_ID}.meta.json"

echo ""
echo "[1/1] Upload des fichiers malveillants via smbclient..."
TS_STEP1_START=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")

UPLOADED=0
for f in "$PAYLOAD_DIR"/*; do
    [ -f "$f" ] || continue
    filename=$(basename "$f")
    echo "  -> uploade ${filename}..."
    smbclient "//${TARGET}/${SHARE}" -U "${USER}%${PASS}" \
        -c "put ${f}" 2>&1 | tee -a "$UPLOAD_LOG" || true
    UPLOADED=$((UPLOADED + 1))
done

TS_STEP1_END=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
echo "[+] ${UPLOADED} fichier(s) uploadé(s). Log : ${UPLOAD_LOG}"

TS_END=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
TS_END_EPOCH=$(date +%s.%N)
DURATION=$(awk -v a="$TS_START_EPOCH" -v b="$TS_END_EPOCH" 'BEGIN{printf "%.3f", b-a}')

cat > "$METAFILE" <<EOF
{
  "scenario": "S5_FILE_UPLOAD",
  "run_id": "${RUN_ID}",
  "target_ip": "${TARGET}",
  "actor_ip": "10.0.1.50",
  "share": "${SHARE}",
  "payload_dir": "${PAYLOAD_DIR}",
  "user": "${USER}",
  "files_uploaded": ${UPLOADED},
  "ts_start_utc": "${TS_START}",
  "ts_end_utc": "${TS_END}",
  "duration_seconds": ${DURATION},
  "steps": {
    "1_upload": { "start": "${TS_STEP1_START}", "end": "${TS_STEP1_END}", "log": "${UPLOAD_LOG}" }
  },
  "expected_rule": "SMB_MALICIOUS_FILE_001",
  "mitre": ["T1080", "T1204.002"]
}
EOF

echo "=================================================="
echo " Fin (UTC)  : ${TS_END}"
echo " Durée      : ${DURATION}s"
echo " Métadonnées: ${METAFILE}"
echo "=================================================="
echo "[+] Terminé. Vérifie l'alerte SMB_MALICIOUS_FILE_001 côté SOC."
