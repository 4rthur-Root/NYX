#!/usr/bin/env bash
# NYX — SOC verification script
# Vérifie que tout est correct après provisionnement
# Usage: sudo bash soc_verify.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

ERRORS=0

log "=== Vérification SOC ==="

# 1. Utilisateur soc
log "[1] Utilisateur soc..."
if id soc &>/dev/null; then
  log "  OK — Utilisateur soc existe"
  if id soc | grep -q adm; then
    log "  OK — soc est dans le groupe adm"
  else
    log "  FAIL — soc n'est pas dans adm"
    ERRORS=$((ERRORS + 1))
  fi
else
  log "  FAIL — Utilisateur soc manquant"
  ERRORS=$((ERRORS + 1))
fi

# 2. Réseau
log "[2] Réseau..."
if ip a show enp2s0 2>/dev/null | grep -q "10.0.1.10/24"; then
  log "  OK — IP 10.0.1.10/24 sur enp2s0"
else
  log "  FAIL — IP non trouvée sur enp2s0"
  ERRORS=$((ERRORS + 1))
fi

if ping -c 1 -W 2 10.0.1.1 &>/dev/null; then
  log "  OK — Ping OK vers 10.0.1.1 (OPNsense)"
else
  log "  FAIL — Ping échoué vers 10.0.1.1"
  ERRORS=$((ERRORS + 1))
fi

if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
  log "  OK — Ping OK vers 8.8.8.8 (Internet)"
else
  log "  FAIL — Ping échoué vers 8.8.8.8"
  ERRORS=$((ERRORS + 1))
fi

# 3. Rsyslog
log "[3] Rsyslog..."
if systemctl is-active --quiet rsyslog; then
  log "  OK — rsyslog actif"
else
  log "  FAIL — rsyslog inactif"
  ERRORS=$((ERRORS + 1))
fi

if ss -tulpn | grep -q ":514 "; then
  log "  OK — Port 514 UDP ouvert"
else
  log "  FAIL — Port 514 non ouvert"
  ERRORS=$((ERRORS + 1))
fi

if [ -f /etc/rsyslog.d/10-remote.conf ]; then
  log "  OK — /etc/rsyslog.d/10-remote.conf présent"
else
  log "  FAIL — /etc/rsyslog.d/10-remote.conf manquant"
  ERRORS=$((ERRORS + 1))
fi

# 4. Répertoires
log "[4] Répertoires..."
for dir in /var/log/remote /var/log/nyxsoc/alerts; do
  if [ -d "$dir" ]; then
    log "  OK — $dir existe"
  else
    log "  FAIL — $dir manquant"
    ERRORS=$((ERRORS + 1))
  fi
done

# 5. Permissions
log "[5] Permissions..."
if [ "$(stat -c %U /var/log/remote)" = "soc" ]; then
  log "  OK — /var/log/remote appartient à soc"
else
  log "  FAIL — /var/log/remote n'appartient pas à soc"
  ERRORS=$((ERRORS + 1))
fi

PERMS=$(stat -c %a /var/log/remote)
if [ "$PERMS" = "750" ]; then
  log "  OK — /var/log/remote a le mode 750"
else
  log "  FAIL — /var/log/remote a le mode $PERMS (attendu: 750)"
  ERRORS=$((ERRORS + 1))
fi

# Bilan
log "=== Bilan ==="
if [ "$ERRORS" -eq 0 ]; then
  log "OK — Tout est bon, SOC prêt à recevoir les logs"
else
  log "FAIL — $ERRORS erreur(s) détectée(s), corriger avant de continuer"
  exit 1
fi
