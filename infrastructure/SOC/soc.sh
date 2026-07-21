#!/usr/bin/env bash
# NYX — SOC provisioning script
# À exécuter en root sur la VM (idempotent : peut être relancé sans casser l'existant)
# Usage : sudo bash soc.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

log "=== Provisioning SOC ==="

# 0. Vérification pré-requis réseau
check_network_manager

# 1. Installation des paquets (un seul apt update grâce à apt_install)
log "Installation rsyslog + python3..."
apt_install rsyslog python3 python3-pip python3-venv

# 2. Création de l'utilisateur soc
log "Création de l'utilisateur soc..."
ensure_user soc
usermod -aG adm soc

# 3. Configuration rsyslog
log "Configuration rsyslog..."
cp "$SCRIPT_DIR/rsyslog.conf" /etc/rsyslog.conf
cp "$SCRIPT_DIR/10-remote.conf" /etc/rsyslog.d/10-remote.conf

# 4. Création des répertoires et permissions
log "Création des répertoires de logs..."
mkdir -p /var/log/remote /var/log/nyxsoc/alerts
chown -R soc:soc /var/log/remote /var/log/nyxsoc
chmod 750 /var/log/remote /var/log/nyxsoc

# 5. Redémarrage
log "Redémarrage rsyslog..."
systemctl enable rsyslog
systemctl restart rsyslog

# 6. Vérifications immédiates (échec bloquant si KO)
log "Vérification rsyslog..."
if ! systemctl is-active --quiet rsyslog; then
  log "ERREUR : rsyslog n'a pas démarré"
  systemctl status rsyslog --no-pager
  exit 1
fi

if ! ss -tulpn | grep -q ':514 '; then
  log "ERREUR : rsyslog n'écoute pas sur le port 514"
  exit 1
fi

log "=== Provisioning terminé avec succès ==="