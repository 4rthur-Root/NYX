#!/usr/bin/env bash
# NYX — SOC provisioning script
# À exécuter en root sur la VM
# Usage : sudo bash soc.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

log "=== Provisioning SOC ==="

# 1. Mise à jour
log "Mise à jour des paquets..."
apt_install

# 2. Installation des paquets
log "Installation rsyslog + python3..."
apt_install rsyslog python3 python3-pip

# 3. Création de l'utilisateur soc
log "Création de l'utilisateur soc..."
ensure_user soc
usermod -aG adm soc

# 4. Configuration rsyslog
log "Configuration rsyslog..."
cp "$SCRIPT_DIR/rsyslog.conf" /etc/rsyslog.conf
cp "$SCRIPT_DIR/10-remote.conf" /etc/rsyslog.d/10-remote.conf

# 5. Création des répertoires et permissions
log "Création des répertoires de logs..."
mkdir -p /var/log/remote /var/log/nyxsoc/alerts
chown -R soc:soc /var/log/remote /var/log/nyxsoc
chmod 750 /var/log/remote /var/log/nyxsoc

# 6. Redémarrage
log "Redémarrage rsyslog..."
systemctl restart rsyslog

# 7. Vérification
log "Vérification rsyslog..."
systemctl status rsyslog --no-pager
ss -tulpn | grep 514 || log "ATTENTION : rsyslog n'écoute pas sur le port 514"

log "=== Provisionning terminé ==="