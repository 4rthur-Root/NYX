#!/usr/bin/env bash
# ============================================================
# Phase 1 — Installation de base du Server NYX
# Idempotent : peut être relancé sans casser l'existant
# Usage : sudo bash base_installation.sh
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

HOSTNAME="srv-pme.nyx.tg"
IP_PRIV="10.0.1.20"
INTERFACE_PRIV="enp2s0"

log "=== Provisioning base du Server ==="

# ── 1. Hostname ─────────────────────────────────────────────
current_hostname=$(hostname)
if [ "$current_hostname" = "$HOSTNAME" ]; then
  log "Hostname déjà configuré : $HOSTNAME"
else
  log "Configuration du hostname : $HOSTNAME"
  hostnamectl set-hostname "$HOSTNAME"
fi

# ── 2. Fichier /etc/hosts ───────────────────────────────────
if grep -q "10.0.1.20.*srv-pme" /etc/hosts; then
  log "/etc/hosts déjà configuré"
else
  log "Déploiement de /etc/hosts"
  backup_file /etc/hosts
  cp "$SCRIPT_DIR/hosts.conf" /etc/hosts
fi

# ── 3. Interface privée statique ────────────────────────────
if grep -q "iface $INTERFACE_PRIV inet static" /etc/network/interfaces 2>/dev/null; then
  log "Interface $INTERFACE_PRIV déjà configurée en statique"
else
  log "Configuration de l'interface $INTERFACE_PRIV en statique ($IP_PRIV)"
  cat >> /etc/network/interfaces << EOF

# Interface privée (réseau labo nyx)
auto $INTERFACE_PRIV
iface $INTERFACE_PRIV inet static
    address $IP_PRIV
    netmask 255.255.255.0
EOF
  systemctl restart networking
  log "Interface $INTERFACE_PRIV redémarrée"
fi

# ── 4. Mise à jour et outils de base ────────────────────────
log "Installation des outils de base..."
apt_install vim curl net-tools acl git rsyslog

# ── 5. Rsyslog : écoute locale UDP + forward vers SOC ───────
log "Configuration de rsyslog..."

# Activation imudp si nécessaire
if grep -q '^module(load="imudp")' /etc/rsyslog.conf; then
  log "  → imudp déjà activé"
else
  sed -i 's/#module(load="imudp")/module(load="imudp")/' /etc/rsyslog.conf
  sed -i 's/#input(type="imudp" port="514")/input(type="imudp" port="514")/' /etc/rsyslog.conf
  log "  → imudp activé"
fi

# Forward vers le SOC
if [ -f /etc/rsyslog.d/50-forward.conf ]; then
  log "  → Forward SOC déjà configuré"
else
  cp "$SCRIPT_DIR/50-forward.conf" /etc/rsyslog.d/50-forward.conf
  log "  → Forward SOC déployé"
fi

systemctl restart rsyslog

if ss -uln | grep -q ':514 '; then
  log "  → rsyslog écoute sur UDP 514 ✓"
else
  log "  → ATTENTION : rsyslog n'écoute pas sur UDP 514"
fi

# ── 6. Chrony (NTP) ────────────────────────────────────────
log "Installation de Chrony..."
if is_installed chrony; then
  log "  → Chrony déjà installé"
else
  apt_install chrony
fi
cp "$SCRIPT_DIR/chrony.conf" /etc/chrony/chrony.conf
systemctl restart chrony
log "  → Chrony configuré (sync vers 10.0.1.1)"

# ── 7. Docker ──────────────────────────────────────────────
log "Installation de Docker..."
bash "$SCRIPT_DIR/docker_install.sh"

# ── Résumé ──────────────────────────────────────────────────
log ""
log "============================================================"
log "✅ Base installation terminée"
log "============================================================"
log "Prochaines étapes :"
log "  1. Samba AD DC        : sudo bash samba-ad_installation.sh"
log "  2. Partages Samba     : sudo bash samba_installation.sh"
log "  3. Dolibarr (Docker)  : bash dolibarr/deploy_dolibarr.sh"
