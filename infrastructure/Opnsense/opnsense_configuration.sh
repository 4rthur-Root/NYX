#!/usr/bin/env bash
# =============================================================
# NYX — Configuration post-install OPNsense 26.1.x
# Exécuté depuis l'hôte après installation manuelle via virt-install
# Prérequis : SSH root accessible sur 192.168.121.254
# Usage: bash scripts_shell/opnsense_configuration.sh
# =============================================================
set -euo pipefail

VM_NAME="Opnsense"
OPNSENSE_IP="192.168.121.254"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTime=10"

# 1. Vérification connectivité SSH
echo "[1/5] Vérification SSH sur ${OPNSENSE_IP}..."
if ! ssh $SSH_OPTS root@"${OPNSENSE_IP}" "echo ok" &>/dev/null; then
  echo "[ERROR] Impossible de joindre OPNsense via SSH."
  echo "        Vérifiez que la VM tourne et que SSH est activé :"
  echo "        → Option 8 (Shell) dans le menu OPNsense"
  echo "        → service openssh start"
  exit 1
fi
echo "[OK] SSH opératiel."

# 2. Configuration SSH persistante
echo "[2/5] Configuration SSH persistante..."
ssh $SSH_OPTS root@"${OPNSENSE_IP}" 'bash -s' << 'REMOTE'
set -e

# SSH root login persistant
if ! grep -q "PermitRootLogin yes" /etc/ssh/sshd_config; then
  echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
fi
if ! grep -q "PasswordAuthentication yes" /etc/ssh/sshd_config; then
  echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
fi

# Activer SSH au démarrage via rc.conf
if ! grep -q 'openssh_enable' /etc/rc.conf; then
  echo 'openssh_enable="YES"' >> /etc/rc.conf
fi

service openssh restart
echo "[OK] SSH configuré et redémarré."
REMOTE

# 3. Configuration rsyslog filterlog vers SOC
echo "[3/5] Configuration rsyslog filterlog..."
ssh $SSH_OPTS root@"${OPNSENSE_IP}" 'bash -s' << 'REMOTE'
set -e

SOC_IP="10.0.1.10"
SOC_PORT="514"

# Configurer syslog natif OPNsense (newsyslog / syslog.conf)
# OPNsense utilise /etc/syslog.conf (FreeBSD)
SYSLOG_CONF="/etc/syslog.conf"
REMOTE_LINE="*.*\t@${SOC_IP}:${SOC_PORT}"

if ! grep -q "$SOC_IP" "$SYSLOG_CONF" 2>/dev/null; then
  echo "" >> "$SYSLOG_CONF"
  echo "# NYX — Forward tous les logs vers le SOC" >> "$SYSLOG_CONF"
  printf "%s\n" "$REMOTE_LINE" >> "$SYSLOG_CONF"
  echo "[OK] Forwarding syslog → ${SOC_IP}:${SOC_PORT} ajouté."
else
  echo "[INFO] Forwarding syslog déjà configuré."
fi

# Redémarre syslogd
service syslogd restart || true
echo "[OK] syslogd redémarré."
REMOTE

# 4. Snapshot virsh
echo "[4/5] Création du snapshot baseline..."

# Supprimer l'ancien snapshot s'il existe
if virsh snapshot-info "$VM_NAME" snap-baseline &>/dev/null; then
  echo "[INFO] Snapshot existant détecté — suppression..."
  virsh snapshot-delete "$VM_NAME" snap-baseline
fi

virsh snapshot-create-as "$VM_NAME" snap-baseline \
  --description "OPNsense 26.1.6 — SSH + syslog forward vers SOC configurés" \
  --atomic

# 5. Extraction et versioning de config.xml
echo "[5/5] Extraction de la configuration OPNsense..."
CONFIG_BACKUP="config.xml"
ssh $SSH_OPTS root@"${OPNSENSE_IP}" "cat /conf/config.xml" > "$CONFIG_BACKUP"
echo "[OK] Configuration sauvegardée dans ${CONFIG_BACKUP}"

echo ""
echo "======================================"
echo "[OK] OPNsense configuré avec succès."
echo "     Snapshot : snap-baseline"
echo "     SSH      : root@${OPNSENSE_IP}"
echo "     Syslog   : → 10.0.1.10:514 (UDP)"
echo "     Config   : ${CONFIG_BACKUP}"
echo "======================================"