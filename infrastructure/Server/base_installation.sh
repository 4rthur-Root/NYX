#!/bin/bash
set -e

# Variables
HOSTNAME="srv-pme.nyx.tg"
IP_PRIV="10.0.1.20"
INTERFACE_NAT="enp1s0"   # À adapter selon le système
INTERFACE_PRIV="enp2s0"  # À adapter selon le système

# 1. Hostname
echo "=== Configuration du hostname ==="
hostnamectl set-hostname $HOSTNAME
echo "10.0.1.20   $HOSTNAME   srv-pme" >> /etc/hosts

# 2. Interface privée statique
echo "=== Configuration de l'interface privée ==="
cat >> /etc/network/interfaces << EOF

# Interface privée (réseau labo)
auto $INTERFACE_PRIV
iface $INTERFACE_PRIV inet static
    address $IP_PRIV
    netmask 255.255.255.0
EOF

systemctl restart networking

# 3. Mise à jour et outils
echo "=== Mise à jour des paquets ==="
apt update && apt upgrade -y
apt install -y vim curl net-tools acl git

# 4. Chrony
echo "=== Installation et configuration de Chrony ==="
apt install -y chrony
sed -i 's/^pool.*/server 10.0.1.1 iburst/' /etc/chrony/chrony.conf
systemctl restart chrony

echo "=== Phase 1 terminée ==="
echo "Vérifie avec : chronyc tracking"