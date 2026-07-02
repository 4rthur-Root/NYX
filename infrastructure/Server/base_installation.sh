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

# 2. Fichier hosts
echo "=== Configuration du fichier hosts ==="
cp /tmp/server-provision/hosts.conf /etc/hosts

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

# 4. Mise à jour et outils de base
echo "=== Mise à jour des paquets ==="
apt update && apt upgrade -y
apt install -y vim curl net-tools acl git

# 5. Installation de la configuration Chrony
echo "=== Installation de la configuration Chrony ==="
apt install -y chrony
cp /tmp/server-provision/chrony.conf /etc/chrony/chrony.conf
systemctl restart chrony

# 6. Installation de Docker
echo "=== Installation de Docker ==="
bash /tmp/server-provision/docker_install.sh