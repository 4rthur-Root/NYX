#!/bin/bash
set -e

# Variables
HOSTNAME="srv-pme.nyx.tg"
IP_PRIV="10.0.1.20"
INTERFACE_PRIV="enp2s0"  # À vérifier avec `ip a` avant exécution

# 1. Hostname
echo "=== Configuration du hostname ==="
hostnamectl set-hostname $HOSTNAME

# 2. Fichier hosts
echo "=== Configuration du fichier hosts ==="
cp /tmp/server-provision/hosts.conf /etc/hosts

# 3. Interface privée statique
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
apt install -y vim curl net-tools acl git rsyslog

# 5. Configuration rsyslog : écoute locale UDP + forward vers le SOC
#    Nécessaire pour que le driver syslog Docker de Dolibarr
#    (udp://127.0.0.1:514) puisse écrire, puis que rsyslog relaie
#    ces logs (et ceux d'auth/authpriv/daemon) vers le SOC.
echo "=== Activation de l'écoute syslog locale (imudp) ==="
if ! grep -q '^module(load="imudp")' /etc/rsyslog.conf; then
    sed -i 's/#module(load="imudp")/module(load="imudp")/' /etc/rsyslog.conf
    sed -i 's/#input(type="imudp" port="514")/input(type="imudp" port="514")/' /etc/rsyslog.conf
else
    echo "  → module imudp déjà activé"
fi

echo "=== Déploiement du forward vers le SOC (10.0.1.10) ==="
cp /tmp/server-provision/50-forward.conf /etc/rsyslog.d/50-forward.conf

systemctl restart rsyslog

echo "=== Vérification de l'écoute UDP 514 ==="
ss -uln | grep 514 || echo "ATTENTION : rsyslog n'écoute pas sur le port 514"

# 6. Installation de la configuration Chrony
echo "=== Installation de la configuration Chrony ==="
apt install -y chrony
cp /tmp/server-provision/chrony.conf /etc/chrony/chrony.conf
systemctl restart chrony

# 7. Installation de Docker
echo "=== Installation de Docker ==="
bash /tmp/server-provision/docker_install.sh

echo ""
echo "============================================================"
echo "✅ Base installation terminée"
echo "============================================================"
echo "Prochaines étapes :"
echo "  1. Samba AD DC        : sudo bash samba-ad_installation.sh"
echo "  2. Partages Samba     : sudo bash samba_installation.sh"
echo "  3. Dolibarr (Docker)  : bash deploy_dolibarr.sh"
