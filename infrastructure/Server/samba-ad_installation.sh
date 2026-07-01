#!/bin/bash
# install_samba_ad.sh

set -e

REALM="NYX.TG"
DOMAIN="NYX"
ADMIN_PASS="AdminNyx2026!"

# 1. Installation
echo "=== Installation Samba et dépendances ==="
apt install -y samba smbclient winbind libpam-winbind libnss-winbind krb5-user krb5-config

# 2. Arrêt des services
systemctl stop smbd nmbd winbind
systemctl disable smbd nmbd winbind

# 3. Provisionnement (non interactif)
echo "=== Provisionnement du domaine ==="
samba-tool domain provision --realm=$REALM --domain=$DOMAIN --adminpass=$ADMIN_PASS --use-rfc2307 --dns-backend=SAMBA_INTERNAL

# 4. Résolveur DNS
echo "=== Configuration DNS ==="
echo "nameserver 127.0.0.1" > /etc/resolv.conf
echo "search nyx.tg" >> /etc/resolv.conf
chattr +i /etc/resolv.conf

# 5. Démarrage Samba
systemctl unmask samba-ad-dc
systemctl enable samba-ad-dc
systemctl start samba-ad-dc

# 6. Création groupes et utilisateurs
echo "=== Création des groupes ==="
samba-tool group add direction
samba-tool group add comptabilite
samba-tool group add technique

echo "=== Création des utilisateurs ==="
samba-tool user create dir1 Nyx2026! --given-name="Directeur" --surname="Un"
samba-tool user create comptal Nyx2026! --given-name="Comptable" --surname="Un"
samba-tool user create tech1 Nyx2026! --given-name="Technicien" --surname="Un"
samba-tool user create soc_reader Nyx2026! --given-name="SOC" --surname="Reader"

echo "=== Ajout aux groupes ==="
samba-tool group addmembers direction dir1
samba-tool group addmembers comptabilite comptal
samba-tool group addmembers technique tech1

echo "=== Phase 3 terminée ==="
echo "Teste avec : smbclient -L localhost -U dir1"