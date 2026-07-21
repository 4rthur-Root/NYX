#!/bin/bash
# ============================================================
# Phase 4 - Configuration des partages Samba (AD DC)
# ============================================================

set -e

echo "============================================================"
echo "PHASE 4 : Configuration des partages Samba"
echo "============================================================"

DOMAIN="NYX"
USER_PASS="Nyx2026!"

# 1. Création des répertoires
echo "→ Création des répertoires de partage"
mkdir -p /srv/samba/{direction,comptabilite,technique,commun}

# 2. Permissions Unix + ACL
echo "→ Configuration des permissions"
chown root:"domain users" /srv/samba/direction
chmod 2770 /srv/samba/direction
setfacl -m g:direction:rwx /srv/samba/direction

chown root:"domain users" /srv/samba/comptabilite
chmod 2770 /srv/samba/comptabilite
setfacl -m g:comptabilite:rwx /srv/samba/comptabilite

chown root:"domain users" /srv/samba/technique
chmod 2770 /srv/samba/technique
setfacl -m g:technique:rwx /srv/samba/technique

chown root:"domain users" /srv/samba/commun
chmod 2777 /srv/samba/commun
setfacl -m g:direction:rwx /srv/samba/commun
setfacl -m g:comptabilite:rwx /srv/samba/commun
setfacl -m g:technique:rwx /srv/samba/commun

# 3. Ajout des partages dans smb.conf
echo "→ Ajout des partages dans smb.conf"
cat >> /etc/samba/smb.conf << EOF

# =====================
#     PARTAGES PME
# =====================

[direction]
   path = /srv/samba/direction
   valid users = @$DOMAIN\\direction
   read only = no
   create mask = 0660
   directory mask = 2770
   force group = direction
   browseable = yes
   comment = Documents confidentiels - Direction

[comptabilite]
   path = /srv/samba/comptabilite
   valid users = @$DOMAIN\\comptabilite
   read only = no
   create mask = 0660
   directory mask = 2770
   force group = comptabilite
   browseable = yes
   comment = Relevés financiers - Comptabilité

[technique]
   path = /srv/samba/technique
   valid users = @$DOMAIN\\technique
   read only = no
   create mask = 0660
   directory mask = 2770
   force group = technique
   browseable = yes
   comment = Configurations et scripts - Technique

[commun]
   path = /srv/samba/commun
   valid users = @$DOMAIN\\direction @$DOMAIN\\comptabilite @$DOMAIN\\technique
   read only = no
   create mask = 0664
   directory mask = 2777
   force group = $DOMAIN\\domain users
   browseable = yes
   comment = Zone d'échange transversale
EOF

# 4. Validation et redémarrage
echo "→ Validation de la configuration"
testparm -s

echo "→ Redémarrage de Samba AD DC"
systemctl restart samba-ad-dc

# 5. Vérifications
echo ""
echo "========================"
echo "   VÉRIFICATIONS   "
echo "========================"

echo "→ Test partage direction (dir1) :"
smbclient //localhost/direction -U dir1 --password=$USER_PASS -c "ls" && echo "✅ OK" || echo "❌ ÉCHEC"

echo ""
echo "→ Test partage comptabilite (compta1) :"
smbclient //localhost/comptabilite -U compta1 --password=$USER_PASS -c "ls" && echo "✅ OK" || echo "❌ ÉCHEC"

echo ""
echo "→ Test partage technique (tech1) :"
smbclient //localhost/technique -U tech1 --password=$USER_PASS -c "ls" && echo "✅ OK" || echo "❌ ÉCHEC"

echo ""
echo "→ Test partage commun (soc_reader) :"
smbclient //localhost/commun -U soc_reader --password=$USER_PASS -c "ls" && echo "✅ OK" || echo "❌ ÉCHEC"

echo ""
echo "============================================================"
echo "✅ PHASE 4 TERMINÉE"
echo "============================================================"
echo "Partages disponibles :"
echo "  - //10.0.1.20/direction    (groupe direction)"
echo "  - //10.0.1.20/comptabilite (groupe comptabilite)"
echo "  - //10.0.1.20/technique    (groupe technique)"
echo "  - //10.0.1.20/commun       (tous les groupes)"
