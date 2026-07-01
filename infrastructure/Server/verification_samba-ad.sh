#!/bin/bash
# check_samba_ad.sh - Script de vérification autonome

echo "============================="
echo "VÉRIFICATION DE SAMBA AD DC"
echo "============================="

echo ""
echo "1. Service samba-ad-dc :"
if systemctl is-active --quiet samba-ad-dc; then
    echo "   ✅ ACTIF"
else
    echo "   ❌ INACTIF"
    exit 1
fi

echo ""
echo "2. Kerberos (kinit administrator) :"
echo "AdminNyx2026!" | kinit administrator@NYX.TG 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ Ticket obtenu"
    klist
else
    echo "   ❌ Échec"
    exit 1
fi

echo ""
echo "3. DNS :"
if host srv-pme.nyx.tg >/dev/null 2>&1; then
    echo "   ✅ Résolution OK"
    host srv-pme.nyx.tg
else
    echo "   ❌ Échec"
    exit 1
fi

echo ""
echo "4. SRV LDAP :"
if host -t SRV _ldap._tcp.nyx.tg >/dev/null 2>&1; then
    echo "   ✅ SRV LDAP OK"
    host -t SRV _ldap._tcp.nyx.tg
else
    echo "   ❌ Échec"
    exit 1
fi

echo ""
echo "5. Connexion Samba :"
if smbclient //localhost/netlogon -U dir1 --password=Nyx2026! -c "ls" >/dev/null 2>&1; then
    echo "   ✅ Connexion OK"
    smbclient -L localhost -U dir1 --password=Nyx2026!
else
    echo "   ❌ Échec"
    exit 1
fi

echo ""
echo "=========================================="
echo "✅ TOUTES LES VÉRIFICATIONS SONT PASSÉES"
echo "=========================================="