#!/bin/bash
# ============================================================
# Phase 3 - Installation et configuration de Samba 4 AD DC
# Objectif : Transformer Debian Server en contrôleur de domaine
#            compatible Active Directory
# ============================================================

set -e  # Arrête le script en cas d'erreur

# ============================================================
# VARIABLES (modifiables selon besoin)
# ============================================================

REALM="NYX.TG"                      # Nom de domaine Kerberos (MAJUSCULES)
DOMAIN="NYX"                        # Nom NetBIOS du domaine (MAJUSCULES)
ADMIN_PASS="AdminNyx2026!"          # Mot de passe administrateur
USER_PASS="Nyx2026!"                # Mot de passe des utilisateurs standards

# ============================================================
# ÉTAPE 1 : Installation des paquets Samba et dépendances
# ============================================================

echo "============================================================"
echo "ÉTAPE 1 : Installation de Samba 4, Kerberos et Winbind"
echo "============================================================"
echo ""
echo "Pourquoi ? Samba 4 intègre un contrôleur de domaine Active Directory"
echo "compatible avec Kerberos (authentification centralisée) et LDAP."
echo "Winbind permet la résolution des utilisateurs du domaine."
echo ""

apt update
apt install -y samba smbclient winbind libpam-winbind libnss-winbind krb5-user krb5-config

# ============================================================
# ÉTAPE 2 : Sauvegarde et nettoyage de la configuration existante
# ============================================================

echo ""
echo "============================================================"
echo "ÉTAPE 2 : Sauvegarde de l'ancienne configuration Samba"
echo "============================================================"
echo ""
echo "Pourquoi ? Le provisionnement de Samba en mode AD DC nécessite"
echo "un fichier smb.conf propre. Si un fichier existe déjà,"
echo "Samba refuse de provisionner et demande de le régénérer."
echo "On le sauvegarde donc au cas où."
echo ""

if [ -f /etc/samba/smb.conf ]; then
    echo "→ Sauvegarde de /etc/samba/smb.conf vers smb.conf.bak"
    sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.bak
else
    echo "→ Aucun fichier smb.conf existant, pas besoin de sauvegarde."
fi

# ============================================================
# ÉTAPE 3 : Arrêt des services Samba par défaut
# ============================================================

echo ""
echo "============================================================"
echo "ÉTAPE 3 : Arrêt des services Samba/Winbind par défaut"
echo "============================================================"
echo ""
echo "Pourquoi ? Les services 'smbd' et 'nmbd' (serveur SMB classique)"
echo "entrent en conflit avec le mode 'samba-ad-dc' qui est un service"
echo "unifié. On les désactive pour éviter tout conflit."
echo ""

systemctl stop smbd nmbd winbind 2>/dev/null || true
systemctl disable smbd nmbd winbind 2>/dev/null || true

# ============================================================
# ÉTAPE 4 : Provisionnement du domaine Active Directory
# ============================================================

echo ""
echo "============================================================"
echo "ÉTAPE 4 : Provisionnement du domaine Active Directory"
echo "============================================================"
echo ""
echo "Pourquoi ? Cette commande crée la base LDAP, les politiques"
echo "de groupe, les DNS intégrés, et toutes les structures"
echo "nécessaires à un contrôleur de domaine Samba 4."
echo ""
echo "Paramètres :"
echo "  --realm=$REALM        : Domaine Kerberos"
echo "  --domain=$DOMAIN      : Nom NetBIOS du domaine"
echo "  --use-rfc2307         : Active les schémas POSIX (UID/GID)"
echo "  --dns-backend=SAMBA_INTERNAL : DNS intégré à Samba"
echo ""

samba-tool domain provision --realm=$REALM \
                            --domain=$DOMAIN \
                            --adminpass=$ADMIN_PASS \
                            --use-rfc2307 \
                            --dns-backend=SAMBA_INTERNAL

# ============================================================
# ÉTAPE 5 : Configuration du résolveur DNS
# ============================================================

echo ""
echo "============================================================"
echo "ÉTAPE 5 : Configuration du résolveur DNS local"
echo "============================================================"
echo ""
echo "Pourquoi ? Le contrôleur de domaine intègre un serveur DNS."
echo "On configure le système pour interroger le DNS de Samba"
echo "(127.0.0.1) afin de résoudre les noms du domaine."
echo ""

echo "nameserver 127.0.0.1" > /etc/resolv.conf
echo "search nyx.tg" >> /etc/resolv.conf

# On rend le fichier immuable pour éviter qu'il soit écrasé
# par NetworkManager ou dhclient
chattr +i /etc/resolv.conf 2>/dev/null || echo "→ chattr non disponible, ignorer."

echo "→ /etc/resolv.conf configuré et verrouillé."

# ============================================================
# ÉTAPE 6 : Démarrage du service Samba AD DC
# ============================================================

echo ""
echo "============================================================"
echo "ÉTAPE 6 : Démarrage du service Samba AD DC"
echo "============================================================"
echo ""
echo "Pourquoi ? On active et démarre le service unifié 'samba-ad-dc'"
echo "qui remplace les anciens services smbd/nmbd/winbind."
echo ""

systemctl unmask samba-ad-dc
systemctl enable samba-ad-dc
systemctl start samba-ad-dc

echo "→ Service samba-ad-dc démarré."

# ============================================================
# ÉTAPE 7 : Création des groupes Active Directory
# ============================================================

echo ""
echo "============================================================"
echo "ÉTAPE 7 : Création des groupes Active Directory"
echo "============================================================"
echo ""
echo "Pourquoi ? Ces groupes correspondent aux services de la PME :"
echo "  - direction     : documents confidentiels (contrats)"
echo "  - comptabilite  : relevés financiers (Mobile Money)"
echo "  - technique     : configurations et scripts"
echo ""

samba-tool group add direction
samba-tool group add comptabilite
samba-tool group add technique

echo "→ Groupes créés : direction, comptabilite, technique"

# ============================================================
# ÉTAPE 8 : Création des utilisateurs Active Directory
# ============================================================

echo ""
echo "============================================================"
echo "ÉTAPE 8 : Création des utilisateurs Active Directory"
echo "============================================================"
echo ""
echo "Pourquoi ? Ces utilisateurs simulent les employés de la PME :"
echo "  - dir1      : Directeur (groupe direction)"
echo "  - comptal   : Comptable (groupe comptabilite)"
echo "  - tech1     : Technicien (groupe technique)"
echo "  - soc_reader: Compte du SOC pour analyse YARA"
echo ""

samba-tool user create dir1 $USER_PASS \
    --given-name="Directeur" \
    --surname="Un" \
    --mail-address=dir1@nyx.tg

samba-tool user create comptal $USER_PASS \
    --given-name="Comptable" \
    --surname="Un" \
    --mail-address=comptal@nyx.tg

samba-tool user create tech1 $USER_PASS \
    --given-name="Technicien" \
    --surname="Un" \
    --mail-address=tech1@nyx.tg

samba-tool user create soc_reader $USER_PASS \
    --given-name="SOC" \
    --surname="Reader" \
    --mail-address=soc@nyx.tg

echo "→ Utilisateurs créés : dir1, comptal, tech1, soc_reader"

# ============================================================
# ÉTAPE 9 : Ajout des utilisateurs à leurs groupes
# ============================================================

echo ""
echo "============================================================"
echo "ÉTAPE 9 : Ajout des utilisateurs à leurs groupes"
echo "============================================================"

samba-tool group addmembers direction dir1
samba-tool group addmembers comptabilite comptal
samba-tool group addmembers technique tech1

echo "→ dir1 → direction"
echo "→ comptal → comptabilite"
echo "→ tech1 → technique"
echo "→ soc_reader : aucun groupe (lecture seule)"

# ============================================================
# ÉTAPE 10 : VÉRIFICATIONS AUTOMATIQUES
# ============================================================

echo ""
echo "============================================================"
echo "ÉTAPE 10 : VÉRIFICATIONS AUTOMATIQUES"
echo "============================================================"
echo ""
echo "On va maintenant valider que tout fonctionne correctement."
echo ""

# Vérification 1 : Service Samba
echo "------------------------------------------------------------"
echo "✓ VÉRIFICATION 1 : Service samba-ad-dc en cours d'exécution ?"
echo "------------------------------------------------------------"
if systemctl is-active --quiet samba-ad-dc; then
    echo "✅ SUCCÈS : Samba AD DC est actif."
else
    echo "❌ ÉCHEC : Samba AD DC n'est pas actif."
    systemctl status samba-ad-dc --no-pager
    exit 1
fi

# Vérification 2 : Tickets Kerberos
echo ""
echo "------------------------------------------------------------"
echo "✓ VÉRIFICATION 2 : Authentification Kerberos fonctionnelle ?"
echo "------------------------------------------------------------"
echo "→ On demande un ticket pour administrator@NYX.TG"
if echo "$ADMIN_PASS" | kinit administrator@NYX.TG 2>/dev/null; then
    echo "✅ SUCCÈS : Ticket Kerberos obtenu."
    echo ""
    echo "→ Tickets actuels :"
    klist
else
    echo "❌ ÉCHEC : Impossible d'obtenir un ticket Kerberos."
    exit 1
fi

# Vérification 3 : Résolution DNS
echo ""
echo "------------------------------------------------------------"
echo "✓ VÉRIFICATION 3 : Résolution DNS fonctionnelle ?"
echo "------------------------------------------------------------"
echo "→ Résolution de srv-pme.nyx.tg"
if host srv-pme.nyx.tg >/dev/null 2>&1; then
    echo "✅ SUCCÈS : Le nom srv-pme.nyx.tg résout correctement."
    host srv-pme.nyx.tg
else
    echo "❌ ÉCHEC : Le nom ne résout pas."
    exit 1
fi

# Vérification 4 : Enregistrements SRV (découverte du DC)
echo ""
echo "------------------------------------------------------------"
echo "✓ VÉRIFICATION 4 : Enregistrements SRV LDAP/Kerberos ?"
echo "------------------------------------------------------------"
echo "→ Recherche du service LDAP sur _ldap._tcp.nyx.tg"
if host -t SRV _ldap._tcp.nyx.tg >/dev/null 2>&1; then
    echo "✅ SUCCÈS : SRV LDAP trouvé."
    host -t SRV _ldap._tcp.nyx.tg
else
    echo "❌ ÉCHEC : Pas de SRV LDAP."
    exit 1
fi

# Vérification 5 : Connexion Samba
echo ""
echo "------------------------------------------------------------"
echo "✓ VÉRIFICATION 5 : Connexion Samba en tant qu'utilisateur ?"
echo "------------------------------------------------------------"
echo "→ Connexion avec dir1 (partage netlogon)"
if smbclient //localhost/netlogon -U dir1 --password=$USER_PASS -c "ls" >/dev/null 2>&1; then
    echo "✅ SUCCÈS : Connexion Samba avec dir1 OK."
    echo ""
    echo "→ Liste des partages :"
    smbclient -L localhost -U dir1 --password=$USER_PASS
else
    echo "❌ ÉCHEC : Impossible de se connecter avec dir1."
    exit 1
fi

# Vérification 6 : Groupes
echo ""
echo "------------------------------------------------------------"
echo "✓ VÉRIFICATION 6 : Groupes et membres corrects ?"
echo "------------------------------------------------------------"
echo "→ Membres du groupe direction :"
samba-tool group listmembers direction
echo ""
echo "→ Membres du groupe comptabilite :"
samba-tool group listmembers comptabilite
echo ""
echo "→ Membres du groupe technique :"
samba-tool group listmembers technique

# ============================================================
# FIN DU SCRIPT
# ============================================================

echo ""
echo "============================================================"
echo "✅ PHASE 3 TERMINÉE AVEC SUCCÈS !"
echo "============================================================"
echo ""
echo "RÉSUMÉ :"
echo "  - Domaine : $REALM"
echo "  - Admin   : administrator@$REALM"
echo "  - Utilisateurs : dir1, comptal, tech1, soc_reader"
echo "  - Groupes : direction, comptabilite, technique"
echo ""
echo "✅ Toutes les vérifications sont PASSÉES."
echo ""
echo "Prochaine étape : Phase 4 - Configuration des partages Samba"
echo "============================================================"