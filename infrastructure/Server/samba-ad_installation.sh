#!/usr/bin/env bash
# ============================================================
# Phase 3 — Installation et configuration de Samba 4 AD DC
# Idempotent : vérifie l'état avant chaque action
# Usage : sudo bash samba-ad_installation.sh
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# ============================================================
# VARIABLES
# ============================================================

REALM="NYX.TG"
DOMAIN="NYX"
ADMIN_PASS="AdminNyx2026!"
USER_PASS="Nyx2026!"

log "=== Installation Samba 4 AD DC ==="

# ============================================================
# ÉTAPE 1 : Installation des paquets
# ============================================================

log "ÉTAPE 1 : Installation des paquets Samba, Kerberos, Winbind"

PACKAGES="samba samba-ad-dc smbclient winbind libpam-winbind libnss-winbind krb5-user krb5-config python3-samba samba-ad-provision samba-dsdb-modules"
MISSING=""
for pkg in $PACKAGES; do
  if ! is_installed "$pkg"; then
    MISSING="$MISSING $pkg"
  fi
done

if [ -n "$MISSING" ]; then
  apt_install $MISSING
  log "  → Paquets installés :$MISSING"
else
  log "  → Tous les paquets Samba déjà installés"
fi

# ============================================================
# ÉTAPE 2 : Sauvegarde de la config existante
# ============================================================

log "ÉTAPE 2 : Nettoyage de smb.conf"
if [ -f /etc/samba/smb.conf ]; then
  if grep -q "server role = active directory domain controller" /etc/samba/smb.conf 2>/dev/null; then
    log "  → smb.conf AD DC déjà présent, conservation"
  else
    backup_file /etc/samba/smb.conf
    rm -f /etc/samba/smb.conf
    log "  → smb.conf non-AD supprimé (sera régénéré par le provisionnement)"
  fi
else
  log "  → Aucun smb.conf existant"
fi

# ============================================================
# ÉTAPE 3 : Arrêt des services par défaut
# ============================================================

log "ÉTAPE 3 : Arrêt des services smbd/nmbd/winbind"
systemctl stop smbd nmbd winbind 2>/dev/null || true
systemctl disable smbd nmbd winbind 2>/dev/null || true

# ============================================================
# ÉTAPE 4 : Provisionnement du domaine AD
# ============================================================

# Vérifier si le domaine est déjà provisionné
if [ -f /var/lib/samba/private/secrets.ldb ] && samba-tool domain level show 2>/dev/null | grep -q "Domain.*Level"; then
  log "ÉTAPE 4 : Domaine AD déjà provisionné, skip"
else
  log "ÉTAPE 4 : Provisionnement du domaine $REALM"
  export LDB_MODULES_PATH="/usr/lib/x86_64-linux-gnu/samba/ldb"
  samba-tool domain provision --realm="$REALM" \
                              --domain="$DOMAIN" \
                              --adminpass="$ADMIN_PASS" \
                              --use-rfc2307 \
                              --dns-backend=SAMBA_INTERNAL
  log "  → Domaine $REALM provisionné"
fi

# ============================================================
# ÉTAPE 5 : Résolveur DNS
# ============================================================

log "ÉTAPE 5 : Configuration du DNS local"

RESOLV_CONTENT="nameserver 127.0.0.1
search nyx.tg"

if grep -q "127.0.0.1" /etc/resolv.conf 2>/dev/null; then
  log "  → /etc/resolv.conf déjà pointé vers 127.0.0.1"
else
  backup_file /etc/resolv.conf
  echo "$RESOLV_CONTENT" > /etc/resolv.conf
  chattr +i /etc/resolv.conf 2>/dev/null || log "  → chattr non disponible, ignorer"
  log "  → /etc/resolv.conf configuré et verrouillé"
fi

# ============================================================
# ÉTAPE 6 : Service samba-ad-dc
# ============================================================

log "ÉTAPE 6 : Activation du service samba-ad-dc"
systemctl unmask samba-ad-dc 2>/dev/null || true
systemctl enable samba-ad-dc
systemctl start samba-ad-dc
log "  → Service samba-ad-dc démarré"

# ============================================================
# ÉTAPE 7 : Création des groupes
# ============================================================

log "ÉTAPE 7 : Création des groupes AD"

EXISTING_GROUPS=$(samba-tool group list 2>/dev/null || true)

for group in direction comptabilite technique; do
  if echo "$EXISTING_GROUPS" | grep -q "^$group$"; then
    log "  → Groupe '$group' existe déjà"
  else
    samba-tool group add "$group"
    log "  → Groupe '$group' créé"
  fi
done

# ============================================================
# ÉTAPE 8 : Création des utilisateurs
# ============================================================

log "ÉTAPE 8 : Création des utilisateurs AD"

EXISTING_USERS=$(samba-tool user list 2>/dev/null || true)

declare -A USERS=(
  [dir1]="Directeur:Un:dir1@nyx.tg"
  [compta1]="Comptable:Un:compta1@nyx.tg"
  [tech1]="Technicien:Un:tech1@nyx.tg"
  [soc_reader]="SOC:Reader:soc@nyx.tg"
)

for user in "${!USERS[@]}"; do
  IFS=':' read -r given surname mail <<< "${USERS[$user]}"
  if echo "$EXISTING_USERS" | grep -q "^$user$"; then
    log "  → Utilisateur '$user' existe déjà"
  else
    samba-tool user create "$user" "$USER_PASS" \
      --given-name="$given" \
      --surname="$surname" \
      --mail-address="$mail"
    log "  → Utilisateur '$user' créé"
  fi
done

# ============================================================
# ÉTAPE 9 : Ajout des utilisateurs aux groupes
# ============================================================

log "ÉTAPE 9 : Ajout des utilisateurs à leurs groupes"

samba-tool group addmembers direction dir1 2>/dev/null || log "  → dir1 déjà dans direction"
samba-tool group addmembers comptabilite compta1 2>/dev/null || log "  → compta1 déjà dans comptabilite"
samba-tool group addmembers technique tech1 2>/dev/null || log "  → tech1 déjà dans technique"

log "  → dir1 → direction"
log "  → compta1 → comptabilite"
log "  → tech1 → technique"
log "  → soc_reader : aucun groupe (lecture seule)"

# ============================================================
# ÉTAPE 10 : VÉRIFICATIONS
# ============================================================

log ""
log "ÉTAPE 10 : VÉRIFICATIONS AUTOMATIQUES"

ERRORS=0

# 1. Service
if systemctl is-active --quiet samba-ad-dc; then
  log "  ✓ Service samba-ad-dc actif"
else
  log "  ✗ Service samba-ad-dc INACTIF"
  ERRORS=$((ERRORS + 1))
fi

# 2. Kerberos
if echo "$ADMIN_PASS" | kinit administrator@NYX.TG 2>/dev/null; then
  log "  ✓ Ticket Kerberos obtenu"
else
  log "  ✗ Kerberos échoué"
  ERRORS=$((ERRORS + 1))
fi

# 3. DNS
if host srv-pme.nyx.tg >/dev/null 2>&1; then
  log "  ✓ DNS srv-pme.nyx.tg résout correctement"
else
  log "  ✗ DNS ne résout pas srv-pme.nyx.tg"
  ERRORS=$((ERRORS + 1))
fi

# 4. SRV LDAP
if host -t SRV _ldap._tcp.nyx.tg >/dev/null 2>&1; then
  log "  ✓ SRV LDAP trouvé"
else
  log "  ✗ Pas de SRV LDAP"
  ERRORS=$((ERRORS + 1))
fi

# 5. Connexion Samba
if smbclient //localhost/netlogon -U dir1 --password="$USER_PASS" -c "ls" >/dev/null 2>&1; then
  log "  ✓ Connexion Samba avec dir1 OK"
else
  log "  ✗ Connexion Samba échouée"
  ERRORS=$((ERRORS + 1))
fi

# 6. Groupes
for group in direction comptabilite technique; do
  if samba-tool group listmembers "$group" 2>/dev/null | grep -q .; then
    log "  ✓ Groupe '$group' a des membres"
  else
    log "  ✗ Groupe '$group' vide"
    ERRORS=$((ERRORS + 1))
  fi
done

# ── Résumé ──────────────────────────────────────────────────
log ""
if [ "$ERRORS" -eq 0 ]; then
  log "============================================================"
  log "✅ PHASE 3 TERMINÉE AVEC SUCCÈS"
  log "============================================================"
  log "  Domaine    : $REALM"
  log "  Admin      : administrator@$REALM"
  log "  Utilisateurs : dir1, compta1, tech1, soc_reader"
  log "  Groupes    : direction, comptabilite, technique"
  log ""
  log "Prochaine étape : Phase 4 — Configuration des partages Samba"
else
  log "============================================================"
  log "❌ PHASE 3 TERMINÉE AVEC $ERRORS ERREUR(S)"
  log "============================================================"
  exit 1
fi
