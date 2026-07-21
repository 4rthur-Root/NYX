#!/usr/bin/env bash
# ============================================================
# Phase 4 — Configuration des partages Samba (AD DC)
# Idempotent : vérifie l'existence des partages avant création
# Usage : sudo bash samba_installation.sh
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

DOMAIN="NYX"
USER_PASS="Nyx2026!"

log "=== Configuration des partages Samba ==="

# ── 1. Création des répertoires ────────────────────────────

log "Création des répertoires de partage"
for share in direction comptabilite technique commun; do
  ensure_dir "/srv/samba/$share"
done

# ── 2. Permissions Unix + ACL ──────────────────────────────

log "Configuration des permissions"

# S'assurer que le répertoire parent est traversable
chmod 755 /srv/samba

# Récupérer les GIDs mappés par winbind pour les groupes AD
DIR_GID=$(wbinfo --group-info=direction 2>/dev/null | cut -d: -f3)
COMPTA_GID=$(wbinfo --group-info=comptabilite 2>/dev/null | cut -d: -f3)
TECH_GID=$(wbinfo --group-info=technique 2>/dev/null | cut -d: -f3)

for share in direction comptabilite technique; do
  case "$share" in
    direction)   GID="$DIR_GID" ;;
    comptabilite) GID="$COMPTA_GID" ;;
    technique)   GID="$TECH_GID" ;;
  esac
  chown root:"${GID}" "/srv/samba/$share"
  chmod 2770 "/srv/samba/$share"
done

chown root:root /srv/samba/commun
chmod 2777 /srv/samba/commun

log "  → Permissions configurées"

# ── 3. Vérification smb.conf avant ajout ────────────────────

log "Vérification des partages dans smb.conf"

NEED_SHARES=false
for share in direction comptabilite technique commun; do
  if grep -q "^\[$share\]" /etc/samba/smb.conf 2>/dev/null; then
    log "  → Partage '[$share]' déjà présent"
  else
    NEED_SHARES=true
  fi
done

if [ "$NEED_SHARES" = true ]; then
  log "Ajout des partages manquants dans smb.conf"
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
  log "  → Partages ajoutés"
else
  log "  → Tous les partages déjà présents"
fi

# ── 4. Validation et redémarrage ───────────────────────────

log "Validation de la configuration (testparm)"
if testparm -s >/dev/null 2>&1; then
  log "  → testparm OK"
else
  log "  → ATTENTION : testparm a des avertissements"
  testparm -s 2>&1 | tail -5
fi

log "Redémarrage de samba-ad-dc"
systemctl restart samba-ad-dc
sleep 3

# ── 5. Vérifications ──────────────────────────────────────

log ""
log "========================"
log "   VÉRIFICATIONS"
log "========================"

ERRORS=0

for share_user in "direction:dir1" "comptabilite:compta1" "technique:tech1" "commun:dir1"; do
  IFS=':' read -r share user <<< "$share_user"
  if smbclient //localhost/"$share" -U "$DOMAIN"\\\\"$user" --password="$USER_PASS" -c "ls" >/dev/null 2>&1; then
    log "  ✓ Partage $share ($user) accessible"
  else
    log "  ✗ Partage $share ($user) inaccessible"
    ERRORS=$((ERRORS + 1))
  fi
done

log ""
if [ "$ERRORS" -eq 0 ]; then
  log "============================================================"
  log "✅ PHASE 4 TERMINÉE"
  log "============================================================"
  log "Partages disponibles :"
  log "  - //10.0.1.20/direction    (groupe direction)"
  log "  - //10.0.1.20/comptabilite (groupe comptabilite)"
  log "  - //10.0.1.20/technique    (groupe technique)"
  log "  - //10.0.1.20/commun       (tous les groupes)"
else
  log "============================================================"
  log "❌ PHASE 4 TERMINÉE AVEC $ERRORS ERREUR(S)"
  log "============================================================"
  exit 1
fi
