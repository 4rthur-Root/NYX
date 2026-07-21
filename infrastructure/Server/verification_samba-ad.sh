#!/usr/bin/env bash
# ============================================================
# Vérification autonome de Samba AD DC
# Usage : sudo bash verification_samba-ad.sh
# ============================================================

set -euo pipefail

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

ADMIN_PASS="AdminNyx2026!"
USER_PASS="Nyx2026!"

log "============================="
log "VÉRIFICATION DE SAMBA AD DC"
log "============================="

ERRORS=0

# ── 1. Service ─────────────────────────────────────────────

if systemctl is-active --quiet samba-ad-dc; then
  log "  ✓ Service samba-ad-dc : ACTIF"
else
  log "  ✗ Service samba-ad-dc : INACTIF"
  ERRORS=$((ERRORS + 1))
fi

# ── 2. Kerberos ────────────────────────────────────────────

if echo "$ADMIN_PASS" | kinit administrator@NYX.TG 2>/dev/null; then
  log "  ✓ Kerberos : ticket obtenu"
  klist 2>/dev/null | head -5
else
  log "  ✗ Kerberos : échec"
  ERRORS=$((ERRORS + 1))
fi

# ── 3. DNS ─────────────────────────────────────────────────

if host srv-pme.nyx.tg >/dev/null 2>&1; then
  log "  ✓ DNS : srv-pme.nyx.tg → $(host srv-pme.nyx.tg 2>/dev/null | head -1)"
else
  log "  ✗ DNS : srv-pme.nyx.tg ne résout pas"
  ERRORS=$((ERRORS + 1))
fi

# ── 4. SRV LDAP ────────────────────────────────────────────

if host -t SRV _ldap._tcp.nyx.tg >/dev/null 2>&1; then
  log "  ✓ SRV LDAP : trouvé"
else
  log "  ✗ SRV LDAP : introuvable"
  ERRORS=$((ERRORS + 1))
fi

# ── 5. SRV Kerberos ───────────────────────────────────────

if host -t SRV _kerberos._tcp.nyx.tg >/dev/null 2>&1; then
  log "  ✓ SRV Kerberos : trouvé"
else
  log "  ✗ SRV Kerberos : introuvable"
  ERRORS=$((ERRORS + 1))
fi

# ── 6. Connexion Samba ────────────────────────────────────

if smbclient //localhost/netlogon -U dir1 --password="$USER_PASS" -c "ls" >/dev/null 2>&1; then
  log "  ✓ Connexion Samba : dir1 sur netlogon OK"
else
  log "  ✗ Connexion Samba : échec"
  ERRORS=$((ERRORS + 1))
fi

# ── 7. Groupes ─────────────────────────────────────────────

for group in direction comptabilite technique; do
  count=$(samba-tool group listmembers "$group" 2>/dev/null | wc -l)
  if [ "$count" -gt 0 ]; then
    log "  ✓ Groupe '$group' : $count membre(s)"
  else
    log "  ✗ Groupe '$group' : vide"
    ERRORS=$((ERRORS + 1))
  fi
done

# ── Résumé ──────────────────────────────────────────────────

log ""
if [ "$ERRORS" -eq 0 ]; then
  log "=========================================="
  log "✅ TOUTES LES VÉRIFICATIONS SONT PASSÉES"
  log "=========================================="
else
  log "=========================================="
  log "❌ $ERRORS VÉRIFICATION(S) ÉCHOUÉE(S)"
  log "=========================================="
  exit 1
fi
