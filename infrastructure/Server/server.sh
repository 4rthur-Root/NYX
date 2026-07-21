#!/usr/bin/env bash
# NYX — Server provisioning script (consolidé)
# Exécute toutes les phases de provisioning en une seule passe.
# Idempotent : peut être relancé sans casser l'existant.
# Usage : sudo bash server.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

log "=== Provisioning complet du Server NYX ==="

# Phase 1 : Base système
log "--- Phase 1 : Base système ---"
bash "$SCRIPT_DIR/base_installation.sh"

# Phase 2 : Samba AD DC
log "--- Phase 2 : Samba AD DC ---"
bash "$SCRIPT_DIR/samba-ad_installation.sh"

# Phase 3 : Partages Samba
log "--- Phase 3 : Partages Samba ---"
bash "$SCRIPT_DIR/samba_installation.sh"

# Phase 4 : Dolibarr
log "--- Phase 4 : Dolibarr ---"
bash "$SCRIPT_DIR/dolibarr/deploy_dolibarr.sh"

# Vérification finale
log "--- Vérification finale ---"
bash "$SCRIPT_DIR/verification_samba-ad.sh"

log "=== Provisioning terminé avec succès ==="
log "Services : Samba AD DC, Docker, Dolibarr, Chrony, Rsyslog"
log "Dolibarr : http://10.0.1.20 (admin/admin)"
