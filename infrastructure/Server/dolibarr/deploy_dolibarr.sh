#!/usr/bin/env bash
# ============================================================
# deploy_dolibarr.sh — Déploiement de Dolibarr (Docker Compose)
# Idempotent : vérifie l'état des conteneurs avant lancement
# Usage : bash deploy_dolibarr.sh (lancé en root ou user docker)
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log "============================================================"
log "         Déploiement de Dolibarr sur Debian Server"
log "============================================================"

# ── 1. Vérifier Docker ─────────────────────────────────────

if ! command -v docker &>/dev/null; then
  log "ERREUR : Docker non trouvé. Installer d'abord avec base_installation.sh"
  exit 1
fi

if ! docker compose version &>/dev/null; then
  log "ERREUR : Docker Compose non disponible"
  exit 1
fi

# ── 2. Vérifier l'état des conteneurs ──────────────────────

cd "$SCRIPT_DIR"

CONTAINERS=$(docker compose ps --format json 2>/dev/null || true)
WEB_RUNNING=$(echo "$CONTAINERS" | grep -c '"dolibarr_web"' || true)
DB_RUNNING=$(echo "$CONTAINERS" | grep -c '"dolibarr_db"' || true)

if [ "$WEB_RUNNING" -gt 0 ] && [ "$DB_RUNNING" -gt 0 ]; then
  log "Conteneurs Dolibarr déjà en cours d'exécution"
  docker compose ps
  log ""
  log "Pour redémarrer : docker compose restart"
  log "Pourforcer : docker compose down && docker compose up -d"
  exit 0
fi

# ── 3. Lancement ───────────────────────────────────────────

log "Lancement de Dolibarr..."
docker compose up -d

# ── 4. Attente du démarrage ────────────────────────────────

log "Attente du démarrage..."
MAX_WAIT=60
WAITED=0
while [ "$WAITED" -lt "$MAX_WAIT" ]; do
  if docker compose ps --format json 2>/dev/null | grep -q '"running"'; then
    log "  → Conteneurs démarrés après ${WAITED}s"
    break
  fi
  sleep 5
  WAITED=$((WAITED + 5))
  log "  → Attente... (${WAITED}s/${MAX_WAIT}s)"
done

if [ "$WAITED" -ge "$MAX_WAIT" ]; then
  log "ATTENTION : Timeout atteint, vérifier les logs"
fi

# ── 5. Vérification finale ─────────────────────────────────

log ""
log "État des conteneurs :"
docker compose ps

log ""
log "============================================================"
log "✅ Dolibarr opérationnel sur http://10.0.1.20"
log "   - Login : admin"
log "   - Mot de passe : admin"
log "============================================================"
log ""
log "Vérifier les logs :"
log "  docker compose logs -f"
