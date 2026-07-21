#!/usr/bin/env bash
# ============================================================
# Installation Docker CE + Compose sur Debian
# Idempotent : vérifie avant chaque étape
# Usage : bash docker_install.sh (lancé en root)
# ============================================================

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

# ── Vérification si Docker est déjà installé ────────────────
if command -v docker &>/dev/null; then
  log "Docker déjà installé : $(docker --version)"
  log "Vérification du dépôt APT..."

  if [ ! -f /etc/apt/sources.list.d/docker.list ]; then
    log "  → Dépôt Docker manquant, réinstallation..."
  else
    log "  → Dépôt Docker présent ✓"
    log "Vérification de Docker Compose..."
    if docker compose version &>/dev/null; then
      log "  → Docker Compose disponible ✓"
      log "Docker est à jour, rien à faire."
      exit 0
    fi
  fi
fi

log "=== Installation de Docker CE + Compose ==="

# ── 1. Prérequis ───────────────────────────────────────────
log "Installation des prérequis..."
apt-get update -qq
apt-get install -y -qq ca-certificates curl

# ── 2. Clé GPG officielle ──────────────────────────────────
log "Ajout de la clé GPG Docker..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# ── 3. Dépôt APT ──────────────────────────────────────────
log "Ajout du dépôt Docker..."
CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $CODENAME stable" \
  > /etc/apt/sources.list.d/docker.list

# ── 4. Installation ────────────────────────────────────────
log "Installation de Docker CE + Compose..."
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# ── 5. Groupe docker ───────────────────────────────────────
if id -nG "${SUDO_USER:-root}" 2>/dev/null | grep -qw docker; then
  log "Utilisateur déjà dans le groupe docker"
else
  usermod -aG docker "${SUDO_USER:-root}" 2>/dev/null || true
  log "Utilisateur ajouté au groupe docker"
fi

# ── 6. Activation du service ───────────────────────────────
systemctl enable docker
systemctl start docker

# ── 7. Vérification ────────────────────────────────────────
log ""
log "============================================================"
log "✅ Docker installé avec succès"
log "  $(docker --version)"
log "  $(docker compose version)"
log "============================================================"
