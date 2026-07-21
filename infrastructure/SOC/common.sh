#!/usr/bin/env bash
# NYX — common provisioning functions
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

apt_update_once() {
  # Ne met à jour qu'une fois par exécution de script (flag sous /tmp)
  local flag="/tmp/.nyx_apt_updated"
  if [ ! -f "$flag" ]; then
    apt-get update -qq
    touch "$flag"
  fi
}

apt_install() {
  apt_update_once
  apt-get install -y -qq --no-install-recommends "$@"
}

apt_clean() {
  apt-get clean
  rm -rf /var/lib/apt/lists/*
}

ensure_user() {
  local user="$1"
  if ! id "$user" &>/dev/null; then
    useradd -m -s /bin/bash "$user"
    log "Utilisateur $user créé"
  else
    log "Utilisateur $user existe déjà"
  fi
}

check_network_manager() {
  # Vérifie qu'il n'y a pas de conflit ifupdown / NetworkManager
  if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    log "ATTENTION : NetworkManager actif, risque de conflit avec /etc/network/interfaces"
  fi
}