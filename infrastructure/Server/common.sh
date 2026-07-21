#!/usr/bin/env bash
# NYX — Server common provisioning functions
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

apt_update_once() {
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

is_installed() {
  dpkg -l "$1" 2>/dev/null | grep -q "^ii"
}

ensure_dir() {
  local dir="$1"
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir"
    log "Répertoire créé : $dir"
  fi
}

backup_file() {
  local file="$1"
  if [ -f "$file" ] && [ ! -f "${file}.bak" ]; then
    cp "$file" "${file}.bak"
    log "Sauvegarde : $file → ${file}.bak"
  fi
}
