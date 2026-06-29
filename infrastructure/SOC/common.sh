#!/usr/bin/env bash
# NYX — common provisioning functions
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

apt_install() {
  apt-get update -qq
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
  fi
}