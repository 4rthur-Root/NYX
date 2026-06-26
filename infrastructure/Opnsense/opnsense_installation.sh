#!/usr/bin/env bash
# NYX — OPNsense VM creation
# Usage: bash opnsense_install.sh

set -euo pipefail

VM_NAME="Opnsense"
ISO_PATH="/home/adrien/Downloads/ISO/OPNsense-26.1.6-dvd-amd64.iso"
MEMORY_MB=1536
DISK_SIZE_GB=8

# Vérifie que l'ISO existe
if [[ ! -f "$ISO_PATH" ]]; then
  echo "[ERROR] ISO non trouvé : $ISO_PATH" >&2
  exit 1
fi

# Vérifie si la VM existe déjà
if virsh dominfo "$VM_NAME" &>/dev/null; then
  echo "[WARNING] Une VM nommée '$VM_NAME' existe déjà."

  read -rp "Voulez-vous la supprimer et la recréer ? (y/N) : " CONFIRM

  case "$CONFIRM" in
    y|Y|yes|YES)
      echo "[INFO] Suppression de la VM '$VM_NAME'..."

      virsh destroy "$VM_NAME" 2>/dev/null || true
      virsh undefine "$VM_NAME" --remove-all-storage 2>/dev/null || true
      ;;
    *)
      echo "[INFO] Opération annulée."
      exit 0
      ;;
  esac
fi

echo "[INFO] Création de la VM OPNsense..."
sudo virt-install \
  --name "$VM_NAME" \
  --memory "$MEMORY_MB" \
  --vcpus 1 \
  --disk size="$DISK_SIZE_GB",bus=virtio,format=qcow2 \
  --cdrom "$ISO_PATH" \
  --network network=nyx,model=virtio \
  --network network=default,model=virtio \
  --os-variant freebsd13.0 \
  --graphics vnc,listen=127.0.0.1 \
  --noautoconsole

echo "[INFO] Attente du démarrage de la VM..."
sleep 5

echo "[INFO] Ouverture du viewer VNC..."
virt-viewer "$VM_NAME"