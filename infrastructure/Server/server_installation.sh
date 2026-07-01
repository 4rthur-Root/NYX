#!/usr/bin/env bash
# NYX — Debian Server VM creation
# Usage: bash server_installation.sh

set -euo pipefail

VM_NAME="Server"
ISO_PATH="/home/adrien/Downloads/ISO/debian-13.5.0-amd64-netinst.iso"
MEMORY_MB=2048
DISK_SIZE_GB=8
STORAGE_POOL="default"

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

echo "[INFO] Création de la VM $VM_NAME..."

sudo virt-install \
  --name "$VM_NAME" \
  --memory "$MEMORY_MB" \
  --vcpus 1 \
  --disk size="$DISK_SIZE_GB",bus=virtio,format=qcow2 \
  --cdrom "$ISO_PATH" \
  --network network=nyx,model=virtio \
  --network network=default,model=virtio \
  --os-variant debiantrixie \
  --graphics vnc,listen=127.0.0.1 \
  --noautoconsole

echo "[INFO] VM créée. Lancement..."
sleep 5

echo "[INFO] Pour suivre l'installation : virt-viewer $VM_NAME"
echo "[INFO] Une fois Debian installée et le réseau configuré :"
echo "  scp -r infrastructure/Server/ user@10.0.1.20:/tmp/server-provision"
echo "  ssh user@10.0.1.20 'sudo bash /tmp/server-provision/base_installation.sh'"

echo ""
echo "Hostname à appliquer : srv-pme.nyx.tg"