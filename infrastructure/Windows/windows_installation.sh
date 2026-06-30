#!/usr/bin/env bash
# NYX — Windows 10 VM creation
# Usage: bash windows_installation.sh

set -euo pipefail

VM_NAME="Windows10"
ISO_WIN10="/home/adrien/Downloads/ISO/Win10_22H2_English_x64.iso"
ISO_VIRTIO="/home/adrien/Downloads/ISO/virtio-win-0.1.285.iso"
MEMORY_MB=3072
DISK_SIZE_GB=50

# Vérifie que les ISOs existent
if [[ ! -f "$ISO_WIN10" ]]; then
  echo "[ERROR] ISO Windows 10 non trouvé : $ISO_WIN10" >&2
  echo "  Télécharger depuis : https://www.microsoft.com/software-download/windows10" >&2
  exit 1
fi

if [[ ! -f "$ISO_VIRTIO" ]]; then
  echo "[ERROR] ISO VirtIO non trouvé : $ISO_VIRTIO" >&2
  echo "  Télécharger depuis : https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso" >&2
  exit 1
fi

# Vérifie si la VM existe déjà
if virsh dominfo "$VM_NAME" &>/dev/null; then
  echo "[WARNING] VM '$VM_NAME' existe déjà."
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
  --vcpus 2 \
  --disk size="$DISK_SIZE_GB",bus=virtio,format=qcow2 \
  --cdrom "$ISO_WIN10" \
  --disk path="$ISO_VIRTIO",device=cdrom \
  --network network=default,model=virtio \
  --network network=nyx,model=virtio \
  --os-variant win10 \
  --graphics vnc,listen=127.0.0.1 \
  --noautoconsole

echo "[INFO] VM '$VM_NAME' créée."
echo "[INFO] Lancer l'installation : virt-viewer $VM_NAME"
echo ""
echo "[INFO] Pendant l'installation de Windows :"
echo "  1. Au choix du disque -> Load driver"
echo "  2. Parcourir E: -> vioscsi -> w10 -> amd64"
echo "  3. Sélectionner le pilote, le disque apparaît"
echo "  4. Continuer normalement"
echo ""
echo "[INFO] Après installation :"
echo "  - Lancer D: (virtio-win) -> virtio-win-gt-x64.msi"
echo "  - Configurer IP statique sur le réseau nyx (10.0.1.20/24)"
