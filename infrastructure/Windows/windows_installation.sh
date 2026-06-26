#!/usr/bin/env bash
# =============================================================
# NYX — Build et packaging de la box Windows 10 22H2
# Usage: bash scripts_shell/windows_installation.sh
# =============================================================
set -euo pipefail

PACKER_DIR="packer/windows"
OUTPUT_DIR="${PACKER_DIR}/output-windows_10"
QCOW2_FILE="${OUTPUT_DIR}/packer-win10_22h2"
BOX_FILE="${OUTPUT_DIR}/windows-10-libvirt.box"
BOX_NAME="windows-10"
BOX_TMP="${OUTPUT_DIR}/box_tmp"

# 1. Vérification de l'ISO
ISO_PATH="/home/adrien/Downloads/ISO/Win10_22H2_EnglishInternational_x64v1.iso"
if [[ ! -f "$ISO_PATH" ]]; then
  echo "[ERROR] ISO Windows non trouvé : ${ISO_PATH}" >&2
  exit 1
fi

# 2. Espace disque (le build nécessite ~70 Go libres)
AVAIL_GB=$(df --output=avail -BG ~ | tail -1 | tr -d 'G ')
if [[ "$AVAIL_GB" -lt 70 ]]; then
  echo "[ERROR] Espace insuffisant : ${AVAIL_GB} Go disponibles, 70 Go requis." >&2
  exit 1
fi
echo "[INFO] Espace disponible : ${AVAIL_GB} Go — OK."

# 3. Packer init + build
echo "[1/3] Packer init..."
cd "$PACKER_DIR"
packer init win10_22h2.pkr.hcl

echo "[2/3] Packer build (peut prendre 1h30-2h)..."
packer build win10_22h2.pkr.hcl

cd - > /dev/null

# 4. Vérification du qcow2 produit
if [[ ! -f "$QCOW2_FILE" ]]; then
  echo "[ERROR] Build Packer terminé mais qcow2 introuvable : ${QCOW2_FILE}" >&2
  exit 1
fi
echo "[INFO] qcow2 produit : $(du -sh "$QCOW2_FILE" | cut -f1)"

# 5. Packaging en box Vagrant
echo "[3/3] Packaging box Vagrant..."

# Nettoyage d'un éventuel run précédent
rm -rf "$BOX_TMP"
mkdir -p "$BOX_TMP"

# Copie du disque
echo "[INFO] Copie du qcow2 (peut prendre quelques minutes)..."
cp "$QCOW2_FILE" "${BOX_TMP}/box.img"

# Vagrantfile minimal libvirt
cat > "${BOX_TMP}/Vagrantfile" << 'EOF'
Vagrant.configure("2") do |config|
  config.vm.provider :libvirt do |libvirt|
    libvirt.driver = "kvm"
  end
end
EOF

# Métadonnées
cat > "${BOX_TMP}/metadata.json" << 'EOF'
{
  "provider": "libvirt",
  "format": "qcow2",
  "virtual_size": 60
}
EOF

# Compression
echo "[INFO] Compression de la box (peut prendre 5-10 minutes)..."
cd "$BOX_TMP"
tar czf "../windows-10-libvirt.box" ./metadata.json ./Vagrantfile ./box.img
cd - > /dev/null

# Nettoyage tmp
rm -rf "$BOX_TMP"

echo "[INFO] Box créée : $(du -sh "$BOX_FILE" | cut -f1) → ${BOX_FILE}"

# 6. Enregistrement dans Vagrant
echo "[INFO] Enregistrement dans Vagrant..."
vagrant box remove "$BOX_NAME" --provider libvirt 2>/dev/null || true
vagrant box add "$BOX_NAME" "$BOX_FILE" --provider libvirt

echo ""
echo "======================================"
echo "[OK] Windows 10 22H2 — box prête."
echo "     Vagrant box : ${BOX_NAME}"
vagrant box list | grep "$BOX_NAME"
echo "======================================"