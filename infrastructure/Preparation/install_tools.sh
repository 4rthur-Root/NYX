#!/usr/bin/env bash
# ==================================================
# NYX — Installation des dépendances (Fedora 44+)
# Usage: bash scripts_shell/install_tools.sh
# ==================================================
set -euo pipefail

VAGRANT_VERSION="2.4.9"
VAGRANT_RPM="vagrant-${VAGRANT_VERSION}-1.x86_64.rpm"
VAGRANT_URL="https://releases.hashicorp.com/vagrant/${VAGRANT_VERSION}/${VAGRANT_RPM}"

echo "======================================"
echo "   NYX — Installation des outils"
echo "   Cible : Fedora $(rpm -E %fedora)"
echo "======================================"

# 1. KVM / Libvirt
echo ""
echo "[1/5] KVM / Libvirt..."
sudo dnf install -y \
  qemu-kvm libvirt libvirt-daemon-kvm libvirt-client \
  virt-install virt-viewer libguestfs-tools \
  bridge-utils

sudo systemctl enable --now libvirtd

# Ajouter l'utilisateur courant aux groupes nécessaires
sudo usermod -aG libvirt,kvm "$USER"

# URI libvirt par défaut (évite le problème qemu:///session vs system)
if ! grep -q 'LIBVIRT_DEFAULT_URI' ~/.bashrc; then
  echo 'export LIBVIRT_DEFAULT_URI="qemu:///system"' >> ~/.bashrc
  echo "[INFO] LIBVIRT_DEFAULT_URI ajouté à ~/.bashrc"
fi
export LIBVIRT_DEFAULT_URI="qemu:///system"

# 2. Packe
echo ""
echo "[2/5] Packer..."
if ! command -v packer &>/dev/null; then
  sudo dnf install -y dnf-plugins-core
  sudo dnf config-manager addrepo \
    --from-repofile=https://rpm.releases.hashicorp.com/fedora/hashicorp.repo
  sudo dnf install -y packer
else
  echo "[INFO] Packer déjà installé : $(packer version)"
fi

# 3. Vagran
echo ""
echo "[3/5] Vagrant ${VAGRANT_VERSION}..."
if command -v vagrant &>/dev/null; then
  INSTALLED=$(vagrant --version | grep -oP '\d+\.\d+\.\d+')
  if [[ "$INSTALLED" == "$VAGRANT_VERSION" ]]; then
    echo "[INFO] Vagrant ${VAGRANT_VERSION} déjà installé."
  else
    echo "[WARN] Version installée : ${INSTALLED} — mise à jour vers ${VAGRANT_VERSION}..."
    wget -q "$VAGRANT_URL" -O "/tmp/${VAGRANT_RPM}"
    sudo dnf install -y "/tmp/${VAGRANT_RPM}"
    rm -f "/tmp/${VAGRANT_RPM}"
  fi
else
  echo "[INFO] Téléchargement de Vagrant ${VAGRANT_VERSION}..."
  wget -q "$VAGRANT_URL" -O "/tmp/${VAGRANT_RPM}"
  sudo dnf install -y "/tmp/${VAGRANT_RPM}"
  rm -f "/tmp/${VAGRANT_RPM}"
fi

# 4. Dépendances de compilation pour vagrant-libvirt
echo ""
echo "[4/5] Dépendances de compilation..."
sudo dnf install -y \
  gcc make \
  libvirt-devel libxml2-devel \
  ruby-devel libguestfs-tools

# 5. Plugin vagrant-libvirt
echo ""
echo "[5/5] Plugin vagrant-libvirt..."
if vagrant plugin list | grep -q 'vagrant-libvirt'; then
  echo "[INFO] Plugin vagrant-libvirt déjà installé."
else
  vagrant plugin install vagrant-libvirt
fi

# Ansible
echo ""
echo "[+] Ansible..."
if ! command -v ansible &>/dev/null; then
  sudo dnf install -y ansible
else
  echo "[INFO] Ansible déjà installé : $(ansible --version | head -n1)"
fi

# Vérification finale
echo ""
echo "======================================"
echo "          Vérification"
echo "======================================"
echo "Vagrant      : $(vagrant --version)"
echo "Packer       : $(packer version)"
echo "Ansible      : $(ansible --version | head -n1)"
echo "Libvirt      : $(systemctl is-active libvirtd)"
echo "Plugins      : $(vagrant plugin list | grep libvirt || echo 'NON INSTALLÉ')"
echo ""
echo "[!] Reconnecte-toi pour que les groupes libvirt/kvm soient effectifs."
echo "[!] Source ~/.bashrc ou relance le shell pour LIBVIRT_DEFAULT_URI."