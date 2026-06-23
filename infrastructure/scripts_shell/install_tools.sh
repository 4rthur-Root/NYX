#!/bin/bash
set -e

echo "======================================"
echo "    Installing DevSecOps Lab Tools"
echo "======================================"

# Update packages
echo "[*] Updating system packages..."
sudo apt-get update

# Install prerequisites for Vagrant-libvirt
echo "[*] Installing KVM/Libvirt and prerequisites..."
sudo apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils curl software-properties-common apt-transport-https wget

# Start and enable libvirtd
sudo systemctl enable --now libvirtd

# Install Ansible
echo "[*] Installing Ansible..."
if ! command -v ansible >/dev/null 2>&1; then
    sudo apt-add-repository --yes --update ppa:ansible/ansible
    sudo apt-get install -y ansible
else
    echo "Ansible already installed."
fi

# Install Vagrant
echo "[*] Installing Vagrant..."
if ! command -v vagrant >/dev/null 2>&1; then
    wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
    sudo apt-get update
    sudo apt-get install -y vagrant
else
    echo "Vagrant already installed."
fi

# Install vagrant-libvirt plugin
echo "[*] Installing vagrant-libvirt plugin..."
# Installing via apt is recommended for debian/ubuntu to match system ruby
sudo apt-get install -y vagrant-libvirt ruby-libvirt

# Sometimes we still need to install the plugin directly if apt version is outdated or user prefers
vagrant plugin install vagrant-libvirt || echo "Plugin vagrant-libvirt already installed or managed by apt."

echo ""
echo "======================================"
echo "          Verification Phase"
echo "======================================"

echo "[*] Ansible Version:"
ansible --version | head -n 1

echo "[*] Vagrant Version:"
vagrant --version

echo "[*] Vagrant Plugins:"
vagrant plugin list

echo "[*] Libvirt Status:"
systemctl status libvirtd --no-pager | grep Active || true

echo ""
echo "Installation and verification complete!"
echo "Note: If you encounter permission issues with libvirt, ensure your user is added to the libvirt and kvm groups:"
echo "sudo usermod -aG libvirt,kvm \$USER"
echo "Then log out and log back in."
