packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.0"
    }
    vagrant = {
      source  = "github.com/hashicorp/vagrant"
      version = "~> 1.0"
    }
  }
}

variable "iso_url" {
  default = "/home/adrien/Downloads/ISO/OPNsense-26.1.6-dvd-amd64.iso"
}

variable "iso_checksum" {
  # Calculez avec: sha256sum ~/Downloads/ISO/OPNsense-26.1.6-dvd-amd64.iso
  default = "sha256:19f8cf0e68d5fa15144b33e72723af32f2bccb025ea48aa42803330c434cc570"
}

source "qemu" "opnsense" {
  iso_url           = var.iso_url
  iso_checksum      = var.iso_checksum
  output_directory  = "output-opnsense"
  vm_name           = "opnsense"
  disk_size         = "8G"
  format            = "qcow2"
  headless          = true
  accelerator       = "kvm"
  memory            = 1024
  cpu_model         = "host"
  cores             = 1
  net_device        = "virtio-net"
  disk_interface    = "virtio"
  boot_wait         = "10s"
  boot_command = [
    "<enter>",  # Démarrer l'installateur
    "<wait>",
    "<enter>",  # Clavier US
    "<wait>",
    "i",        # Installer
    "<enter>",
    "<wait>",
    "<enter>",  # Guide
    "<wait>",
    "<enter>",  # Partitionnement auto
    "<wait>",
    "<enter>",  # Nouveau disque
    "<wait>",
    "y",        # Confirmer
    "<enter>",
    "<wait>",
    "<enter>",  # SWAP
    "<wait>",
    "y",        # Confirmer
    "<enter>",
    "<wait>",
    "<enter>",  # Mot de passe root
    "<wait>",
    "vagrant",  # root password
    "<enter>",
    "<wait>",
    "vagrant",  # confirm
    "<enter>",
    "<wait>",
    "<enter>",  # Interface WAN
    "<wait>",
    "<enter>",  # vtnet0
    "<wait>",
    "<enter>",  # Interface LAN
    "<wait>",
    "<enter>",  # vtnet1
    "<wait>",
    "y",        # DHCP WAN
    "<enter>",
    "<wait>",
    "n",        # Pas de VLAN
    "<enter>",
    "<wait>",
    "n",        # Pas de DHCP LAN
    "<enter>",
    "<wait>",
    "n",        # Pas de relais DHCP
    "<enter>",
    "<wait>",
    "y",        # Confirmer
    "<enter>",
    "<wait>",
    "y",        # Démarrer OPNsense
    "<enter>"
  ]
  ssh_username   = "root"
  ssh_password   = "vagrant"
  ssh_timeout    = "30m"
  ssh_port       = 22
}

build {
  sources = ["source.qemu.opnsense"]

  # Installation des outils Vagrant pour FreeBSD
  provisioner "shell" {
    inline = [
      "pkg install -y curl",
      "curl -L https://raw.githubusercontent.com/hashicorp/vagrant/main/contrib/bsd/install.sh | sh"
    ]
  }

  post-processor "vagrant" {
    output = "opnsense-libvirt.box"
  }
}