# ========================================
# Packer configuration pour Debian 12
# ========================================

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
  default = "/home/adrien/Downloads/ISO/debian-12.0.0-amd64-netinst.iso"
}

variable "iso_checksum" {
  default = "sha256:3b0e9718e3653435f20d8c2124de6d363a51a1fd7f911b9ca0c6db6b3d30d53e"
}

source "qemu" "debian" {
  iso_url           = var.iso_url
  iso_checksum      = var.iso_checksum
  output_directory  = "output-debian"
  vm_name           = "debian-12"
  disk_size         = "15G"
  format            = "qcow2"
  headless          = false
  accelerator       = "kvm"
  memory            = 1024
  cpu_model         = "host"
  cores             = 2
  net_device        = "virtio-net"
  disk_interface    = "virtio"
  boot_wait         = "5s"
  boot_command = [
    "<tab><wait>",
    " auto=true priority=critical",
    " preseed/url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg",
    "<enter>"
  ]
  http_directory = "."
  ssh_username   = "root"
  ssh_password   = "vagrant"
  ssh_timeout    = "60m"
}

build {
  sources = ["source.qemu.debian"]

  provisioner "shell" {
  inline = [
    "mkdir -p /home/vagrant/.ssh",
    "wget -qO /home/vagrant/.ssh/authorized_keys https://raw.githubusercontent.com/hashicorp/vagrant/main/keys/vagrant.pub",
    "chmod 700 /home/vagrant/.ssh",
    "chmod 600 /home/vagrant/.ssh/authorized_keys",
    "chown -R vagrant:vagrant /home/vagrant/.ssh",
    "apt-get clean",
    "apt-get autoremove --purge -y",
    "rm -rf /tmp/*"
    ]
  }

  post-processor "vagrant" {
    output = "debian-12-libvirt.box"
  }
}