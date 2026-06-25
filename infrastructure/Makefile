.PHONY: help install-tools network build-debian build-windows add-boxes opnsense opnsense-config opnsense-snapshot up provision down destroy clean

BOX_DEBIAN_NAME := debian-12
BOX_DEBIAN_PATH := packer/debian/debian-12-libvirt.box
BOX_WINDOWS_NAME := windows-10
BOX_WINDOWS_PATH := packer/windows/output-windows_10/windows-10-libvirt.box

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  install-tools      Installer Vagrant, Ansible, Libvirt et les dépendances (Fedora)"
	@echo "  network            Créer le réseau isolé 'nyx' dans libvirt"
	@echo "  opnsense           Installer la VM OPNsense (virt-install + VNC)"
	@echo "  opnsense-config    Configurer OPNsense (syslog forward, SSH)"
	@echo "  opnsense-snapshot  Créer le snapshot baseline d'OPNsense"
	@echo "  build-debian       Construire la box Debian 12 avec Packer"
	@echo "  build-windows      Construire la box Windows 10 avec Packer"
	@echo "  add-boxes          Enregistrer les box Debian 12 et Windows 10 dans Vagrant"
	@echo "  up                 Démarrer les VMs Debian (SOC/Server) et Windows avec Vagrant"
	@echo "  provision          Lancer le provisioning Ansible des VMs"
	@echo "  down               Arrêter l'infrastructure (halt)"
	@echo "  destroy            Détruire l'infrastructure Vagrant"
	@echo "  clean              Supprimer les box locales et nettoyer le cache Vagrant"

install-tools:
	@echo "=> Installation des dépendances et outils..."
	@bash scripts_shell/install_tools.sh

network:
	@echo "=> Création du réseau virtuel 'nyx'..."
	@bash scripts_shell/create_network.sh

opnsense:
	@echo "=> Installation d'OPNsense..."
	@bash scripts_shell/opnsense_installation.sh

opnsense-config:
	@echo "=> Configuration d'OPNsense..."
	@bash scripts_shell/opnsense_configuration.sh

opnsense-snapshot:
	@echo "=> Création d'un snapshot de l'OPNsense..."
	virsh snapshot-create-as Opnsense snap-baseline \
       --description "OPNsense 26.1.6 post-install, SSH + syslog configurés" \
       --atomic

build-debian:
	@echo "=> Construction de la box Debian 12 avec Packer..."
	cd packer/debian && packer build debian.pkr.hcl

build-windows:
	@echo "=> Construction de la box Windows 10 avec Packer..."
	bash scripts_shell/windows_installation.sh

add-boxes:
	@echo "=> Enregistrement des box Vagrant..."
	@if [ -f $(BOX_DEBIAN_PATH) ]; then \
		vagrant box add $(BOX_DEBIAN_NAME) $(BOX_DEBIAN_PATH) --provider libvirt --force; \
	else \
		echo "[WARNING] Box Debian introuvable, veuillez lancer 'make build-debian' d'abord."; \
	fi
	@if [ -f $(BOX_WINDOWS_PATH) ]; then \
		vagrant box add $(BOX_WINDOWS_NAME) $(BOX_WINDOWS_PATH) --provider libvirt --force; \
	else \
		echo "[WARNING] Box Windows introuvable, veuillez lancer 'make build-windows' d'abord."; \
	fi

up:
	@echo "=> Démarrage de l'infrastructure..."
	vagrant up --provider=libvirt

provision:
	@echo "=> Provisioning Ansible..."
	vagrant provision

down:
	@echo "=> Arrêt de l'infrastructure..."
	vagrant halt

destroy:
	@echo "=> Destruction de l'infrastructure..."
	vagrant destroy -f

clean:
	@echo "=> Nettoyage..."
	vagrant box remove $(BOX_DEBIAN_NAME) --provider libvirt || true
	vagrant box remove $(BOX_WINDOWS_NAME) --provider libvirt || true
