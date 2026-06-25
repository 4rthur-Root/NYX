.PHONY: help install-tools add-box build-box up down destroy clean

BOX_NAME := debian-12
BOX_PATH := packer/debian/debian-12-libvirt.box

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  install-tools  Installer Vagrant, Ansible, Libvirt, et les plugins"
	@echo "  add-box        Ajouter la box Vagrant (Debian 12 libvirt) locale"
	@echo "  build-box      Construire la box Debian 12 avec Packer"
	@echo "  up             Démarrer l'infrastructure avec Vagrant"
	@echo "  down           Arrêter l'infrastructure (halt)"
	@echo "  destroy        Détruire l'infrastructure"
	@echo "  clean          Supprimer la box locale du cache Vagrant"

install-tools:
	@echo "=> Installation des dépendances et outils..."
	@bash scripts_shell/install_tools.sh

add-box:
	@echo "=> Ajout de la box Vagrant..."
	vagrant box add $(BOX_NAME) $(BOX_PATH) --provider libvirt --force

build-box:
	@echo "=> Construction de la box avec Packer..."
	cd packer/debian && packer build debian.pkr.hcl

up:
	@echo "=> Démarrage de l'infrastructure..."
	vagrant up --provider=libvirt

down:
	@echo "=> Arrêt de l'infrastructure..."
	vagrant halt

destroy:
	@echo "=> Destruction de l'infrastructure..."
	vagrant destroy -f

clean:
	@echo "=> Nettoyage..."
	vagrant box remove $(BOX_NAME) --provider libvirt || true

opnsense:
	@echo "=> Installation d'OPNsense..."
	@bash scripts_shell/opnsense_installation.sh

opnsense-snapshot:
	@echo "=> Création d'un snapshot de l'OPNsense..."
	virsh snapshot-create-as opnsense snap-baseline \
       --description "OPNsense 26.1.6 post-install, SSH enabled" \
       --atomic

windows:
	@echo "=> Installation de Windows 10..."
	cd packer/windows
	@bash scripts_shell/windows_installation.sh
