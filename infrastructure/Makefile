.PHONY: help install-tools network build-debian build-windows add-boxes \
        opnsense opnsense-config opnsense-snapshot up provision down destroy clean \
        soc-create soc-provision soc-verify

BOX_DEBIAN_NAME := debian-12
BOX_DEBIAN_PATH := packer/debian/debian-12-libvirt.box
BOX_WINDOWS_NAME := windows-10
BOX_WINDOWS_PATH := packer/windows/output-windows_10/windows-10-libvirt.box

# SOC variables (surchargeables)
SOC_USER ?= user
SOC_IP   ?= 10.0.1.10

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Infrastructure:"
	@echo "  install-tools      Installer Vagrant, Ansible, Libvirt et les dépendances (Fedora)"
	@echo "  network            Créer le réseau isolé 'nyx' dans libvirt"
	@echo ""
	@echo "OPNsense:"
	@echo "  opnsense           Installer la VM OPNsense (virt-install + VNC)"
	@echo "  opnsense-config    Configurer OPNsense (syslog forward, SSH)"
	@echo "  opnsense-snapshot  Créer le snapshot baseline d'OPNsense"
	@echo ""
	@echo "SOC:"
	@echo "  soc-create         Créer la VM SOC (virt-install)"
	@echo "  soc-provision      Copier les scripts et provisionner la VM"
	@echo "  soc-verify         Vérifier l'état du SOC après provisionnement"
	@echo ""
	@echo "Boxes Vagrant (Debian / Windows):"
	@echo "  build-debian       Construire la box Debian 12 avec Packer"
	@echo "  build-windows      Construire la box Windows 10"
	@echo "  add-boxes          Enregistrer les box dans Vagrant"
	@echo "  up                 Démarrer les VMs Vagrant"
	@echo "  provision          Lancer le provisioning Ansible"
	@echo "  down               Arrêter l'infrastructure Vagrant"
	@echo "  destroy            Détruire l'infrastructure Vagrant"
	@echo "  clean              Supprimer les box locales"

# --- Outils et réseau ---

install-tools:
	@echo "=> Installation des dépendances et outils..."
	@bash Preparation/install_tools.sh

network:
	@echo "=> Création du réseau virtuel 'nyx'..."
	@bash Preparation/create_network.sh

# --- OPNsense ---

opnsense:
	@echo "=> Installation d'OPNsense..."
	@bash Opnsense/opnsense_installation.sh

opnsense-config:
	@echo "=> Configuration d'OPNsense..."
	@bash Opnsense/opnsense_configuration.sh

opnsense-snapshot:
	@echo "=> Création d'un snapshot de l'OPNsense..."
	virsh snapshot-create-as Opnsense snap-baseline \
       --description "OPNsense post-install, SSH + syslog configurés" \
       --atomic

# --- SOC ---

soc-create:
	@echo "=> Création de la VM SOC..."
	@bash SOC/soc_creation.sh

soc-provision:
	@echo "=> Copie des scripts et provisionnement du SOC..."
	@if ping -c 1 -W 1 $(SOC_IP) &>/dev/null; then \
		scp -r SOC/ $(SOC_USER)@$(SOC_IP):/tmp/soc-provision; \
		ssh $(SOC_USER)@$(SOC_IP) 'sudo bash /tmp/soc-provision/soc.sh'; \
	else \
		echo "ERREUR : $(SOC_IP) inaccessible. Vérifier SOC_IP et SOC_USER."; \
		exit 1; \
	fi

soc-verify:
	@echo "=> Vérification du SOC..."
	@if ping -c 1 -W 1 $(SOC_IP) &>/dev/null; then \
		ssh $(SOC_USER)@$(SOC_IP) 'sudo bash /tmp/soc-provision/soc_verify.sh'; \
	else \
		echo "ERREUR : $(SOC_IP) inaccessible. Vérifier SOC_IP et SOC_USER."; \
		exit 1; \
	fi

# --- Boxes Vagrant ---

build-debian:
	@echo "=> Construction de la box Debian 12 avec Packer..."
	cd packer/debian && packer build debian.pkr.hcl

build-windows:
	@echo "=> Construction de la box Windows 10..."
	@echo "[WARNING] Script windows_installation.sh non trouvé"
	@bash Preparation/windows_installation.sh 2>/dev/null || echo "  -> Ignoré"

add-boxes:
	@echo "=> Enregistrement des box Vagrant..."
	@if [ -f $(BOX_DEBIAN_PATH) ]; then \
		vagrant box add $(BOX_DEBIAN_NAME) $(BOX_DEBIAN_PATH) --provider libvirt --force; \
	else \
		echo "[WARNING] Box Debian introuvable, lancer 'make build-debian' d'abord."; \
	fi
	@if [ -f $(BOX_WINDOWS_PATH) ]; then \
		vagrant box add $(BOX_WINDOWS_NAME) $(BOX_WINDOWS_PATH) --provider libvirt --force; \
	else \
		echo "[WARNING] Box Windows introuvable, lancer 'make build-windows' d'abord."; \
	fi

up:
	@echo "=> Démarrage de l'infrastructure Vagrant..."
	vagrant up --provider=libvirt

provision:
	@echo "=> Provisioning Ansible..."
	vagrant provision

down:
	@echo "=> Arrêt de l'infrastructure Vagrant..."
	vagrant halt

destroy:
	@echo "=> Destruction de l'infrastructure Vagrant..."
	vagrant destroy -f

clean:
	@echo "=> Nettoyage..."
	vagrant box remove $(BOX_DEBIAN_NAME) --provider libvirt || true
	vagrant box remove $(BOX_WINDOWS_NAME) --provider libvirt || true
