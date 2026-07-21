.PHONY: help install-tools network \
        opnsense opnsense-config opnsense-snapshot \
        soc-create soc-provision soc-verify \
        server-install server-provision server-provision-all \
        server-samba-ad server-samba-verify \
        server-samba-shares server-samba-mount-soc \
        server-dolibarr server-dolibarr-verify

# SOC variables (surchargeables)
SOC_USER ?= user
SOC_IP   ?= 10.0.1.10

# Server variables (surchargeables)
SERVER_USER ?= user
SERVER_IP   ?= 10.0.1.20

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Infrastructure:"
	@echo "  install-tools      Installer libvirt, virt-install, virt-viewer (Fedora)"
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
	@echo "Server:"
	@echo "  server-install           Créer la VM Debian Server (virt-install)"
	@echo "  server-provision         Copier les scripts et provisionner la VM (base)"
	@echo "  server-provision-all     Provisionnement complet (base + Samba AD + partages + Dolibarr)"
	@echo "  server-samba-ad          Installer et configurer Samba AD DC"
	@echo "  server-samba-verify      Vérifier l'état de Samba AD"
	@echo "  server-samba-shares      Configurer les partages Samba (direction/comptabilite/technique/commun)"
	@echo "  server-samba-mount-soc   Monter les partages Samba en lecture seule sur le SOC"
	@echo "  server-dolibarr          Déployer Dolibarr (Docker Compose)"
	@echo "  server-dolibarr-verify   Vérifier le pipeline de logs Dolibarr"

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

# --- Server ---

server-install:
	@echo "=> Installation de la VM Debian Server..."
	@bash Server/server_installation.sh 

server-provision:
	@echo "=> Copie des scripts et provisionnement du Server (base)..."
	@if ping -c 1 -W 1 $(SERVER_IP) &>/dev/null; then \
		scp -r Server/ $(SERVER_USER)@$(SERVER_IP):/tmp/server-provision; \
		ssh $(SERVER_USER)@$(SERVER_IP) 'sudo bash /tmp/server-provision/base_installation.sh'; \
	else \
		echo "ERREUR : $(SERVER_IP) inaccessible. Vérifier SERVER_IP et SERVER_USER."; \
		exit 1; \
	fi

server-provision-all:
	@echo "=> Copie des scripts et provisionnement complet du Server..."
	@if ping -c 1 -W 1 $(SERVER_IP) &>/dev/null; then \
		scp -r Server/ $(SERVER_USER)@$(SERVER_IP):/tmp/server-provision; \
		ssh $(SERVER_USER)@$(SERVER_IP) 'sudo bash /tmp/server-provision/server.sh'; \
	else \
		echo "ERREUR : $(SERVER_IP) inaccessible. Vérifier SERVER_IP et SERVER_USER."; \
		exit 1; \
	fi

server-samba-ad:
	@echo "=> Installation et configuration de Samba AD DC..."
	@if ping -c 1 -W 1 $(SERVER_IP) &>/dev/null; then \
		ssh $(SERVER_USER)@$(SERVER_IP) 'sudo bash /tmp/server-provision/samba-ad_installation.sh'; \
	else \
		echo "ERREUR : $(SERVER_IP) inaccessible. Vérifier SERVER_IP et SERVER_USER."; \
		exit 1; \
	fi

server-samba-verify:
	@echo "=> Vérification de Samba AD..."
	@if ping -c 1 -W 1 $(SERVER_IP) &>/dev/null; then \
		ssh $(SERVER_USER)@$(SERVER_IP) 'sudo bash /tmp/server-provision/verification_samba-ad.sh'; \
	else \
		echo "ERREUR : $(SERVER_IP) inaccessible. Vérifier SERVER_IP et SERVER_USER."; \
		exit 1; \
	fi

server-samba-shares:
	@echo "=> Configuration des partages Samba..."
	@if ping -c 1 -W 1 $(SERVER_IP) &>/dev/null; then \
		ssh $(SERVER_USER)@$(SERVER_IP) 'sudo bash /tmp/server-provision/samba_installation.sh'; \
	else \
		echo "ERREUR : $(SERVER_IP) inaccessible. Vérifier SERVER_IP et SERVER_USER."; \
		exit 1; \
	fi

server-samba-mount-soc:
	@echo "=> Montage des partages Samba en lecture seule sur le SOC..."
	@if ping -c 1 -W 1 $(SOC_IP) &>/dev/null; then \
		scp Server/samba_montage-soc.sh $(SOC_USER)@$(SOC_IP):/tmp/; \
		ssh $(SOC_USER)@$(SOC_IP) 'sudo bash /tmp/samba_montage-soc.sh'; \
	else \
		echo "ERREUR : $(SOC_IP) inaccessible. Vérifier SOC_IP et SOC_USER."; \
		exit 1; \
	fi

server-dolibarr:
	@echo "=> Déploiement de Dolibarr (Docker Compose)..."
	@if ping -c 1 -W 1 $(SERVER_IP) &>/dev/null; then \
		ssh $(SERVER_USER)@$(SERVER_IP) 'cd /tmp/server-provision/dolibarr && bash deploy_dolibarr.sh'; \
	else \
		echo "ERREUR : $(SERVER_IP) inaccessible. Vérifier SERVER_IP et SERVER_USER."; \
		exit 1; \
	fi

server-dolibarr-verify:
	@echo "=> Vérification du pipeline de logs Dolibarr..."
	@if ping -c 1 -W 1 $(SERVER_IP) &>/dev/null; then \
		ssh $(SERVER_USER)@$(SERVER_IP) 'sudo bash /tmp/server-provision/dolibarr/test_dolibarr.sh'; \
	else \
		echo "ERREUR : $(SERVER_IP) inaccessible. Vérifier SERVER_IP et SERVER_USER."; \
		exit 1; \
	fi
