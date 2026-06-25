# 🛡️ Infrastructure du Laboratoire NYX

Ce document décrit l'architecture, la structure des répertoires et les procédures pour déployer, configurer et administrer de manière automatisée le laboratoire de simulation d'attaques NYX.

---

## 🏗️ Structure du Projet

L'infrastructure est organisée comme suit :

```text
infrastructure/
├── Makefile                      # Cible de commandes unifiées (Réseau, Packer, Vagrant, Ansible)
├── Vagrantfile                   # Configuration et orchestration des VMs (soc, debian-server, windows10)
├── Infrastructure.md             # Ce document de documentation d'architecture
├── ISSUES.md                     # Journal des problèmes rencontrés et de leurs résolutions
│
├── scripts_shell/                # Scripts utilitaires pour l'hôte Fedora
│   ├── install_tools.sh          # Installation de Vagrant, Libvirt, Ansible, etc.
│   ├── create_network.sh         # Création du pont L2 isolé 'nyx' dans libvirt
│   ├── opnsense_installation.sh  # Installation initiale d'OPNsense via virt-install
│   ├── opnsense_configuration.sh # Configuration post-install d'OPNsense (SSH, rsyslog)
│   └── windows_installation.sh   # Script de compilation/packaging de la box Windows 10
│
├── packer/                       # Gabarits de création d'images (Golden Images)
│   ├── debian/                   # Configuration Packer pour Debian 12 (avec preseed)
│   └── windows/                  # Configuration Packer pour Windows 10 (Autounattend)
│
└── ansible/                      # Provisioning et configuration interne des VMs
    ├── ansible.cfg               # Configuration globale d'Ansible
    ├── inventory.ini             # Liste des machines et de leurs variables de connexion LAN
    ├── playbooks/                # Playbooks pour appeler les rôles
    └── roles/                    # Rôles Ansible par type de machine
        ├── common/               # Config commune Linux (Chrony, routes réseaux étanches)
        ├── soc/                  # Installation du collecteur Rsyslog et moteur de détection
        ├── debian_server/        # Serveur cible (Apache, MariaDB, Samba AD)
        └── windows/              # Configuration Windows (Chocolatey, Sysmon, NXLog, routes)
```

---

## 🖥️ Fiches des Machines Virtuelles (Spécifications)

| VM (Nom IaC) | OS / Version | Rôle dans le lab | Réseaux Libvirt | Ressources matérielles | IP Statique LAN |
|---|---|---|---|---|---|
| **Opnsense** | OPNsense 26.1.6 (FreeBSD) | Pare-feu, Passerelle et DHCP principal | `nyx` + `default` + `vagrant-libvirt` | 1 vCPU, 1.5 Go RAM, 8 Go Disque | `10.0.1.1` (LAN) |
| **soc** | Debian 12 (x64) | Collecteur de logs & Moteur de corrélation | `nyx` + `vagrant-libvirt` | 2 vCPUs, 2 Go RAM, 15 Go Disque | `10.0.1.10` (LAN) |
| **debian-server** | Debian 12 (x64) | Serveur cible (Samba AD, Apache, MariaDB) | `nyx` + `vagrant-libvirt` | 2 vCPUs, 3 Go RAM, **30 Go Disque** | `10.0.1.20` (LAN) |
| **windows10** | Windows 10 22H2 (x64) | Machine victime (Sysmon, NXLog) | `nyx` + `vagrant-libvirt` | 2 vCPUs, 3 Go RAM, 60 Go Disque | `10.0.1.30` (LAN) |

---

## 🌐 Architecture Réseau & Étanchéité (Sécurité)

Pour garantir que les machines virtuelles ne puissent pas bypasser le pare-feu **OPNsense**, le routage a été entièrement sécurisé afin d'empêcher les flux d'échapper à sa vue par le réseau d'administration Vagrant (`vagrant-libvirt` sur `192.168.121.0/24`).

```
                          [Hôte Fedora (Physique)]
                                     |
             +-----------------------+-----------------------+
             |                                               |
       vagrant-libvirt (NAT)                          default (NAT)
     192.168.121.0/24 (DHCP)                        192.168.122.0/24
             |                                               |
       (Administration)                               (Accès Internet)
             |                                               |
     [OPNsense OPT1]                                  [OPNsense WAN]
     192.168.121.254                                  192.168.122.254
             \                                               /
              \                                             /
               +--------------[OPNsense LAN]---------------+
                              10.0.1.1/24 (Passerelle)
                                     |
                       Réseau isolé L2 libvirt 'nyx'
                                     |
               +---------------------+---------------------+
               |                     |                     |
            [soc]             [debian-server]         [windows10]
          10.0.1.10              10.0.1.20             10.0.1.30
```

### Principes de sécurité réseau implémentés :
1. **Isolation L2 de `nyx`** : Le réseau `nyx` ne possède aucune adresse IP sur l'hôte Fedora, coupant tout routage ou DHCP sauvage en provenance de l'hyperviseur. OPNsense sert les baux DHCP et les requêtes DNS de manière unique.
2. **Neutralisation de la passerelle Vagrant (Linux)** : Le template réseau des machines Debian coupe la route par défaut de l'interface `eth0` via `post-up ip route del default dev eth0 || true` dès son démarrage.
3. **Métrique haute pour Windows** : Windows 10 est provisionné avec une passerelle par défaut vers OPNsense (`10.0.1.1`) avec une métrique faible (`10`) et la carte de management Vagrant se voit attribuer une métrique d'interface de `500` (priorité très basse), ce qui force tout le trafic externe à traverser le LAN OPNsense.

---

## 🚀 Guide de Démarrage Rapide

### 1. Recommandations de ressources (Avant de lancer)

> [!WARNING]
> Le laboratoire au complet consomme environ **9.5 Go de RAM** alloués aux VMs :
> * OPNsense : 1.5 Go
> * SOC : 2 Go
> * Debian Server : 3 Go
> * Windows 10 : 3 Go
> 
> **Sur votre hôte Fedora** :
> * **Fermez les applications gourmandes** (navigateurs web avec de nombreux onglets ouverts, IDE lourds, autres VMs en arrière-plan) avant de démarrer l'infrastructure pour éviter la saturation de la RAM (swap/OOM killer) et les ralentissements d'E/S disque.
> * Assurez-vous d'avoir au moins **100 Go d'espace disque disponible** (principalement en raison du provisionnement dynamique des disques Windows de 60 Go et Debian de 30 Go).

### 2. Procédure de déploiement pas à pas

Ouvrez un terminal dans ce répertoire et exécutez les cibles du Makefile :

```bash
# 1. Installer les outils requis sur Fedora (libvirt, vagrant, plugins)
make install-tools

# 2. Créer le réseau libvirt isolé 'nyx' (L2 pur)
make network

# 3. Déployer et démarrer la VM OPNsense
# (Suivez l'assistant d'installation sur la console VNC qui s'ouvre)
make opnsense

# 4. Configurer la VM OPNsense (Une fois installée et démarrée)
# (Active le SSH permanent et configure le forward des logs réseau vers le SOC)
make opnsense-config

# 5. Enregistrer un instantané de référence d'OPNsense
make opnsense-snapshot

# 6. Enregistrer vos box Packer dans le catalogue Vagrant local
make add-boxes

# 7. Démarrer les VMs du laboratoire (soc, debian-server, windows10)
make up

# 8. Lancer le provisioning Ansible (Configuration des routes et des agents de sécurité)
make provision
```

### 3. Gestion courante

*   **Arrêter proprement les VMs** : `make down` (sauvegarde l'état des disques en les éteignant proprement).
*   **Détruire tout le laboratoire Vagrant** : `make destroy` (supprime les VMs du laboratoire, sauf OPNsense qui est gérée via virsh).
*   **Nettoyer l'hôte** : `make clean` (supprime les box Vagrant de votre cache).