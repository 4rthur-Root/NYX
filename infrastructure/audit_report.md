# 📋 Rapport d'Audit & Validation de l'IaC — Laboratoire NYX

Ce rapport présente l'analyse de votre infrastructure IaC pour le laboratoire NYX sous Fedora/Libvirt, les corrections apportées pour assurer l'étanchéité du réseau inter-VMs, ainsi qu'un récapitulatif détaillé de chaque VM.

---

## 🛡️ Étanchéité Réseau & Isolation de l'administration (Vagrant)

La contrainte principale est d'empêcher les machines virtuelles du laboratoire (`soc`, `debian-server`, `windows10`) de contourner le pare-feu **OPNsense** en acheminant leur trafic externe directement par la passerelle par défaut du réseau d'administration Vagrant (`vagrant-libvirt`, IP `192.168.121.1` sur l'hôte).

### 🔍 Analyse de la configuration initiale (Bug & Risques)

1. **Conflit d'IP sur `nyx` :**
   - Le script [create_network.sh](file:///home/adrien/My_codes_and_Projects/NYX/infrastructure/scripts_shell/create_network.sh) créait le réseau privé `nyx` en attribuant l'IP `10.0.1.1` à l'interface de pont de l'hôte (`virbr2`) et démarrait un serveur DHCP local.
   - **Risque :** Conflit direct avec l'IP statique LAN de l'OPNsense (`10.0.1.1`), provoquant des instabilités de routage majeures et une compétition DHCP entre l'hôte Fedora et la VM OPNsense.

2. **Perte de l'interface `eth0` sous Debian :**
   - Le template Ansible [interfaces.j2](file:///home/adrien/My_codes_and_Projects/NYX/infrastructure/ansible/roles/common/templates/interfaces.j2) réécrivait complètement `/etc/network/interfaces` en omettant complètement l'interface d'administration `eth0`.
   - **Risque :** Perte irrémédiable de la connexion SSH de management Vagrant lors du provisioning Ansible.

3. **Fuite réseau (Echappement à OPNsense) :**
   - Par défaut, l'attribution d'adresses IP DHCP sur l'interface d'administration Vagrant configure une passerelle par défaut (Gateway) pointant vers l'hôte. Sans configuration réseau spécifique, les VMs routent leur trafic internet directement via la passerelle d'administration Vagrant (NAT de l'hôte) au lieu d'utiliser l'OPNsense (`10.0.1.1`), rendant le pare-feu invisible pour ce trafic.
   - Sur Windows, aucune configuration de routage ou de passerelle n'était présente dans Ansible.

---

### 🛠️ Corrections Appliquées

Les configurations IaC ont été modifiées afin de garantir une isolation parfaite :

1. **Réseau Libvirt `nyx` épuré (L2 pur) :**
   - Le script [create_network.sh](file:///home/adrien/My_codes_and_Projects/NYX/infrastructure/scripts_shell/create_network.sh) a été corrigé pour retirer les balises `<ip>` et `<dhcp>` du fichier XML de définition. Le réseau `nyx` est désormais un switch virtuel de niveau 2 isolé (mode `none`) sans adresse IP portée par l'hôte. C'est l'OPNsense qui fait office de seul routeur et serveur DHCP/DNS sur ce segment.
   
2. **Persistence et protection de la route Debian (`common`) :**
   - Le template [interfaces.j2](file:///home/adrien/My_codes_and_Projects/NYX/infrastructure/ansible/roles/common/templates/interfaces.j2) a été mis à jour pour réintroduire l'interface de management `eth0` afin d'éviter les coupures SSH.
   - Une règle `post-up` a été ajoutée sous `eth0` : `post-up ip route del default dev eth0 || true`. Dès que l'interface d'administration monte, sa route par défaut est supprimée.
   - L'interface LAN `eth1` conserve sa route par défaut pointant sur l'IP LAN d'OPNsense (`10.0.1.1`) : `post-up ip route replace default via {{ gateway }} dev eth1`.

3. **Protection de la route Windows (`windows`) :**
   - Le rôle Ansible [tasks/main.yml](file:///home/adrien/My_codes_and_Projects/NYX/infrastructure/ansible/roles/windows/tasks/main.yml) a été complété avec une tâche PowerShell qui :
     - Ajoute/met à jour une route par défaut via l'interface LAN (`10.0.1.30`) pointant sur le pare-feu `10.0.1.1` avec une métrique faible (`10`).
     - Modifie la métrique d'interface de la carte de management Vagrant (`192.168.121.*`) pour lui donner une valeur élevée (`500`). Windows privilégie ainsi le LAN OPNsense pour toutes les requêtes externes.

4. **Installation effective des agents de sécurité Windows :**
   - L'installation automatique de **Sysmon** et **NXLog** (qui manquaient complètement et généraient des erreurs lors du provisioning) est désormais assurée via le gestionnaire Chocolatey (déjà intégré à votre image de base Windows Packer).

---

## 🖥️ Fiches Détaillées des Machines Virtuelles

Voici le descriptif complet de l'état final visé pour chaque VM après le provisioning Ansible :

```mermaid
graph TD
    Fedora[Hôte Fedora]
    OPN[OPNsense<br>10.0.1.1 / 192.168.121.254 / 192.168.122.254]
    SOC[soc VM<br>10.0.1.10]
    SRV[debian-server VM<br>10.0.1.20]
    WIN[windows10 VM<br>10.0.1.30]

    subgraph Réseau nyx isolated LAN
        OPN --- SOC
        OPN --- SRV
        OPN --- WIN
    end

    subgraph Réseau vagrant-libvirt OOB management
        Fedora -. SSH/WinRM .- SOC
        Fedora -. SSH/WinRM .- SRV
        Fedora -. SSH/WinRM .- WIN
        Fedora -. SSH .- OPN
    end

    subgraph Réseau default WAN
        OPN ---|NAT| Fedora
    end
```

### 1. Gateway / Firewall — `Opnsense`
*   **OS :** OPNsense 26.1.6 (basé sur FreeBSD 13)
*   **Rôle :** Passerelle de sécurité, routage inter-zones, journalisation réseau.
*   **Ressources :** RAM : **1536 Mo** | CPU : **1** | Disque : **8 Go** (format qcow2, VirtIO)
*   **Interfaces Réseau :**
    - `vtnet0` (LAN) : `10.0.1.1/24` (Rseau `nyx`) — Passerelle des VMs du laboratoire.
    - `vtnet1` (WAN) : `192.168.122.254/24` (Réseau `default` libvirt) — Accès Internet NAT.
    - `vtnet2` (OPT1) : `192.168.121.254/24` (Réseau `vagrant-libvirt`) — Administration hors-bande (OOB).
*   **Services Activés :**
    - **Filtrage de paquets (PF) :** Journalisation réseau active (`filterlog`).
    - **SSH (openssh) :** Port 22 actif sur l'interface d'administration OPT1.
    - **Syslog Forwarder :** Redirection de tous les journaux système et de filtrage de paquets en UDP vers le SOC (`10.0.1.10:514`).
    - **DNS/DHCP Services :** Assure la résolution DNS locale et les baux pour le réseau `nyx`.

### 2. Monitoring / SOC — `soc`
*   **OS :** Debian 12
*   **Rôle :** Collecte des journaux, corrélation et tableau de bord.
*   **Ressources :** RAM : **2048 Mo** | CPU : **2** | Disque : **15 Go** (Packer debian-12)
*   **Interfaces Réseau :**
    - `eth0` (Management) : IP DHCP (`192.168.121.X`/24, réseau `vagrant-libvirt`) — *Passerelle par défaut désactivée*.
    - `eth1` (LAN) : IP statique `10.0.1.10/24` (réseau `nyx`) — *Passerelle par défaut : 10.0.1.1*.
*   **Services Activés & Provisionnés :**
    - **Rsyslog (Collector) :** Écoute sur les ports 514 (UDP & TCP). Réceptionne et trie les logs dans `/var/log/remote/`.
    - **Chrony :** Synchronisation temporelle avec les serveurs NTP.
    - **Auditd & AIDE :** Sécurisation et intégrité de l'hôte SOC.
    - **Python Correlation Engine :** Déploiement dans `/opt/soc-engine/` (prêt à recevoir vos scripts de détection).
    - *(Note : Grafana et YARA sont documentés dans le guide mais absents des tâches Ansible actuelles. Ils devront être installés ultérieurement).*

### 3. Target Server — `debian-server` (Nommé `server` dans la doc)
*   **OS :** Debian 12
*   **Rôle :** Serveur de production (Active Directory, Partage de fichiers, Web).
*   **Ressources :** RAM : **3072 Mo** | CPU : **2** | Disque : **30 Go** (Redimensionné via Vagrantfile & growpart)
*   **Interfaces Réseau :**
    - `eth0` (Management) : IP DHCP (`192.168.121.X`/24, réseau `vagrant-libvirt`) — *Passerelle par défaut désactivée*.
    - `eth1` (LAN) : IP statique `10.0.1.20/24` (réseau `nyx`) — *Passerelle par défaut : 10.0.1.1*.
*   **Services Activés & Provisionnés :**
    - **Samba AD / DC & BIND9 :** Paquets d'infrastructure installés pour créer le domaine `lab.local`.
    - **Apache2 & PHP :** Serveur web installé pour l'hébergement d'outils type Dolibarr.
    - **MariaDB Server/Client :** Gestion de base de données active.
    - **Rsyslog Forwarder :** Journalisation locale (`auth`, `syslog`, `daemon`) redirigée en UDP vers le SOC (`10.0.1.10:514`).
    - **Chrony :** Synchronisation de l'heure.

### 4. Victim Client — `windows10` (Nommé `win10` dans la doc)
*   **OS :** Windows 10 Professional (22H2)
*   **Rôle :** Poste utilisateur simulé, cible d'attaque (Phishing, BEC, Ransomware).
*   **Ressources :** RAM : **3072 Mo** | CPU : **2** | Disque : **60 Go** (Packer windows-10)
*   **Interfaces Réseau :**
    - Interface d'Administration : IP DHCP (`192.168.121.X`/24, réseau `vagrant-libvirt`) — *Métrique forcée à 500 pour rejeter le routage*.
    - Interface LAN : IP statique `10.0.1.30/24` (réseau `nyx`) — *Passerelle par défaut : 10.0.1.1 (Métrique 10)*.
*   **Services Activés & Provisionnés :**
    - **WinRM (Windows Remote Management) :** Écoute sur HTTPS pour l'orchestration Ansible.
    - **Sysmon (System Monitor) :** Agent de télémétrie noyau Microsoft installé. Surveille les lancements de processus, écritures de fichiers et connexions réseau (selon vos règles d'exclusion de `svchost.exe`).
    - **NXLog :** Service de collecte configuré pour extraire les événements de journalisation Sysmon (`Microsoft-Windows-Sysmon/Operational`) et les transmettre en temps réel en UDP vers le SOC (`10.0.1.10:514`) au format Syslog.

---

## 🔄 Analyse des Flux et Communications Réseau

Le flux d'informations et les communications au sein du laboratoire suivent ce schéma :

| Source | Destination | Protocole/Port | Description |
|---|---|---|---|
| **VMs (soc, server, win10)** | **OPNsense (LAN)** | Tout trafic sortant | Passage obligatoire pour l'accès externe (mises à jour, payloads). |
| **debian-server** | **soc** | UDP/514 | Envoi des logs système Debian via `rsyslog`. |
| **windows10** | **soc** | UDP/514 | Envoi des journaux Sysmon au SOC via `NXLog`. |
| **OPNsense (OPT1)** | **soc** | UDP/514 | Transmission des logs de filtrage réseau (`filterlog`). |
| **Hôte Fedora** | **VMs (soc, server, windows10)** | TCP/22 (SSH) ou TCP/5986 (WinRM) | Flux d'administration local Vagrant/Ansible restreint au subnet `192.168.121.0/24`. |

---

## 📈 Prochaines Étapes Suggérées

1.  **Démarrer le réseau et OPNsense :**
    - Exécutez `make network` pour initialiser le pont isolé `nyx` sans conflit.
    - Démarrez la VM OPNsense via `virsh start Opnsense`.
2.  **Lancer et Provisionner le lab :**
    - Exécutez `make up` pour créer les instances Debian et Windows.
    - Exécutez `make provision` pour déployer les configurations Rsyslog, Sysmon, NXLog et modifier automatiquement les tables de routage des invités.
