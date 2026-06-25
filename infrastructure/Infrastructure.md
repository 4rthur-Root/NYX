# NYX Infrastructure

This document describes the infrastructure of the NYX laboratory, its components, and the procedures to deploy and manage it in an automated manner.

> [!IMPORTANT]
> **Prerequisites:** For all installations, you need at least 100 GB of free space, and you may need to replace *dnf* with your local package manager.

## Technologies used

![Vagrant](https://shields.io) ![Ansible](https://shields.io) ![Libvirt/KVM](https://shields.io) ![Packer](https://shields.io)

---

## 🚀 Démarrage Rapide

Un `Makefile` centralise toutes les opérations courantes.

```bash
# 1. Installer les dépendances (Fedora)
make install-tools

# 2. Créer les réseaux virtuels libvirt
make network

# 3. Déployer OPNsense (installation manuelle guidée)
make opnsense

# 4. Construire les box Packer (Debian + Windows)
make build-debian
make build-windows

# 5. Enregistrer les box dans Vagrant
make add-boxes

# 6. Démarrer les VMs Debian (SOC + Server) et Windows
make up

# 7. Provisionner avec Ansible
make provision
```

---

## 🏗️ Architecture et Outils

| Outil | Rôle |
|---|---|
| **Packer** | Création des golden images (Debian 12, Windows 10 22H2) |
| **Vagrant** | Orchestration du cycle de vie des VMs via le provider `libvirt` |
| **Ansible** | Provisioning différencié : rôle SOC vs rôle Server sur Debian |
| **KVM/Libvirt** | Hyperviseur sous-jacent (performances natives sous Linux) |
| **virsh** | Gestion directe d'OPNsense (hors cycle Vagrant) |

---

## 🖥️ Machines Virtuelles

| VM | OS | Rôle | Réseau | IP |
|---|---|---|---|---|
| **opnsense** | OPNsense 26.1.6 (FreeBSD) | Gateway / Firewall | nyx + default + vagrant-libvirt | LAN: 10.0.1.1 / OPT1: 192.168.121.254 / WAN: 192.168.122.254 |
| **soc** | Debian 12 | Moteur de corrélation Python, rsyslog collecteur, Grafana | nyx + vagrant-libvirt | 10.0.1.10 |
| **server** | Debian 12 | Serveur cible (SSH, SMB, Apache) | nyx + vagrant-libvirt | 10.0.1.20 |
| **win10** | Windows 10 22H2 | Machine victime (simulation attaques S1/S2/S3) | nyx + vagrant-libvirt | 10.0.1.30 |

---

## 🌐 Réseaux Virtuels

| Réseau libvirt | Bridge | Subnet | Rôle |
|---|---|---|---|
| `nyx` | virbr2 | 10.0.1.0/24 | LAN isolé — communication inter-VMs |
| `default` | virbr0 | 192.168.122.0/24 | WAN NAT — accès internet |
| `vagrant-libvirt` | virbr1 | 192.168.121.0/24 | Management — SSH Vagrant |

---

## 📦 Box Packer

| Box | Fichier source | Provider |
|---|---|---|
| `debian-12` | `packer/debian/debian-12-libvirt.box` | libvirt |
| `windows-10` | `packer/windows/output-windows_10/windows-10-libvirt.box` | libvirt |

OPNsense n'a pas de box Vagrant — elle est gérée directement via `virt-install` et `virsh`.

---

## 🔧 Provisioning Ansible

Les playbooks sont différenciés par rôle :

| Playbook | Cible | Contenu |
|---|---|---|
| `ansible/soc.yml` | VM soc | rsyslog collecteur, Python engine, Grafana, YARA |
| `ansible/server.yml` | VM server | rsyslog émetteur, SSH, Apache, Samba |
| `ansible/win10.yml` | VM win10 | WinRM, logs Windows Event, agents rsyslog |

OPNsense est configuré via `scripts_shell/opnsense_configuration.sh` (shell FreeBSD) — pas via Ansible.

---

## 🗺️ Topologie réseau

```
                    [Hôte Fedora 44]
                          |
            +-------------+-------------+
            |                           |
      vagrant-libvirt              default (NAT)
      192.168.121.0/24          192.168.122.0/24
            |                           |
     [OPNsense OPT1]            [OPNsense WAN]
     192.168.121.254             192.168.122.254
                    \
                  [OPNsense LAN]
                   10.0.1.1/24
                        |
          +-------------+-------------+
          |             |             |
       [soc]        [server]       [win10]
      10.0.1.10    10.0.1.20    10.0.1.30
```

---

## 📋 Scénarios d'attaque supportés

| Scénario | Description | Sources de logs |
|---|---|---|
| **S1** | SSH Brute-force | auth.log (server) + filterlog (opnsense) |
| **S2** | Exfiltration SMB | samba.log (server) + filterlog (opnsense) |
| **S3** | BEC + payload Windows | Windows Event Log (win10) + filterlog (opnsense) |