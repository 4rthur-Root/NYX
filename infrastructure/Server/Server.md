# Server

## Overview

La VM **Server** (Debian 13) est le contrôleur de domaine Active Directory et l'hébergeur de Dolibarr (ERP) de l'infrastructure NYX.

| Propriété | Valeur |
|---|---|
| Hostname | `srv-pme.nyx.tg` |
| Domaine AD | `NYX.TG` (NetBIOS: `NYX`) |
| Interface NAT | `enp1s0` — `192.168.122.143/24` |
| Interface LAN | `enp2s0` — `10.0.1.20/24` |
| Services | Samba AD DC, Docker, Dolibarr, Chrony, Rsyslog |

## Prérequis

Sur l'hôte (Fedora/RHEL) :

```bash
sudo dnf install -y @virtualization virt-install virt-viewer sshpass
```

## Installation de la VM

Créer la VM avec le script [server_installation.sh](server_installation.sh) :

```bash
make server-install
```

Paramètres configurables dans le script :
- `ISO_PATH` — chemin vers l'ISO Debian (défaut : `~/Downloads/ISO/debian-13.5.0-amd64-netinst.iso`)
- `VM_NAME` — nom de la VM (défaut : `Server`)
- `MEMORY_MB` — RAM (défaut : `2048`)
- `DISK_SIZE_GB` — taille du disque (défaut : `8`)

> ⚠️ Vérifier le nom des interfaces réseau avec `ip a` — le script suppose `enp1s0` (NAT) et `enp2s0` (nyx).

## Provisioning complet

Le script consolidé [server.sh](server.sh) exécute toutes les phases en une seule commande :

```bash
make server-provision-all
```

Ou phase par phase :

```bash
make server-provision          # Phase 1 : base (hostname, réseau, Docker)
make server-samba-ad           # Phase 2 : Samba AD DC
make server-samba-shares       # Phase 3 : partages Samba
make server-dolibarr           # Phase 4 : Dolibarr
```

### Phase 1 — Base ([base_installation.sh](base_installation.sh))

- Hostname : `srv-pme.nyx.tg`
- Fichier hosts : déployé depuis [`hosts.conf`](hosts.conf)
- Interface `enp2s0` : statique `10.0.1.20/24`
- Outils : vim, curl, net-tools, acl, git
- Rsyslog : écoute UDP 514 + forwarding vers SOC ([`50-forward.conf`](50-forward.conf))
- Chrony : sync NTP avec OPNsense (`10.0.1.1`) via [`chrony.conf`](chrony.conf)
- Docker CE + Compose ([docker_install.sh](docker_install.sh))

### Phase 2 — Samba AD DC ([samba-ad_installation.sh](samba-ad_installation.sh))

- Installe Samba 4, Kerberos, Winbind, python3-samba, samba-ad-dc
- Provisionne le domaine `NYX.TG`
- DNS forwarder : `10.0.1.1`
- Crée les groupes : `direction`, `comptabilite`, `technique`
- Crée les utilisateurs : `dir1`, `compta1`, `tech1`, `soc_reader`

### Phase 3 — Partages Samba ([samba_installation.sh](samba_installation.sh))

4 partages avec ACL par groupe :

| Partage | Groupe | Accès |
|---|---|---|
| `/srv/samba/direction` | direction | dir1 (RW), soc_reader (lecture si ajouté) |
| `/srv/samba/comptabilite` | comptabilite | compta1 (RW) |
| `/srv/samba/technique` | technique | tech1 (RW) |
| `/srv/samba/commun` | tous | tous les utilisateurs (RW) |

### Phase 4 — Dolibarr ([deploy_dolibarr.sh](dolibarr/deploy_dolibarr.sh))

- MariaDB + Dolibarr via Docker Compose
- Accès : `http://10.0.1.20`
- Logs : forwarding syslog vers rsyslocal (UDP 127.0.0.1:514)

## Vérification

```bash
make server-samba-verify       # Vérification complète Samba AD
make server-dolibarr-verify    # Pipeline de logs Dolibarr
```

Ou directement sur la VM :

```bash
sudo bash /tmp/server-provision/verification_samba-ad.sh
sudo bash /tmp/server-provision/dolibarr/test_dolibarr.sh
```

### Vérification rapide

```bash
# Services
systemctl is-active samba-ad-dc docker chrony rsyslog

# DNS
host srv-pme.nyx.tg 127.0.0.1

# Partages
smbclient //localhost/commun -U dir1 --password=Nyx2026! -c "ls"

# Dolibarr
curl -s http://10.0.1.20 | head -5
```

## Montage des partages sur le SOC

Le script [samba_montage-soc.sh](samba_montage-soc.sh) monte les 4 partages en lecture seule sur le SOC (`/mnt/samba/`) pour le scan YARA :

```bash
make server-samba-mount-soc
```

## Credentials

| Service | Login | Mot de passe |
|---|---|---|
| SSH VM | `server` | `server1` |
| Samba AD (admin) | `Administrator` | `AdminNyx2026!` |
| Samba AD (utilisateurs) | `dir1` / `compta1` / `tech1` / `soc_reader` | `Nyx2026!` |
| Dolibarr | `admin` | `admin` |
| MariaDB (Docker) | `root` | `root` |

> ⚠️ Changer le mot de passe Dolibarr (`admin`/`admin`) après la première connexion.

## Après redémarrage de la VM

Tous les services sont activés au démarrage (`enabled`) :

| Service | Unité systemd | État |
|---|---|---|
| Samba AD DC | `samba-ad-dc.service` | enabled |
| Docker | `docker.service` + `docker.socket` | enabled |
| Chrony | `chrony.service` | enabled |
| Rsyslog | `rsyslog.service` | enabled |

**Après un redémarrage, il suffit de :**

1. **Attendre ~30s** que tous les services démarrent
2. **Vérifier** que la VM est accessible :
   ```bash
   ping 10.0.1.20
   ssh server@10.0.1.20
   ```
3. **Vérifier les services** (optionnel) :
   ```bash
   echo 'server1' | sudo -S systemctl is-active samba-ad-dc docker chrony rsyslog
   ```
4. **Redémarrer Dolibarr** si nécessaire :
   ```bash
   cd /tmp/server-provision/dolibarr && echo 'server1' | sudo -S docker compose up -d
   ```

> 💡 Les conteneurs Docker ont `restart: unless-stopped`, donc Dolibarr redémarre automatiquement sauf s'il a été arrêté manuellement avec `docker compose stop`.

## Structure des fichiers

```
Server/
├── server_installation.sh          # Création de la VM (virt-install)
├── server.sh                       # Script consolidé (toutes phases)
├── common.sh                       # Bibliothèque partagée (log, apt_install, etc.)
├── base_installation.sh            # Phase 1 : base système
├── docker_install.sh               # Docker CE + Compose
├── samba-ad_installation.sh        # Phase 2 : Samba AD DC
├── samba_installation.sh           # Phase 3 : partages Samba
├── verification_samba-ad.sh        # Vérification Samba AD
├── samba_montage-soc.sh            # Montage partages sur le SOC
├── hosts.conf                      # Fichier /etc/hosts
├── chrony.conf                     # Configuration Chrony
├── 50-forward.conf                 # Forwarding rsyslog → SOC
├── smb.conf                        # (ancien, non utilisé)
├── Server.md                       # Ce fichier
└── dolibarr/
    ├── deploy_dolibarr.sh          # Phase 4 : déploiement Dolibarr
    ├── docker-compose.yml          # MariaDB + Dolibarr
    └── test_dolibarr.sh            # Test pipeline de logs
```
