# Server

## Prérequis

Installer les outils nécessaires depuis votre poste :

```bash
# Sur Fedora/RHEL
sudo dnf install -y @virtualization virt-install virt-viewer
```

## Installation de la VM

Ce dossier sert à provisionner la VM Debian Server.

Pour créer la VM, utiliser le script [server_installation.sh](server_installation.sh) :

```bash
make server-install
```

Les paramètres configurables dans le script :
- `ISO_PATH` — chemin vers l'ISO Debian (défaut : `/home/adrien/Downloads/ISO/debian-13.5.0-amd64-netinst.iso`)
- `VM_NAME` — nom de la VM (défaut : `Server`)
- `MEMORY_MB` — quantité de RAM (défaut : `2048`)
- `DISK_SIZE_GB` — taille du disque (défaut : `8`)

⚠️ Avant de lancer le provisioning, vérifier le nom réel des interfaces réseau avec `ip a` — le script suppose `enp1s0` (NAT) et `enp2s0` (réseau `nyx`), mais l'ordre peut varier.

## Configuration de base

Une fois la VM installée et le réseau configuré, appliquer la configuration :

```bash
make server-provision
```

Le script [base_installation.sh](base_installation.sh) installe et configure en une seule passe :

- **Hostname** : `srv-pme.nyx.tg`
- **Fichier hosts** : déployé depuis [`hosts.conf`](hosts.conf)
- **Interface privée** : configuration statique sur `enp2s0` (10.0.1.20/24)
- **Outils de base** : vim, curl, net-tools, acl, git
- **rsyslog** : installation, activation de l'écoute locale UDP (`imudp`, nécessaire pour le driver syslog Docker de Dolibarr), et déploiement du forward vers le SOC ([`50-forward.conf`](50-forward.conf))
- **Chrony** : synchronisation NTP avec OPNsense (10.0.1.1), via [`chrony.conf`](chrony.conf)
- **Docker** : installation de Docker CE + Compose ([docker_install.sh](docker_install.sh))

### Vérification rapide

```bash
ss -uln | grep 514                  # udp 0.0.0.0:514
chronyc tracking
docker --version
```

## Samba AD DC

Le script [samba-ad_installation.sh](samba-ad_installation.sh) transforme le serveur en contrôleur de domaine Active Directory.

### Installation

```bash
make server-samba-ad
```

Ce script :
- Installe Samba 4, Kerberos, Winbind et les dépendances
- Provisionne le domaine `NYX.TG` avec `samba-tool domain provision`
- Crée les groupes `direction`, `comptabilite`, `technique`
- Crée les utilisateurs `dir1`, `compta1`, `tech1`, `soc_reader`

### Vérification

```bash
make server-samba-verify
# ou directement :
sudo bash verification_samba-ad.sh
```

### Partages Samba

Une fois Samba AD DC opérationnel, configurer les partages avec [samba_installation.sh](samba_installation.sh) :

```bash
make server-samba-shares
```

Ce script crée les 4 partages (`direction`, `comptabilite`, `technique`, `commun`) avec ACL par groupe, et teste l'accès de chaque utilisateur.

### Montage pour le SOC

Le script [samba_montage-soc.sh](samba_montage-soc.sh) monte les 4 partages en lecture seule sur le SOC (`/mnt/samba/`), pour que le moteur de corrélation puisse y exécuter des scans YARA :

```bash
sudo bash samba_montage-soc.sh
```

## Dolibarr (ERP)

Une fois Docker installé, déployer Dolibarr avec [deploy_dolibarr.sh](deploy_dolibarr.sh) :

```bash
bash deploy_dolibarr.sh
```

Ce script lance `docker compose up -d` à partir de [docker-compose.yml](docker-compose.yml) (MariaDB + Dolibarr), attend le démarrage, et affiche l'état des conteneurs.

Accès : `http://10.0.1.20` — login `admin` / mot de passe `admin`.

### Vérifier le pipeline de logs Dolibarr

```bash
sudo bash test_dolibarr.sh
```

Ce script vérifie que le driver syslog Docker écrit bien vers rsyslog local, puis que les logs sont relayés vers le SOC (`10.0.1.10`). L'activation d'`imudp` est déjà faite par `base_installation.sh` — pas besoin de correctif séparé.
