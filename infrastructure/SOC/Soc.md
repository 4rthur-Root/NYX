# SOC (Security Operations Center)

## Description

Le SOC est le cœur du système NYX. Il reçoit les logs de toutes les sources (OPNsense, Debian Server, Windows) via syslog UDP, les stocke dans `/var/log/remote/`, et exécute le moteur de corrélation.

**Principe :** l'ensemble de la configuration est automatisée par des scripts. La documentation détaillée est là pour référence ; dans la pratique, on exécute les scripts.

---

## Quick Start 

### Pré-requis

- Réseau libvirt `nyx` créé (`make network`)
- OPNsense déployée et joignable sur `10.0.1.1`

### 1. Créer la VM

```bash
make soc-create
# ou directement :
bash infrastructure/SOC/soc_creation.sh
```

Lance l'assistant d'installation Debian via VNC.

### 2. Installer Debian

```bash
virt-viewer Soc
```

Choix d'installation minimal : **SSH server + standard system utilities**.

### 3. Configurer le réseau

Une fois la VM démarrée et accessible via SSH, configurer les interfaces :

```bash
sudo nano /etc/network/interfaces
# → Copier la configuration ci-dessous (section Réseau)
sudo systemctl restart networking
```

### 4. Provisionner

```bash
make soc-provision SOC_IP=10.0.1.10
# ou manuellement :
scp -r infrastructure/SOC/ user@10.0.1.10:/tmp/soc-provision
ssh user@10.0.1.10 'sudo bash /tmp/soc-provision/soc.sh'
```

### 5. Vérifier

```bash
make soc-verify SOC_IP=10.0.1.10
# ou manuellement :
ssh user@10.0.1.10 'sudo bash /tmp/soc-provision/soc_verify.sh'
```

---

## Scripts

### `soc_creation.sh`

Crée la VM KVM avec `virt-install` :
- 2 vCPU, 2 Go RAM, 8 Go disque
- Réseau `nyx` (isolé) + réseau `default` (NAT)
- OS : Debian (image ISO à télécharger)

### `soc.sh`

Provisionne la VM après installation :
- Met à jour les paquets
- Installe `rsyslog` et `python3`
- Crée l'utilisateur `soc` (groupe `adm`)
- Copie `rsyslog.conf` (imudp activé) et `10-remote.conf`
- Crée `/var/log/remote/` et `/var/log/nyxsoc/alerts/`
- Applique les permissions `soc:soc`, `chmod 750`
- Redémarre rsyslog et vérifie le port 514

### `common.sh`

Fonctions partagées : `log()`, `apt_install()`, `ensure_user()`.

### `soc_verify.sh`

Vérification complète après provisionnement :
- Utilisateur `soc` + groupe `adm`
- IP `10.0.1.10/24` et connectivité
- rsyslog actif + port 514
- Fichier `10-remote.conf` présent
- Répertoires de logs existants
- Permissions correctes

### `10-remote.conf`

Filtre rsyslog : aiguille les logs provenant du `10.0.1.0/24` vers `/var/log/remote/%HOSTNAME%.log`.

### `rsyslog.conf`

Fichier de configuration rsyslog avec `imudp` (port 514) déjà activé.

---

## Détails de configuration

### Réseau

Fichier `/etc/network/interfaces` :

```
auto lo
iface lo inet loopback

auto enp1s0
iface enp1s0 inet dhcp

auto enp2s0
iface enp2s0 inet static
    address 10.0.1.10
    netmask 255.255.255.0
    gateway 10.0.1.1
    dns-nameservers 8.8.8.8 1.1.1.1
```

### Rsyslog

Dans `/etc/rsyslog.conf` (déjà fait dans le fichier livré) :

```
module(load="imudp")
input(type="imudp" port="514")
```

Fichier `/etc/rsyslog.d/10-remote.conf` :

```
$FileOwner soc
$FileGroup soc
$FileCreateMode 0640
$template RemoteLogs,"/var/log/remote/%HOSTNAME%.log"
if $fromhost-ip startswith '10.0.1.' then ?RemoteLogs
& stop
```

### Répertoires et permissions

```bash
/var/log/remote/           # Logs des sources (OPNsense, Debian Server, Windows)
/var/log/nyxsoc/alerts/    # Alertes générées par le moteur de corrélation

sudo chown -R soc:soc /var/log/remote /var/log/nyxsoc
sudo chmod 750 /var/log/remote /var/log/nyxsoc
```

### Vérification manuelle

```bash
ss -tulpn | grep 514                  # udp 0.0.0.0:514
sudo tail -f /var/log/remote/OPNsense.internal.log
```

---

## Dépendances

- Réseau **NYX** (`10.0.1.0/24`) actif
- **OPNsense** configuré pour forwarder les logs vers `10.0.1.10:514`
- **Debian Server** configuré pour forwarder `daemon.*` vers `10.0.1.10:514`
