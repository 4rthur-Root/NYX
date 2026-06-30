# Windows 10

## Description

Machine cliente Windows 10 du lab NYX. Elle fait partie du réseau isolé `10.0.1.0/24` et envoie ses logs au SOC.

Référence vidéo : [How to install Windows 10 in Linux QEMU VM with virtio](https://www.youtube.com/watch?v=WYQFptZfdwE)

---

## Quick Start

### Pré-requis (à télécharger)

- [Windows 10 ISO](https://www.microsoft.com/software-download/windows10) 
- [VirtIO drivers ISO](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso)

### 1. Créer la VM

```bash
bash infrastructure/Windows/windows_installation.sh
```

### 2. Installer Windows

```bash
virt-viewer Windows10
```

**Pendant l'installation :**
1. Au moment du choix du disque, cliquer **"Load driver"**
2. Parcourir le lecteur CD `virtio-win` → `vioscsi` → `w10` → `amd64`
3. Sélectionner le pilote, le disque apparaît
4. Continuer l'installation normalement

### 3. Pilotes VirtIO

Une fois Windows installé et la session ouverte :

1. Ouvrir le lecteur CD `virtio-win`
2. Lancer `virtio-win-gt-x64.msi` (installation complète)
3. Cocher tous les composants : **NetKVM**, **Balloon**, **vioserial**, **pvpanic**
4. Redémarrer

### 4. QEMU Guest Agent

```powershell
# Dans le gestionnaire de périphériques, mettre à jour le pilote du
# "PCI simple communications controller" → choisir le dossier
# virtio-win\vioserial\w10\amd64
```

Ou via le MSI (inclus dans l'étape 3 si coché).

### 5. Vérifier le réseau

Vérifier dans les paramètres réseau que les deux interfaces sont reconnues :
- **Interface 1** — NAT (DHCP, accès internet)
- **Interface 2** — NYX (`10.0.1.x`, à configurer en statique)

---

## Configuration réseau

### IP statique sur le réseau NYX

1. Panneau de configuration → Centre Réseau et partage → Modifier les paramètres de la carte
2. Identifier l'interface du réseau `nyx` (celle qui n'a pas internet)
3. Propriétés → IPv4 → Utiliser l'adresse suivante :

| Champ | Valeur |
|-------|--------|
| Adresse IP | `10.0.1.20` |
| Masque | `255.255.255.0` |
| Passerelle | `10.0.1.1` |
| DNS | `8.8.8.8` |

### Vérification

```powershell
ipconfig
# Doit montrer 10.0.1.20/24

ping 10.0.1.1
# Doit répondre (OPNsense)

ping 10.0.1.10
# Doit répondre (SOC)
```

---

## Envoi des logs vers le SOC

### Avec nxlog (recommandé)

1. Télécharger et installer [nxlog Community Edition](https://nxlog.co/products/nxlog-community-edition/download)
2. Configurer `/Program Files/nxlog/conf/nxlog.conf` :

```
define ROOT C:\Program Files\nxlog
define HOSTNAME Windows10

Modulename im_msvistalog
    <Query>
        <XmlQuery>
            SELECT * FROM System
        </XmlQuery>
    </Query>

<Output out>
    Module om_udp
    Host 10.0.1.10
    Port 514
    OutputType Syslog_RFC3164
</Output>

<Route r>
    Path => out
</Route>
```

3. Redémarrer le service nxlog :

```powershell
Restart-Service nxlog
```

### Vérifier sur le SOC

```bash
sudo tail -f /var/log/remote/Windows10.log
```

---

## Scripts

| Script | Rôle |
|--------|------|
| `windows_installation.sh` | Crée la VM Windows 10 via virt-install |

Note : l'installation de Windows elle-même reste manuelle (clic dans le VNC). Les scripts automatisent la création de la VM et l'attachement des ISOs.
