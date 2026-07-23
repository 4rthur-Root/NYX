# Windows 10

## Description

Machine cliente Windows 10 du lab NYX (`NYX-PME`). Elle est membre du domaine `NYX.TG`, fait partie du réseau isolé `10.0.1.0/24` (`10.0.1.30`), et envoie ses logs Sysmon + Security au SOC via NXLog.

Référence vidéo pour l'installation initiale : [How to install Windows 10 in Linux QEMU VM with virtio](https://www.youtube.com/watch?v=WYQFptZfdwE)

**Principe :** comme pour le SOC et le Server, la VM est créée manuellement (pas de Vagrant), puis pilotée à distance via SSH une fois OpenSSH Server activé. Les scripts PowerShell automatisent le reste.

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

### 4. Activer OpenSSH Server

Pour piloter la VM à distance comme le reste de la topologie (Server, SOC), activer OpenSSH depuis l'interface graphique (une seule fois, avant d'avoir accès à distance) :

- Paramètres → Applications → Fonctionnalités facultatives → Ajouter une fonctionnalité → **OpenSSH Server**

Ou en PowerShell local :
```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

À partir de cette étape, toutes les commandes suivantes s'exécutent depuis l'hôte, via SSH :
```bash
ssh dir1@<IP_NAT>
```
(l'IP NAT est visible avec `ipconfig` sur l'interface `Ethernet`, réseau `default`/libvirt NAT — sert uniquement à l'administration, jamais utilisée par les VMs pour sortir vers Internet)

⚠️ Le shell par défaut d'une session SSH Windows est `cmd.exe`. Taper `powershell` pour repasser en PowerShell et utiliser les cmdlets ci-dessous.

### 5. Configuration réseau

Vérifier les deux interfaces :
```powershell
Get-NetAdapter
ipconfig
```

- **Interface NAT** (`Ethernet` généralement) : DHCP, sert uniquement à l'accès SSH admin, jamais de sortie Internet pour les VMs.
- **Interface NYX** (`Ethernet 2` généralement) : à configurer en statique.

#### IP statique sur le réseau NYX

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 10.0.1.30 -PrefixLength 24 -DefaultGateway 10.0.1.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" -ServerAddresses 10.0.1.20
```

⚠️ **Point de vigilance** : si les deux interfaces ont la même métrique (`InterfaceMetric`), Windows peut choisir arbitrairement quel DNS interroger en premier, ce qui casse la résolution du domaine même si la config est correcte. Vérifier et forcer si besoin :
```powershell
Get-NetIPInterface -InterfaceAlias "Ethernet", "Ethernet 2" | Select InterfaceAlias, InterfaceMetric
Set-NetIPInterface -InterfaceAlias "Ethernet 2" -InterfaceMetric 10
Set-NetIPInterface -InterfaceAlias "Ethernet" -InterfaceMetric 100
```

#### Vérification

```powershell
ipconfig
# Ethernet 2 doit montrer 10.0.1.30/24

ping 10.0.1.1
# Doit répondre (OPNsense)

nslookup srv-pme.nyx.tg
# Doit résoudre via 10.0.1.20 (Samba AD DNS), pas via un DNS public
```

### 6. Renommer la machine (optionnel mais recommandé)

Le nom par défaut (`DESKTOP-XXXXXXX`) doit être changé avant le join du domaine :
```powershell
Rename-Computer -NewName "NYX-PME" -Restart
```
Reconnecte-toi ensuite via SSH sur l'IP NAT (inchangée).

### 7. Rejoindre le domaine NYX.TG

Le DNS doit déjà pointer vers `10.0.1.20` (étape 5) pour que la résolution du domaine fonctionne.

En session SSH (pas de fenêtre graphique disponible), construire le credential en ligne de commande plutôt que `Get-Credential` (qui ouvre une popup graphique incompatible avec SSH) :
```powershell
$securePass = ConvertTo-SecureString "AdminNyx2026!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("NYX\administrator", $securePass)
Add-Computer -DomainName "NYX.TG" -Credential $cred -Restart
```

Après redémarrage, reconnecte-toi en SSH et vérifie :
```powershell
Get-ComputerInfo | Select CsDomain, CsDomainRole
# CsDomain doit être NYX.TG, CsDomainRole doit être MemberWorkstation
```

Teste également la connexion avec un compte de domaine (ex. `compta1`, `tech1`) via l'écran de login Windows (**Other user** → `NYX\compta1`) pour confirmer que l'authentification AD fonctionne réellement sur ce poste.

---

## Sysmon

Le fichier [`sysmonconfig-nyxsoc.xml`](sysmonconfig-nyxsoc.xml) est une version filtrée de la configuration [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), réduite à 4 Event IDs pertinents pour le moteur de corrélation NyxSOC :

| Event ID | Nom | Usage détection |
|----------|-----|------------------|
| 1 | ProcessCreate | Création de processus (exécution suspecte, chaînes d'attaque) |
| 2 | FileCreateTime | Modification d'horodatage (timestomping, anti-forensique) |
| 3 | NetworkConnect | Connexions réseau sortantes (C2, exfiltration) |
| 11 | FileCreate | Création de fichier (dépôt de payload) |

### Installation
D' abord créer le répertoire *NyxSOC/Sysmon* sur windows et lancer . ***(user = dir1)***
```bash
scp Windows/sysmonconfig-nyxsoc.xml user@192.168.122.160:'C:\NyxSOC\Sysmon\'
scp Windows/sysmon_install.ps1 user@192.168.122.160:'C:\NyxSOC\Sysmon\'
ssh user@192.168.122.160 'powershell -ExecutionPolicy Bypass -File C:\NyxSOC\Sysmon\sysmon_install.ps1'
```

Le script :
- Télécharge Sysmon64 depuis Sysinternals si absent
- Installe le service avec la config filtrée
- Vérifie que le service tourne et que des événements sont journalisés

### Vérification manuelle

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

---

## NXLog CE — envoi des logs vers le SOC

Le fichier [`nxlog.conf`](nxlog.conf) collecte :
- Le journal **Sysmon/Operational** (Event IDs 1, 2, 3, 11, déjà filtrés en amont)
- Le journal **Security** (Event IDs 4624, 4625, 4768, 4769 — authentification, cohérent avec Samba AD DC)

Et les forward en **Syslog RFC 5424** vers `10.0.1.10:514` (UDP).

### Installation

Télécharger le .msi depuis [](https://nxlog.co/downloads/nxlog-ce#nxlog-community-edition)

```bash
scp ~/Downloads/nxlog-ce-3.2.2329.msi dir1@192.168.122.160:'C:\NyxSOC\NXLog\nxlog-ce.msi'
scp Windows/nxlog.conf dir1@192.168.122.160:'C:\NyxSOC\NXLog\'
scp Windows/nxlog_install.ps1 dir1@192.168.122.160:'C:\NyxSOC\NXLog\'
ssh dir1@192.168.122.160 'powershell -ExecutionPolicy Bypass -File C:\NyxSOC\NXLog\nxlog_install.ps1'
```

⚠️ Vérifier la version la plus récente de NXLog CE sur [nxlog.co](https://nxlog.co/products/nxlog-community-edition/download) avant exécution — l'URL de téléchargement dans `nxlog_install.ps1` doit être mise à jour périodiquement.

### Vérifier sur le SOC

```bash
sudo tail -f /var/log/remote/NYX-PME.log
```

---

## Scripts

| Fichier | Rôle |
|---------|------|
| `windows_installation.sh` | Crée la VM Windows 10 via virt-install |
| `sysmonconfig-nyxsoc.xml` | Config Sysmon filtrée (Event IDs 1, 2, 3, 11) |
| `sysmon_install.ps1` | Installe et configure Sysmon |
| `nxlog.conf` | Config NXLog (RFC 5424, forward vers le SOC) |
| `nxlog_install.ps1` | Installe et configure NXLog CE |

Note : l'installation de Windows elle-même reste manuelle (clic dans le VNC/virt-viewer). Tout le reste (réseau, join domaine, Sysmon, NXLog) est piloté à distance via SSH.
