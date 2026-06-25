# Problèmes rencontrés & Solutions — NYX IaC

Documentation des problèmes rencontrés pendant la phase IaC.  
Format : symptôme → cause → solution → leçon retenue.

---

## [IaC-001] Vagrant 2.4.9 non disponible via les dépôts DNF

**Phase** : Installation de Vagrant  
**Date** : 2026-06-10

**Symptôme**  
Le dépôt HashiCorp (`rpm.releases.hashicorp.com`) ne proposait que Vagrant 2.3.4
via `dnf install vagrant`, malgré l'ajout du repo officiel. La contrainte
`Vagrant.require_version ">= 2.4.9"` dans le Vagrantfile bloquait immédiatement
le démarrage.

**Cause**  
Le dépôt RPM HashiCorp pour Fedora était en retard d'un an sur les releases
officielles. Le miroir DNF ne reflétait pas la dernière version stable.

**Solution**  
Téléchargement manuel du RPM depuis la page officielle des releases HashiCorp :
```
https://releases.hashicorp.com/vagrant/2.4.9/
```
Installation locale :
```bash
sudo dnf install -y ./vagrant-2.4.9-1.x86_64.rpm
vagrant --version  # → Vagrant 2.4.9
rm vagrant-2.4.9-1.x86_64.rpm
```

**Leçon**  
Pour les outils HashiCorp sur Fedora, privilégier le RPM direct depuis
`releases.hashicorp.com` plutôt que le dépôt DNF qui peut être en retard.

---

## [IaC-002] vagrant plugin install échoue — outils de compilation manquants

**Phase** : Installation du plugin vagrant-libvirt  
**Date** : 2026-06-10

**Symptôme**  
```
ERROR: Failed to build gem native extension.
make failed No such file or directory - make
```
Le plugin `vagrant-libvirt` refusait de s'installer via `vagrant plugin install`.

**Cause**  
Le RPM Vagrant 2.4.9 installé manuellement embarque son propre Ruby isolé
(`/opt/vagrant/embedded/bin/ruby`) mais n'installe pas la chaîne de compilation
native du système (`gcc`, `make`). Les gems nécessitant une extension native
(comme `racc`) ne pouvaient pas être compilés.

**Solution**  
Installation préalable des outils de développement système :
```bash
sudo dnf install -y gcc make libvirt-devel libxml2-devel ruby-devel libguestfs-tools
vagrant plugin install vagrant-libvirt
```

**Leçon**  
L'installation d'un plugin Vagrant via `vagrant plugin install` compile des
extensions natives. Les dépendances `gcc`, `make`, `libvirt-devel` et
`ruby-devel` doivent être présentes sur l'hôte avant toute tentative.

---

## [IaC-003] vagrant up bloqué — DHCP activé sur le réseau libvirt default

**Phase** : Démarrage de la VM soc  
**Date** : 2026-06-22

**Symptôme**  
```
Network default exists but does not have dhcp disabled.
Please fix your configuration and run vagrant again.
```

**Cause**  
Le Vagrantfile spécifiait `libvirt__dhcp_enabled: false` sur une interface
connectée au réseau `default`, mais ce réseau avait le DHCP activé dans sa
configuration libvirt.

**Solution**  
Modification du XML du réseau libvirt via `virsh net-edit default` pour
supprimer le bloc `<dhcp>`. Le Vagrantfile est conservé avec
`libvirt__dhcp_enabled: false` et `auto_config: false`.

```xml
<network>
  <name>default</name>
  <forward mode='nat'/>
  <bridge name='virbr0' stp='on' delay='0'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
  </ip>
</network>
```

L'IP statique est configurée via Ansible avec `nmcli connection add`.

**Leçon**  
`libvirt__dhcp_enabled: false` vérifie que le réseau n'a pas de DHCP — il
ne le désactive pas. Modifier le réseau en amont via `virsh net-edit`.

---

## [IaC-004] virsh net-list vide sans variable LIBVIRT_DEFAULT_URI

**Phase** : Configuration du réseau libvirt  
**Date** : 2026-06-10

**Symptôme**  
`virsh net-list --all` retournait une liste vide alors que les réseaux
existaient bien (visibles avec `sudo virsh net-list --all`).

**Cause**  
Sans `LIBVIRT_DEFAULT_URI`, `virsh` se connecte à `qemu:///session` au lieu
de `qemu:///system`.

**Solution**  
```bash
echo 'export LIBVIRT_DEFAULT_URI="qemu:///system"' >> ~/.bashrc
source ~/.bashrc
```

**Leçon**  
Sur Fedora avec libvirtd en mode système, toujours exporter
`LIBVIRT_DEFAULT_URI="qemu:///system"` dans le profil shell.

---

## [IaC-005] Packer Debian — Timeout SSH après 20 minutes

**Phase** : Build Packer Debian 12  
**Date** : 2026-06-22

**Symptôme**  
```
Timeout waiting for SSH.
Build 'qemu.debian' errored after 20 minutes
```

**Cause**  
L'installation Debian netinst avec téléchargement des paquets depuis internet
dépasse les 20 minutes de timeout SSH par défaut.

**Solution**  
```hcl
ssh_timeout = "60m"
```

**Leçon**  
Toujours prévoir au moins 60m de timeout SSH pour les builds Packer avec
installation réseau. Le timeout par défaut (10-20m) est insuffisant.

---

## [IaC-006] Packer Debian — sudo: a password is required

**Phase** : Provisioner shell Packer Debian  
**Date** : 2026-06-22

**Symptôme**  
```
sudo: a terminal is required to read the password
Script exited with non-zero exit status: 1
```

**Cause**  
Le provisioner shell se connectait en tant que `vagrant` mais le NOPASSWD
sudoers n'était pas encore appliqué, et SSH était configuré pour `vagrant`
alors que root était nécessaire pour les opérations de provisioning.

**Solution**  
Deux corrections combinées :
1. Dans `preseed.cfg` — `late_command` qui configure NOPASSWD et `PermitRootLogin yes`
2. Dans `debian.pkr.hcl` — `ssh_username = "root"` pour le provisioner

**Leçon**  
Pour les builds Packer Debian, se connecter directement en root via SSH
est plus simple que de gérer sudo dans les provisioners. Activer
`PermitRootLogin yes` dans le `late_command` du preseed.

---

## [IaC-007] Packer Windows — ProductKey manquant bloque le setup

**Phase** : Build Packer Windows 10  
**Date** : 2026-06-24

**Symptôme**  
```
Windows cannot read the <ProductKey> setting from the unattend answer file.
```
Windows Setup affichait une popup bloquante et attendait une interaction manuelle.

**Cause**  
Le bloc `<ProductKey>` dans `Autounattend.xml` était vide (commentaire uniquement).
Windows Setup détecte l'absence de clé et lève une erreur UI.

**Solution**  
Ajout de la clé KMS générique publique Microsoft pour Windows 10 Pro :
```xml
<ProductKey>
  <Key>W269N-WFGWX-YVC9B-4J6C9-T83GX</Key>
  <WillShowUI>Never</WillShowUI>
</ProductKey>
```
Cette clé est officielle (docs.microsoft.com) — elle permet l'installation
sans activer Windows.

**Leçon**  
Un `Autounattend.xml` pour Windows 10 Pro doit toujours contenir une clé
KMS générique. `<WillShowUI>Never</WillShowUI>` empêche toute popup même
en cas d'erreur non fatale.

---

## [IaC-008] Packaging box Windows — I/O error sur cp du qcow2

**Phase** : Packaging manuel de la box Windows  
**Date** : 2026-06-24

**Symptôme**  
```
cp: failed to clone 'box_tmp/box.img' from 'packer-win10_22h2': Input/output error
```

**Cause**  
Le build Windows produit un fichier qcow2 intermédiaire de ~65 Go. La copie
via `cp` sur btrfs tente un clone CoW qui échoue lorsque la RAM est saturée
(swap utilisé à >40% par d'autres processus actifs).

**Solution**  
Fermer tous les processus non essentiels (navigateur notamment) avant le
packaging, puis relancer. Le `cp` standard réussit avec suffisamment de RAM libre.

**Leçon**  
Le build et le packaging Windows nécessitent ~70 Go de disque libre et une
RAM aussi disponible que possible. Éviter de faire tourner d'autres VM ou
applications lourdes en parallèle.

---

## [IaC-009] OPNsense — service sshd start incorrect sur FreeBSD

**Phase** : Activation SSH OPNsense  
**Date** : 2026-06-23

**Symptôme**  
```
sshd does not exist in /etc/rc.d or the local startup directories.
```

**Cause**  
Sur OPNsense/FreeBSD, le service SSH s'appelle `openssh`, pas `sshd`.

**Solution**  
```bash
service openssh start
# Et pour le rendre persistant :
echo 'openssh_enable="YES"' >> /etc/rc.conf
```

**Leçon**  
Sur FreeBSD/OPNsense : `service openssh start` (pas `sshd`).
Sur Linux : `systemctl start sshd` ou `service ssh start`.

---

*Dernière mise à jour : 2026-06-25 — Phase Vagrant + Ansible en cours*