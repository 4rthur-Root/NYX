# OPNsense

## Installation

Pour créer la VM OPNsense, utiliser le script [opnsense_installation.sh](opnsense_installation.sh).

```bash
bash infrastructure/Opnsense/opnsense_installation.sh
```

Les paramètres suivants sont configurables en tête du script :
- `ISO_PATH` — chemin vers l'image ISO OPNsense
- `VM_NAME` — nom de la VM
- `MEMORY_MB` — quantité de RAM (défaut : `1536`)
- `DISK_SIZE_GB` — taille du disque (défaut : `8`)

## Configuration

### Accès SSH sur OPNsense

Par défaut, **SSH ne répond pas** sur `192.168.121.254`. Deux causes possibles :

- SSH n'est pas activé sur OPNsense
  
- Le firewall bloque l'interface `OPT1`

#### Activation depuis le shell OPNsense (option 8 dans virt-viewer)

```bash
# 1. Vérifier si sshd tourne
ps aux | grep sshd

# 2. Activer SSH dans la config OPNsense
/usr/local/sbin/opnsense-shell sshd enable 2>/dev/null || \
  echo 'openssh_enable="YES"' >> /etc/rc.conf

# 3. Démarrer sshd
service sshd start || /usr/local/etc/rc.d/openssh start

# 4. Vérifier la config SSH
grep -E "PermitRootLogin|Port|ListenAddress" /etc/ssh/sshd_config

# 5. Vérifier que le processus tourne
ps aux | grep sshd
```

#### Connexion depuis l'hôte

```bash
ssh -o StrictHostKeyChecking=no root@192.168.121.254
```

#### Vérification du firewall

Si SSH ne répond toujours pas, vérifier que les règles de firewall autorisent le trafic entrant sur `OPT1` (port 22).

![Activation SSH OPNsense](../Screenshots/SSH-opnsense.png)
![Activation SSH OPNsense](../Screenshots/Opnsense-dashboard.png)
