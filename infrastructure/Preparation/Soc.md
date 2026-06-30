# SOC (Security Onion)

## Configuration réseau

### Interfaces réseau

Le SOC dispose de deux interfaces réseau :
- **enp1s0** — Interface de management / OOBM (accès internet)
- **enp2s0** — Interface isolée du réseau NYX (`10.0.1.10/24`)

### Configuration de `/etc/network/interfaces`

Si les IP ne sont pas déjà configurées sur les deux interfaces, éditer le fichier :

```bash
sudo nano /etc/network/interfaces
```

Coller le contenu suivant :

```
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# Management interface (NAT / default) — DHCP
auto enp1s0
iface enp1s0 inet dhcp

# NYX network (isolated) — Static IP
auto enp2s0
iface enp2s0 inet static
    address 10.0.1.10
    netmask 255.255.255.0
    gateway 10.0.1.1
    dns-nameservers 8.8.8.8 1.1.1.1
```

Si l'interface de management n'a pas de DHCP (ex: `default` sans DHCP), utiliser une IP statique à la place du bloc DHCP ci-dessus :

```
# Management interface (NAT / default) — Static IP
auto enp1s0
iface enp1s0 inet static
    address 192.168.122.10/24
```

Puis redémarrer le réseau :

```bash
sudo systemctl restart networking
```

### Configuration du réseau libvirt `default` (NAT)

Si le réseau `default` de libvirt n'a pas de forwarding NAT ni de DHCP, vérifier et corriger sa configuration :

Fichier de définition du réseau libvirt :

```xml
<network>
  <name>default</name>
  <uuid>b45dcab1-7921-4491-a50c-c21ce3798b43</uuid>
  <forward mode='nat'/>
  <bridge name='virbr0' stp='on' delay='0'/>
  <mac address='52:54:00:75:03:99'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
    </dhcp>
  </ip>
</network>
```

Appliquer les modifications :

```bash
virsh net-destroy default
virsh net-start default
```

### Vérification

Une fois la configuration appliquée, vérifier :

```bash
# Vérifier que l'interface isolée est up et a la bonne IP
ip a show enp2s0
# Doit montrer UP et 10.0.1.10/24

# Tester la connectivité vers la gateway OPNsense
ping 10.0.1.1
# Doit répondre

# Tester la connectivité internet (via OPNsense)
ping 8.8.8.8
# Doit répondre
```

> **Note** : Le trafic depuis `10.0.1.0/24` (interface `enp2s0` du SOC) doit transiter par OPNsense (`10.0.1.1`) pour atteindre internet. Vérifier que les règles NAT/firewall sur OPNsense autorisent ce flux.
