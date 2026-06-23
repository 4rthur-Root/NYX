echo "==== Création du réseau virtuel 'nyx' avec libvirt... ===="
cat > /tmp/nyx.xml << 'EOF'
<network>
  <name>nyx</name>
  <forward mode='none'/>
  <bridge name='virbr2' stp='on' delay='0'/>
  <domain name='nyx'/>
  <ip address='10.0.1.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='10.0.1.100' end='10.0.1.200'/>
    </dhcp>
  </ip>
</network>
EOF

echo "==== Définition et démarrage du réseau 'nyx'... ===="
virsh net-destroy nyx
virsh net-undefine nyx
virsh net-define /tmp/nyx.xml
virsh net-start nyx
virsh net-autostart nyx

echo "==== Liste des réseaux virtuels... ===="
virsh net-list --all

virsh net-dumpxml nyx