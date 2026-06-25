echo "==== Création du réseau virtuel 'nyx' avec libvirt... ===="
cat > /tmp/nyx.xml << 'EOF'
<network>
  <name>nyx</name>
  <forward mode='none'/>
  <bridge name='virbr2' stp='on' delay='0'/>
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