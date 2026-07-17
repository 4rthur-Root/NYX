#!/bin/bash
echo "==== Création du réseau virtuel 'nyx' avec libvirt... ===="
cat > /tmp/nyx.xml << 'EOF'
<network>
  <name>nyx</name>
  <forward mode='none'/>
  <bridge name='virbr2' stp='on' delay='0'/>
</network>
EOF

echo "==== Nettoyage d'une éventuelle définition précédente... ===="
virsh net-destroy nyx 2>/dev/null || true
virsh net-undefine nyx 2>/dev/null || true

echo "==== Définition et démarrage du réseau 'nyx'... ===="
virsh net-define /tmp/nyx.xml
virsh net-start nyx
virsh net-autostart nyx

echo "==== Liste des réseaux virtuels... ===="
virsh net-list --all

echo "==== Détails du réseau 'nyx'... ===="
virsh net-dumpxml nyx