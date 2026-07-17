sudo mkdir -p /home/adrien/vms
sudo virsh pool-define-as nyxsoc-pool dir --target /home/adrien/vms
sudo virsh pool-build nyxsoc-pool
sudo virsh pool-start nyxsoc-pool
sudo virsh pool-autostart nyxsoc-pool


echo "==== Liste des pools de stockage... ===="
virsh pool-list --all