#!/bin/bash
# ============================================================
# fix_rsyslog_dolibarr.sh - Active l'écoute UDP 514 sur rsyslog
# ============================================================

set -e

echo "============================================================"
echo "CORRECTION RSYSLOG POUR DOLIBARR"
echo "============================================================"

# 1. Activer imudp dans rsyslog.conf
echo "→ Activation du module imudp dans /etc/rsyslog.conf"
if ! grep -q "^module(load=\"imudp\")" /etc/rsyslog.conf; then
    sudo sed -i 's/#module(load="imudp")/module(load="imudp")/' /etc/rsyslog.conf
    sudo sed -i 's/#input(type="imudp" port="514")/input(type="imudp" port="514")/' /etc/rsyslog.conf
else
    echo "  → module imudp déjà activé"
fi

# 2. Redémarrer rsyslog
echo "→ Redémarrage de rsyslog"
sudo systemctl restart rsyslog

# 3. Vérifier l'écoute UDP 514
echo "→ Vérification de l'écoute sur UDP 514"
sudo ss -uln | grep 514

# 4. Redémarrer Dolibarr
echo "→ Redémarrage de Dolibarr"
cd /opt/dolibarr
sudo docker compose down
sudo docker compose up -d

echo ""
echo "============================================================"
echo "✅ CORRECTION EFFECTUÉE"
echo "============================================================"
echo "Teste avec :"
echo "  sudo tail -f /var/log/syslog | grep dolibarr"
echo "  sudo tcpdump -i any port 514 -n"
echo ""
echo "Puis génère du trafic sur http://10.0.1.20"