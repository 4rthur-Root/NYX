#!/bin/bash
# ============================================================
# test_dolibarr_logs.sh - Vérifie le pipeline de logs Dolibarr
# ============================================================

set -e

echo "============================================================"
echo "TEST DU PIPELINE DE LOGS DOLIBARR"
echo "============================================================"

echo ""
echo "1. Vérification du driver syslog Docker :"
sudo docker inspect dolibarr_web | grep -A 5 "LogConfig" | head -6

echo ""
echo "2. Vérification de la configuration rsyslog :"
sudo cat /etc/rsyslog.d/50-forward.conf

echo ""
echo "3. Vérification que rsyslog écoute sur UDP 514 :"
sudo netstat -uln | grep 514 || echo "⚠️  Pas de socket UDP 514 en écoute ?"

echo ""
echo "4. Génération de logs Dolibarr (connexion admin)..."
echo "→ Va sur http://10.0.1.20 et connecte-toi avec admin/admin"
echo "→ Puis clique sur 'Setup' → 'Modules/Applications'"
echo ""
read -p "Appuie sur Entrée quand c'est fait..."

echo ""
echo "5. Vérification des logs dans /var/log/syslog :"
sudo grep -i dolibarr /var/log/syslog | tail -5

echo ""
echo "6. Vérification du forwarding vers le SOC (10.0.1.10) :"
echo "→ Capture en cours (5 secondes)..."
sudo timeout 5 tcpdump -i any port 514 -n 2>/dev/null | grep "10.0.1.10" || echo "⚠️  Aucun paquet vers 10.0.1.10 détecté"

echo ""
echo "============================================================"
echo "RÉSULTATS :"
echo "============================================================"
echo "✅ Si tu vois des logs Dolibarr dans /var/log/syslog → rsyslog reçoit"
echo "✅ Si tu vois des paquets vers 10.0.1.10 → forwarding actif"
echo "✅ Si tu vois des logs sur le SOC → pipeline complet OK"
echo ""
echo "Pour vérifier sur le SOC :"
echo "  ssh soc@10.0.1.10"
echo "  sudo tail -f /var/log/remote/debian.log | grep dolibarr"