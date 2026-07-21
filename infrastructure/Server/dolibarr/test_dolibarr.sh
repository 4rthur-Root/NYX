#!/bin/bash
# ============================================================
# test_dolibarr.sh - Vérifie le pipeline de logs Dolibarr
# À utiliser après déploiement, imudp étant déjà activé par
# base_installation.sh (pas besoin de script de correction séparé)
# ============================================================

set -e

echo "============================================================"
echo "TEST DU PIPELINE DE LOGS DOLIBARR"
echo "============================================================"

echo ""
echo "1. Vérification du driver syslog Docker :"
docker inspect dolibarr_web | grep -A 5 "LogConfig" | head -6

echo ""
echo "2. Vérification de la configuration rsyslog (forward vers SOC) :"
cat /etc/rsyslog.d/50-forward.conf

echo ""
echo "3. Vérification que rsyslog écoute sur UDP 514 :"
ss -uln | grep 514 || echo "⚠️  Pas de socket UDP 514 en écoute — vérifier base_installation.sh"

echo ""
echo "4. Génération de logs Dolibarr (connexion admin)..."
echo "→ Va sur http://10.0.1.20 et connecte-toi avec admin/admin"
echo "→ Puis clique sur 'Setup' → 'Modules/Applications'"
echo ""
read -p "Appuie sur Entrée quand c'est fait..."

echo ""
echo "5. Vérification des logs dans /var/log/syslog :"
grep -i dolibarr /var/log/syslog | tail -5

echo ""
echo "6. Vérification du forwarding vers le SOC (10.0.1.10) :"
echo "→ Capture en cours (5 secondes)..."
timeout 5 tcpdump -i any port 514 -n 2>/dev/null | grep "10.0.1.10" || echo "⚠️  Aucun paquet vers 10.0.1.10 détecté"

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
