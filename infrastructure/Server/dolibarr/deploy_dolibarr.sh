#!/bin/bash
# deploy.sh - Script de déploiement pour Dolibarr

set -e

echo "============================================================"
echo "         Déploiement de Dolibarr sur Debian Server          "
echo "============================================================"

# 1. Vérifier que Docker est installé
if ! command -v docker &> /dev/null; then
    echo "❌ Docker non trouvé. Installez-le d'abord."
    exit 1
fi

# 2. Démarrer Dolibarr
echo "→ Lancement de Dolibarr..."
docker compose up -d

# 3. Attendre que le service soit prêt
echo "→ Attente du démarrage de Dolibarr..."
sleep 20

# 4. Vérifier l'état
echo "→ État des conteneurs :"
docker compose ps

echo ""
echo "✅ Dolibarr est opérationnel sur http://10.0.1.20"
echo "   - Login : admin"
echo "   - Mot de passe : admin"
echo ""
echo "→ Vérifier les logs :"
echo "   sudo docker compose logs"