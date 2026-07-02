#!/bin/bash
# ============================================================
# Phase 4.5 - Montage des partages pour le SOC
# ============================================================
# Usage : sudo ./mount_samba_soc.sh
# ============================================================

set -e

echo "============================================================"
echo "PHASE 4.5 : Montage des partages Samba en lecture seule"
echo "============================================================"

# === VÉRIFICATION PRÉALABLE ===
echo ""
echo "→ Vérification que soc_reader peut accéder à /commun"
if smbclient //localhost/commun -U soc_reader --password=Nyx2026! -c "ls" >/dev/null 2>&1; then
    echo "✅ soc_reader a accès à /commun"
else
    echo "❌ soc_reader n'a PAS accès à /commun"
    echo "   → Ajout manuel aux groupes :"
    echo "     samba-tool group addmembers direction soc_reader"
    echo "     samba-tool group addmembers comptabilite soc_reader"
    echo "     samba-tool group addmembers technique soc_reader"
    echo "   → Puis redémarre Samba : systemctl restart samba-ad-dc"
    echo "   → Réessaie : smbclient //localhost/commun -U soc_reader --password=Nyx2026! -c \"ls\""
    exit 1
fi

# === CRÉATION DES POINTS DE MONTAGE ===
echo ""
echo "→ Création des points de montage"
mkdir -p /mnt/samba/{direction,comptabilite,technique,commun}

# === MONTAGE ===
echo ""
echo "→ Montage des partages en lecture seule"

# Direction
echo "  → Montage de /direction"
mount -t cifs //10.0.1.20/direction /mnt/samba/direction \
    -o username=soc_reader,password=Nyx2026!,domain=NYX,ro

# Comptabilite
echo "  → Montage de /comptabilite"
mount -t cifs //10.0.1.20/comptabilite /mnt/samba/comptabilite \
    -o username=soc_reader,password=Nyx2026!,domain=NYX,ro

# Technique
echo "  → Montage de /technique"
mount -t cifs //10.0.1.20/technique /mnt/samba/technique \
    -o username=soc_reader,password=Nyx2026!,domain=NYX,ro

# Commun
echo "  → Montage de /commun"
mount -t cifs //10.0.1.20/commun /mnt/samba/commun \
    -o username=soc_reader,password=Nyx2026!,domain=NYX,ro

# === VÉRIFICATION ===
echo ""
echo "============================================================"
echo "VÉRIFICATION DES MONTAGES"
echo "============================================================"
df -h | grep /mnt/samba

echo ""
echo "→ Contenu de /mnt/samba/direction :"
ls -la /mnt/samba/direction/ 2>/dev/null || echo "  (vide)"

echo ""
echo "→ Contenu de /mnt/samba/commun :"
ls -la /mnt/samba/commun/ 2>/dev/null || echo "  (vide)"

echo ""
echo "=============================================="
echo "✅ PHASE 4.5 TERMINÉE"
echo "=============================================="
echo "Les partages sont montés en /mnt/samba/"
echo "Le SOC peut maintenant scanner les fichiers avec YARA."