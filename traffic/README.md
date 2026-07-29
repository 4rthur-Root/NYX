# NYX — Générateur de Bruit de Fond & Trafic (Traffic Generator)

Module autonome de simulation du comportement légitime d'utilisateurs et d'employés PME pour le SOC NYX.

---

## 🎯 Objectifs

1. **Test de résistance du SOC** : Générer un flux d'activité réseau, web et fichiers régulier et légitime.
2. **Validation anti-faux positifs** : S'assurer que le moteur de corrélation (`engine`) ingère et valide les événements sans déclencher d'alertes intempestives.
3. **Réalisme contextuel** : Sessions SSH réelles (`paramiko`), CookieJars indépendants par utilisateur Web, cloisonnement des partages Samba par rôle, et gestion du rythme diurne / nocturne (*workday jitter*).

---

## 🏗️ Structure du Dossier `traffic/`

```
traffic/
├── config.py         # Paramètres centralisés (IPs, comptes rôles, endpoints, délais, partages)
├── time_utils.py     # Utilitaires de rythme temporel (heures de bureau vs nuit, pas réactifs)
├── sim_web.py        # Simulation de navigation et sessions ERP Dolibarr (CookieJar par user)
├── sim_samba.py      # Simulation de création/lecture de fichiers sains sur partages SMB
├── sim_auth.py       # Simulation de sessions d'administration SSH réelles via Paramiko
├── orchestrator.py   # Script maître d'orchestration multithreadé (gestion signaux & CLI)
├── Makefile          # Auto-détection Docker/Podman, build automatique & cibles d'exécution
├── Dockerfile        # Image Docker/Podman Python 3.13-slim alignée avec l'engine
├── requirements.txt  # Dépendances (paramiko)
└── README.md         # Documentation d'utilisation
```

---

## 🚀 Utilisation (Docker / Podman Agnostique)

Le `Makefile` détecte automatiquement si `docker` ou `podman` est présent sur la machine hôte/Kali et reconstruit automatiquement l'image si nécessaire avant de lancer le conteneur.

### 1. Commandes Makefile (Recommandé)

```bash
cd traffic/

# Build l'image + Lance tout le bruit au rythme standard (ralenti la nuit)
make run

# Build l'image + FORCE le rythme diurne dense (idéal pour tests de nuit / gros dataset)
make run-workday

# Build l'image + Lance un module spécifique
make run-web
make run-samba
make run-auth

# Exécution locale directe sans conteneur
make run-local

# Ouvrir un shell interactif dans le conteneur
make shell
```

### 2. Utilisation directe Python CLI

```bash
# Lancer tout le bruit
python3 -m traffic.orchestrator --mode all

# Forcer la fréquence diurne dense même la nuit (option --force-workday)
python3 -m traffic.orchestrator --mode all --force-workday

# Variantes par module
python3 -m traffic.orchestrator --mode web
python3 -m traffic.orchestrator --mode samba
python3 -m traffic.orchestrator --mode auth
```

### 3. Arrêt propre

Appuyez simplement sur `Ctrl+C` dans le terminal. L'orchestrateur ferme tous les threads proprement et immédiatement.

---

## 🌙 Gestion des Heures de Nuit vs Mode Test Dense

Par défaut, `time_utils.py` applique la logique suivante :
- **Journée (07h00 - 19h00)** : Délais standard (`JITTER_WEB` 5-15s, `JITTER_SAMBA` 10-30s, `JITTER_AUTH` 60-180s).
- **Nuit (19h00 - 07h00)** : Délais multipliés par 6 (activité réduite).

💡 **Pour vos tests et rapports réalisés de nuit** :  
Pour obtenir un **volume élevé de logs normaux** de nuit afin d'enrichir vos tableaux de bord et votre dataset de démonstration, tapez :
```bash
make run-workday
```
(ou passez l'option `--force-workday`, ou définissez la variable d'environnement `NYX_FORCE_WORKDAY=1`).
