# NYX — Générateur de Bruit de Fond & Trafic (Traffic Generator)

Module autonome de simulation de comportement légitime d'utilisateurs et d'employés pour le SOC NYX.

---

## 🎯 Objectifs

1. **Test de résistance du SOC** : Générer un flux d'activité réseau, web et fichier régulier et légitime.
2. **Validation anti-faux positifs** : S'assurer que le moteur de corrélation (`engine`) ingère et valide les événements sans déclencher d'alertes intempestives.
3. **Réalisme** : Délais aléatoires (*jitter*), comptes utilisateurs du domaine et navigation HTTP fluide.

---

## 🏗️ Structure du Dossier `traffic/`

```
traffic/
├── config.py         # Paramètres centralisés (IPs, comptes, endpoints, délais)
├── sim_web.py        # Simulation de navigation et formulaires ERP Dolibarr
├── sim_samba.py      # Simulation de création/lecture de fichiers sains sur partages SMB
├── sim_auth.py       # Simulation de requêtes réseau et sessions d'administration SSH
├── orchestrator.py   # Script maître d'orchestration multithreadé
└── README.md         # Documentation d'utilisation
```

---

## 🚀 Utilisation

### Prérequis
- Python 3.10+
- Aucune dépendance externe complexe nécessaire (utilise la bibliothèque standard Python).

### 1. Démarrer tout le bruit de fond (Web + Samba + Auth)

```bash
python3 traffic/orchestrator.py
```

### 2. Démarrer un module spécifique uniquement

```bash
# Tester seulement la simulation Web (Dolibarr)
python3 traffic/orchestrator.py --mode web

# Tester seulement la simulation des partages Samba
python3 traffic/orchestrator.py --mode samba

# Tester seulement l'activité réseau / SSH
python3 traffic/orchestrator.py --mode auth
```

### 3. Exécution directe des modules autonomes

Chaque module peut aussi être exécuté individuellement :

```bash
python3 traffic/sim_web.py
python3 traffic/sim_samba.py
python3 traffic/sim_auth.py
```

### 4. Arrêt propre

Appuyez simplement sur `Ctrl+C` dans le terminal. L'orchestrateur ferme tous les threads proprement.

---

## ⚙️ Personnalisation (`config.py`)

Vous pouvez ajuster les paramètres suivants dans `traffic/config.py` ou via variables d'environnement :

- `NYX_SERVER_IP` : IP du serveur cible (par défaut `10.0.1.20`).
- `JITTER_WEB` : Plage de temps d'attente (en secondes) entre chaque requête Web (par défaut 5-15s).
- `JITTER_SAMBA` : Plage de temps d'attente (en secondes) entre chaque action fichier (par défaut 10-30s).
- `USERS` : Liste des comptes employés simulés.
