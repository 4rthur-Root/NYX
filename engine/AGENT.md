# Agent Context & Workspace Analysis — NyxSOC

Ce document centralise le contexte de travail, l'analyse de l'architecture du projet NYX, la logique de détection et la feuille de route d'implémentation. Il sert de référence pour l'Agent d'IA et le superviseur dans le cadre du développement du SIEM/Moteur de corrélation de NyxSOC.

---

## 1. Vision du Projet et Objectifs

**NYX** est avant tout un projet axé sur la **Corrélation d'événements de sécurité et la réponse automatisée (SOAR)**. L'objectif principal est de construire de zéro un moteur de corrélation stateful (`soc-engine`) capable de détecter des attaques complexes en analysant des logs multi-sources. 

*Note: L'Infrastructure as Code (IaC) présente dans le projet n'est pas le cœur du sujet, mais sert d'outil pour rendre le laboratoire de test reproductible, fiable et facile à déployer.*

### Objectifs Clés :
1. **Moteur de corrélation stateful multi-sources (`soc-engine`)** : (Le Cœur du Projet). Analyser les logs en temps réel, normaliser les événements, évaluer des règles complexes (seuils et séquences temporelles), lancer des scans antivirus via YARA et générer des alertes structurées.
2. **Intégration SOAR** : Transmettre les alertes critiques à un module de réponse automatisée.
3. **Émulation d'infrastructure reproductible (IaC)** : Déployer automatiquement les cibles et les sources de logs (OPNsense, Debian, Windows) via Vagrant et Ansible pour fournir des données au moteur.
4. **Collecte centralisée** : Acheminer les logs applicatifs et système vers le moteur via rsyslog et NXLog.

---

## 2. Structure et Organisation du Projet

Le dépôt est divisé en trois sections principales :

### A. Infrastructure (`infrastructure/`)
Gère l'automatisation du laboratoire avec Vagrant, Packer et Ansible.
*   `Vagrantfile` : Orchestre 4 VMs sur un réseau privé isolé nommé `nyx` (10.0.1.0/24) :
    *   `opnsense` (10.0.1.1) : Firewall et routeur de l'infra.
    *   `soc` (10.0.1.10) : Machine centrale du SOC (reçoit les logs, exécute le moteur).
    *   `debian-server` (10.0.1.20) : Serveur interne hébergeant Samba AD et l'ERP Dolibarr.
    *   `windows10` (10.0.1.30) : Client Windows supervisé avec Sysmon et NXLog.
*   `ansible/` : Playbooks et rôles de provisionnement :
    *   `roles/common` : Configuration de base (temps NTP via chrony, interfaces réseau).
    *   `roles/opnsense` : Mise à jour et vérification des règles de filtrage.
    *   `roles/debian_server` : Installation de Samba AD, Apache, MariaDB et PHP pour Dolibarr.
    *   `roles/soc` : Installation de `rsyslog` configuré pour écouter sur le port 514, création de `/var/log/remote` et de `/opt/soc-engine`.
    *   `roles/windows` : Installation de NXLog et Sysmon avec des règles de redirection vers le SOC.
*   `packer/` : Fichiers de configuration pour créer la golden image Debian 12 initiale.
*   `scripts_shell/` : Utilitaires pour automatiser l'installation des outils hôtes, la création du réseau Libvirt et l'installation des VMs.
*   `ISSUES.md` : Document de suivi des problèmes techniques rencontrés (erreurs DHCP Vagrant, plugins compilés, variables d'environnement libvirt).

### B. Moteur de Détection (`engine/`)
Moteur Python 3.12 autonome s'exécutant sur la VM `soc` pour la corrélation d'événements.
*   `main.py` : Point d'entrée. Initialise les threads de lecture, traitement, purge de base SQLite et gestion des signaux d'arrêt (`SIGTERM`).
*   `reader.py` : Surveille le répertoire `/var/log/remote/` via la bibliothèque `watchdog` (inotify) et insère les nouvelles lignes dans une file d'attente (Queue) thread-safe de taille 10 000 max.
*   `dispatcher.py` : Dépile les logs bruts, détermine le parser approprié en fonction du nom du fichier de log (défini dans `config.yaml`), valide le format normalisé via `jsonschema` et l'envoie au gestionnaire d'état.
*   `parsers/` : Contient trois scripts de parsing :
    *   `syslog_parser.py` : Parse les logs syslog Linux (SSH, Samba, requêtes HTTP Apache).
    *   `filterlog_parser.py` : Parse les logs au format CSV du pare-feu OPNsense (bloquages réseau, scans).
    *   `windows_parser.py` : Extrait et parse l'enveloppe syslog de NXLog puis le XML interne de Sysmon/Windows EventLog.
*   `state_manager.py` : Interagit avec une base SQLite locale (`engine.db`) configurée en mode WAL (Write-Ahead Logging) pour assurer des lectures/écritures simultanées rapides. Tables clés : `events` (rétention de 24 heures) et `contexts` (suivi des étapes de règles multi-step).
*   `rule_engine.py` : Évalue les événements par rapport aux règles YAML chargées. Gère les règles de seuil simple (Type 1) et les règles séquentielles d'attaque (Type 2, machine à états).
*   `yara_scanner.py` : Effectue des scans YARA sur les fichiers créés (détectés via Sysmon/EventID 11) à l'aide de signatures locales.
*   `alerter.py` : Loggue les alertes de sévérité `WARNING` et `CRITICAL` dans `alerts.log` / `alert_[UUID].json` et pousse les alertes `CRITICAL` vers l'API HTTP du SOAR.
*   `rules/` : Règles de détection YAML (`ssh_bruteforce.yaml`, `malicious_file.yaml`, `smb_exfil.yaml`).
*   `tests/` : Emplacement pour les tests unitaires (`tests/unit/`) et d'intégration (`tests/integration/`).

### C. Documentation (`docs/`)
Fichiers d'architecture, rapports, schémas de données et ressources.
*   `alert-schema.json` : Schéma de validation JSON strict pour la structure des alertes envoyées au SOAR.
*   `drawio/` et `Tex/` : Fichiers sources des topologies et documentations du projet.

---

## 3. Schéma et Contrats de Données Clés

### A. Événement Normalisé (Entrée du StateManager)
Tous les parsers doivent retourner ce format JSON unifié :
```json
{
  "timestamp": 1719234567000,
  "source_host": "debian-server",
  "event_type": "ssh_failure",
  "actor_ip": "10.0.1.30",
  "actor_user": "admin",
  "target_host": "debian-server",
  "target_port": 22,
  "extra": {
    "port": 53210,
    "auth_method": "password"
  },
  "raw_log": "Jun 24 14:05:01 debian-server sshd[12345]: Failed password for admin from 10.0.1.30 port 53210 ssh2"
}
```

### B. Taxonomie des Événements (`event_type`)
*   `ssh_failure` / `logon_success` / `logon_failure`
*   `samba_read` / `smb_failure`
*   `http_request`
*   `net_scan` / `firewall_block`
*   `file_create` (Sysmon 11) / `process_exec` (Sysmon 1) / `net_connect` (Sysmon 3)

### C. Alerte Générée (Sortie vers le SOAR)
Conforme au schéma `docs/alert-schema.json` :
*   `alert_id` : UUID unique.
*   `timestamp` : Unix ms de l'alerte.
*   `rule_id` : Règle correspondante.
*   `severity` : `WARNING` ou `CRITICAL`.
*   `attacker_ip` / `target_host` / `target_ip`.
*   `mitre_tactic` (ex: `TA0011`) / `mitre_technique` (ex: `T1048`).
*   `events` : Objet contenant le compte et le détail des événements pivots constituant la preuve (1 à 5 max).
*   `yara_match` : Résultats du scan YARA si applicable, sinon `null`.

---

## 4. Analyse de l'État Actuel de l'Implémentation

À la date du 24 Juin 2026, l'analyse approfondie du code révèle les faits suivants :
1.  **L'infrastructure IaC (Vagrant/Ansible) est structurée et opérationnelle** pour le déploiement. Les fichiers de configuration (rôles Ansible, Vagrantfile) sont complets.
2.  **Le moteur de détection (`engine/`) est à l'état de coquille vide** :
    *   `main.py` contient une simple importation invalide (`import pyYAML` au lieu de `import yaml`).
    *   `reader.py`, `dispatcher.py`, `state_manager.py`, `yara_scanner.py` et les fichiers de `parsers/` font **0 octet**.
    *   `rule_engine.py` et `alerter.py` ne contiennent que de légères esquisses / squelettes de code.
    *   Le dossier de tests `tests/` est totalement vide.
    *   Le fichier `config.yaml` requis par le moteur n'est pas encore présent dans `engine/`.

### 🚨 Risques Techniques & Remarques d'Expertise
*   **Variable non résolue dans NXLog** : Le fichier `nxlog.conf` contient des variables Jinja2 (`{{ nxlog_server }}` et `{{ nxlog_port }}`) mais est copié avec `win_copy` au lieu de `win_template`. Cela entraînera des erreurs de configuration NXLog sur Windows si le serveur Ansible ne résout pas ces variables statiquement.
*   **Importations erronées** : La présence de `import pyYAML` dans `main.py` échouera en Python car le module s'importe en minuscules (`import yaml`).
*   **Performance SQLite & Verrous** : L'accès concurrent entre le thread d'écriture (`Dispatcher`) et les threads d'évaluation de règles / de purge devra être synchronisé proprement avec un `Lock` ou en utilisant le mode WAL de SQLite et une bonne gestion des connexions.

---

## 5. Feuille de Route d'Implémentation du Moteur (`soc-engine`)

Pour réussir l'implémentation robuste de NyxSOC, nous devons suivre les étapes ordonnées suivantes :

### Étape 1 : Fichier de Configuration et Initialisation du Projet
*   Créer `engine/config.yaml` avec les mappings de fichiers de logs (`debian.log` -> `syslog`, etc.), la rétention, la taille de file d'attente et l'endpoint SOAR.
*   Mettre à jour `requirements.txt` avec toutes les dépendances requises (`pyyaml`, `watchdog`, `jsonschema`, `yara-python`, `requests`, `pytest`, `pytest-cov`).

### Étape 2 : Couche de Persistance (`state_manager.py`)
*   Mettre en place la base SQLite `engine.db`.
*   Écrire les fonctions de création de tables (`events` et `contexts`) avec index.
*   Implémenter `store_event()`, `count_events()`, `get_events()`, `get_context()`, `set_context()`, `purge_old_events()` et `expire_contexts()`.
*   Ajouter un verrou thread-safe (`threading.Lock`) pour synchroniser les accès en écriture.

### Étape 3 : Parsers de Logs (`parsers/`)
*   `syslog_parser.py` : Regex compilées pour parser `sshd`, `smbd` et `apache2`. Extraction des champs normalisés.
*   `filterlog_parser.py` : Parsing CSV positionnel robuste pour OPNsense (vérification du nombre de champs selon le protocole TCP/UDP/ICMP).
*   `windows_parser.py` : Parsing de l'enveloppe syslog de NXLog puis extraction XML (`xml.etree.ElementTree`) pour les Event IDs Sysmon (1, 3, 11) et Windows (4625).

### Étape 4 : Le Dispatcher et le Reader
*   `dispatcher.py` : Gestion du routage basé sur `config.yaml`, validation des événements via le schéma JSON d'entrée avant transmission au StateManager.
*   `reader.py` : Implémentation du moniteur de fichiers basé sur `watchdog`. Gestion de la queue thread-safe partagée de 10 000 éléments max.

### Étape 5 : Le Moteur de Règles (`rule_engine.py`)
*   Chargement dynamique des règles YAML au démarrage.
*   **Évaluation Type 1 (Seuil)** : Requête SQLite de comptage (`count_events`) et levée d'alerte si le seuil est dépassé.
*   **Évaluation Type 2 (Séquentiel)** : Gestionnaire d'étapes basé sur la table `contexts`. Vérification de la transition d'état, de la fenêtre temporelle et de la clé de pivotement (`actor_user`, `actor_ip`).

### Étape 6 : Modules Périphériques (`yara_scanner.py` & `alerter.py`)
*   `yara_scanner.py` : Intégration de la bibliothèque `yara-python`. Scan du chemin du fichier créé si demandé. Calcul de hash MD5/SHA256 du fichier scanné.
*   `alerter.py` : Écriture atomique et thread-safe des alertes en local. Publication HTTP POST vers l'endpoint SOAR configuré pour les alertes de niveau `CRITICAL`.

### Étape 7 : Tests Unitaires et d'Intégration
*   Créer les tests unitaires pour chaque parser et pour le gestionnaire de base de données.
*   Créer des jeux de données de test (logs fictifs) dans `tests/fixtures/`.
*   Écrire un test d'intégration complet (`test_engine_full.py`) simulant un flux de logs réels pour déclencher les règles et vérifier la validité des alertes produites.

---

## 6. Lignes Directrices et Conseils d'Encadrement (Mentorat)

1.  **Robustesse face aux données imprévues** : Les logs bruts provenant de serveurs réels peuvent être malformés ou contenir des caractères inattendus. Les parsers doivent être extrêmement défensifs (blocs `try/except` larges, retours `None` propres et journalisation des anomalies).
2.  **Gestion de la concurrence** : Le multi-threading est inhérent à cette architecture (Reader, Dispatcher, Purgeur). L'accès aux structures partagées et à la base de données doit être exempt de conditions de concurrence (race conditions).
3.  **Auditabilité et Traçabilité** : Chaque rejet d'événement (schéma invalide, parser en échec) ou alerte levée doit être enregistré dans les logs de l'application (`engine.log`) avec des détails clairs pour faciliter le débogage.
4.  **Simplicité & Efficacité** : SQLite en mode WAL est parfait ici, mais évitez les transactions trop longues qui bloqueraient les threads d'ingestion. Les index sur la table `events` (notamment sur `timestamp`, `event_type` et `actor_ip`) sont indispensables pour garantir des temps d'évaluation de règles inférieurs à la milliseconde.
