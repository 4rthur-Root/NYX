# Agent Context & Workspace Analysis — NyxSOC

Ce document centralise le contexte de travail, l'analyse de l'architecture du projet NYX, la logique de détection et la feuille de route d'implémentation. Il sert de référence pour l'Agent d'IA et le superviseur dans le cadre du développement du SIEM/Moteur de corrélation de NyxSOC.

---

## 1. Vision du Projet et Objectifs

**NYX** est avant tout un projet axé sur la **Corrélation d'événements de sécurité et la réponse automatisée (SOAR)**. L'objectif principal est de construire de zéro un moteur de corrélation stateful (`soc-engine`) capable de détecter des attaques complexes en analysant des logs multi-sources. 

*Note: L'Infrastructure as Code (IaC) présente dans le projet n'est pas le cœur du sujet, mais sert d'outil pour rendre le laboratoire de test reproductible, fiable et facile à déployer.*

### Objectifs Clés :
1. **Moteur de corrélation stateful multi-sources (`soc-engine`)** : (Le Cœur du Projet). Analyser les logs en temps réel, normaliser les événements, évaluer des règles complexes (seuils et séquences temporelles), lancer des scans antivirus via YARA et générer des alertes structurées.
2. **Intégration SOAR** : Transmettre les alertes critiques à un module de réponse automatisée.
3. **Émulation d'infrastructure reproductible (IaC)** : Déployer automatiquement les cibles et les sources de logs (OPNsense, Debian, Windows) via libvirt/KVM et Ansible pour fournir des données au moteur.
4. **Collecte centralisée** : Acheminer les logs applicatifs et système vers le moteur via rsyslog et NXLog.

---

## 2. Structure et Organisation du Projet

Le dépôt est divisé en trois sections principales :

### A. Infrastructure (`infrastructure/`)
Gère l'automatisation du laboratoire avec libvirt/KVM, virt-install et Ansible.
*   `Makefile` : Orchestre 4 VMs sur un réseau isolé nommé `nyx` (10.0.1.0/24) :
    *   `opnsense` (10.0.1.1) : Firewall et routeur de l'infra.
    *   `soc` (10.0.1.10) : Machine centrale du SOC (reçoit les logs, exécute le moteur).
    *   `debian-server` (10.0.1.20) : Serveur interne hébergeant Samba AD et l'ERP Dolibarr.
    *   `windows10` (10.0.1.30) : Client Windows supervisé avec Sysmon et NXLog.
*   `SOC/`, `Server/`, `Opnsense/`, `Windows/` : Scripts de création, provisionnement et vérification des VMs.
*   `Preparation/` : Scripts d'installation des outils hôtes, création du réseau, ISO.

### B. Moteur de Détection (`engine/`)
Moteur Python 3.13 autonome s'exécutant sur la VM `soc` pour la corrélation d'événements.
*   `main.py` : Point d'entrée. Initialise les threads de lecture, traitement, purge de base SQLite et gestion des signaux d'arrêt (`SIGTERM`).
*   `reader.py` : Surveille le répertoire `/var/log/remote/` via la bibliothèque `watchdog` (inotify) et insère les nouvelles lignes dans une file d'attente (Queue) thread-safe de taille 10 000 max.
*   `dispatcher.py` : Dépile les logs bruts, détermine le parser approprié en fonction du nom du fichier de log (défini dans `config.yaml`), valide le format normalisé via `jsonschema` et l'envoie au gestionnaire d'état.
*   `parsers/` : Contient quatre scripts de parsing :
    *   `base_parser.py` : ABC avec `parse_timestamp()` (RFC 5424, RFC 3164, NXLog).
    *   `syslog_parser.py` : Parse les logs syslog Linux (SSH, Samba smbd, audit JSON Samba).
    *   `filterlog_parser.py` : Parse les logs au format CSV du pare-feu OPNsense (bloquages réseau, scans, connexions).
    *   `windows_parser.py` : Extrait et parse l'enveloppe syslog de NXLog puis le XML interne de Sysmon/Windows EventLog.
    *   `web_parser.py` : Parse les logs web Dolibarr (Apache Combined Log Format) depuis `localhost.log`.
*   `state_manager.py` : Interagit avec une base SQLite locale (`engine.db`) configurée en mode WAL (Write-Ahead Logging) pour assurer des lectures/écritures simultanées rapides. Tables clés : `events` (rétention de 24 heures) et `contexts` (suivi des étapes de règles multi-step).
*   `rule_engine.py` : Évalue les événements par rapport aux règles YAML chargées. Gère les règles de seuil simple (Type 1), séquentielles (Type 2), co-occurrence (Type 3) et YARA directe (Type 4).
*   `yara_scanner.py` : Effectue des scans YARA sur les fichiers créés (détectés via samba_write) à l'aide de signatures locales.
*   `alerter.py` : Loggue les alertes de sévérité `WARNING` et `CRITICAL` dans `alerts.log` / `alert_[UUID].json` avec écriture atomique.
*   `validator.py` : Valide les événements normalisés contre un schéma jsonschema inline et une taxonomie fermée de 14 types d'événements.
*   `config.yaml` : Configuration des sources, chemins, rétention, queue et mounts Samba.
*   `rules/` : Règles de détection YAML (`attack/`) et signatures YARA (`yara/`).
*   `tests/` : Tests unitaires et d'intégration (121 tests, tous passants).

### C. Documentation (`docs/`)
Fichiers d'architecture, rapports, schémas de données et ressources.
*   `alert-schema.json` : Schéma de validation JSON strict pour la structure des alertes envoyées au SOAR.
*   `rule-schema.json` : Schéma de validation des règles YAML.
*   `drawio/` et `Tex/` : Fichiers sources des topologies et documentations du projet.

---

## 3. Schéma et Contrats de Données Clés

### A. Événement Normalisé (Entrée du StateManager)
Tous les parsers doivent retourner ce format JSON unifié :
```json
{
  "timestamp": 1719234567000,
  "source_host": "localhost",
  "event_type": "http_request",
  "actor_ip": "10.0.1.1",
  "actor_user": null,
  "target_host": null,
  "target_port": 80,
  "extra": {
    "http_method": "GET",
    "http_path": "/admin/modules.php",
    "http_status": 302,
    "user_agent": "Mozilla/5.0 ...",
    "referer": "http://10.0.1.20/",
    "response_size": 390,
    "pid": "794"
  },
  "yara_match": null,
  "raw_log": "2026-07-02T16:39:30+00:00 localhost dolibarr[794]: ..."
}
```

### B. Taxonomie des Événements (`event_type`) — 14 types fermés
*   `ssh_failure` / `logon_success` / `logon_failure`
*   `samba_read` / `samba_write` / `smb_failure`
*   `http_request` (Dolibarr/Apache Combined Log)
*   `net_scan` / `firewall_block` / `net_connect`
*   `file_create` (Sysmon 11) / `process_exec` (Sysmon 1) / `net_connect` (Sysmon 3)
*   `tgt_request` (Samba 4768) / `tgs_request` (Samba 4769)

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

## 4. État Actuel de l'Implémentation (Juillet 2026)

Le moteur de détection est **entièrement implémenté et testé**.

### Modules complétés
| Module | Lignes | Statut | Notes |
|---|---|---|---|
| `main.py` | 285 | ✅ | Orchestration, 3 threads, signaux SIGTERM/SIGINT |
| `config.yaml` | 44 | ✅ | 4 sources actives, rétention 24h, queue 10k |
| `state_manager.py` | 318 | ✅ | SQLite WAL + threading.Lock, purge horaire |
| `rule_engine.py` | 448 | ✅ | 4 types de règles, validation jsonschema |
| `dispatcher.py` | 173 | ✅ | Pipeline complet route→parse→validate→YARA→store→evaluate→alert |
| `reader.py` | 175 | ✅ | Watchdog inotify, position-tracking, catch-up initial |
| `alerter.py` | 204 | ✅ | WARNING/CRITICAL, atomic JSON, truncation events |
| `validator.py` | 69 | ✅ | jsonschema + taxonomie fermée (14 types) |
| `yara_scanner.py` | 104 | ✅ | Compilation unique, scan timeout 30s, hash MD5 |
| `parsers/base_parser.py` | 71 | ✅ | ABC, parse_timestamp RFC 5424/3164/NXLog |
| `parsers/syslog_parser.py` | ~320 | ✅ | sshd, smbd, samba-audit JSON (4768/4769), nmbd ignoré |
| `parsers/filterlog_parser.py` | 220 | ✅ | OPNsense BSD CSV, IPv4/IPv6, classification block/pass |
| `parsers/windows_parser.py` | 339 | ✅ | NXLog XML, EventIDs 4624/4625/1/3/11 |
| `parsers/web_parser.py` | ~180 | ✅ | Dolibarr/Apache Combined Log → `http_request` |

### Tests
*   **121 tests passants** (54 parser + 35 autres + 32 web_parser)
*   Couverture : unitaire parsers, validator, state_manager, rule_engine, dispatcher, yara_scanner, intégration complète
*   `tests/fixtures/` : logs synthétiques pour chaque source

### Infrastructure
*   Pas Vagrant — libvirt/KVM direct via `virt-install`
*   `infrastructure/Makefile` fonctionnel (175 lignes, 15+ targets)
*   Réseau isolé `nyx` (10.0.1.0/24)
*   4 VMs : OPNsense, SOC, Debian Server (Samba AD + Dolibarr), Windows 10

### Docker / CI
*   `Dockerfile` : Python 3.13-slim, dépendances complètes, bash par défaut
*   `Makefile` : Workflow Docker-first — tous les tests/lint/typecheck s'exécutent dans le conteneur
*   Commandes : `make docker-test`, `make docker-test-unit`, `make docker-lint`, `make docker-typecheck`

---

## 5. Feuille de Route

### ✅ Complété
*   Configuration et initialisation du projet
*   Couche de persistance SQLite (WAL, lock-thread, purge horaire)
*   Parsers : syslog (SSH/Samba/Kerberos), filterlog (OPNsense), Windows (NXLog/EventLog), web (Dolibarr Combined Log)
*   Dispatcher et Reader (watchdog inotify)
*   Moteur de règles 4 types avec chargement YAML dynamique
*   Modules YARA et Alerter (atomic JSON)
*   Tests unitaires et d'intégration (121 passants)
*   Makefile Docker-first (test, lint, typecheck, shell)
*   Dockerfile pour environnement de test Python 3.13 reproductible

### 🔄 En cours / À venir
*   Intégration SOAR HTTP (actuellement sortie fichier uniquement)
*   CI/CD GitHub Actions (mypy --strict, flake8, pytest)
*   Documentation utilisateur et guide de déploiement

---

## 6. Lignes Directrices et Conseils d'Encadrement

1.  **Robustesse face aux données imprévues** : Les parsers sont extrêmement défensifs (try/except, retours None propres, logging des anomalies).
2.  **Gestion de la concurrence** : Threading.Lock sur écritures SQLite uniquement ; WAL permet les lectures concurrentes.
3.  **Auditabilité et Traçabilité** : Chaque rejet d'événement ou alerte est loggé avec détails.
4.  **Simplicité & Efficacité** : SQLite WAL suffisant pour le volume. Index sur `timestamp`, `event_type`, `actor_ip` pour évaluations < 1ms.
5.  **Dépendances explicites** : Tous les imports sont explicites, pas de imports relatifs non résolus.
6.  **Workflow Docker-first** : Le Makefile exécute tests, lint et typecheck exclusivement dans le conteneur Docker pour garantir la reproductibilité.
7.  **Élimination du code mort** : Aucun parser orphelin, tous les event_types sont produits par au moins un parser actif.

---

*Dernière mise à jour : Juillet 2026*
