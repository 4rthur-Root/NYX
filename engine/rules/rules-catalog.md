# Catalogue des règles de détection — NyxSOC

**Référence schéma** : `docs/rule-schema.json`  
**Règles stockées dans** : `engine/rules/*.yaml`  
**Version** : 1.0.0  
**Auteur** : Adrien

---

## 1. Philosophie de création des règles

### 1.1 Principe fondamental — une règle détecte un comportement, pas une technique

C'est la distinction la plus importante. Une règle NYX ne dit pas
"détecte Hydra" ou "détecte nmap". Elle dit "détecte un comportement
de brute-force" — c'est-à-dire un volume anormal de tentatives échouées
depuis une même source dans un temps donné. Que l'outil utilisé soit
Hydra, Medusa, ou un script maison, le comportement est identique et
une seule règle le couvre.

**Conséquence directe** : deux attaques qui partagent le même comportement
observable dans les logs ne justifient pas deux règles distinctes.

---

### 1.2 Quand créer une nouvelle règle

Crée une nouvelle règle uniquement si **au moins un** de ces critères est vrai :

**Critère 1 — Source différente**
Le même comportement sur un protocole ou service différent génère des
event_types différents — qui ne peuvent pas être regroupés dans une seule
règle sans modifier le schéma. Un brute-force SSH (`ssh_failure`) et un
brute-force web (`http_request`) sont deux règles distinctes parce que
les parsers produisent des event_types différents.

**Critère 2 — Chaîne causale différente**
La séquence des événements est fondamentalement différente. Un brute-force
SSH pur (S1) et une chaîne scan→brute-force→exfiltration (S2) ne peuvent
pas être exprimés dans la même règle parce que la structure de corrélation
est différente (Type 1 vs Type 3).

**Critère 3 — Seuil incommensurable**
Deux variantes du même comportement ont des seuils si différents qu'une
règle commune produirait soit trop de faux positifs, soit trop de faux
négatifs. Dans ce cas, deux règles du même type avec des paramètres
différents sont préférables à une règle unique avec un seuil de compromis.

**Critère 4 — Contexte métier distinct**
Le même comportement technique a des implications métier différentes selon
la cible. Un brute-force sur Dolibarr (ERP, données financières) peut
mériter une sévérité CRITICAL là où un brute-force SSH mérite WARNING
en première détection. La sévérité différente justifie une règle séparée.

---

### 1.3 Quand NE PAS créer une nouvelle règle

**Même event_type, outil différent** : Hydra vs Medusa vs script custom
sur SSH → même `ssh_failure` → même règle `SSH_BRUTEFORCE_001`.

**Même comportement, utilisateur cible différent** : brute-force sur
`root` vs brute-force sur `admin` → même event_type, même comptage →
même règle. Le champ `actor_user` dans l'alerte documente qui était ciblé.

**Variante plus lente de la même attaque** : un attaquant qui fait
5 tentatives par minute au lieu de 50 par minute fait du "slow brute-force".
La réponse correcte est d'ajuster le paramètre `threshold` et
`window_seconds` de la règle existante, pas de créer une nouvelle règle.
Si le lab valide que le seuil actuel rate les attaques lentes, on crée
`SSH_BRUTEFORCE_002` avec une fenêtre plus large — documenté avec
justification dans ce catalogue.

---

### 1.4 Calibration des seuils — contexte lab vs production

Les seuils définis dans ce catalogue sont **calibrés pour un environnement
de laboratoire** avec un trafic légitime minimal (1-2 connexions par heure).
En production, une PME avec 20 employés peut générer 50 échecs SSH
légitimes par jour (mauvais mot de passe, clé expirée). Les seuils
devraient être revus à la hausse. Cette limite est documentée comme
hypothèse de lab dans `engine.md` (H-E5).

---

### 1.5 Sévérité — règle de décision

| Sévérité | Condition |
|---|---|
| `WARNING` | Pattern suspect détecté, mais la chaîne d'attaque n'est pas confirmée. Le contexte pourrait être légitime. Aucune action SOAR automatique. |
| `CRITICAL` | Chaîne d'attaque complète confirmée, ou comportement dont le taux de faux positifs est proche de zéro dans le contexte lab. Déclenche l'évaluation du playbook SOAR. |

**Règle pratique** : si un administrateur système légitime peut déclencher
cette règle dans le cadre de son travail normal → `WARNING`. Si seul un
attaquant peut déclencher cette séquence dans ce lab → `CRITICAL`.

---

## 2. Types de règles

### Type 1 — Seuil simple

Détecte un volume anormal d'un seul event_type depuis une même source
dans une fenêtre temporelle. Utiliser quand le comportement malveillant
se distingue du comportement légitime uniquement par sa **fréquence**.

Champs requis : `trigger.event_type`, `trigger.threshold`,
`trigger.window_seconds`, `trigger.group_by`.

### Type 2 — Étapes séquentielles

Détecte une kill-chain où les étapes doivent se produire dans un **ordre
précis**. L'étape N doit précéder l'étape N+1. Utiliser quand la causalité
est directionnelle — un fichier doit être créé avant d'être exécuté.

Champs requis : `steps[]` avec au minimum 2 étapes numérotées.

### Type 3 — Cooccurrence multi-sources

Détecte la **présence simultanée** de plusieurs event_types dans une
fenêtre, sans ordre imposé. Utiliser quand plusieurs signaux faibles
provenant de sources différentes constituent ensemble une attaque, mais
que l'ordre d'arrivée peut varier selon les délais réseau et de logging.

Champs requis : `condition.event_types` (≥2), `condition.window_seconds`,
`condition.group_by`.

---

## 3. Catalogue des règles actives

### SSH_BRUTEFORCE_001

| Champ | Valeur |
|---|---|
| **Fichier** | `engine/rules/ssh_bruteforce.yaml` |
| **Type** | 1 — seuil simple |
| **Sévérité** | CRITICAL |
| **MITRE Tactic** | TA0006 — Credential Access |
| **MITRE Technique** | T1110 — Brute Force |
| **Scénario** | S1 |

**Ce que la règle détecte** : un volume anormal d'échecs d'authentification
SSH depuis la même IP dans une fenêtre de 60 secondes. Seuil fixé à 10
tentatives — en dessous, un utilisateur légitime qui oublie son mot de
passe peut déclencher 3-5 erreurs ; au-dessus de 10 en 60 secondes,
c'est un outil automatisé.

**Pourquoi CRITICAL et non WARNING** : dans ce lab, aucun trafic SSH
légitime ne provient de `10.0.1.50` (Kali). Toute tentative SSH depuis
cette IP est par définition suspecte. Le seuil de 10 est une tolérance
minimale pour éviter les faux positifs sur les 2-3 premiers paquets
de retransmission TCP, pas une concession au trafic légitime.

**Pourquoi une seule règle couvre Hydra, Medusa, et tout script custom** :
tous ces outils génèrent des entrées `Failed password` dans `/var/log/auth.log`
via PAM. Le parser produit `event_type: ssh_failure`. La règle évalue
le comptage de cet event_type — l'outil utilisé n'est pas observable
dans les logs et n'entre pas dans la détection.

```yaml
rule_id: SSH_BRUTEFORCE_001
type: 1
description: >
  Brute-force SSH détecté — volume anormal d'échecs d'authentification
  depuis une même IP sur 60 secondes. Couvre tous les outils de brute-force
  (Hydra, Medusa, scripts custom) car le comportement observable est identique.
severity: CRITICAL
mitre_tactic: "TA0006"
mitre_technique: "T1110"
source_host_pattern: "debian*"

trigger:
  event_type: ssh_failure
  threshold: 10
  window_seconds: 60
  group_by: actor_ip

response:
  alert: true
```

---

### SMB_EXFIL_001

| Champ | Valeur |
|---|---|
| **Fichier** | `engine/rules/smb_exfil.yaml` |
| **Type** | 3 — cooccurrence multi-sources |
| **Sévérité** | CRITICAL |
| **MITRE Tactic** | TA0010 — Exfiltration |
| **MITRE Technique** | T1021.002 — Remote Services: SMB/Windows Admin Shares |
| **Scénario** | S2 |

**Ce que la règle détecte** : la cooccurrence d'un scan réseau
(OPNsense filterlog) et d'un accès à un partage Samba (Debian daemon)
depuis la même IP dans une fenêtre de 5 minutes. La combinaison scan +
accès SMB depuis la même source constitue la signature de la chaîne
reconnaissance → exploitation.

**Pourquoi Type 3 et non Type 2** : le scan OPNsense et les logs Samba
arrivent de deux sources différentes avec des délais de transmission
variables. Le scan peut apparaître dans les logs après les premières
tentatives SMB si rsyslog bufférise différemment. Type 3 accepte
la cooccurrence sans ordre imposé — plus robuste aux désordres temporels
inter-sources.

**Pourquoi une seule règle couvre CrackMapExec et smbclient** : les deux
outils génèrent des connexions SMB qui apparaissent dans les logs Samba
comme `daemon` facility. Le parser produit `smb_failure` ou `samba_read`.
La règle corrèle ces event_types avec `net_scan` — l'outil utilisé
n'est pas discriminant.

**Pourquoi 5 minutes et non 60 secondes** : contrairement au brute-force
SSH qui se produit en rafale, la chaîne scan → accès SMB peut inclure
un délai humain (l'attaquant analyse les résultats du scan avant d'agir).
5 minutes est un compromis entre sensibilité et précision dans ce lab.

```yaml
rule_id: SMB_EXFIL_001
type: 3
description: >
  Exfiltration SMB détectée — cooccurrence d'un scan réseau et d'un accès
  à un partage Samba depuis la même IP dans une fenêtre de 5 minutes.
  Couvre CrackMapExec, smbclient et tout client SMB car le comportement
  observable (scan + accès partage) est identique.
severity: CRITICAL
mitre_tactic: "TA0010"
mitre_technique: "T1021.002"
source_host_pattern: "*"

condition:
  event_types:
    - net_scan
    - samba_read
  window_seconds: 300
  group_by: actor_ip
  min_count_per_type: 1

response:
  alert: true
```

---

### MALICIOUS_FILE_EXEC_001

| Champ | Valeur |
|---|---|
| **Fichier** | `engine/rules/malicious_file.yaml` |
| **Type** | 2 — étapes séquentielles |
| **Sévérité** | CRITICAL |
| **MITRE Tactic** | TA0002 — Execution |
| **MITRE Technique** | T1204.002 — User Execution: Malicious File |
| **Scénario** | S3 — BEC kill-chain |

**Ce que la règle détecte** : la séquence ordonnée — dépôt d'un fichier
sur un partage Samba suivi de la création du même fichier sur Windows
(Sysmon EventID 11) puis de son exécution (Sysmon EventID 1) par le même
utilisateur dans une fenêtre de 4 heures. YARA enrichit l'alerte si le
fichier est accessible au moment du scan.

**Pourquoi Type 2 et non Type 3** : la causalité est directionnelle et
obligatoire. Un fichier ne peut pas être exécuté avant d'avoir été créé.
L'ordre step 1 → step 2 → step 3 est une contrainte métier, pas une
simplification. Type 2 enforces cet ordre — Type 3 ne le ferait pas.

**Pourquoi fenêtre de 4 heures** : un employé peut recevoir un mail de
phishing le matin, télécharger la pièce jointe, et ne l'ouvrir qu'après
sa pause déjeuner. Une fenêtre de 60 secondes ou 5 minutes raterait
complètement ce scénario réaliste documenté par INTERPOL 2025 pour le
vecteur BEC en Afrique de l'Ouest.

**Pourquoi `yara_match_required: false`** : l'alerte doit être générée
même si YARA ne peut pas scanner le fichier (supprimé entre le dépôt
et le scan, partage non monté sur le SOC au moment du scan). La séquence
comportementale est suffisante pour justifier l'alerte — YARA enrichit,
il ne conditionne pas.

**Pourquoi `match_on: actor_user`** : on s'assure que c'est le même
utilisateur Windows qui a créé et exécuté le fichier. Sans ce filtre,
la règle pourrait corréler le dépôt par `dir1` avec l'exécution par
`tech1` — deux événements non liés.

```yaml
rule_id: MALICIOUS_FILE_EXEC_001
type: 2
description: >
  Kill-chain BEC détectée — dépôt d'un fichier sur partage Samba suivi
  de sa création et exécution sur le poste Windows par le même utilisateur
  dans une fenêtre de 4 heures. Enrichi par YARA si le fichier est accessible.
severity: CRITICAL
mitre_tactic: "TA0002"
mitre_technique: "T1204.002"
source_host_pattern: "*"

steps:
  - step: 1
    event_type: samba_read
    source_host_pattern: "debian*"

  - step: 2
    event_type: file_create
    source_host_pattern: "DESKTOP*"
    window_seconds: 14400
    match_on: actor_user
    check_yara: true
    yara_match_required: false

  - step: 3
    event_type: process_exec
    source_host_pattern: "DESKTOP*"
    window_seconds: 14400
    match_on: actor_user

response:
  alert: true
```

---

### WEB_BRUTEFORCE_001

| Champ | Valeur |
|---|---|
| **Fichier** | `engine/rules/web_bruteforce.yaml` |
| **Type** | 1 — seuil simple |
| **Sévérité** | WARNING |
| **MITRE Tactic** | TA0006 — Credential Access |
| **MITRE Technique** | T1110.001 — Brute Force: Password Guessing |
| **Scénario** | S4 — Dolibarr |

**Ce que la règle détecte** : un volume anormal de requêtes HTTP en échec
(codes 401 et 403) vers Dolibarr depuis la même IP dans une fenêtre de
2 minutes. Ces codes indiquent des tentatives d'authentification échouées
sur l'interface web de l'ERP.

**Pourquoi WARNING et non CRITICAL** : contrairement au brute-force SSH,
un brute-force web peut être déclenché par un scanner de vulnérabilités
légitime, un outil de test de performance, ou un navigateur qui rejoue
des credentials expirés. La sévérité WARNING indique que le pattern est
suspect mais qu'une investigation humaine est nécessaire avant action.
Le SOAR loggue sans bloquer automatiquement.

**Pourquoi une règle séparée de SSH_BRUTEFORCE_001** : le brute-force
SSH génère `event_type: ssh_failure` depuis le parser syslog. Le brute-force
web génère `event_type: http_request` depuis le parser Apache. Ce sont
deux event_types distincts — une seule règle ne peut pas couvrir les deux
sans modifier la taxonomie. La séparation est imposée par l'architecture
des parsers, pas par un choix arbitraire.

**Pourquoi seuil 20 et fenêtre 120 secondes** : Apache loggue toutes les
requêtes, y compris les assets statiques (CSS, JS, images) qui peuvent
retourner 404. Une navigation légitime sur Dolibarr peut générer 10-15
requêtes par minute. Le seuil de 20 requêtes en erreur en 2 minutes est
calibré pour ne pas déclencher sur une navigation légitime maladroite.

```yaml
rule_id: WEB_BRUTEFORCE_001
type: 1
description: >
  Brute-force interface web Dolibarr détecté — volume anormal de requêtes
  HTTP en échec (401/403) depuis la même IP en 2 minutes. Sévérité WARNING
  car le taux de faux positifs est plus élevé que sur SSH (scanners légitimes,
  credentials expirés en cache navigateur).
severity: WARNING
mitre_tactic: "TA0006"
mitre_technique: "T1110.001"
source_host_pattern: "debian*"

trigger:
  event_type: http_request
  threshold: 20
  window_seconds: 120
  group_by: actor_ip
  filter:
    http_status: [401, 403]

response:
  alert: true
```

---

## 4. Matrice de couverture

| Vecteur d'attaque | Règle | Type | Scénario | Couvert |
|---|---|---|---|---|
| Brute-force SSH (tout outil) | SSH_BRUTEFORCE_001 | 1 | S1 | ✓ |
| Scan réseau + accès SMB | SMB_EXFIL_001 | 3 | S2 | ✓ |
| Dépôt payload + exécution Windows | MALICIOUS_FILE_EXEC_001 | 2 | S3 | ✓ |
| Brute-force ERP web | WEB_BRUTEFORCE_001 | 1 | S4 | ✓ |
| Slow brute-force SSH (< 10/min) | — | — | — | ✗ Limite documentée |
| Pivoting inter-IP | — | — | — | ✗ Limite documentée |
| Exfiltration DNS | — | — | — | ✗ Hors scope |
| Ransomware (chiffrement massif) | — | — | — | ✗ Hors scope |

---

## 5. Procédure d'ajout d'une nouvelle règle

Avant de créer une nouvelle règle, répondre à ces quatre questions :

**Q1** : Est-ce que l'event_type produit par le parser est déjà couvert
par une règle existante ? Si oui, ajuster les paramètres de la règle
existante plutôt que d'en créer une nouvelle.

**Q2** : Est-ce que la chaîne causale est fondamentalement différente
des règles existantes ? Si non (même comportement, outil différent),
ne pas créer.

**Q3** : Est-ce que le nouveau pattern est lié à l'un des scénarios
documentés (S1-S4) ou à une extension justifiée ? Si ni l'un ni l'autre,
discuter avec le superviseur avant de créer.

**Q4** : Valider le fichier YAML contre `docs/rule-schema.json` avant
de le commiter :

```bash
# Validation via Python
python3 -c "
import yaml, json, jsonschema
with open('docs/rule-schema.json') as f:
    schema = json.load(f)
with open('engine/rules/nouvelle_regle.yaml') as f:
    rule = yaml.safe_load(f)
jsonschema.validate(rule, schema)
print('Règle valide.')
"
```

Ajouter la nouvelle règle à ce catalogue avec la même structure de
justification que les règles existantes — pourquoi cette règle, pourquoi
ce type, pourquoi ce seuil, pourquoi cette sévérité.
