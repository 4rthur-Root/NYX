# Catalogue des règles de détection — NyxSOC

**Référence schéma** : `docs/rule-schema.json`  
**Règles stockées dans** : `engine/rules/*.yaml`  
**Version** : 1.1.0  
**Auteur** : KPODONOU Kossigan Gaël God-Love

---

## 1. Philosophie de création des règles

### 1.1 Principe fondamental — une règle détecte un comportement, pas un outil

Une règle NyxSOC ne dit pas "détecte Hydra" ou "détecte nmap". Elle dit
"détecte un comportement de brute-force" — un volume anormal de tentatives
échouées depuis une même source dans un temps donné. Que l'outil soit Hydra,
Medusa ou un script custom, le comportement observable dans les logs est
identique. Une seule règle couvre tous ces cas.

### 1.2 Quand créer une nouvelle règle

Crée une nouvelle règle uniquement si **au moins un** de ces critères est vrai :

**Critère 1 — event_type différent** : le même comportement sur un service
différent génère un event_type différent — les parsers produisent des types
distincts. Un brute-force SSH (`ssh_failure`) et un brute-force web
(`http_request`) sont deux règles séparées parce que les event_types sont
différents. La séparation est imposée par l'architecture des parsers, pas
par un choix arbitraire.

**Critère 2 — Structure de corrélation différente** : une séquence ordonnée
de plusieurs event_types distincts (Type 2) ne peut pas être exprimée comme
un simple seuil (Type 1). La nature de la corrélation impose le type.

**Critère 3 — Seuil incommensurable** : deux variantes du même comportement
ont des paramètres si différents qu'une règle commune produirait soit trop
de faux positifs soit trop de faux négatifs. Dans ce cas, deux règles du
même type avec des paramètres distincts sont préférables à une règle de
compromis. Documenter les deux dans ce catalogue avec justification.

**Critère 4 — Sévérité distincte justifiée** : le même comportement sur
des cibles différentes peut avoir des implications métier différentes. Un
brute-force sur l'ERP Dolibarr (données financières) mérite WARNING — un
brute-force SSH direct mérite CRITICAL. La sévérité différente justifie
une règle séparée.

### 1.3 Quand NE PAS créer une nouvelle règle

**Même event_type, outil différent** : Hydra vs Medusa sur SSH → même
`ssh_failure` → même règle.

**Même comportement, utilisateur cible différent** : brute-force sur `root`
vs `admin` → même comptage, même règle. Le champ `actor_user` dans l'alerte
documente la cible.

**Variante plus lente du même comportement** : slow brute-force SSH (2/min
au lieu de 50/min). La réponse correcte est d'ajuster `threshold` et
`window_seconds` dans la règle existante, ou de créer `SSH_BRUTEFORCE_002`
avec fenêtre plus large — documenté ici avec justification explicite.

### 1.4 Sévérité — règle de décision

| Sévérité | Condition |
|---|---|
| `WARNING` | Pattern suspect mais taux de faux positifs non négligeable dans le contexte lab. Aucune action SOAR automatique. |
| `CRITICAL` | Comportement dont le taux de faux positifs est proche de zéro dans ce lab, ou chaîne complète confirmée. Déclenche le playbook SOAR. |

**Règle pratique** : si un administrateur légitime peut déclencher cette
règle dans son travail normal → `WARNING`. Si seul un attaquant peut
déclencher cette séquence dans ce lab → `CRITICAL`.

### 1.5 YARA — rôle dans l'architecture

YARA n'est pas une condition dans une règle. C'est une couche d'enrichissement
systématique déclenchée par le **Dispatcher** sur tout événement `samba_write`,
avant même que le RuleEngine évalue les règles. Tout fichier déposé ou modifié
sur n'importe quel partage Samba (montés en read-only sur le SOC via CIFS) est
scanné par YARA, indépendamment de son extension ou de son nom.

Le résultat du scan est stocké dans le champ `yara_match` de l'événement
normalisé. Les règles peuvent utiliser ce champ comme condition
(`condition.yara_match: required`) mais n'ont pas à déclencher YARA
elles-mêmes.

Le Type 4 est une règle autonome qui se déclenche sur `samba_write` + `yara_match`
présent — sans étapes supplémentaires. Cela couvre le cas d'un employé
naïf qui dépose un fichier malveillant sans qu'aucune chaîne d'attaque
préalable ne soit nécessaire.

### 1.6 Calibration des seuils — contexte lab

Les seuils sont calibrés pour un lab avec trafic légitime minimal.
En production avec 20 employés actifs, certains seuils devraient être
revus. Cette limite est documentée dans `engine.md` (H-E5).

---

## 2. Types de règles

| Type | Nom | Structure | Cas d'usage |
|---|---|---|---|
| 1 | Seuil simple | Un event_type, comptage sur fenêtre | Brute-force, flood |
| 2 | Étapes séquentielles | N event_types ordonnés | Kill-chain, BEC |
| 3 | Cooccurrence multi-sources | N event_types sans ordre | Scan + exploitation |
| 4 | Détection YARA directe | samba_write + yara_match | Fichier malveillant direct |

---

## 3. Règles actives

### SSH_BRUTEFORCE_001

| | |
|---|---|
| **Fichier** | `engine/rules/ssh_bruteforce.yaml` |
| **Type** | 1 — seuil simple |
| **Sévérité** | CRITICAL |
| **MITRE** | TA0006 / T1110 |
| **Scénario** | S1 |

**Ce que détecte la règle** : volume anormal d'échecs SSH depuis la même IP
en 60 secondes. Seuil fixé à 10 — en dessous, un utilisateur légitime
oubliant son mot de passe peut générer 3 à 5 erreurs ; au-dessus de 10
en 60 secondes c'est systématiquement un outil automatisé.

**Pourquoi CRITICAL** : dans ce lab, aucun trafic SSH légitime ne provient
de `10.0.1.50`. Toute tentative SSH depuis Kali est par définition suspecte.

**Pourquoi une règle couvre tous les outils** : Hydra, Medusa et tout script
custom produisent des entrées `Failed password` dans PAM/sshd. Le parser
produit `event_type: ssh_failure`. L'outil n'est pas observable.

```yaml
rule_id: SSH_BRUTEFORCE_001
type: 1
description: >
  Brute-force SSH détecté — volume anormal d'échecs d'authentification
  depuis la même IP sur 60 secondes. Couvre tous les outils (Hydra,
  Medusa, scripts custom) car le comportement observable est identique.
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

| | |
|---|---|
| **Fichier** | `engine/rules/smb_exfil.yaml` |
| **Type** | 3 — cooccurrence multi-sources |
| **Sévérité** | CRITICAL |
| **MITRE** | TA0010 / T1021.002 |
| **Scénario** | S2 |

**Ce que détecte la règle** : cooccurrence d'un scan réseau (OPNsense) et
d'un accès Samba (Debian Server) depuis la même IP en 5 minutes. La
combinaison reconnaissance + accès SMB depuis la même source constitue la
signature de la chaîne scan → exploitation.

**Pourquoi Type 3 et non Type 2** : le scan OPNsense et les logs Samba
arrivent de deux sources avec des délais de transmission variables. Le scan
peut apparaître dans les logs après les premières tentatives SMB si rsyslog
bufférise différemment. Type 3 accepte la cooccurrence sans ordre imposé —
plus robuste aux désordres temporels inter-sources.

**Pourquoi 5 minutes** : la chaîne scan → brute-force SMB → exfiltration
peut inclure un délai humain (analyse des résultats nmap avant d'agir).
60 secondes raterait les attaques manuelles.

```yaml
rule_id: SMB_EXFIL_001
type: 3
description: >
  Exfiltration SMB — cooccurrence d'un scan réseau et d'un accès Samba
  depuis la même IP en 5 minutes. Couvre CrackMapExec, smbclient et
  tout client SMB.
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

| | |
|---|---|
| **Fichier** | `engine/rules/malicious_file.yaml` |
| **Type** | 2 — étapes séquentielles |
| **Sévérité** | CRITICAL |
| **MITRE** | TA0002 / T1204.002 |
| **Scénario** | S3 — BEC kill-chain |

**Ce que détecte la règle** : séquence ordonnée — dépôt d'un fichier
malveillant sur un partage Samba (step 1, avec match YARA requis) suivi
de son exécution sur le poste Windows par le même utilisateur en 4 heures.

**Pourquoi Type 2 et non Type 4** : Type 4 couvre le dépôt seul sans suite.
`MALICIOUS_FILE_EXEC_001` couvre la chaîne complète jusqu'à l'exécution —
information critique pour le SOAR (le payload a déjà été lancé, pas
seulement déposé). Les deux règles peuvent déclencher en parallèle sur
le même incident : Type 4 alerte immédiatement au dépôt, Type 2 confirme
l'exécution effective.

**Pourquoi `yara_match: required` sur step 1** : sans ce filtre, tout dépôt
de fichier sur Samba démarrerait le contexte. Avec ce filtre, seuls les
fichiers identifiés comme malveillants par YARA démarrent la chaîne.
Réduit drastiquement les faux positifs sur les fichiers légitimes.

**Pourquoi fenêtre de 4 heures** : un employé peut télécharger un fichier
le matin et ne l'ouvrir qu'après sa pause déjeuner. Une fenêtre courte
raterait ce scénario documenté par INTERPOL 2025 pour le vecteur BEC.

```yaml
rule_id: MALICIOUS_FILE_EXEC_001
type: 2
description: >
  Kill-chain BEC — fichier malveillant (confirmé YARA) déposé sur partage
  Samba puis exécuté sur poste Windows par le même utilisateur en 4 heures.
  Complémentaire à YARA_MALICIOUS_FILE_001 qui alerte dès le dépôt.
severity: CRITICAL
mitre_tactic: "TA0002"
mitre_technique: "T1204.002"
source_host_pattern: "*"
steps:
  - step: 1
    event_type: samba_write
    source_host_pattern: "debian*"
    condition:
      yara_match: required
  - step: 2
    event_type: process_exec
    source_host_pattern: "DESKTOP*"
    window_seconds: 14400
    match_on: actor_user
response:
  alert: true
```

---

### WEB_BRUTEFORCE_001

| | |
|---|---|
| **Fichier** | `engine/rules/web_bruteforce.yaml` |
| **Type** | 1 — seuil simple |
| **Sévérité** | WARNING |
| **MITRE** | TA0006 / T1110.001 |
| **Scénario** | S4 — Dolibarr |

**Ce que détecte la règle** : volume anormal de requêtes HTTP en échec
(codes 401/403) sur Dolibarr depuis la même IP en 2 minutes.

**Pourquoi WARNING et non CRITICAL** : un brute-force web peut être
déclenché par un scanner de vulnérabilités légitime, un outil de test
de performance, ou un navigateur rejoujant des credentials expirés.
Le taux de faux positifs est structurellement plus élevé que sur SSH.
WARNING indique que le pattern est suspect mais qu'une confirmation
est nécessaire avant action.

**Pourquoi une règle séparée de SSH_BRUTEFORCE_001** : les deux comportements
sont fonctionnellement identiques (tentatives répétées sur un service
d'authentification) mais les event_types produits par les parsers sont
différents : `ssh_failure` vs `http_request`. Une seule règle ne peut
pas couvrir les deux sans modifier la taxonomie.

```yaml
rule_id: WEB_BRUTEFORCE_001
type: 1
description: >
  Brute-force interface web Dolibarr — volume anormal de requêtes HTTP
  en échec (401/403) depuis la même IP en 2 minutes. Sévérité WARNING
  car taux de faux positifs plus élevé que sur SSH.
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

### YARA_MALICIOUS_FILE_001

| | |
|---|---|
| **Fichier** | `engine/rules/yara_malicious_file.yaml` |
| **Type** | 4 — détection YARA directe |
| **Sévérité** | CRITICAL |
| **MITRE** | TA0001 / T1566.002 |
| **Scénario** | S3 variante — employé naïf, upload direct sans chaîne préalable |

**Ce que détecte la règle** : tout fichier déposé sur n'importe quel partage
Samba qui déclenche un match YARA. Aucune condition préalable — pas de
brute-force, pas de scan réseau. Couvre le cas d'un employé qui reçoit
un fichier malveillant par mail et l'uploade directement sur le partage
sans que l'attaquant ait eu à compromettre quoi que ce soit en amont.

**Pourquoi Type 4 et non Type 2** : Type 2 attend une chaîne d'événements.
Un employé naïf n'est pas précédé d'un brute-force. Le fichier malveillant
arrive directement via un vecteur social (phishing, clé USB, mail). YARA
est la seule détection possible dans ce cas — pas d'événement réseau
préalable observable.

**Pourquoi CRITICAL immédiatement** : un match YARA sur un fichier exécutable
malveillant connu a un taux de faux positifs proche de zéro dans ce contexte.
Les règles `neo23x0/signature-base` sont conservatrices et précises. Une
alerte immédiate est justifiée pour permettre au SOAR de supprimer le fichier
du partage avant qu'un employé ne l'exécute.

**Complémentarité avec MALICIOUS_FILE_EXEC_001** : les deux règles peuvent
déclencher sur le même incident. `YARA_MALICIOUS_FILE_001` alerte dès le
dépôt (CRITICAL immédiat). `MALICIOUS_FILE_EXEC_001` confirme l'exécution
effective (CRITICAL avec contexte complet incluant le process). Le SOAR
reçoit deux alertes corrélées par `actor_ip` — information plus riche
pour la décision de remédiation.

```yaml
rule_id: YARA_MALICIOUS_FILE_001
type: 4
description: >
  Fichier malveillant détecté sur partage Samba par YARA. Alerte immédiate
  sans condition préalable. Couvre le vecteur phishing/BEC où un employé
  uploade directement un fichier malveillant reçu par mail.
  Complémentaire à MALICIOUS_FILE_EXEC_001 qui suit l'exécution.
severity: CRITICAL
mitre_tactic: "TA0001"
mitre_technique: "T1566.002"
yara_trigger:
  event_type: samba_write
  yara_match: required
  source_host_pattern: "debian*"
response:
  alert: true
```

---

## 4. Matrice de couverture

| Vecteur | Règle | Scénario | Couvert |
|---|---|---|---|
| Brute-force SSH (tout outil) | SSH_BRUTEFORCE_001 | S1 | ✓ |
| Scan réseau + accès SMB | SMB_EXFIL_001 | S2 | ✓ |
| Kill-chain BEC (dépôt + exécution) | MALICIOUS_FILE_EXEC_001 | S3 | ✓ |
| Upload direct fichier malveillant | YARA_MALICIOUS_FILE_001 | S3 variante | ✓ |
| Brute-force ERP web | WEB_BRUTEFORCE_001 | S4 | ✓ |
| Slow brute-force SSH (< 10/min) | — | — | ✗ Limite documentée |
| Pivoting inter-IP | — | — | ✗ Limite documentée |
| Exfiltration DNS/HTTPS | — | — | ✗ Hors scope |

---

## 5. Procédure d'ajout d'une règle

Avant de créer, répondre à ces quatre questions :

**Q1** : L'event_type est-il déjà couvert par une règle existante ?
Si oui, ajuster les paramètres de l'existante.

**Q2** : La chaîne causale est-elle fondamentalement différente ?
Si non, ne pas créer.

**Q3** : Le pattern est-il lié à un scénario documenté ou à une extension
justifiée ? Sinon, discuter avec le superviseur.

**Q4** : Valider contre `docs/rule-schema.json` avant tout commit :

```bash
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

Ajouter la règle à ce catalogue avec la même structure de justification.