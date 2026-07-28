# S3 - Compromission de poste employé (BEC / kill-chain)

Scénario d'attaque documenté dans [Topologie.pdf](../../docs/PDFs/Topologie.pdf) §6.3. Simule un employé qui reçoit un fichier
malveillant (phishing/dépôt réseau), le récupère depuis un partage Samba commun, puis l'exécute
depuis son poste Windows.

## Contexte PME

Un attaquant (ou un employé piégé) dépose un fichier malveillant sur le partage `commun/`.
L'employé (`dir1`, `compta1`, etc.) le copie ensuite sur son poste puis l'exécute — sans
interaction humaine manuelle, conformément à `Topologie.pdf` §4.4.2.

## Chaîne d'attaque

1. Kali (`10.0.1.50`) dépose le payload sur `//10.0.1.20/commun` via `smbclient`.
2. Debian Server journalise l'accès (`samba_write`) — le Dispatcher appelle **YARA** sur ce
   fichier **avant** que la séquence ne progresse vers les étapes suivantes (§6.7).
3. L'employé (script PowerShell, simulant l'action) copie le fichier du partage vers son poste
   local → Sysmon **EventID 11** (`file_create`).
4. L'employé exécute le fichier → Sysmon **EventID 1** (`process_exec`), si le fichier survit.
5. Règle attendue côté moteur : **`MALICIOUS_FILE_EXEC_001`** — séquence ordonnée de 3 étapes
   (`samba_write` → `file_create` → `process_exec`) en fenêtre de 4h, corrélée par `actor_user`
   → alerte `CRITICAL`, enrichie du match YARA.

**Sources corrélées** : `daemon/Samba` (Debian Server) + Sysmon EventID 1 et 11 (Windows 10).
**MITRE ATT&CK** : TA0002 (Execution) / T1204.002 (User Execution: Malicious File).

---

## Fichiers

```
S3-kill-chain/
├── gen_eicar.py           # génère le fichier de test EICAR (validation pipeline)
├── deploy_payload.sh      # dépose le payload sur le partage commun/ (exécuté depuis Kali)
├── simulate_employee.ps1  # copie + exécution du fichier côté Windows (exécuté en tant qu'employé)
├── README.md
└── logs/                  # sorties produites par les deux scripts
```

---

## Approche en deux temps : EICAR d'abord, payload réel ensuite

`Topologie.pdf` §6.7 liste **EICAR** explicitement comme "validation pipeline YARA sans payload réel
(tests unitaires)". C'est l'usage prévu, pas un contournement : EICAR est une chaîne de test standard
reconnue par tout antivirus/EDR, totalement inoffensive, mais qui déclenche les mêmes détections
qu'un vrai malware (signature YARA, alerte Defender).

**Pourquoi cet ordre** : Windows Defender est actif sur `NYX-PME` et aucun accès admin n'est
disponible pour créer une exclusion. Tester directement avec un vrai payload (Meterpreter `.exe`)
aurait mélangé deux inconnues (le script fonctionne-t-il ? Defender bloque-t-il ?) sans pouvoir les
distinguer. EICAR isole le problème : s'il est bloqué, c'est bien Defender — pas le script.

**Bascule vers Meterpreter** : remplacer `eicar_test.txt` par le payload `.exe` (`msfvenom
-p windows/x64/meterpreter/reverse_tcp ...`) dans les mêmes scripts, sans modification de code —
seul `--FileName`/paramètre `-FileName` change. Nécessitera très probablement une exclusion
Windows Defender (accès admin requis) pour survivre à la copie.

---

## 1. `gen_eicar.py`

Génère le fichier de test EICAR (chaîne standard 68 octets), reconnu par tous les AV/EDR sans
être un malware réel.

### Usage

```bash
python3 gen_eicar.py --out eicar_test.txt
```

---

## 2. `deploy_payload.sh`

**Exécuté depuis Kali.** Dépose le payload sur le partage `commun/`, simulant l'attaquant (ou
l'employé piégé par phishing) qui pousse le fichier après l'intrusion initiale.

### Usage

```bash
./deploy_payload.sh <target_ip> <ad_user> <ad_password> <payload_file>
```

### Exemple

```bash
./deploy_payload.sh 10.0.1.20 dir1 'Nyx2026!' eicar_test.txt
```

Ce dépôt déclenche `samba_write` côté Debian Server — **étape 1** de la séquence
`MALICIOUS_FILE_EXEC_001`. Le timestamp affiché sert de départ à la fenêtre de corrélation de 4h.

**Note** : n'importe quel compte AD avec droits d'écriture sur `commun/` fonctionne (`dir1`,
`compta1`, `tech1`) — pas besoin d'un utilisateur spécifique pour ce dépôt.

---

## 3. `simulate_employee.ps1`

**Exécuté depuis une session PowerShell sur `NYX-PME`**, en tant qu'employé (`dir1` ou autre).
Copie le fichier du partage vers le poste local, puis tente de l'exécuter.

### Prérequis avant lancement

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
(nécessaire une fois par session — ne modifie rien de permanent, disparaît à la fermeture de la
fenêtre PowerShell).

### Usage

```powershell
.\simulate_employee.ps1 -ShareHost 10.0.1.20 -ShareName commun -FileName eicar_test.txt `
    -ShareUser "NYX\dir1" -SharePassword "Nyx2026!"
```

### Paramètres

| Paramètre | Défaut | Rôle |
|---|---|---|
| `-ShareHost` | `10.0.1.20` | IP du serveur Samba |
| `-ShareName` | `commun` | Nom du partage |
| `-FileName` | *(requis)* | Nom du fichier à copier/exécuter |
| `-LocalDir` | `$env:USERPROFILE\Downloads` | Dossier local de destination |
| `-Execute` | `$true` | Tente l'exécution après copie |
| `-ShareUser` | *(vide)* | Compte AD pour authentification SMB explicite (ex: `NYX\dir1`) |
| `-SharePassword` | *(vide)* | Mot de passe associé |

### Pourquoi `-ShareUser`/`-SharePassword` sont nécessaires

La session Windows locale (`dir1` local, pré-jonction domaine) n'a pas de credentials valides pour
s'authentifier automatiquement sur le partage Samba AD (`NYX\dir1`). Sans authentification
explicite, `Copy-Item` échoue avec une erreur trompeuse (`Cannot find path ... because it does not
exist`), qui ressemble à un chemin invalide mais qui est en réalité un **échec d'authentification
SMB silencieux**. Le script fait un `net use` explicite avant la copie pour éviter ce piège, et
nettoie la connexion en fin de run.

### Étapes internes

1. **`[0/2]`** Authentification SMB explicite (`net use`) si `-ShareUser` fourni.
2. **`[1/2]`** Copie du fichier (`Copy-Item`) → déclenche Sysmon **EventID 11**.
3. **`[2/2]`** Tentative d'exécution :
   - Fichier `.exe` → `Start-Process` (lancement réel, déclenche Sysmon **EventID 1**).
   - Fichier non-exécutable (`.txt`, EICAR) → lecture simulée (`Get-Content`), pas de vraie
     exécution possible. C'est normal en phase de validation — le vrai test `process_exec`
     n'intervient qu'avec le payload `.exe`.
4. Écrit les métadonnées dans `logs/<run_id>.meta.json`, y compris en cas d'échec de copie.
5. Ferme la connexion SMB explicite.

### Sorties produites

```
logs/
└── s3_<timestamp>.meta.json
```

Exemple (succès de copie, résultat observé en test) :
```json
{
  "scenario": "S3_MALICIOUS_FILE_EXEC",
  "run_id": "s3_20260728_131840",
  "actor_user": "dir1",
  "share_path": "\\\\10.0.1.20\\commun\\eicar_test.txt",
  "local_path": "C:\\Users\\dir1\\Downloads\\eicar_test.txt",
  "copy_succeeded": true,
  "execution_attempted": true,
  "expected_rule": "MALICIOUS_FILE_EXEC_001",
  "mitre": "T1204.002"
}
```

---

## Rôle attendu par machine

| Machine | Rôle dans ce scénario |
|---|---|
| Kali (`10.0.1.50`) | Dépose le payload sur `commun/` via smbclient. |
| Debian Server (`10.0.1.20`) | Journalise `samba_write`, héberge le partage, applique YARA au dépôt. |
| Windows 10 / NYX-PME (`10.0.1.30`) | Copie + exécute le fichier (session employé), génère Sysmon 11/1. |
| SOC (`10.0.1.10`) | Reçoit `daemon/Samba` + logs Sysmon (via NXLog), le moteur corrèle la séquence. |

---

## Résultat de validation (run réel)

Testé avec EICAR sur `dir1` et `compta1` — succès confirmé de bout en bout jusqu'à l'étape 2 :

```
2026-07-28T13:18:41+01:00 NYX-PME.nyx.tg Microsoft-Windows-Sysmon[2368] File created:
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  TargetFilename: C:\Users\dir1\Downloads\eicar_test.txt
  User: NYX-PME\dir1
```

L'événement remonte correctement jusqu'à `/var/log/remote/NYX-PME.nyx.tg.log` sur le SOC — la
chaîne `smbclient → samba_write → Copy-Item → Sysmon EventID 11 → NXLog → SOC` est validée.

**Étape 3 (process_exec) non atteinte avec EICAR** : Windows Defender intercepte la lecture du
fichier (`Operation did not complete successfully because the file contains a virus`) — c'est le
comportement *attendu* d'EICAR, pas un échec du script. La trace de l'intervention de Defender est
elle-même visible dans Sysmon (`MsMpEng.exe` touchant le fichier juste après sa création).

---

## Limites connues

- **Windows Defender actif, aucun accès admin disponible** sur `NYX-PME` au moment du test. Une
  exclusion sera nécessaire pour tester l'étape 3 avec un vrai payload `.exe`. Documenté comme
  limite plutôt que forcé — pas de contournement (désactivation, mode sans échec) tenté sans
  validation préalable.
- **Étape 3 (`process_exec`) non validée en conditions réelles** avec EICAR (fichier non-exécutable
  de toute façon, et bloqué par Defender avant lecture). À valider séparément avec Meterpreter si
  le temps le permet.
- Deux comptes `dir1` distincts coexistent sur `NYX-PME` : un compte **local** (pré-jonction
  domaine, utilisé par SSH) et un compte **AD** (`NYX\dir1`, utilisé pour SMB). Ne pas confondre
  les credentials des deux lors des tests.
- Le script ne gère qu'un seul utilisateur par run — pour tester plusieurs comptes (`dir1`,
  `compta1`, `tech1`), relancer le script séparément pour chacun.
