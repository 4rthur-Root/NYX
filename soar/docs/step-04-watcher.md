# Étape 4 — Watcher (surveillance du dossier d'alertes)

**Date :** 23 juillet 2026
**Objectif :** surveiller le dossier `/var/log/nyx/` et déclencher le pipeline à chaque nouvelle alerte.

---

## Fichiers créés

```
src/soar/watcher/
├── __init__.py          # Export public (AlertWatcher, AlertFileHandler)
└── alert_watcher.py     # Watcher watchdog + FileSystemEventHandler
```

---

## Architecture

### Principe

Le module SOAR reçoit les alertes du moteur de corrélation via des fichiers JSON écrits atomiquement dans `/var/log/nyx/`. Le mécanisme côté moteur (garanti par Gaël) :

1. Écrit le JSON dans un fichier temporaire `.tmp`
2. Renomme atomiquement via `os.rename()` → `alert_{uuid}.json`

Le `rename()` est atomique. Le watcher SOAR ne voit jamais un fichier partiel — il voit soit le fichier complet, soit rien.

### Décision architecturale importante (DCD section 4.6)

**Ce n'est PAS un flux JSONL** contrairement à ce que suggérait le planning initial. C'est **un fichier par alerte** avec rename atomique. Pas besoin de gestion d'offset ni de `tail -f`.

---

## Détail des classes

### `AlertFileHandler` (watchdog `FileSystemEventHandler`)

| Élément | Valeur |
|---------|--------|
| Événements écoutés | `on_moved` (rename atomique) **et** `on_created` (sécurité) |
| Filtre | Extension `.json` uniquement (ignore `.tmp` résiduels) |
| Dédup | `Set[str]` des `alert_id` déjà vus en mémoire |
| Gestion d'erreur | Toute exception est logguée, jamais propagée |
| Non-blocage | Le handler appelle un callback : le traitement lourd est délégué |

### `AlertWatcher` (orchestrateur watchdog)

| Élément | Valeur |
|---------|--------|
| `start()` | Crée le dossier si absent, précharge les fichiers existants, démarre l'observation |
| `stop()` | Arrêt propre du thread watchdog (timeout 5s) |
| `_preload_existing()` | Parse les fichiers `.json` déjà présents au démarrage pour les marquer comme "déjà vus" |

### Contrat de non-intrusion

Le SOAR est **purement lecteur** sur `/var/log/nyx/`. Il ne doit **jamais** :
- Renommer, déplacer ou supprimer un fichier d'alerte
- Écrire quoi que ce soit dans ce dossier

La dédup à long terme se fera via SQLite (table `alerts`, Étape 11). En attendant, un `Set[str]` mémoire assure l'idempotence.

---

## Tests unitaires (8 tests)

| Test | Scénario |
|------|----------|
| `test_processes_valid_alert` | Nouveau fichier `.json` → callback reçoit l'`Alert` |
| `test_dedup_same_alert_id` | Même fichier traité 2x → callback appelé 1x |
| `test_ignores_tmp_files` | Fichier `.json.tmp` → ignoré |
| `test_invalid_json_does_not_crash` | JSON invalide → log warning, pas de crash |
| `test_non_existent_file_ignored` | Fichier supprimé entre détection et lecture → ignoré |
| `test_on_moved_triggers_processing` | Renommage `temp.tmp` → `alert_final.json` → callback |
| `test_preloads_existing_alerts` | Fichiers présents au démarrage → marqués comme vus |
| `test_start_stop_does_not_crash` | Cycle start/stop complet → pas d'erreur |

---

## Commit

```
feat(watcher): add AlertWatcher with watchdog, dedup and preload
```
