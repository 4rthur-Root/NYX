## Explications sur le schéma de sortie des parsers 
Chaque parser reçoit une ligne brute et doit produire exactement ce dict. Voici ce que chaque champ signifie concrètement, avec des exemples réels tirés des trois sources.
```
{
    # QUAND s'est passé l'événement, pas quand il est arrivé au SOC.
    # Toujours converti en Unix millisecondes pour que SQLite puisse
    # comparer des timestamps de sources différentes sans se soucier
    # des formats (ISO 8601 Debian, BSD syslog OPNsense, XML Windows).
    # Obligatoire — un événement sans timestamp est inutilisable.
    "timestamp": int,

    # QUI a émis ce log — la machine source, pas l'attaquant.
    # "debian-server" si le log vient de Debian, "OPNsense.internal"
    # si c'est le firewall, "DESKTOP-PME" si c'est Windows.
    # Permet au RuleEngine de filtrer les règles par source_host_pattern
    # (ex: "debian*" pour les règles SSH, "DESKTOP*" pour Sysmon).
    # Obligatoire.
    "source_host": str,

    # CE QUI s'est passé — la taxonomie fermée à 12 valeurs.
    # C'est le champ le plus important : c'est lui que les règles YAML
    # interrogent. "ssh_failure", "samba_write", "net_scan", etc.
    # Jamais de valeur libre — si le parser ne reconnaît pas l'événement,
    # il retourne None plutôt que d'inventer un event_type.
    # Obligatoire.
    "event_type": str,

    # QUI agit — l'IP de l'entité qui déclenche l'événement.
    # Pour un brute-force SSH : l'IP de Kali (10.0.1.50).
    # Pour un scan OPNsense : l'IP source du scan.
    # Absent dans les logs Sysmon Windows (pas d'IP source directe
    # dans EventID 1 ou 11) → None.
    "actor_ip": str | None,

    # QUI agit — le nom d'utilisateur si l'événement en contient un.
    # "root" pour un Failed password SSH, "dir1" pour un accès Samba,
    # "PME\employe" pour un logon Windows.
    # Absent dans filterlog OPNsense → None.
    # Convention stricte : None si absent, jamais "" (chaîne vide).
    "actor_user": str | None,

    # QUI est visé — la machine ciblée si différente de source_host.
    # Utile pour les règles de corrélation cross-sources : OPNsense
    # voit une connexion vers 10.0.1.20, ce champ dit que la cible
    # est debian-server même si le log vient d'OPNsense.
    # Souvent None pour les logs système (la cible est implicitement
    # la machine elle-même).
    "target_host": str | None,

    # VERS QUEL PORT — uniquement pertinent pour les événements réseau.
    # 22 pour SSH, 445 pour SMB, 80/443 pour HTTP.
    # Absent dans les logs auth Debian ou les logs Sysmon de création
    # de processus → None.
    "target_port": int | None,

    # TOUT LE RESTE — champs spécifiques à la source qui n'ont pas
    # de place dans le schéma commun mais sont utiles pour l'alerte.
    # Pour Windows Sysmon EventID 1 : hash du processus, chemin complet
    # de l'exécutable, ligne de commande complète, Logon ID.
    # Pour Samba samba_write : nom du fichier déposé (utilisé par YARA).
    # Pour filterlog OPNsense : interface réseau, protocole, flags TCP.
    # Sérialisé en JSON string dans SQLite, désérialisé à la lecture.
    "extra": dict | None,

    # RÉSULTAT YARA — renseigné uniquement par le Dispatcher,
    # jamais par les parsers eux-mêmes.
    # Vaut None à la sortie du parser. Le Dispatcher le remplit
    # si event_type == "samba_write" après avoir appelé YaraScanner.
    # Structure quand renseigné :
    # {"rule_name": "Meterpreter_Reverse_Shell",
    #  "file_path": "/mnt/samba/commun/payload.exe",
    #  "file_hash": "md5:abc123...",
    #  "ruleset":   "neo23x0/signature-base"}
    "yara_match": dict | None,

    # LA LIGNE BRUTE originale, telle quelle, sans modification.
    # Toujours présente pour l'audit et pour alimenter le tableau
    # events.details dans alert.json.
    # Permet de retrouver le log source exact en cas d'investigation.
    "raw_log": str,
}
```
# Ce que ça donne sur un vrai exemple par source
##  Log SSH Debian : 
```
2026-06-19T10:23:41+00:00 debian sshd[1234]:
Failed password for root from 10.0.1.50 port 52341 ssh2
```

Produit 

```
{
    "timestamp":   1750329821000,
    "source_host": "debian-server",
    "event_type":  "ssh_failure",
    "actor_ip":    "10.0.1.50",
    "actor_user":  "root",
    "target_host": None,
    "target_port": 22,
    "extra":       None,
    "yara_match":  None,
    "raw_log":     "2026-06-19T10:23:41+00:00 debian sshd[1234]: Failed password..."
}
```

## Log filterlog OPNsense :

```
filterlog[56373]: 76,,,uuid,vtnet1,match,block,in,4,0x0,,64,0,0,none,6,tcp,
60,10.0.1.50,10.0.1.20,54321,22,0
```
Produit 

```
{
    "timestamp":   1750329821000,
    "source_host": "OPNsense.internal",
    "event_type":  "firewall_block",
    "actor_ip":    "10.0.1.50",
    "actor_user":  None,          # réseau — pas d'utilisateur
    "target_host": "debian-server",
    "target_port": 22,
    "extra":       {"interface": "vtnet1", "protocol": "tcp", "action": "block"},
    "yara_match":  None,
    "raw_log":     "filterlog[56373]: 76,,,uuid,vtnet1,match,block..."
}
```

## Log Sysmon Windows (EventID 1 — process_exec) :


```
<EventID>1</EventID>
<Computer>DESKTOP-PME</Computer>
<Data Name="Image">C:\Users\employe\Downloads\payload.exe</Data>
<Data Name="Hashes">MD5=abc123</Data>
<Data Name="User">PME\employe</Data>
```
Produit 

```
{
    "timestamp":   1750329821000,
    "source_host": "DESKTOP-PME",
    "event_type":  "process_exec",
    "actor_ip":    None,          # Sysmon ne donne pas l'IP source
    "actor_user":  "PME\\employe",
    "target_host": None,
    "target_port": None,
    "extra":       {
        "process_path": "C:\\Users\\employe\\Downloads\\payload.exe",
        "process_hash": "md5:abc123",
        "logon_id":     "0x3E7"
    },
    "yara_match":  None,          # toujours None à la sortie du parser
    "raw_log":     "<Event xmlns=...>"
}
```

## Log Samba (samba_write) — après que le Dispatcher a appelé YARA :

```
{
    "timestamp":   1750329821000,
    "source_host": "debian-server",
    "event_type":  "samba_write",
    "actor_ip":    "10.0.1.50",
    "actor_user":  "dir1",
    "target_host": None,
    "target_port": None,
    "extra":       {"filename": "payload.exe", "share": "commun"},
    "yara_match":  {              # renseigné par le Dispatcher, pas le parser
        "rule_name": "Meterpreter_Reverse_Shell",
        "file_path": "/mnt/samba/commun/payload.exe",
        "file_hash": "md5:abc123",
        "ruleset":   "neo23x0/signature-base"
    },
    "raw_log":     "smbd[1234]: dir1 wrote payload.exe on //commun..."
}
```
# La règle absolue : les parsers produisent toujours yara_match: None. C'est le Dispatcher qui le renseigne après coup. Un parser ne sait pas ce que YARA va trouver — ce n'est pas son rôle.