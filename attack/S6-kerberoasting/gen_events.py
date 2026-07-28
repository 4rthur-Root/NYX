"""Génère des événements Kerberos synthétiques au format JSON Samba AD.

Produit des lignes syslog simulées qui déclenchent les règles
KERBEROASTING_001 (EventID 4769, event_type: tgs_request) et
ASREP_ROASTING_001 (EventID 4768, event_type: tgt_request) de NyxSOC.

Format :
  {timestamp} {host} samba-audit[{pid}]: {{"Authentication": {{"eventId": 4768|4769, ...}}}}

Usage :
  python3 gen_events.py > /tmp/kerberos_test.log
  python3 gen_events.py --event-type tgs --count 8 > kerberoast.log
  python3 gen_events.py --event-type tgt --output /var/log/remote/srv-pme.log

Le fichier généré peut être ingéré par l'engine s'il est placé dans
/var/log/remote/ (ou le log_dir configuré dans engine/config.yaml).
"""

import argparse
import datetime
import json
import sys

# Hostname Samba AD DC tel qu'attendu par le parser
SOURCE_HOST = "debian-server"
PROGRAM = "samba-audit"
PID = 2

# IP attaquante (Kali par défaut)
ATTACKER_IP = "10.0.1.50"

# SPN fictifs pour simuler un AD avec plusieurs services
SPNS = [
    "cifs/srv-pme.nyx.tg",
    "cifs/srv-02.nyx.tg",
    "HTTP/websrv.nyx.tg",
    "MSSQLSvc/sql.nyx.tg:1433",
    "ldap/dc01.nyx.tg",
    "HOST/srv-pme.nyx.tg",
    "HTTP/srv-pme.nyx.tg",
]


def gen_event(ts_iso: str, event_id: int, ip: str, port: int, spn: str | None, user: str, host: str = SOURCE_HOST) -> str:
    """Génère une ligne syslog avec payload JSON Samba audit."""
    if event_id == 4769:
        payload = {
            "Authentication": {
                "eventId": 4769,
                "remoteAddress": f"ipv4:{ip}:{port}",
                "servicePrincipalName": spn or "cifs/srv-pme.nyx.tg",
                "accountName": user,
            }
        }
    else:
        payload = {
            "Authentication": {
                "eventId": 4768,
                "remoteAddress": f"ipv4:{ip}:{port}",
                "accountName": user,
            }
        }
    return f"{ts_iso} {host} {PROGRAM}[{PID}]: {json.dumps(payload)}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--event-type",
        choices=["tgs", "tgt", "both"],
        default="both",
        help="Type d'événements à générer (défaut: both)",
    )
    parser.add_argument(
        "--count", type=int, default=8,
        help="Nombre d'événements par type (défaut: 8, seuil SOC: 5)",
    )
    parser.add_argument(
        "--window", type=int, default=10,
        help="Fenêtre temporelle en secondes (défaut: 10)",
    )
    parser.add_argument(
        "--ip", default=ATTACKER_IP,
        help=f"IP attaquante (défaut: {ATTACKER_IP})",
    )
    parser.add_argument(
        "--user", default="employe",
        help="Nom du compte AD attaquant (défaut: employe)",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="Fichier de sortie (défaut: stdout)",
    )
    parser.add_argument(
        "--host", default=SOURCE_HOST,
        help=f"Hostname source Samba AD (défaut: {SOURCE_HOST})",
    )

    args = parser.parse_args()
    host = args.host

    out = open(args.output, "w") if args.output else sys.stdout

    now = datetime.datetime.now(datetime.timezone.utc)
    count = args.count
    window = args.window

    def write_events(event_id: int, label: str):
        spn = None
        for i in range(count):
            ts = now + datetime.timedelta(seconds=(i * window / max(count - 1, 1)))
            ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"
            port = 56100 + i
            if event_id == 4769:
                spn = SPNS[i % len(SPNS)]
            line = gen_event(ts_iso, event_id, args.ip, port, spn, args.user, host)
            out.write(line + "\n")

        print(f"  [{label}] {count} événements générés pour IP {args.ip} "
              f"dans {window}s", file=sys.stderr)

    if args.event_type in ("tgs", "both"):
        write_events(4769, "Kerberoasting   (TGS)  ")
    if args.event_type in ("tgt", "both"):
        write_events(4768, "AS-REP Roasting (TGT)  ")

    if args.output:
        print(f"Écrit dans {args.output}", file=sys.stderr)
        out.close()


if __name__ == "__main__":
    main()
