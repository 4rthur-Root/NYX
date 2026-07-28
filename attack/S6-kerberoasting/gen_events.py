"""
Génère des événements Kerberos synthétiques au format JSON Samba AD.

Utilisé pour valider le pipeline de détection NyxSOC quand l'attaque réelle
est bloquée par une incompatibilité Samba 4.22 (voir README.md, section
Difficultés).

Format produit :
  {ts} {host} samba-audit[{pid}]: {"Authentication": {"eventId": 4768|4769, ...}}

Scénarios :
  --scenario burst     Rafale d'attaque (défaut) — 6+ événements en 30s
  --scenario slow      Attaque lente — étalée sur plusieurs minutes
  --scenario mixed     Trafic légitime + rafale d'attaque (le plus réaliste)
  --scenario multi-ip  Attaque depuis plusieurs sources

Usage :
  python3 gen_events.py --scenario burst --count 8 --ip 10.0.1.50
  python3 gen_events.py --scenario mixed -o /tmp/kerberos_realistic.log
  python3 gen_events.py --scenario multi-ip --ips 10.0.1.50,10.0.1.60
"""

import argparse
import datetime
import json
import random
import sys

SOURCE_HOST = "srv-pme"
PROGRAM = "samba-audit"
PID = 2

DEFAULT_USERS = ["dir1", "compta1", "tech1", "employe"]
DEFAULT_SPNS = [
    "cifs/srv-pme.nyx.tg",
    "cifs/srv-02.nyx.tg",
    "HTTP/websrv.nyx.tg",
    "MSSQLSvc/sql.nyx.tg:1433",
    "ldap/dc01.nyx.tg",
    "HOST/srv-pme.nyx.tg",
    "HTTP/srv-pme.nyx.tg",
    "cifs/srv-pme",
    "HOST/SRV-PME",
]


def gen_event(ts_iso: str, event_id: int, ip: str, port: int,
              spn: str | None, user: str, host: str) -> str:
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


def write_events(out, events):
    for (ts, evt) in events:
        out.write(gen_event(ts, *evt) + "\n")


# ── Scénarios ──────────────────────────────────────────────────

def _etype(args):
    """Retourne les event_id à générer selon --event-type."""
    if args.event_type == "tgs":
        return [4769]
    if args.event_type == "tgt":
        return [4768]
    return [4769, 4768]


def scenario_burst(args):
    """Rafale d'attaque simple : N événements par type en window secondes."""
    now = datetime.datetime.now(datetime.timezone.utc)
    events = []
    for eid in _etype(args):
        for i in range(args.count):
            ts = now + datetime.timedelta(
                seconds=i * args.window / max(args.count - 1, 1))
            ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"
            spn = DEFAULT_SPNS[i % len(DEFAULT_SPNS)] if eid == 4769 else None
            events.append((ts_iso, (eid, args.ip, 56100 + i, spn, args.user, args.host)))
    return events


def scenario_slow(args):
    """Attaque lente : étalée sur window*3 secondes, seuil difficile à atteindre."""
    now = datetime.datetime.now(datetime.timezone.utc)
    events = []
    spread = args.window * 3
    for eid in _etype(args):
        for i in range(args.count):
            ts = now + datetime.timedelta(
                seconds=i * spread / max(args.count - 1, 1))
            ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"
            spn = DEFAULT_SPNS[i % len(DEFAULT_SPNS)] if eid == 4769 else None
            events.append((ts_iso, (eid, args.ip, 56100 + i, spn, args.user, args.host)))
    return events


def scenario_mixed(args):
    """Trafic légitime intermittent + rafale soudaine (le plus réaliste)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    events = []

    # Bruit de fond : requêtes normales et espacées (utilisateurs légitimes)
    for i in range(12):
        ts = now + datetime.timedelta(minutes=i * 5 + random.randint(0, 60))
        ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"
        user = random.choice(DEFAULT_USERS)
        ip = "10.0.1." + str(random.randint(10, 50))
        eid = random.choice([4768, 4769])
        spn = random.choice(DEFAULT_SPNS) if eid == 4769 else None
        events.append((ts_iso, (eid, ip, 56100 + i, spn, user, args.host)))

    # Rafale d'attaque : count événements par type en 25s depuis l'IP attaquante
    for eid in _etype(args):
        for i in range(args.count):
            ts = now + datetime.timedelta(
                hours=1, seconds=i * 25 / max(args.count - 1, 1))
            ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"
            spn = DEFAULT_SPNS[i % len(DEFAULT_SPNS)] if eid == 4769 else None
            events.append((ts_iso, (eid, args.ip, 56100 + i, spn, args.user, args.host)))

    events.sort(key=lambda x: x[0])
    return events


def scenario_multi_ip(args):
    """Plusieurs attaquants tirent des TGS/TGT en même temps."""
    now = datetime.datetime.now(datetime.timezone.utc)
    events = []
    ips = [ip.strip() for ip in args.ips.split(",")]
    per_ip = max(1, args.count // len(ips))
    for eid in _etype(args):
        for ip in ips:
            for i in range(per_ip):
                ts = now + datetime.timedelta(
                    seconds=i * args.window / max(per_ip - 1, 1))
                ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"
                spn = DEFAULT_SPNS[i % len(DEFAULT_SPNS)] if eid == 4769 else None
                events.append((ts_iso, (eid, ip, 56100 + i, spn, args.user, args.host)))
    return events


SCENARIOS = {
    "burst":    scenario_burst,
    "slow":     scenario_slow,
    "mixed":    scenario_mixed,
    "multi-ip": scenario_multi_ip,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-type", choices=["tgs", "tgt", "both"],
                        default="both")
    parser.add_argument("--count", type=int, default=8)
    parser.add_argument("--window", type=int, default=30,
                        help="Fenêtre temporelle en secondes (défaut: 30)")
    parser.add_argument("--ip", default="10.0.1.50")
    parser.add_argument("--ips", default="10.0.1.50,10.0.1.60",
                        help="IPs pour le scénario multi-ip (virgule)")
    parser.add_argument("--user", default="svc_backup")
    parser.add_argument("--output", "-o", default=None)
    parser.add_argument("--host", default=SOURCE_HOST)
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()),
                        default="burst",
                        help="Pattern d'attaque (défaut: burst)")
    args = parser.parse_args()

    out = open(args.output, "w") if args.output else sys.stdout
    fn = SCENARIOS[args.scenario]
    events = fn(args)

    write_events(out, events)
    total = len(events)
    attack_events = len([e for e in events if e[1][1] == args.ip]) if args.scenario != "multi-ip" else total
    print(f"  [{args.scenario}] {total} événements générés "
          f"({attack_events} depuis IP {args.ip}) "
          f"dans {args.window}s", file=sys.stderr)

    if args.output:
        print(f"  Écrit dans {args.output}", file=sys.stderr)
        out.close()


if __name__ == "__main__":
    main()
