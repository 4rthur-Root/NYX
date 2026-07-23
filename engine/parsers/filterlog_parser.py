# parsers/filterlog_parser.py
import logging
from parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)

# Positions fixes des champs communs (IPv4 et IPv6)
# Format : rulnum,anchor,tracker,realint,iface,reason,action,direction,ipver,...
_IDX_IFACE   = 4
_IDX_REASON  = 5
_IDX_ACTION  = 6
_IDX_DIR     = 7
_IDX_IPVER   = 8

# IPv4 : ...ipver,tos,ecn,ttl,id,offset,flags,proto_id,proto_txt,length,src,dst,...
_IDX4_PROTO_TXT = 16
_IDX4_LENGTH    = 17
_IDX4_SRC       = 18
_IDX4_DST       = 19
# Après src/dst : sport,dport (TCP/UDP) ou type (ICMP)

# IPv6 : ...ipver,class,flowlabel,hlim,proto_txt,proto_id,length,src,dst,...
_IDX6_PROTO_TXT = 13
_IDX6_LENGTH    = 15
_IDX6_SRC       = 16
_IDX6_DST       = 17


class FilterlogParser(BaseParser):
    """Parser pour les logs filterlog BSD d'OPNsense.

    Gère le format CSV positionnel dont les colonnes varient selon
    la version IP (v4/v6) et le protocole (TCP/UDP/ICMP).
    Produit les event_types : 'firewall_block', 'net_scan'.

    Attributes:
        debug: Active le logging des lignes ignorées.
    """

    def __init__(self, debug: bool = False) -> None:
        """Initialise le parser filterlog.

        Args:
            debug: Si True, loggue les lignes non reconnues au niveau DEBUG.
        """
        self.debug = debug

    def parse(self, line: str) -> dict | None:
        """Parse une ligne de log filterlog OPNsense en événement normalisé.

        La ligne contient une enveloppe syslog RFC 5424 suivie de la payload
        filterlog CSV. On extrait d'abord l'enveloppe, puis on parse le CSV.

        Args:
            line: Ligne brute issue de OPNsense.internal.log.

        Returns:
            Dict conforme au schéma EventNormalized, ou None si la ligne
            ne correspond pas à un log filterlog valide.
        """
        stripped = line.strip()
        if not stripped:
            return None

        # Extraire l'enveloppe syslog : "2026-06-19T10:23:38+00:00 OPNsense.internal filterlog[56373]: <payload>"
        # On cherche "filterlog[" pour identifier la source
        try:
            parts = stripped.split(" ", 3)
            if len(parts) < 4:
                return None
            ts_str, source_host, program_raw, payload = parts
        except ValueError:
            return None

        if "filterlog" not in program_raw.lower():
            if self.debug:
                logger.debug("Ligne ignorée — pas filterlog : %s", stripped[:80])
            return None

        # Parse timestamp
        try:
            timestamp = self.parse_timestamp(ts_str)
        except ValueError:
            if self.debug:
                logger.debug("Timestamp invalide '%s'", ts_str)
            return None

        return self._parse_filterlog_payload(
            payload=payload.strip(),
            timestamp=timestamp,
            source_host=source_host,
            raw_log=stripped,
        )

    def _parse_filterlog_payload(
        self,
        payload: str,
        timestamp: int,
        source_host: str,
        raw_log: str,
    ) -> dict | None:
        """Parse le CSV filterlog extrait de la ligne syslog.

        Args:
            payload: La partie CSV brute après le préfixe "filterlog[NNN]: ".
            timestamp: Timestamp Unix en ms déjà converti.
            source_host: Hostname OPNsense émetteur.
            raw_log: Ligne brute complète pour l'audit.

        Returns:
            Dict normalisé ou None si le format est invalide.
        """
        # Supprimer un éventuel préfixe "filterlog[NNN]: "
        if ": " in payload:
            payload = payload.split(": ", 1)[1]

        fields = payload.split(",")
        n = len(fields)

        if n < 10:
            if self.debug:
                logger.debug("Filterlog : nombre de champs insuffisant (%d) : %s", n, payload[:80])
            return None

        try:
            action    = fields[_IDX_ACTION].lower()   # "block" | "pass"
            direction = fields[_IDX_DIR].lower()      # "in" | "out"
            ipver     = fields[_IDX_IPVER]            # "4" | "6"
            iface     = fields[_IDX_IFACE]
        except IndexError:
            return None

        # Extraire src, dst, ports selon la version IP
        if ipver == "4":
            if n < _IDX4_DST + 1:
                return None
            proto_txt = fields[_IDX4_PROTO_TXT].lower()
            src_ip    = fields[_IDX4_SRC]
            dst_ip    = fields[_IDX4_DST]
            sport, dport = self._extract_ports(fields, start=_IDX4_DST + 1, proto=proto_txt)
        elif ipver == "6":
            if n < _IDX6_DST + 1:
                return None
            proto_txt = fields[_IDX6_PROTO_TXT].lower()
            src_ip    = fields[_IDX6_SRC]
            dst_ip    = fields[_IDX6_DST]
            sport, dport = self._extract_ports(fields, start=_IDX6_DST + 1, proto=proto_txt)
        else:
            if self.debug:
                logger.debug("Version IP inconnue : '%s'", ipver)
            return None

        # Déduire event_type
        event_type = self._classify_event(action, direction, dport)

        extra: dict = {
            "interface":  iface,
            "action":     action,
            "direction":  direction,
            "protocol":   proto_txt,
            "ipver":      ipver,
        }
        if sport is not None:
            extra["src_port"] = sport
        if dport is not None:
            extra["dst_port"] = dport

        return {
            "timestamp":   timestamp,
            "source_host": source_host,
            "event_type":  event_type,
            "actor_ip":    src_ip if src_ip else None,
            "actor_user":  None,
            "target_host": None,
            "target_port": dport,
            "extra":       extra,
            "yara_match":  None,
            "raw_log":     raw_log,
        }

    @staticmethod
    def _extract_ports(fields: list[str], start: int, proto: str) -> tuple[int | None, int | None]:
        """Extrait les ports source et destination selon le protocole.

        Args:
            fields: Liste des champs CSV.
            start: Index du premier champ après dst_ip.
            proto: Protocole en minuscules ('tcp', 'udp', 'icmp', ...).

        Returns:
            Tuple (sport, dport) ou (None, None) si non applicable.
        """
        if proto in ("tcp", "udp"):
            try:
                sport = int(fields[start])
                dport = int(fields[start + 1])
                return sport, dport
            except (IndexError, ValueError):
                return None, None
        return None, None

    @staticmethod
    def _classify_event(action: str, direction: str, dport: int | None) -> str:
        """Détermine le type d'événement selon l'action et le port destination.

        Heuristique : un 'block' entrant sur un port < 1024 est traité comme
        un net_scan (sondage de port). Un 'pass' est un net_connect ordinaire.

        Args:
            action: 'block' ou 'pass'.
            direction: 'in' ou 'out'.
            dport: Port destination ou None.

        Returns:
            event_type conforme à la taxonomie NyxSOC.
        """
        if action == "block":
            return "net_scan" if direction == "in" else "firewall_block"
        # pass in/out → connexion réseau observable
        return "net_connect"
