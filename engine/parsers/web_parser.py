# parsers/web_parser.py
"""Parser pour les logs web Dolibarr / Apache Combined Log Format.

Les logs sont émis par le processus ``dolibarr`` sur ``localhost`` et
atterrissent dans ``localhost.log``. Ils respectent le format Apache
Combined Log :

    IP ident [date] "METHOD path HTTP/version" status size "referer" "user-agent"

enveloppé dans une enveloppe syslog RFC 5424 ou RFC 3164.

Produit le event_type ``http_request`` avec les champs extra :
``http_method``, ``http_path``, ``http_status``, ``user_agent``,
``referer``, ``response_size``.
"""
import logging
import re
from parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)

# Enveloppe syslog
# RFC 5424 : 2026-06-19T10:23:41+00:00 host program[pid]: message
_RE_ENVELOPE_RFC5424 = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.]\d+)?(?:[+-]\d{2}:\d{2}|Z))"
    r"\s+(?P<host>[\w.\-]+)"
    r"\s+(?P<program>[\w.\-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$",
    re.DOTALL,
)
# RFC 3164 : Jun 19 10:23:41 host program[pid]: message
_RE_ENVELOPE_RFC3164 = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>[\w.\-]+)"
    r"\s+(?P<program>[\w.\-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$",
    re.DOTALL,
)

# Apache Combined Log Format
# 10.0.1.1 - - [02/Jul/2026:16:39:30 +0000] "GET /path HTTP/1.1" 302 390 "ref" "ua"
_RE_COMBINED = re.compile(
    r"^(?P<ip>[\d.]+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<ts_combined>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+'
    r"(?P<path>\S+)\s+"
    r'HTTP/[^"]*"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<size>\S+)\s+"
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)


class WebParser(BaseParser):
    """Parse les logs web Dolibarr (Apache Combined Log Format).

    Attributes:
        debug: Active le logging des lignes ignorées.
    """

    def __init__(self, debug: bool = False) -> None:
        """Initialise le parser web.

        Args:
            debug: Si True, loggue les lignes non parsées au niveau DEBUG.
        """
        self.debug = debug

    def parse(self, line: str) -> dict | None:
        """Parse une ligne de log web Dolibarr en événement normalisé.

        Args:
            line: Ligne brute issue de localhost.log.

        Returns:
            Dict conforme au schéma EventNormalized, ou None si la ligne
            ne correspond pas au format Apache Combined Log.
        """
        stripped = line.strip()
        if not stripped:
            return None

        # 1. Extraire l'enveloppe syslog
        envelope = self._parse_envelope(stripped)
        if envelope is None:
            if self.debug:
                logger.debug("Ligne non reconnue par l'enveloppe syslog : %s",
                             stripped[:80])
            return None

        ts_str, source_host, program, pid, message = envelope

        # 2. Vérifier que c'est bien un processus web (dolibarr / apache / httpd)
        program_lower = program.lower()
        if program_lower not in ("dolibarr", "apache2", "httpd"):
            if self.debug:
                logger.debug("Programme '%s' ignoré par WebParser", program)
            return None

        # 3. Parser le Combined Log Format
        combined = self._parse_combined(message)
        if combined is None:
            if self.debug:
                logger.debug("Message non reconnu par Combined Log : %s",
                             message[:80])
            return None

        # 4. Convertir le timestamp
        try:
            timestamp = self.parse_timestamp(ts_str)
        except ValueError:
            if self.debug:
                logger.debug("Timestamp invalide '%s'", ts_str)
            return None

        # 5. Construire l'événement normalisé
        extra: dict = {
            "http_method":  combined["method"],
            "http_path":    combined["path"],
            "http_status":  int(combined["status"]),
            "user_agent":   combined["user_agent"] or None,
            "referer": combined["referer"] if combined["referer"] not in ("", "-") else None,
        }

        # response_size peut être "-" (pas de contenu)
        size = combined["size"]
        if size and size != "-":
            try:
                extra["response_size"] = int(size)
            except ValueError:
                extra["response_size"] = None
        else:
            extra["response_size"] = None

        # Injecter PID dans extra si présent
        if pid:
            extra["pid"] = pid

        return {
            "timestamp":   timestamp,
            "source_host": source_host,
            "event_type":  "http_request",
            "actor_ip":    combined["ip"],
            "actor_user":  None,
            "target_host": None,
            "target_port": 80,
            "extra":       extra,
            "yara_match":  None,
            "raw_log":     stripped,
        }

    def _parse_envelope(self, line: str) -> tuple | None:
        """Extrait l'enveloppe syslog d'une ligne de log.

        Args:
            line: Ligne brute complète.

        Returns:
            Tuple (timestamp_str, host, program, pid, message) ou None.
        """
        # Tentative RFC 5424 d'abord, puis RFC 3164
        m = _RE_ENVELOPE_RFC5424.match(line)
        if not m:
            m = _RE_ENVELOPE_RFC3164.match(line)
        if not m:
            return None

        data = m.groupdict()
        return (
            data["timestamp"],
            data["host"],
            data["program"],
            data.get("pid"),
            data["message"],
        )

    def _parse_combined(self, message: str) -> dict | None:
        """Parse le message Apache Combined Log Format.

        Args:
            message: Corps du message syslog (sans enveloppe).

        Returns:
            Dict avec les champs extraits, ou None si le format est invalide.
        """
        m = _RE_COMBINED.match(message.strip())
        if not m:
            return None
        return m.groupdict()
