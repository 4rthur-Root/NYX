# parsers/base_parser.py
from abc import ABC, abstractmethod
from datetime import datetime, timezone
import calendar


class BaseParser(ABC):
    """Contrat commun à tous les parsers NyxSOC.

    Tout parser concret doit implémenter parse(). Le Dispatcher
    ne connaît que cette interface — principe de substitution de Liskov.
    """

    @abstractmethod
    def parse(self, line: str) -> dict | None:
        """Parse une ligne de log brute en événement normalisé.

        Args:
            line: Ligne brute issue du fichier source.

        Returns:
            Dict conforme au schéma EventNormalized, ou None si
            la ligne ne correspond à aucun pattern connu.
        """
        ...

    def parse_timestamp(self, ts_str: str) -> int:
        """Convertit un timestamp string en Unix millisecondes.

        Supporte RFC 5424 (ISO 8601 avec timezone), RFC 3164 (BSD syslog
        sans année) et le format NXLog Windows (ISO 8601 sans timezone).

        Args:
            ts_str: Chaîne de timestamp à convertir.

        Returns:
            Timestamp Unix en millisecondes.

        Raises:
            ValueError: Si aucun format connu ne correspond.
        """
        ts = ts_str.strip()

        # Formats ordonnés du plus précis au moins précis
        formats = [
            "%Y-%m-%dT%H:%M:%S%z",        # ISO 8601 avec offset  : 2026-06-19T10:23:41+00:00
            "%Y-%m-%dT%H:%M:%S.%f%z",     # ISO 8601 µs avec offset
            "%Y-%m-%dT%H:%M:%S",           # ISO 8601 naïf (NXLog) : 2026-06-19T10:23:41
            "%Y-%m-%dT%H:%M:%S.%f",        # ISO 8601 µs naïf
            "%b %d %H:%M:%S",              # BSD RFC 3164           : Jun 19 10:23:41
            "%b  %d %H:%M:%S",             # BSD RFC 3164 (jour <10): Jun  9 10:23:41
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(ts, fmt)
                if dt.tzinfo is None:
                    # Timestamps sans timezone → on suppose UTC
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt.year == 1900:
                    # RFC 3164 n'inclut pas l'année — on injecte l'année courante
                    now = datetime.now(tz=timezone.utc)
                    dt = dt.replace(year=now.year)
                    # Si le timestamp est dans le futur (changement d'année en fin déc.)
                    if dt > now:
                        dt = dt.replace(year=now.year - 1)
                return int(dt.timestamp() * 1000)
            except ValueError:
                continue

        raise ValueError(f"Format timestamp non reconnu : '{ts_str}'")
