# parsers/base_parser.py
from abc import ABC, abstractmethod
from datetime import datetime

class BaseParser(ABC):
    """Contrat commun à tous les parsers Nyx.

    Tout parser concret doit implémenter parse(). 
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

        Supporte RFC 5424 (ISO 8601), RFC 3164 (BSD syslog),
        et le format NXLog Windows.

        Args:
            ts_str: Chaîne de timestamp à convertir.

        Returns:
            Timestamp Unix en millisecondes.

        Raises:
            ValueError: Si aucun format connu ne correspond.
        """
        dt = datetime.fromisoformat(ts_str)
        return int(dt.timestamp() * 1000)
