# parsers/windows_parser.py
import logging
import re
import xml.etree.ElementTree as ET
from parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)

# Namespace XML Windows EventLog
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# EventIDs Sysmon et Windows Security Log gérés
_HANDLED_EVENT_IDS = {"1", "3", "11", "4624", "4625"}

# Pattern enveloppe syslog NXLog
_RE_NXLOG_ENVELOPE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2})?)"
    r"\s+(?P<host>[\w\.-]+)"
    r"\s+(?P<program>\S+)"
    r"(?:\[(?P<pid>\d+)\])?:"
    r"\s+(?P<xml_payload><Event.+>)\s*$",
    re.DOTALL,
)


class WindowsParser(BaseParser):
    """Parser pour les logs Windows EventLog transmis via NXLog en syslog.

    Déshabille l'enveloppe syslog NXLog puis parse le XML interne
    (Windows EventLog + Sysmon). Gère les EventIDs :
    - 4624 → logon_success
    - 4625 → logon_failure
    - 1    → process_exec  (Sysmon)
    - 3    → net_connect   (Sysmon)
    - 11   → file_create   (Sysmon)

    Attributes:
        debug: Active le logging des lignes ignorées.
    """

    def __init__(self, debug: bool = False) -> None:
        """Initialise le parser Windows.

        Args:
            debug: Si True, loggue les lignes non reconnues au niveau DEBUG.
        """
        self.debug = debug

    def parse(self, line: str) -> dict | None:
        """Parse une ligne syslog NXLog contenant un XML EventLog Windows.

        Args:
            line: Ligne brute issue de DESKTOP-PME.log.

        Returns:
            Dict conforme au schéma EventNormalized, ou None si la ligne
            ne correspond pas à un événement Windows géré.
        """
        stripped = line.strip()
        if not stripped:
            return None

        m = _RE_NXLOG_ENVELOPE.match(stripped)
        if not m:
            if self.debug:
                logger.debug("Ligne non reconnue par l'enveloppe NXLog : %s", stripped[:100])
            return None

        ts_str      = m.group("timestamp")
        source_host = m.group("host")
        xml_payload = m.group("xml_payload")

        try:
            timestamp = self.parse_timestamp(ts_str)
        except ValueError:
            if self.debug:
                logger.debug("Timestamp invalide '%s'", ts_str)
            return None

        return self._parse_xml(xml_payload, timestamp, source_host, stripped)

    def _parse_xml(
        self,
        xml_str: str,
        timestamp: int,
        source_host: str,
        raw_log: str,
    ) -> dict | None:
        """Parse le XML Windows EventLog et construit l'événement normalisé.

        Args:
            xml_str: Contenu XML brut de l'événement Windows.
            timestamp: Timestamp Unix ms extrait de l'enveloppe syslog.
            source_host: Hostname Windows émetteur.
            raw_log: Ligne brute complète pour l'audit.

        Returns:
            Dict normalisé ou None si l'EventID n'est pas géré.
        """
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as exc:
            if self.debug:
                logger.debug("XML invalide : %s — %s", exc, xml_str[:80])
            return None

        # Extraire EventID depuis System/EventID
        event_id_el = root.find("e:System/e:EventID", _NS)
        if event_id_el is None:
            # Essai sans namespace (certaines versions NXLog omettent le ns)
            event_id_el = root.find("System/EventID")
        if event_id_el is None or event_id_el.text is None:
            return None

        event_id = event_id_el.text.strip()
        if event_id not in _HANDLED_EVENT_IDS:
            if self.debug:
                logger.debug("EventID %s ignoré (non géré)", event_id)
            return None

        # Extraire le Computer si disponible (peut différer du source_host syslog)
        computer_el = root.find("e:System/e:Computer", _NS)
        if computer_el is None:
            computer_el = root.find("System/Computer")
        host = computer_el.text.strip() if (computer_el is not None and computer_el.text) else source_host

        # Helper : récupérer un champ EventData par son attribut Name
        def get_data(name: str) -> str | None:
            for el in root.iter():
                if el.get("Name") == name and el.text:
                    return el.text.strip()
            return None

        # Dispatcher selon EventID
        if event_id == "4624":
            return self._build_logon_success(get_data, timestamp, host, raw_log)
        if event_id == "4625":
            return self._build_logon_failure(get_data, timestamp, host, raw_log)
        if event_id == "1":
            return self._build_process_exec(get_data, timestamp, host, raw_log)
        if event_id == "3":
            return self._build_net_connect(get_data, timestamp, host, raw_log)
        if event_id == "11":
            return self._build_file_create(get_data, timestamp, host, raw_log)

        return None  # pragma: no cover

    # ------------------------------------------------------------------
    # Builders par EventID
    # ------------------------------------------------------------------

    @staticmethod
    def _build_logon_success(get_data, timestamp: int, host: str, raw_log: str) -> dict:
        """Construit un événement logon_success depuis EventID 4624.

        Args:
            get_data: Callable récupérant un champ EventData par nom.
            timestamp: Timestamp Unix ms.
            host: Hostname Windows.
            raw_log: Ligne brute.

        Returns:
            Dict normalisé event_type='logon_success'.
        """
        user = get_data("TargetUserName")
        ip   = get_data("IpAddress")
        logon_type = get_data("LogonType")
        return {
            "timestamp":   timestamp,
            "source_host": host,
            "event_type":  "logon_success",
            "actor_ip":    ip if (ip and ip != "-") else None,
            "actor_user":  user if (user and user not in ("", "-")) else None,
            "target_host": host,
            "target_port": None,
            "extra":       {"logon_type": logon_type} if logon_type else None,
            "yara_match":  None,
            "raw_log":     raw_log,
        }

    @staticmethod
    def _build_logon_failure(get_data, timestamp: int, host: str, raw_log: str) -> dict:
        """Construit un événement logon_failure depuis EventID 4625.

        Args:
            get_data: Callable récupérant un champ EventData par nom.
            timestamp: Timestamp Unix ms.
            host: Hostname Windows.
            raw_log: Ligne brute.

        Returns:
            Dict normalisé event_type='logon_failure'.
        """
        user = get_data("TargetUserName")
        ip   = get_data("IpAddress")
        return {
            "timestamp":   timestamp,
            "source_host": host,
            "event_type":  "logon_failure",
            "actor_ip":    ip if (ip and ip != "-") else None,
            "actor_user":  user if (user and user not in ("", "-")) else None,
            "target_host": host,
            "target_port": None,
            "extra":       None,
            "yara_match":  None,
            "raw_log":     raw_log,
        }

    @staticmethod
    def _build_process_exec(get_data, timestamp: int, host: str, raw_log: str) -> dict:
        """Construit un événement process_exec depuis Sysmon EventID 1.

        Args:
            get_data: Callable récupérant un champ EventData par nom.
            timestamp: Timestamp Unix ms.
            host: Hostname Windows.
            raw_log: Ligne brute.

        Returns:
            Dict normalisé event_type='process_exec'.
        """
        image     = get_data("Image")
        user      = get_data("User")
        hashes    = get_data("Hashes")
        cmdline   = get_data("CommandLine")
        parent    = get_data("ParentImage")
        logon_id  = get_data("LogonId")

        # Extraire le hash MD5 depuis la chaine "MD5=abc123,SHA256=..."
        file_hash = None
        if hashes:
            for part in hashes.split(","):
                if part.upper().startswith("MD5="):
                    file_hash = "md5:" + part.split("=", 1)[1].lower()
                    break

        extra: dict = {}
        if image:
            extra["process_path"] = image
        if file_hash:
            extra["process_hash"] = file_hash
        if cmdline:
            extra["cmdline"] = cmdline
        if parent:
            extra["parent_image"] = parent
        if logon_id:
            extra["logon_id"] = logon_id

        return {
            "timestamp":   timestamp,
            "source_host": host,
            "event_type":  "process_exec",
            "actor_ip":    None,
            "actor_user":  user if user else None,
            "target_host": None,
            "target_port": None,
            "extra":       extra if extra else None,
            "yara_match":  None,
            "raw_log":     raw_log,
        }

    @staticmethod
    def _build_net_connect(get_data, timestamp: int, host: str, raw_log: str) -> dict:
        """Construit un événement net_connect depuis Sysmon EventID 3.

        Args:
            get_data: Callable récupérant un champ EventData par nom.
            timestamp: Timestamp Unix ms.
            host: Hostname Windows.
            raw_log: Ligne brute.

        Returns:
            Dict normalisé event_type='net_connect'.
        """
        src_ip   = get_data("SourceIp")
        dst_ip   = get_data("DestinationIp")
        dst_port = get_data("DestinationPort")
        image    = get_data("Image")
        user     = get_data("User")

        try:
            dport = int(dst_port) if dst_port else None
        except ValueError:
            dport = None

        extra: dict = {}
        if dst_ip:
            extra["dst_ip"] = dst_ip
        if image:
            extra["process_path"] = image

        return {
            "timestamp":   timestamp,
            "source_host": host,
            "event_type":  "net_connect",
            "actor_ip":    src_ip if src_ip else None,
            "actor_user":  user if user else None,
            "target_host": None,
            "target_port": dport,
            "extra":       extra if extra else None,
            "yara_match":  None,
            "raw_log":     raw_log,
        }

    @staticmethod
    def _build_file_create(get_data, timestamp: int, host: str, raw_log: str) -> dict:
        """Construit un événement file_create depuis Sysmon EventID 11.

        Args:
            get_data: Callable récupérant un champ EventData par nom.
            timestamp: Timestamp Unix ms.
            host: Hostname Windows.
            raw_log: Ligne brute.

        Returns:
            Dict normalisé event_type='file_create'.
        """
        target_file = get_data("TargetFilename")
        image       = get_data("Image")
        user        = get_data("User")

        extra: dict = {}
        if target_file:
            extra["target_filename"] = target_file
        if image:
            extra["process_path"] = image

        return {
            "timestamp":   timestamp,
            "source_host": host,
            "event_type":  "file_create",
            "actor_ip":    None,
            "actor_user":  user if user else None,
            "target_host": None,
            "target_port": None,
            "extra":       extra if extra else None,
            "yara_match":  None,
            "raw_log":     raw_log,
        }
