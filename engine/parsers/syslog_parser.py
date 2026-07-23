# parsers/syslog_parser.py
import json
import re
import logging
from parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)


class SyslogParser(BaseParser):
    """Parser syslog unifié pour les logs Debian/Linux de NyxSOC.

    Gère les processus : sshd, smbd, nmbd, apache2 (et variantes).
    Dispatch interne par le champ 'program' extrait de l'enveloppe syslog.
    Produit les event_types : ssh_failure, logon_success, samba_read,
    samba_write, smb_failure, http_request.

    Attributes:
        debug: Active le logging des lignes ignorées pour le débogage.
    """

    def __init__(self, debug: bool = False) -> None:
        """Initialise le parser syslog avec les regex compilées.

        Args:
            debug: Si True, loggue les lignes non parsées au niveau DEBUG.
        """
        self.debug = debug

        # --- Enveloppe syslog ---
        # RFC 5424 : 2026-06-19T10:23:41+00:00 host program[pid]: message
        self.RE_ENVELOPE_RFC5424 = re.compile(
            r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.]\d+)?(?:[+-]\d{2}:\d{2}|Z))"
            r"\s+(?P<host>[\w.\-]+)"
            r"\s+(?P<program>[\w.\-]+)"
            r"(?:\[(?P<pid>\d+)\])?:\s+"
            r"(?P<message>.*)$",
            re.DOTALL,
        )
        # RFC 3164 : Jun 19 10:23:41 host program[pid]: message
        self.RE_ENVELOPE_RFC3164 = re.compile(
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
            r"\s+(?P<host>[\w.\-]+)"
            r"\s+(?P<program>[\w.\-]+)"
            r"(?:\[(?P<pid>\d+)\])?:\s+"
            r"(?P<message>.*)$",
            re.DOTALL,
        )

        # --- SSH ---
        self.RE_SSH_FAIL = re.compile(
            r"Failed\s+\S+\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+"
            r"from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
        )
        self.RE_SSH_INVALID = re.compile(
            r"Invalid\s+user\s+(?P<user>\S*)\s+from\s+(?P<ip>[\d.]+)"
        )
        self.RE_SSH_SUCCESS = re.compile(
            r"Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
        )
        self.RE_SSH_DISCONNECT = re.compile(r"Disconnected|Connection closed|Connection reset")

        # --- Samba (smbd) ---
        # "dir1 wrote payload.exe on //commun from 10.0.1.50" (format audit smbd)
        self.RE_SMBD_WRITE = re.compile(
            r"(?P<user>\S+)\s+(?:wrote|stored|created|put)\s+(?P<filename>\S+)\s+on\s+(?P<share>//\S+)"
            r"(?:\s+from\s+(?P<ip>[\d.]+))?"
        )
        # "dir1 read payload.txt from //commun"
        self.RE_SMBD_READ = re.compile(
            r"(?P<user>\S+)\s+(?:read|opened|got)\s+(?P<filename>\S+)\s+(?:from|on)\s+(?P<share>//\S+)"
            r"(?:\s+from\s+(?P<ip>[\d.]+))?"
        )
        # Patterns alternatifs (smbd verbose / audit log)
        self.RE_SMBD_WRITE_ALT = re.compile(
            r"(?:open file|create file|store)\s.*?(?:for\s+write|write)",
            re.IGNORECASE,
        )
        self.RE_SMBD_READ_ALT = re.compile(
            r"(?:open file|read_data|get_attr)\s",
            re.IGNORECASE,
        )
        self.RE_SMBD_AUTH_FAIL = re.compile(
            r"(?:NT_STATUS_WRONG_PASSWORD|NT_STATUS_NO_SUCH_USER|NT_STATUS_LOGON_FAILURE"
            r"|authentication\s+failure|Failed\s+to\s+authenticate)",
            re.IGNORECASE,
        )
        # Extraction user+IP depuis les lignes smbd d'échec
        self.RE_SMBD_USER_IP = re.compile(
            r"(?:for\s+(?P<user>\S+)\s+from|user\s+(?P<user2>\S+))\s+(?P<ip>[\d.]+)"
        )

        # --- Apache2 / web ---
        # Format Combined Log : IP - - [date] "METHOD /path HTTP/1.1" status size
        self.RE_APACHE = re.compile(
            r'(?P<ip>[\d.]+)\s+-\s+-\s+\[[^\]]+\]\s+'
            r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
            r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
        )

    # ------------------------------------------------------------------
    # Méthode principale
    # ------------------------------------------------------------------

    def parse(self, line: str) -> dict | None:
        """Parse une ligne syslog Debian en événement normalisé.

        Args:
            line: Ligne brute issue de debian.log / srv-pme.log.

        Returns:
            Dict conforme au schéma EventNormalized, ou None si la ligne
            ne correspond à aucun pattern connu.
        """
        stripped = line.strip()
        if not stripped:
            return None

        # Tentative RFC 5424 d'abord, puis RFC 3164
        m = self.RE_ENVELOPE_RFC5424.match(stripped)
        if not m:
            m = self.RE_ENVELOPE_RFC3164.match(stripped)
        if not m:
            if self.debug:
                logger.debug("Enveloppe syslog non reconnue : %s", stripped[:100])
            return None

        data        = m.groupdict()
        ts_str      = data["timestamp"]
        source_host = data["host"]
        program     = data["program"].lower()
        pid         = data.get("pid")
        message     = data["message"]

        try:
            timestamp = self.parse_timestamp(ts_str)
        except ValueError:
            if self.debug:
                logger.debug("Timestamp invalide '%s'", ts_str)
            return None

        # Dispatcher par programme
        if program == "sshd":
            result = self._parse_sshd(message)
        elif program in ("smbd", "samba", "samba-audit"):
            if message.strip().startswith("{"):
                result = self._parse_samba_json(message)
            else:
                result = self._parse_smbd(message)
        elif program in ("apache2", "httpd"):
            result = self._parse_apache(message)
        elif program == "nmbd":
            return None  # bruit réseau Netbios — ignoré
        else:
            if self.debug:
                logger.debug("Programme '%s' ignoré", program)
            return None

        if result is None:
            return None

        event_type, actor_ip, actor_user, target_port, extra = result

        if event_type is None:
            return None

        # Injecter PID dans extra si présent
        if pid:
            extra = extra or {}
            extra["pid"] = pid

        return {
            "timestamp":   timestamp,
            "source_host": source_host,
            "event_type":  event_type,
            "actor_ip":    actor_ip,
            "actor_user":  actor_user,
            "target_host": None,
            "target_port": target_port,
            "extra":       extra if extra else None,
            "yara_match":  None,
            "raw_log":     stripped,
        }

    # ------------------------------------------------------------------
    # Sous-parsers par programme
    # ------------------------------------------------------------------

    def _parse_sshd(self, msg: str) -> tuple | None:
        """Parse un message sshd.

        Args:
            msg: Corps du message syslog du processus sshd.

        Returns:
            Tuple (event_type, actor_ip, actor_user, target_port, extra)
            ou None si la ligne est du bruit SSH.
        """
        # Échec SSH — "Failed password for root from 10.0.1.50 port 52341"
        m = self.RE_SSH_FAIL.search(msg)
        if m:
            user = m.group("user") or None
            # Convention stricte : "" → None
            if not user or user.strip() == "":
                user = None
            return (
                "ssh_failure",
                m.group("ip"),
                user,
                22,
                None,
            )

        # Utilisateur inexistant — "Invalid user foo from 10.0.1.50"
        m = self.RE_SSH_INVALID.search(msg)
        if m:
            user = m.group("user").strip() or None
            return "ssh_failure", m.group("ip"), user, 22, None

        # Connexion acceptée
        m = self.RE_SSH_SUCCESS.search(msg)
        if m:
            return (
                "logon_success",
                m.group("ip"),
                m.group("user"),
                22,
                None,
            )

        # Déconnexion / bruit — ignoré silencieusement
        if self.RE_SSH_DISCONNECT.search(msg):
            return None

        if self.debug:
            logger.debug("sshd message non reconnu : %s", msg[:80])
        return None

    def _parse_smbd(self, msg: str) -> tuple | None:
        """Parse un message smbd (Samba).

        Args:
            msg: Corps du message syslog du processus smbd.

        Returns:
            Tuple (event_type, actor_ip, actor_user, target_port, extra)
            ou None si non reconnu.
        """
        # Échec d'authentification Samba
        if self.RE_SMBD_AUTH_FAIL.search(msg):
            m_ui = self.RE_SMBD_USER_IP.search(msg)
            user = None
            ip   = None
            if m_ui:
                user = m_ui.group("user") or m_ui.group("user2")
                ip   = m_ui.group("ip")
            return "smb_failure", ip, user, 445, {"detail": msg[:120]}

        # Écriture fichier Samba (pattern principal)
        m = self.RE_SMBD_WRITE.search(msg)
        if m:
            return (
                "samba_write",
                m.group("ip"),
                m.group("user"),
                445,
                {
                    "filename": m.group("filename"),
                    "share":    m.group("share"),
                },
            )

        # Écriture fichier Samba (pattern alternatif smbd verbose)
        if self.RE_SMBD_WRITE_ALT.search(msg):
            return "samba_write", None, None, 445, {"detail": msg[:120]}

        # Lecture fichier Samba
        m = self.RE_SMBD_READ.search(msg)
        if m:
            return (
                "samba_read",
                m.group("ip"),
                m.group("user"),
                445,
                {
                    "filename": m.group("filename"),
                    "share":    m.group("share"),
                },
            )

        if self.RE_SMBD_READ_ALT.search(msg):
            return "samba_read", None, None, 445, None

        if self.debug:
            logger.debug("smbd message non reconnu : %s", msg[:80])
        return None

    def _parse_samba_json(self, msg: str) -> tuple | None:
        """Parse un log d'audit Samba au format JSON (Samba >= 4.12).
        
        Gère les EventIDs 4768 (TGT) et 4769 (TGS) pour la détection
        d'AS-REP Roasting et Kerberoasting.
        """
        try:
            data = json.loads(msg.strip())
        except json.JSONDecodeError:
            if self.debug:
                logger.debug("Samba JSON invalide : %s", msg[:80])
            return None

        auth = data.get("Authentication", {})
        event_id = auth.get("eventId")
        
        if event_id == 4768:
            event_type = "tgt_request"
        elif event_id == 4769:
            event_type = "tgs_request"
        else:
            return None
            
        ip = auth.get("remoteAddress", "")
        if ip.startswith("ipv4:"):
            ip = ip[5:]
        elif ip.startswith("ipv6:"):
            ip = ip[5:]
            
        if ":" in ip and not ip.startswith("["): 
            ip = ip.rsplit(":", 1)[0]
            
        user = auth.get("accountName")
        spn = auth.get("servicePrincipalName")
        
        extra = {"spn": spn} if spn else None
        
        return (event_type, ip or None, user or None, 88, extra)

    def _parse_apache(self, msg: str) -> tuple | None:
        """Parse un message apache2 (Combined Log Format).

        Args:
            msg: Corps du message syslog du processus apache2.

        Returns:
            Tuple (event_type, actor_ip, actor_user, target_port, extra)
            ou None si non reconnu.
        """
        m = self.RE_APACHE.search(msg)
        if not m:
            if self.debug:
                logger.debug("apache2 message non reconnu : %s", msg[:80])
            return None

        try:
            status = int(m.group("status"))
        except ValueError:
            status = 0

        return (
            "http_request",
            m.group("ip"),
            None,
            80,
            {
                "method":      m.group("method"),
                "path":        m.group("path"),
                "http_status": status,
            },
        )