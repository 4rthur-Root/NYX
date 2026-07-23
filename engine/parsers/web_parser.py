from base_parser import BaseParser
import re, logging

# Configuration du logger standard de Python
# Niveau par défaut: WARNING. On passera à DEBUG si besoin.
logger = logging.getLogger(__name__)
class WebParser(BaseParser):
    """
    Parser Syslog unifié avec dispatching par processus.
    
    Ce parser extrait les champs standard (timestamp, host, process, message) 
    et les transforme en événements normalisés (event_type, actor_user, actor_ip).
    Il gère les erreurs de formatage et fournit un mode debug.

    Attributes:
        debug (bool): Active le logging des lignes ignorées pour le débogage.
    """

    def __init__(self, debug: bool = False):
        """ 
        Initialise les patterns de regex pour les différents processus et configure le mode debug.
        Args:
            debug (bool): Si True, les lignes non parseées seront logguées au niveau DEBUG.
                          Par défaut à False pour éviter de surcharger les logs en production.
        """
        self.debug = debug

        # 1. Pattern Syslog Global (ISO 8601 avec timezone)
        self.WEB_PATTERN = re.compile(
            r'^(?P<timestamp_dol>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})\s+'
            r'(?P<host>[\w\.-]+)\s+'
            r'(?P<process>[\w_-]+)'
            r'(?:\[(?P<pid>\d+)\])?'
            r':\s+'
            r'(?P<ip>\S+)'
            r':\s+-:\s+'
            r'[(?P<timestamp_web>\d{2}/\S+/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\s+]'
            r'(?P<message>.*)$'
        )
        
        # 2. Sudo : USER et COMMAND
        self.SUDO_PATTERN = re.compile(r'USER=(?P<user>\S+).*COMMAND=(?P<cmd>.+)$')

        # 3. PAM Session : "session opened/closed for user <name>"
        self.PAM_SESSION_PATTERN = re.compile(
            r'session\s+(?P<status>\w+)'
            r'\s+for\s+user\s+'
            r'(?P<user>\S+)'
        )

        # 4. PAM Auth : Échec d'authentification
        self.PAM_AUTH_PATTERN = re.compile(
            r'(?:Failed\s+\w+\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)|'
            r'authentication\s+failure.*ruser=\S*\s+user=(?P<user_fail>\S+))',
            re.IGNORECASE
        )

        # 5. Samba : Détection d'actions (Error, Write, Read)
        self.SAMBA_ERROR_PATTERN = re.compile(r'Failed|error|denied|Permission denied', re.IGNORECASE)
        self.SAMBA_WRITE_PATTERN = re.compile(r'create file|open.*for.*write|wrote|store', re.IGNORECASE)
        self.SAMBA_READ_PATTERN = re.compile(r'open.*for.*read|read_data|get_attr', re.IGNORECASE)

        # 6. SSH : Succès et Échec
        self.SSH_SUCCESS_PATTERN = re.compile(r'Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)')
        self.SSH_FAILED_PATTERN = re.compile(
            r'Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d\.]+)'
        )

        # 7. Network : Événements réseau (ifup/down, link status)
        self.NETWORK_PATTERN = re.compile(r'RTNETLINK answers|No such process|Failed to bring up|link down', re.IGNORECASE)

    def _parse_samba(self, msg: str):
        """
        Analyse un message Samba pour déterminer le type d'événement et les détails.
        
        Args:
            msg (str): Le message syslog brut du processus Samba.
            
        Returns:
            tuple: Un tuple (event_type, extra_dict).
                   event_type peut être "smb_failure", "samba_write", "samba_read" ou None.
                   extra_dict contient les détails (ex: "action", "detail").
        """
        if self.SAMBA_ERROR_PATTERN.search(msg):
            return "smb_failure", {"detail": msg[:100]}
        
        if self.SAMBA_WRITE_PATTERN.search(msg):
            return "samba_write", {"action": "write"}
    
        if self.SAMBA_READ_PATTERN.search(msg):
            return "samba_read", {"action": "read"}
    
        return None, None

    def _parse_ssh(self, msg: str):
        """
        Analyse un message SSH pour déterminer le type de connexion (succès ou échec).
        
        Args:
            msg (str): Le message syslog brut du processus SSHD.
            
        Returns:
            tuple: Un tuple (event_type, actor_user, actor_ip).
                   event_type : "logon_success" ou "logon_failure".
                   actor_user / actor_ip : Les valeurs extraites ou None.
        """
        failed_detail = self.SSH_FAILED_PATTERN.search(msg)
        success_detail = self.SSH_SUCCESS_PATTERN.search(msg)
        
        if failed_detail:
            user = failed_detail.group("user")
            ip = failed_detail.group("ip")
            return "logon_failure", user, ip
        
        if success_detail:
            user = success_detail.group("user")
            ip = success_detail.group("ip")
            return "logon_success", user, ip
        
        return None, None, None

    def _parse_sudo(self, msg: str):
        """
        Analyse une entrée Sudo pour extraire l'utilisateur et la commande exécutée.
        
        Args:
            msg (str): Le message syslog brut du processus Sudo.
            
        Returns:
            tuple: Un tuple (event_type, actor_user, extra_dict).
                   event_type : "process_exec".
                   actor_user : L'utilisateur qui a exécuté la commande.
                   extra_dict : Contient la commande exécutée.
        """
        details = self.SUDO_PATTERN.search(msg)
        if details:
            user = details.group("user")
            cmd = details.group('cmd')
            return "process_exec", user, {"Command": cmd}
        return None, None, None

    def _parse_pam(self, msg: str):
        """
        Analyse un message PAM pour déterminer les événements de session ou d'auth.
        
        Args:
            msg (str): Le message syslog brut du processus PAM.
            
        Returns:
            tuple: Un tuple (event_type, actor_user, extra_dict).
                   event_type : "logon_success", "logoff_success", "logon_failure" ou None.
        """
        pam_session = self.PAM_SESSION_PATTERN.search(msg)
        pam_auth = self.PAM_AUTH_PATTERN.search(msg)

        if pam_session:
            status = pam_session.group("status")
            user = pam_session.group("user")
            
            if status == "opened":
                return "logon_success", user, None
            elif status == "closed":
                return "logoff_success", user, None
        
        if pam_auth:
            # Gestion des deux noms de groupe possibles (user ou user_fail)
            user = pam_auth.group("user") or pam_auth.group("user_fail")
            return "logon_failure", user, None

        return None, None, None

    def _parse_network(self, msg: str):
        """
        Analyse les événements réseau (link down, interface failure, etc.).
        
        Args:
            msg (str): Le message syslog brut du processus réseau.
            
        Returns:
            tuple: Un tuple (event_type, actor_user, extra_dict).
                   event_type : "net_connect" ou None.
                   extra_dict : Contient le texte d'erreur.
        """
        if self.NETWORK_PATTERN.search(msg):
            error_text = msg.split(':', 1)[-1].strip() if ':' in msg else msg
            return "net_connect", None, {"error": error_text}
        return None, None, None

    def parse(self, line: str):
        """
        Méthode principale de parsing d'une ligne syslog.
        
        Cette méthode décompose la ligne brute, identifie le processus, 
        appelle les sous-parsers correspondants et assemble le dictionnaire final,
        Loggue les erreurs si debug=True.
        
        Args:
            line (str): La ligne syslog brute à analyser.
            
        Returns:
            dict: Un dictionnaire structuré contenant :
                  - timestamp (int): Unix timestamp en millisecondes.
                  - source_host (str): Hôte émetteur.
                  - event_type (str): Type d'événement normalisé.
                  - actor_user (str | None): Utilisateur concerné.
                  - actor_ip (str | None): IP de l'acteur.
                  - target_host/target_port (None): Non utilisé pour ce parser.
                  - extra (dict | None): Champs spécifiques à la source.
                  - raw_log (str): La ligne brute originale.
        """
        analyzed_line = line.strip()
        
        if not analyzed_line:
            if self.debug:
                logger.debug("Ligne vide ignorée !")

            return None

        matching = self.SYSLOG_PATTERN.match(analyzed_line)
        
        if not matching:
            if self.debug:
                # Log uniquement la première ligne ignorée ou un compte pour éviter le spam
                logger.debug(f"Ligne non reconnue par SYSLOG_PATTERN : {analyzed_line[:100]}...")
            return None

        data = matching.groupdict()
        source_host = data['host']
        ts_str = data['timestamp']
        process = data['process']
        msg = data['message']
        pid = data['pid']
        
        # Initialisation des variables de sortie
        event_type = "unknown"
        actor_user = None
        actor_ip = None
        extra = {"PID": pid} if pid else {}

        # Dispatching intelligent selon le processus
        if process == "samba":
            evt, ext = self._parse_samba(msg)
            event_type = evt
            if ext: 
                extra.update(ext)
            
        elif process == "sudo":
            evt, user, ext = self._parse_sudo(msg)
            event_type = evt
            actor_user = user
            if ext: 
                extra.update(ext)
            
        elif process == "sshd":
            evt, user, ip = self._parse_ssh(msg)
            event_type = evt
            actor_user = user
            actor_ip = ip
            
        elif process in ("pam", "login", "systemd-logind"):
            evt, user, ext = self._parse_pam(msg)
            event_type = evt
            actor_user = user
            if ext: 
                extra.update(ext)
            
        elif process in ("networkd", "ifconfig", "dhclient"):
            evt, user, ext = self._parse_network(msg)
            event_type = evt
            actor_user = user
            if ext: 
                extra.update(ext)

        # Conversion du timestamp déléguée à BaseParser
        try:
            timestamp = self.parse_timestamp(ts_str)
        except ValueError:
            if self.debug:
                logger.debug(f"Timestamp invalide '{ts_str}' dans la ligne : {analyzed_line[:50]}...")
                logger.warning(f"Timestamp invalide pour {source_host}: {ts_str}")
            return None

        return {
            "timestamp": timestamp,
            "source_host": source_host,
            "event_type": event_type,
            "actor_ip": actor_ip,
            "actor_user": actor_user,
            "target_host": None,
            "target_port": None,
            "extra": extra if extra else None,
            "yara_match": None,
            "raw_log": analyzed_line
        }