from base_parser import BaseParser
import re, pyyaml
"""
{
    "timestamp":   int,         # Unix ms — OBLIGATOIRE
    "source_host": str,         # Hostname émetteur — OBLIGATOIRE
    "event_type":  str,         # Taxonomie fermée — OBLIGATOIRE
    "actor_ip":    str | None,
    "actor_user":  str | None,
    "target_host": str | None,
    "target_port": int | None,
    "extra":       dict | None, # Champs spécifiques source
    "yara_match":  dict | None, # Renseigné par Dispatcher sur samba_write
    "raw_log":     str,         # Ligne brute — OBLIGATOIRE
}
"""
class SyslogParser(BaseParser):
    """
    
    """
    def __init__(self):
        # 1. Pattern Syslog Global 
        self.SYSLOG_PATTERN = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2})\s+'
            r'(?P<host>[\w\.-]+)\s+'  # Ajout de '.' pour les FQDN
            r'(?P<process>[\w_-]+)'
            r'(?:\[(?P<pid>\d+)\])?'
            r':\s+'
            r'(?P<message>.*)$'
        )
        
        # 2. Sudo: Capture USER et COMMAND (jusqu'à la fin de la ligne)
        # Correction: .+ au lieu de \S+ pour la commande pour inclure les espaces et arguments
        self.SUDO_PATTERN = re.compile(r'USER=(?P<user>\S+).*COMMAND=(?P<cmd>.+)$')

        # 3. PAM Session: "session opened/closed for user <name>"
        self.PAM_SESSION_PATTERN = re.compile(
            r'session\s+(?P<status>\w+)'
            r'\s+for\s+user\s+'
            r'(?P<user>\S+)'
        )

        # 4. PAM Auth: Échec d'authentification
        # Optimisation: Capture le nom d'utilisateur dans un groupe unique 'user' peu importe la variante
        self.PAM_AUTH_PATTERN = re.compile(
            r'(?:Failed\s+\w+\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)|'
            r'authentication\s+failure.*ruser=\S*\s+user=(?P<user_fail>\S+))',
            re.IGNORECASE
        )

        # 5. Samba: Détection d'actions (Retourne un objet Match si trouvé, sinon None)
        # Inutile de compiler pour de simples recherches de mots-clés si on utilise search(), 
        # mais gardons la structure objet pour la cohérence.
        self.SAMBA_ERROR_PATTERN = re.compile(r'Failed|error|denied|Permission denied', re.IGNORECASE)
        self.SAMBA_WRITE_PATTERN = re.compile(r'create file|open.*for.*write|wrote|store', re.IGNORECASE)
        self.SAMBA_READ_PATTERN = re.compile(r'open.*for.*read|read_data|get_attr', re.IGNORECASE)

        # 6. SSH
        # Succès: "Accepted publickey/password for <user> from <ip>..."
        self.SSH_SUCCESS_PATTERN = re.compile(r'Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)')
        
        # Échec
        self.SSH_FAILED_PATTERN = re.compile(
            r'Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d\.]+)'
        )

        # 7. Network (ifdown/ifup/syslog réseau)
        self.NETWORK_PATTERN = re.compile(r'RTNETLINK answers|No such process|Failed to bring up|link down', re.IGNORECASE)

    # Fonctions utilitaires pour retourner event type , extra, actor_user etc 

    def _parse_samba(self, msg: str):
        # Ici, on suppose qu'une erreur empêche la lecture/écriture, donc on la check d'abord
        if "Failed" in msg or "error" in msg.lower():
            return "smb_failure", {"detail": msg[:100]}
    
        # Ensuite on cherche les actions positives
        if re.search(r'write|create|modify|rename', msg, re.IGNORECASE):
            return "samba_write", {"action": "write"}
    
        if re.search(r'\bopen\b.*\bfor\s+read\b|read|download', msg, re.IGNORECASE):
            return "samba_read", {"action": "read"}
    
        return None, None
    
    def _parse_ssh(self, msg: str):
        # Échec

        return
    
    def _parse_sudo(self):
        return
    
    def _parse_network(self):
        

        return 
    
    def _parse_pam(self):
        return
        
    def parse(self, line: str):
        analyzed_line = line.strip()
        matching = self.SYSLOG_PATTERN.match(analyzed_line)
        data = matching.groupdict()

        # Format inconnu ou ligne à ignorer
        if not analyzed_line or not matching :
            return None

        source_host = data['host']
        ts_str = data['timestamp']
        process = data['process']
        msg = matching.group('message')
        pid = matching.group('pid')

        
        # Dispatching par processus
        if process == "samba":
            event_type, extra = self._parse_samba(msg)

        # Extraction du timestamp
        try:
            timestamp = self.parse_timestamp(ts_str)
        except ValueError:
            return None

        
        return {
            "timestamp": timestamp,
            "source_host": source_host,
            "event_type": event_type,
            "actor_ip": actor_ip,
            "actor_user": actor_user,
            "target_host": None,
            "target_port": None,
            "extra": None,
            "yara_match": None,
            "raw_log": analyzed_line
        }
    
    