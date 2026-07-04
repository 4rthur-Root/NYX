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
        # Initialisation du pattern syslog global
        self.SYSLOG_PATTERN = re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}\d{2})\s+(?P<host>[\w-]+)\s+(?P<process>[\w_-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$')
        
        """  Regex Spécifiques par Processus (pour extraire les entités)  """
        # Sudo: capture USER et COMMAND
        self.SUDO_PATTERN = re.compile(r'USER=(?P<user>\S+).*COMMAND=(?P<cmd>\S+)')
        
        # PAM/Sudo session: capture user et session status
        self.PAM_SESSION_PATTERN = re.compile(r'session\s+(?P<status>\S+)\s+for\s+user\s+(?P<user>\S+)')
        self.PAM_AUTH_PATTERN = re.compile(r'Failed\s+\w+.*for\s+(?:user\s+)?(?P<user>\S+)|authentication\s+failure.*for\s+(?:user\s+)?(?P<user_fail>\S+)')
        # Samba: capture erreurs ou actions
        self.SAMBA_ERROR_PATTERN = re.compile(r'Failed|error|Error')
        self.SAMBA_WRITE_PATTERN = re.compile(r'create|write|open.*for.*write', re.IGNORECASE)
        self.SAMBA_READ_PATTERN = re.compile(r'')
        self.SSH_SUCCESS_PATTERN = re.compile(r'Failed|Error|Success') 
        # Network (ifdown/ifup)
        self.NETWORK_PATTERN = re.compile(r'RTNETLINK|No such process|Failed to bring up')

    def _extract_(self):

        
    def parse(self, line: str):
        analyzed_line = line.strip()

        
        return {
            "timestamp": timestamp_ms,
            "source_host": source_host,
            "event_type": event_type,
            "actor_ip": actor_ip,
            "actor_user": actor_user,
            "target_host": None,
            "target_port": None,
            "extra": extra,
            "yara_match": None,
            "raw_log": analyzed_line
        }
    
    