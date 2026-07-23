# validator.py
import json
import logging
from pathlib import Path

import jsonschema

logger = logging.getLogger(__name__)

# Schéma inline de l'événement normalisé — source de vérité unique
_EVENT_SCHEMA: dict = {
    "type": "object",
    "required": ["timestamp", "source_host", "event_type", "raw_log"],
    "properties": {
        "timestamp":   {"type": "integer"},
        "source_host": {"type": "string", "minLength": 1},
        "event_type":  {"type": "string", "minLength": 1},
        "actor_ip":    {"type": ["string", "null"]},
        "actor_user":  {"type": ["string", "null"]},
        "target_host": {"type": ["string", "null"]},
        "target_port": {"type": ["integer", "null"]},
        "extra":       {"type": ["object", "null"]},
        "yara_match":  {"type": ["object", "null"]},
        "raw_log":     {"type": "string", "minLength": 1},
    },
    "additionalProperties": False,
}

# Taxonomie fermée des event_types acceptés
_VALID_EVENT_TYPES = {
    "ssh_failure", "logon_success", "logon_failure",
    "samba_read", "samba_write", "smb_failure",
    "http_request", "net_scan", "firewall_block",
    "file_create", "process_exec", "net_connect",
}


class EventValidator:
    """Valide les événements normalisés produits par les parsers.

    Encapsule jsonschema.validate() contre le schéma EventNormalized.
    Responsabilité unique : garantir la conformité des dicts avant
    leur insertion dans SQLite et leur passage au RuleEngine.
    """

    def validate(self, event: dict) -> bool:
        """Valide un événement normalisé contre le schéma EventNormalized.

        Args:
            event: Dict produit par un parser concret.

        Returns:
            True si l'événement est conforme, False sinon.
        """
        try:
            jsonschema.validate(instance=event, schema=_EVENT_SCHEMA)
        except jsonschema.ValidationError as exc:
            logger.warning("Événement invalide : %s | event_type=%s",
                           exc.message, event.get("event_type", "?"))
            return False

        # Vérification supplémentaire : event_type doit être dans la taxonomie
        if event.get("event_type") not in _VALID_EVENT_TYPES:
            logger.warning("event_type '%s' hors taxonomie — événement rejeté",
                           event.get("event_type"))
            return False

        return True
