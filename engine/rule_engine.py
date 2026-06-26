import pyyaml    # chargement des règles YAML
import time      # timestamps courants
import fnmatch   # matching du source_host_pattern (debian*, DESKTOP*)

class RuleEngine:
    def process_event(self, event: dict) -> list[dict] | None:
        # Reçoit un événement normalisé
        # Retourne une liste d'alertes déclenchées | None