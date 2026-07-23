# dispatcher.py
import logging
from pathlib import Path

from parsers.base_parser import BaseParser
from validator import EventValidator
from state_manager import StateManager
from yara_scanner import YaraScanner
from rule_engine import RuleEngine
from alerter import Alerter

logger = logging.getLogger(__name__)

# Répertoire de montage Samba par défaut
_SAMBA_MOUNT_BASE = "/mnt/samba"


class Dispatcher:
    """Consomme la queue et orchestre le pipeline de traitement.

    Le Dispatcher est le gardien du contrat de données :
    1. Route chaque ligne vers le bon parser via config.yaml
    2. Valide l'événement normalisé via EventValidator
    3. Enrichit avec YARA si event_type == 'samba_write'
    4. Stocke dans SQLite via StateManager
    5. Évalue les règles via RuleEngine
    6. Publie les alertes via Alerter

    Attributes:
        parsers: Dict {nom_fichier: BaseParser} chargé depuis config.yaml.
        validator: EventValidator partagé.
        state: StateManager partagé.
        yara: YaraScanner partagé.
        rule_engine: RuleEngine partagé.
        alerter: Alerter partagé.
        samba_mounts: Dict {share_name: mount_path} pour la résolution YARA.
    """

    def __init__(
        self,
        parsers: dict[str, BaseParser],
        validator: EventValidator,
        state: StateManager,
        yara: YaraScanner,
        rule_engine: RuleEngine,
        alerter: Alerter,
        samba_mounts: dict[str, str] | None = None,
    ) -> None:
        """Initialise le Dispatcher avec toutes ses dépendances injectées.

        Args:
            parsers: Mapping {filename: parser_instance}.
            validator: Validateur d'événements normalisés.
            state: Gestionnaire de persistance SQLite.
            yara: Scanner YARA pour les fichiers Samba.
            rule_engine: Moteur de règles de détection.
            alerter: Publieur d'alertes.
            samba_mounts: Mapping {share: mount_path} pour résoudre les
                chemins YARA depuis les noms de partage Samba.
        """
        self.parsers     = parsers
        self.validator   = validator
        self.state       = state
        self.yara        = yara
        self.rule_engine = rule_engine
        self.alerter     = alerter
        self.samba_mounts = samba_mounts or {}

    def dispatch(self, line: str, filename: str) -> None:
        """Traite un tuple (ligne, nom_fichier) issu de la queue.

        Séquence complète de traitement :
        1. Identifier le parser via filename
        2. Parser la ligne → dict | None
        3. Valider le schéma → rejeter si invalide
        4. Enrichir avec YARA si samba_write
        5. Stocker dans SQLite
        6. Évaluer les règles
        7. Publier les alertes

        Args:
            line: Ligne de log brute.
            filename: Nom du fichier source (ex: 'debian.log').
        """
        # 1. Trouver le parser pour ce fichier source
        parser = self.parsers.get(filename)
        if parser is None:
            logger.warning("Aucun parser configuré pour '%s' — ligne ignorée", filename)
            return

        # 2. Parser
        try:
            event = parser.parse(line)
        except Exception as exc:
            logger.error("Erreur parser pour '%s' : %s | line=%s", filename, exc, line[:80])
            return

        if event is None:
            return  # ligne ignorée silencieusement (bruit ou format inconnu)

        # 3. Valider le schéma
        if not self.validator.validate(event):
            # warning déjà loggué par EventValidator
            return

        # 4. Enrichissement YARA sur tout samba_write
        if event.get("event_type") == "samba_write":
            file_path = self._resolve_samba_path(event)
            if file_path:
                try:
                    yara_result = self.yara.scan(file_path)
                    event["yara_match"] = yara_result  # None ou dict
                except Exception as exc:
                    logger.error("Erreur YARA sur %s : %s", file_path, exc)
                    event["yara_match"] = None

        # 5. Stocker l'événement
        try:
            self.state.store_event(event)
        except Exception as exc:
            logger.error("Erreur stockage SQLite : %s | event_type=%s",
                         exc, event.get("event_type"))
            return

        # 6. Évaluer les règles
        try:
            alerts = self.rule_engine.process_event(event)
        except Exception as exc:
            logger.error("Erreur RuleEngine : %s | event=%s", exc, event.get("event_type"))
            alerts = None

        # 7. Publier les alertes
        if alerts:
            for alert in alerts:
                try:
                    self.alerter.send(alert)
                except Exception as exc:
                    logger.error("Erreur Alerter : %s | rule=%s", exc, alert.get("rule_id"))

    def _resolve_samba_path(self, event: dict) -> str | None:
        """Résout le chemin absolu d'un fichier Samba pour le scan YARA.

        Utilise le champ extra.share et extra.filename pour construire
        le chemin CIFS monté sur le SOC (/mnt/samba/<share>/<filename>).

        Args:
            event: Événement samba_write normalisé.

        Returns:
            Chemin absolu du fichier, ou None si non résolvable.
        """
        extra = event.get("extra") or {}
        filename = extra.get("filename")
        share    = extra.get("share", "")

        if not filename:
            return None

        # Extraire le nom du partage depuis "//commun" → "commun"
        share_name = share.lstrip("/").split("/")[0] if share else ""
        if share_name and share_name in self.samba_mounts:
            mount_path = self.samba_mounts[share_name]
            return str(Path(mount_path) / filename)

        # Fallback : chercher dans tous les montages
        for mount_path in self.samba_mounts.values():
            candidate = Path(mount_path) / filename
            if candidate.exists():
                return str(candidate)

        logger.debug("Impossible de résoudre le chemin Samba pour '%s' share='%s'",
                     filename, share)
        return None
