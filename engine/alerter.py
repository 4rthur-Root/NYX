# alerter.py
import json
import logging
import os
import tempfile
import time
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)


class Alerter:
    """Publie les alertes produites par le RuleEngine.

    Responsabilité unique : recevoir une alerte dict et la router
    selon sa sévérité :
    - WARNING  → alerts.log uniquement
    - CRITICAL → alerts.log + écriture atomique alert_<uuid>.json

    L'écriture atomique garantit que le SOAR (watchdog inotify) ne
    verra jamais un fichier JSON partiellement écrit.

    Attributes:
        alerts_dir: Répertoire de sortie pour les fichiers alert_*.json.
        alerts_log: Chemin du fichier de log textuel des alertes.
    """

    def __init__(self, alerts_dir: str, alerts_log: str) -> None:
        """Initialise l'Alerter et crée les répertoires nécessaires.

        Args:
            alerts_dir: Chemin absolu du répertoire /var/log/nyxsoc/alerts/.
            alerts_log: Chemin absolu du fichier de log /var/log/nyxsoc/engine.log.
        """
        self.alerts_dir = Path(alerts_dir)
        self.alerts_dir.mkdir(parents=True, exist_ok=True)

        self._log_path = Path(alerts_log)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

        # Handler fichier dédié aux alertes (séparé du logger principal)
        self._alert_logger = logging.getLogger("nyxsoc.alerts")
        if not self._alert_logger.handlers:
            fh = logging.FileHandler(str(self._log_path))
            fh.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s"
            ))
            self._alert_logger.addHandler(fh)
            self._alert_logger.setLevel(logging.DEBUG)
            self._alert_logger.propagate = False

    def send(self, alert: dict) -> None:
        """Route une alerte selon sa sévérité.

        Args:
            alert: Dict conforme au schéma alert-schema.json, produit
                par le RuleEngine. Doit contenir au minimum 'severity',
                'rule_id' et 'alert_id'.
        """
        severity = alert.get("severity", "WARNING")
        rule_id  = alert.get("rule_id", "UNKNOWN")

        if severity == "WARNING":
            self._log_warning(alert)
            logger.info("[WARNING] Alerte générée : rule=%s", rule_id)

        elif severity == "CRITICAL":
            self._log_warning(alert)
            self._write_json(alert)
            logger.info("[CRITICAL] Alerte écrite : rule=%s | alert_id=%s",
                        rule_id, alert.get("alert_id"))
        else:
            logger.error("Sévérité inconnue '%s' pour la règle %s", severity, rule_id)

    # ------------------------------------------------------------------
    # Helpers privés
    # ------------------------------------------------------------------

    def _log_warning(self, alert: dict) -> None:
        """Loggue l'alerte dans le fichier alerts.log.

        Args:
            alert: Dict de l'alerte à journaliser.
        """
        severity  = alert.get("severity", "?")
        rule_id   = alert.get("rule_id", "?")
        attacker  = alert.get("attacker_ip", "?")
        target    = alert.get("target_host", "?")
        self._alert_logger.warning(
            "[%s] rule=%s | attacker=%s | target=%s | alert_id=%s",
            severity, rule_id, attacker, target, alert.get("alert_id", "?"),
        )

    def _write_json(self, alert: dict) -> None:
        """Écrit l'alerte en JSON de façon atomique dans alerts_dir.

        Utilise write-to-temp + os.rename (atomique sur Linux, même fs).
        Le SOAR ne peut jamais observer un fichier partiellement écrit.

        Args:
            alert: Dict de l'alerte CRITICAL à écrire.
        """
        alert_id = alert.get("alert_id", str(uuid.uuid4()))
        target   = self.alerts_dir / f"alert_{alert_id}.json"

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=str(self.alerts_dir),
                delete=False,
                suffix=".tmp",
                encoding="utf-8",
            ) as f:
                json.dump(alert, f, indent=2, ensure_ascii=False)
                tmp_path = f.name

            os.rename(tmp_path, str(target))
            logger.debug("Alert JSON écrit : %s", target)

        except OSError as exc:
            logger.error("Impossible d'écrire alert_%s.json : %s", alert_id, exc)
            # Nettoyage du fichier temp si rename a échoué
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:  # pragma: no cover
                pass


def build_alert(
    rule: dict,
    events: list[dict],
    attacker_ip: str | None = None,
    target_host: str = "",
    target_ip: str = "",
    yara_match: dict | None = None,
) -> dict:
    """Construit un dict d'alerte conforme au schéma alert-schema.json.

    Appelée par le RuleEngine avant de passer l'alerte à l'Alerter.
    Applique la règle de troncature events.details (≤5 → tous, >5 → 2+2).

    Args:
        rule: Dict de la règle YAML déclenchée.
        events: Liste des événements ayant déclenché la règle.
        attacker_ip: IP de l'attaquant (None si attaque interne).
        target_host: Hostname cible.
        target_ip: IP cible.
        yara_match: Résultat YARA si applicable, None sinon.

    Returns:
        Dict conforme au schéma alert-schema.json.
    """
    count   = len(events)
    details = _truncate_events(events)

    # Extraire le champ technique MITRE (sans sous-technique pour le schéma strict)
    mitre_technique = rule.get("mitre_technique", "T0000")
    if "." in mitre_technique:
        mitre_technique = mitre_technique.split(".")[0]

    return {
        "alert_id":        str(uuid.uuid4()),
        "timestamp":       int(time.time() * 1000),
        "rule_id":         rule["rule_id"],
        "severity":        rule["severity"],
        "attacker_ip":     attacker_ip,
        "target_host":     target_host,
        "target_ip":       target_ip,
        "target_resource": None,
        "mitre_tactic":    rule.get("mitre_tactic", "TA0000"),
        "mitre_technique": mitre_technique,
        "events": {
            "count":   count,
            "details": details,
        },
        "yara_match": yara_match,
    }


def _truncate_events(events: list[dict]) -> list[dict]:
    """Applique la règle de troncature events.details.

    ≤5 événements → tous gardés.
    >5 → 2 premiers + 2 derniers + count total dans 'events.count'.

    Args:
        events: Liste complète des événements.

    Returns:
        Liste tronquée de dicts simplifiés pour alert.json.
    """
    def _slim(e: dict) -> dict:
        return {
            "timestamp":   e.get("timestamp"),
            "event_type":  e.get("event_type"),
            "source_host": e.get("source_host"),
            "actor_user":  e.get("actor_user"),
            "raw_log":     e.get("raw_log", ""),
        }

    if len(events) <= 5:
        return [_slim(e) for e in events]
    return [_slim(e) for e in events[:2]] + [_slim(e) for e in events[-2:]]