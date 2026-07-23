from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from soar.config.settings import settings
from soar.engine import DecisionEngine
from soar.handlers.handler import HANDLERS
from soar.models.alert import Alert
from soar.models.decision import Decision
from soar.models.response import Response
from soar.parser import AlertParser
from soar.watcher import AlertWatcher

logger = logging.getLogger("soar.orchestrator")


class AlertOrchestrator:
    def __init__(
        self,
        parser: Optional[AlertParser] = None,
        decision_engine: Optional[DecisionEngine] = None,
        watch_dir: Optional[Path] = None,
    ):
        self._parser = parser or AlertParser()
        self._engine = decision_engine or DecisionEngine()
        self._watch_dir = watch_dir or Path(settings.alerts_incoming)
        self._watcher: Optional[AlertWatcher] = None

    def start(self):
        self._watcher = AlertWatcher(
            watch_dir=self._watch_dir,
            parser=self._parser,
            on_alert=self._on_alert,
        )
        self._watcher.start()
        logger.info("Orchestrateur démarré sur %s", self._watch_dir)

    def stop(self):
        if self._watcher is not None:
            self._watcher.stop()
            logger.info("Orchestrateur arrêté")

    def _on_alert(self, alert: Alert):
        try:
            decision = self._engine.decide(alert)
        except Exception:
            logger.exception("Erreur décision pour %s", alert.alert_id)
            return

        handler = HANDLERS.get(decision.action)
        if handler is None:
            logger.warning(
                "Aucun handler pour action=%s (alert=%s)",
                decision.action, alert.alert_id,
            )
            return

        try:
            response = handler(alert, decision)
            self._on_response(response)
        except Exception:
            logger.exception("Erreur exécution handler pour %s", alert.alert_id)

    def _on_response(self, response: Response):
        logger.info(
            "Réponse: alert=%s action=%s status=%s latency=%dms",
            response.alert_id,
            response.action,
            response.status,
            response.latency_ms,
        )
