from __future__ import annotations

import logging
import signal
import sys
import threading
import time

from soar.db import initialize_db
from soar.logging import setup_soar_logging
from soar.notifications import Notifier
from soar.orchestrator import AlertOrchestrator

logger = logging.getLogger("soar.main")

_shutdown = threading.Event()
_DAILY_INTERVAL_S = 86400


def main():
    setup_soar_logging()
    logger.info("SOAR module démarré")

    try:
        initialize_db()
    except Exception:
        logger.exception("Échec de l'initialisation de la base de données")
        sys.exit(1)

    orchestrator = AlertOrchestrator()
    notifier = Notifier()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    scheduler = threading.Thread(
        target=_daily_loop,
        args=(notifier,),
        daemon=True,
        name="daily-summary",
    )
    scheduler.start()

    try:
        orchestrator.start()
        _shutdown.wait()
    finally:
        orchestrator.stop()
        logger.info("SOAR module arrêté")


def _signal_handler(signum, frame):
    sig_name = signal.Signals(signum).name
    logger.info("Signal %s reçu, arrêt en cours...", sig_name)
    _shutdown.set()


def _daily_loop(notifier: Notifier):
    while not _shutdown.is_set():
        _shutdown.wait(_DAILY_INTERVAL_S)
        if _shutdown.is_set():
            break
        try:
            notifier.send_daily_summary()
        except Exception:
            logger.exception("Erreur lors de l'envoi du résumé quotidien")
