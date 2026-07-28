"""Orchestrateur principal du générateur de trafic NyxSOC.

Coordonne et lance les modules de simulation (Web, Samba, Auth) dans des threads
indépendants. Permet un arrêt propre via Ctrl+C ou l'option --stop.
"""

import argparse
import logging
import signal
import sys
import threading
import time
from pathlib import Path

# Import dynamique des simulateurs du package traffic
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sim_auth import AuthSimulator
from sim_samba import SambaSimulator
from sim_web import WebSimulator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [TRAFFIC_ORCHESTRATOR] %(message)s"
)
logger = logging.getLogger("orchestrator")


class TrafficOrchestrator:
    """Orchestrateur global pour la génération de bruit de fond."""

    def __init__(self, mode: str = "all") -> None:
        self.mode = mode
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []

    def stop(self) -> None:
        """Arrête proprement tous les threads de simulation."""
        logger.info("Signal d'arrêt reçu. Fermeture des simulateurs de bruit...")
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=5.0)
        logger.info("Tous les simulateurs sont arrêtés.")

    def run(self) -> None:
        """Lance l'orchestrateur et attend les signaux d'arrêt."""
        logger.info("=== NYX Traffic Noise Generator ===")
        logger.info("Mode sélectionné: %s", self.mode)

        web_sim = WebSimulator()
        samba_sim = SambaSimulator()
        auth_sim = AuthSimulator()

        if self.mode in ("all", "web"):
            t_web = threading.Thread(
                target=web_sim.run_loop, args=(self.stop_event,), daemon=True, name="Sim-Web"
            )
            self.threads.append(t_web)

        if self.mode in ("all", "samba"):
            t_samba = threading.Thread(
                target=samba_sim.run_loop, args=(self.stop_event,), daemon=True, name="Sim-Samba"
            )
            self.threads.append(t_samba)

        if self.mode in ("all", "auth"):
            t_auth = threading.Thread(
                target=auth_sim.run_loop, args=(self.stop_event,), daemon=True, name="Sim-Auth"
            )
            self.threads.append(t_auth)

        for thread in self.threads:
            thread.start()
            logger.info("Thread '%s' démarré.", thread.name)

        def signal_handler(sig, frame):
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        logger.info("Générateur en cours d'exécution. Appuyez sur Ctrl+C pour arrêter.")

        try:
            while not self.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Générateur de bruit de fond NYX SOC")
    parser.add_argument(
        "--mode",
        choices=["all", "web", "samba", "auth"],
        default="all",
        help="Sélectionner le mode de simulation à exécuter (défaut: all)",
    )
    args = parser.parse_args()

    orchestrator = TrafficOrchestrator(mode=args.mode)
    orchestrator.run()


if __name__ == "__main__":
    main()
