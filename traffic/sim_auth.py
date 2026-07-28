"""Simulateur d'activité de connexion et d'authentification réseau légitime.

Génère des flux de connexion SSH/TCP réguliers et réussis pour simuler
l'activité des administrateurs et des services système.
"""

import logging
import random
import socket
import subprocess
import time

from traffic.config import JITTER_AUTH, SERVER_IP, SSH_PORT, USERS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [AUTH_SIM] %(message)s"
)
logger = logging.getLogger("sim_auth")


class AuthSimulator:
    """Générateur de bruit de fond pour les connexions réseau et l'authentification."""

    def __init__(self, target_ip: str = SERVER_IP) -> None:
        self.target_ip = target_ip

    def check_tcp_port(self, port: int) -> bool:
        """Effectue un handshake TCP basique (simulation ping/connexion réseau)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        try:
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            if result == 0:
                logger.info("Connexion TCP réussie sur %s:%d", self.target_ip, port)
                return True
            else:
                logger.debug("Port TCP fermé ou filtré sur %s:%d", self.target_ip, port)
                return False
        except Exception as e:
            logger.debug("Erreur test TCP %s:%d: %s", self.target_ip, port, e)
            return False

    def simulate_ssh_banner(self) -> None:
        """Connexion de contrôle SSH basique."""
        user = random.choice(USERS)
        logger.info("Simulation de session d'administration SSH pour l'utilisateur '%s'", user["user"])
        self.check_tcp_port(SSH_PORT)

    def run_loop(self, stop_event=None) -> None:
        """Boucle principale du simulateur d'authentification."""
        logger.info("Démarrage de la simulation d'authentification et réseau vers %s...", self.target_ip)

        while stop_event is None or not stop_event.is_set():
            action = random.choice(["ssh_check", "tcp_80", "tcp_445"])
            if action == "ssh_check":
                self.simulate_ssh_banner()
            elif action == "tcp_80":
                self.check_tcp_port(80)
            elif action == "tcp_445":
                self.check_tcp_port(445)

            sleep_time = random.uniform(*JITTER_AUTH)
            time.sleep(sleep_time)

        logger.info("Arrêt de la simulation d'authentification.")


if __name__ == "__main__":
    sim = AuthSimulator()
    sim.run_loop()
