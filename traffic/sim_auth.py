"""Simulateur d'activité SSH légitime.

Établit de VRAIES sessions SSH (connexion, une commande anodine, déconnexion
propre) pour l'utilisateur système 'server' — pas de simples handshakes TCP
répétés, qui ressembleraient à un balayage de ports (comportement de
reconnaissance, cf. S2) plutôt qu'à une authentification légitime.

Nécessite le paquet Python 'paramiko' (pip install paramiko).
"""

import logging
import random
import time

from traffic.config import JITTER_AUTH, SERVER_IP, SSH_PORT, SSH_USER
from traffic.time_utils import sleep_with_workday_jitter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [AUTH_SIM] %(message)s"
)
logger = logging.getLogger("sim_auth")

try:
    import paramiko
except ImportError:
    paramiko = None

# Commandes anodines de contrôle système (ce qu'un admin ferait en vérif rapide)
BENIGN_COMMANDS = [
    "uptime",
    "df -h",
    "whoami",
    "date",
    "echo ok",
]


class AuthSimulator:
    """Générateur de bruit de fond de sessions SSH réelles et courtes."""

    def __init__(self, target_ip: str = SERVER_IP, port: int = SSH_PORT) -> None:
        self.target_ip = target_ip
        self.port = port
        if paramiko is None:
            logger.error(
                "paramiko non installé. Installe-le avec: pip3 install paramiko --break-system-packages"
            )

    def simulate_ssh_session(self) -> bool:
        """Ouvre une session SSH réelle, exécute une commande anodine, ferme proprement."""
        if paramiko is None:
            logger.debug("paramiko indisponible, session ignorée.")
            return False

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=self.target_ip,
                port=self.port,
                username=SSH_USER["user"],
                password=SSH_USER["pass"],
                timeout=5,
                banner_timeout=5,
                auth_timeout=5,
            )
            cmd = random.choice(BENIGN_COMMANDS)
            stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
            _ = stdout.read()
            logger.info("Session SSH pour '%s' -> commande '%s' exécutée", SSH_USER["user"], cmd)
            return True
        except Exception as e:
            logger.debug("Échec session SSH: %s", e)
            return False
        finally:
            client.close()

    def run_loop(self, stop_event=None) -> None:
        logger.info(
            "Démarrage de la simulation de sessions SSH légitimes vers %s...", self.target_ip
        )

        while stop_event is None or not stop_event.is_set():
            self.simulate_ssh_session()
            sleep_with_workday_jitter(JITTER_AUTH, stop_event)

        logger.info("Arrêt de la simulation d'authentification.")


if __name__ == "__main__":
    sim = AuthSimulator()
    sim.run_loop()