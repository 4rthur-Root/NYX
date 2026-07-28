"""Simulateur de trafic Web / ERP Dolibarr légitime.

Génère des requêtes HTTP (GET/POST) réalistes avec gestion de cookies,
User-Agents rotatifs et pauses aléatoires (jitter) pour simuler la navigation d'un employé.
"""

import http.cookiejar
import logging
import random
import time
import urllib.parse
import urllib.request
from typing import Optional

from config import (
    DOLIBARR_BASE_URL,
    DOLIBARR_ENDPOINTS,
    JITTER_WEB,
    USER_AGENTS,
    USERS,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [WEB_SIM] %(message)s"
)
logger = logging.getLogger("sim_web")


class WebSimulator:
    """Générateur de bruit de fond HTTP / Web."""

    def __init__(self) -> None:
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj)
        )

    def _get_headers(self) -> dict[str, str]:
        """Génère des en-têtes HTTP réalistes."""
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
            "Connection": "keep-alive",
        }

    def simulate_page_visit(self, endpoint: str) -> Optional[int]:
        """Effectue une requête GET sur un endpoint spécifique."""
        url = f"{DOLIBARR_BASE_URL}{endpoint}"
        req = urllib.request.Request(url, headers=self._get_headers())
        try:
            with self.opener.open(req, timeout=5) as response:
                status = response.getcode()
                logger.info("Visite %s -> HTTP %d", endpoint, status)
                return status
        except Exception as e:
            logger.debug("Erreur accès page %s: %s", url, e)
            return None

    def simulate_login_attempt(self) -> bool:
        """Simule une tentative de connexion réussie avec un utilisateur légitime."""
        user = random.choice(USERS)
        login_url = f"{DOLIBARR_BASE_URL}/index.php"
        data = urllib.parse.urlencode({
            "username": user["user"],
            "password": user["pass"],
            "actionlogin": "login"
        }).encode("utf-8")

        headers = self._get_headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        req = urllib.request.Request(login_url, data=data, headers=headers)
        try:
            with self.opener.open(req, timeout=5) as response:
                logger.info("Connexion simulée pour '%s' -> HTTP %d", user["user"], response.getcode())
                return True
        except Exception as e:
            logger.debug("Échec connexion simulée '%s': %s", user["user"], e)
            return False

    def run_loop(self, stop_event=None) -> None:
        """Boucle principale du simulateur Web."""
        logger.info("Démarrage de la simulation du trafic Web sur %s", DOLIBARR_BASE_URL)
        
        # Connexion initiale
        self.simulate_login_attempt()

        while stop_event is None or not stop_event.is_set():
            endpoint = random.choice(DOLIBARR_ENDPOINTS)
            self.simulate_page_visit(endpoint)

            # Une fois de temps en temps, on simule une reconnexion
            if random.random() < 0.1:
                self.simulate_login_attempt()

            sleep_time = random.uniform(*JITTER_WEB)
            time.sleep(sleep_time)

        logger.info("Arrêt de la simulation Web.")


if __name__ == "__main__":
    sim = WebSimulator()
    sim.run_loop()
