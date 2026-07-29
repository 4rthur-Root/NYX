"""Simulateur de trafic Web / ERP Dolibarr légitime.

Génère des requêtes HTTP (GET/POST) réalistes avec gestion de cookies,
User-Agents rotatifs et pauses aléatoires (jitter) pour simuler la
navigation d'un employé (dir1, compta1, ou tech1).
"""

import logging
import random
import time
import urllib.parse
import urllib.request
import http.cookiejar
from typing import Optional

from traffic.config import (
    DOLIBARR_BASE_URL,
    DOLIBARR_ENDPOINTS,
    JITTER_WEB,
    USER_AGENTS,
    USERS,
)
from traffic.time_utils import sleep_with_workday_jitter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [WEB_SIM] %(message)s"
)
logger = logging.getLogger("sim_web")


class WebSimulator:
    """Générateur de bruit de fond HTTP / Web, un cookie jar par utilisateur simulé."""

    def __init__(self) -> None:
        # Un cookiejar + opener PAR utilisateur : évite de mélanger les
        # sessions de dir1/compta1/tech1 dans un seul jar partagé, ce qui
        # serait incohérent (un seul navigateur "partagé" par 3 employés).
        self._sessions: dict[str, tuple[http.cookiejar.CookieJar, urllib.request.OpenerDirector]] = {}
        for u in USERS:
            cj = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
            self._sessions[u["user"]] = (cj, opener)

    def _get_headers(self) -> dict[str, str]:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
            "Connection": "keep-alive",
        }

    def simulate_page_visit(self, user: str, endpoint: str) -> Optional[int]:
        """Effectue une requête GET sur un endpoint, avec la session du user donné."""
        _, opener = self._sessions[user]
        url = f"{DOLIBARR_BASE_URL}{endpoint}"
        req = urllib.request.Request(url, headers=self._get_headers())
        try:
            with opener.open(req, timeout=5) as response:
                status = response.getcode()
                logger.info("[%s] Visite %s -> HTTP %d", user, endpoint, status)
                return status
        except Exception as e:
            logger.debug("[%s] Erreur accès page %s: %s", user, url, e)
            return None

    def simulate_login(self, user_entry: dict) -> bool:
        """Simule une connexion réussie pour un utilisateur légitime donné."""
        user = user_entry["user"]
        _, opener = self._sessions[user]
        login_url = f"{DOLIBARR_BASE_URL}/index.php"
        data = urllib.parse.urlencode({
            "username": user,
            "password": user_entry["pass"],
            "actionlogin": "login",
        }).encode("utf-8")

        headers = self._get_headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        req = urllib.request.Request(login_url, data=data, headers=headers)
        try:
            with opener.open(req, timeout=5) as response:
                logger.info("[%s] Connexion simulée -> HTTP %d", user, response.getcode())
                return True
        except Exception as e:
            logger.debug("[%s] Échec connexion simulée: %s", user, e)
            return False

    def run_loop(self, stop_event=None) -> None:
        """Boucle principale : chaque itération choisit un employé et simule
        une action de navigation cohérente pour lui (pas un mélange aléatoire
        d'utilisateurs à chaque requête, plus réaliste d'une session continue)."""
        logger.info("Démarrage de la simulation du trafic Web sur %s", DOLIBARR_BASE_URL)

        for u in USERS:
            self.simulate_login(u)
            time.sleep(random.uniform(1, 3))

        while stop_event is None or not stop_event.is_set():
            user_entry = random.choice(USERS)
            user = user_entry["user"]
            endpoint = random.choice(DOLIBARR_ENDPOINTS)
            self.simulate_page_visit(user, endpoint)

            # Reconnexion occasionnelle (session expirée, nouvelle journée, etc.)
            if random.random() < 0.05:
                self.simulate_login(user_entry)

            sleep_with_workday_jitter(JITTER_WEB, stop_event)

        logger.info("Arrêt de la simulation Web.")


if __name__ == "__main__":
    sim = WebSimulator()
    sim.run_loop()