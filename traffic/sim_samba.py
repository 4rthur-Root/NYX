"""Simulateur d'activité de fichiers sur partages Samba.

Simule des créations, modifications et lectures de fichiers bureautiques sains
(.txt, .csv, .log) sur les partages réseau pour générer des événements
samba_read et samba_write sains qui passent l'analyse YARA sans alerte.
"""

import datetime
import logging
import os
import random
import time
from pathlib import Path

from traffic.config import JITTER_SAMBA, SAMBA_MOUNT_BASE, SAMBA_SHARES
from traffic.time_utils import sleep_with_workday_jitter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SAMBA_SIM] %(message)s"
)
logger = logging.getLogger("sim_samba")

# Modèles de contenu sain pour les fichiers générés
BENIGN_TEMPLATES = [
    "Compte rendu de réunion du {date}\nPrésents: Adrien, Server, Technicien\nPoints traités: Maintenance système, mises à jour.",
    "Rapport financier mensuel - Exercice {date}\nStatut: Validé\nCommentaire: Rapprochement bancaire effectué.",
    "Documentation technique système\nVersion: 1.4\nDernière modification par admin le {date}.\nTout est opérationnel.",
    "Liste des tâches hebdomadaires\n- Vérification des sauvegardes\n- Nettoyage des logs\n- Audit de sécurité régulier.",
]


class SambaSimulator:
    """Générateur de bruit de fond d'activité fichiers Samba."""

    def __init__(self) -> None:
        self.target_dirs: list[Path] = []
        for share in SAMBA_SHARES:
            path = Path(SAMBA_MOUNT_BASE) / share
            if path.exists() and os.access(path, os.W_OK):
                self.target_dirs.append(path)

        # Si les partages Samba ne sont pas montés localement, fallback vers un dossier temporaire local
        if not self.target_dirs:
            fallback = Path("/tmp/samba_sim_test")
            fallback.mkdir(parents=True, exist_ok=True)
            self.target_dirs.append(fallback)
            logger.warning("Partages Samba non montés en écriture. Utilisation du dossier de test: %s", fallback)

    def generate_random_file(self) -> Path:
        """Génère ou modifie un fichier sain dans un des partages."""
        target_dir = random.choice(self.target_dirs)
        filename = f"document_travail_{random.randint(100, 999)}.txt"
        file_path = target_dir / filename

        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        template = random.choice(BENIGN_TEMPLATES)
        content = template.format(date=now_str)

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info("Fichier sain écrit: %s", file_path)
            return file_path
        except Exception as e:
            logger.error("Erreur d'écriture sur %s: %s", file_path, e)
            return file_path

    def read_random_file(self) -> None:
        """Lit un fichier existant dans un des partages."""
        target_dir = random.choice(self.target_dirs)
        files = list(target_dir.glob("*.txt"))
        if not files:
            self.generate_random_file()
            return

        target_file = random.choice(files)
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                _ = f.read()
            logger.info("Fichier lu: %s", target_file)
        except Exception as e:
            logger.debug("Erreur de lecture sur %s: %s", target_file, e)

    def run_loop(self, stop_event=None) -> None:
        """Boucle principale du simulateur Samba."""
        logger.info("Démarrage de la simulation d'activité fichiers Samba...")

        while stop_event is None or not stop_event.is_set():
            action = random.choice(["write", "read", "write"])
            if action == "write":
                self.generate_random_file()
            else:
                self.read_random_file()

            sleep_with_workday_jitter(JITTER_SAMBA, stop_event)

        logger.info("Arrêt de la simulation Samba.")


if __name__ == "__main__":
    sim = SambaSimulator()
    sim.run_loop()
