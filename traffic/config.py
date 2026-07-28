"""Configuration centralisée pour le générateur de trafic et de bruit de fond NYX."""

import os

# Cibles d'infrastructures Nyx
SERVER_IP = os.getenv("NYX_SERVER_IP", "10.0.1.20")
DOLIBARR_PORT = int(os.getenv("NYX_DOLIBARR_PORT", "80"))
SSH_PORT = int(os.getenv("NYX_SSH_PORT", "22"))

# Comptes utilisateurs pour la simulation
USERS = [
    {"user": "server", "pass": "server1"},
    {"user": "svc_backup", "pass": "Backup2026!"},
    {"user": "user_nopreauth", "pass": "User2026!"},
    {"user": "adrien", "pass": "engine1234"},
]

# URLs et endpoints de navigation Dolibarr / Web
DOLIBARR_BASE_URL = f"http://{SERVER_IP}:{DOLIBARR_PORT}"
DOLIBARR_ENDPOINTS = [
    "/",
    "/index.php",
    "/user/home.php",
    "/societe/list.php",
    "/comm/card.php",
    "/product/list.php",
    "/compta/index.php",
]

# User-Agents réalistes pour la simulation Web
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

# Configuration des partages Samba montés
SAMBA_SHARES = [
    "commun",
    "direction",
    "comptabilite",
    "technique",
]

SAMBA_MOUNT_BASE = "/mnt/samba"

# Intervalles de temps (Jitter) en secondes [min, max]
JITTER_WEB = (5, 15)       # Entre 5s et 15s entre chaque clic/page
JITTER_SAMBA = (10, 30)     # Entre 10s et 30s entre chaque opération fichier
JITTER_AUTH = (20, 45)      # Entre 20s et 45s entre chaque connexion SSH/Auth
