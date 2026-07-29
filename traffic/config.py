"""Configuration centralisée pour le générateur de trafic et de bruit de fond NYX.

Exécution prévue depuis Kali (10.0.1.50) — cohérent avec les montages CIFS
côté SOC et l'absence de dépendance signal/SSH spécifique à Windows.
"""

import os

# Cibles d'infrastructure Nyx
SERVER_IP = os.getenv("NYX_SERVER_IP", "10.0.1.20")
DOLIBARR_PORT = int(os.getenv("NYX_DOLIBARR_PORT", "80"))
SSH_PORT = int(os.getenv("NYX_SSH_PORT", "22"))

# Comptes utilisateurs légitimes pour le bruit de fond.
# Volontairement EXCLUS : svc_backup, user_nopreauth (comptes créés pour S6,
# leur activité web/SSH n'a pas de sens PME réaliste et pollue le dataset).
USERS = [
    {"user": "dir1", "pass": "Nyx2026!", "role": "direction"},
    {"user": "compta1", "pass": "Nyx2026!", "role": "comptabilite"},
    {"user": "tech1", "pass": "Nyx2026!", "role": "technique"},
]

# Compte SSH distinct (accès système, pas un compte AD/métier)
SSH_USER = {"user": "server", "pass": "server1"}

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

# Partages Samba, mappés aux comptes qui y ont légitimement accès
# (cohérent avec Topologie.pdf §4.4.2 : cloisonnement par groupe AD)
USER_SHARE_MAP = {
    "dir1": "direction",
    "compta1": "comptabilite",
    "tech1": "technique",
}
COMMON_SHARE = "commun"
SAMBA_SHARES = list(set(USER_SHARE_MAP.values()) | {COMMON_SHARE})

SAMBA_MOUNT_BASE = "/mnt/samba"  # Utilisé si les partages sont montés en CIFS (ex: sur le SOC)

# Intervalles de temps (jitter) en secondes [min, max]
JITTER_WEB = (5, 15)      # Entre chaque page/clic
JITTER_SAMBA = (10, 30)   # Entre chaque opération fichier
JITTER_AUTH = (60, 180)   # Entre chaque session SSH (moins fréquent, plus réaliste qu'un scan)

# Fenêtre d'activité "journée de travail" — hors de cette fenêtre, le bruit
# de fond ralentit fortement (réalisme PME : pas d'activité à 3h du matin).
WORKDAY_START_HOUR = 7
WORKDAY_END_HOUR = 19
OFF_HOURS_JITTER_MULTIPLIER = 6  # Multiplie les délais en dehors des heures de bureau

# Forcer l'activité en mode "journée de travail" (ex: pour générer un gros dataset de test la nuit)
FORCE_WORKDAY = os.getenv("NYX_FORCE_WORKDAY", "0").lower() in ("1", "true", "yes")