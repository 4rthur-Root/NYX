# yara_scanner.py
import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import yara  # type: ignore
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
    logger.warning("yara-python non disponible — YARA désactivé (pip install yara-python)")


class YaraScanner:
    """Scanne les fichiers contre les règles YARA compilées.

    Appelé par le Dispatcher sur tout événement samba_write, avant stockage.
    Les règles sont compilées une seule fois à l'init — pas de recompilation.

    Attributes:
        rules_dir: Répertoire contenant les fichiers .yar/.yara.
        _rules: Objet yara.Rules compilé, ou None si YARA non disponible.
    """

    def __init__(self, rules_dir: str) -> None:
        """Compile les règles YARA à l'initialisation.

        Args:
            rules_dir: Chemin vers le répertoire engine/rules/yara/.
        """
        self.rules_dir = Path(rules_dir)
        self._rules = None

        if not _YARA_AVAILABLE:
            return

        yar_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))
        if not yar_files:
            logger.warning("Aucun fichier .yar trouvé dans %s — YARA désactivé", rules_dir)
            return

        try:
            # Compiler plusieurs fichiers en un objet Rules unique
            filepaths = {f.stem: str(f) for f in yar_files}
            self._rules = yara.compile(filepaths=filepaths)
            logger.info("YARA : %d fichier(s) de règles compilé(s) depuis %s",
                        len(yar_files), rules_dir)
        except yara.SyntaxError as exc:
            logger.error("Erreur compilation YARA : %s", exc)
            self._rules = None

    def scan(self, file_path: str) -> dict | None:
        """Scanne un fichier contre les règles YARA compilées.

        Le scan est indépendant de l'extension — YARA analyse les octets.
        Un exécutable renommé en .docx est détecté normalement.

        Args:
            file_path: Chemin absolu du fichier sur le SOC
                (partage Samba monté via CIFS sous /mnt/samba/).

        Returns:
            Dict {rule_name, file_path, file_hash, ruleset} si match YARA,
            None si aucun match ou fichier inaccessible.
        """
        if self._rules is None:
            return None

        path = Path(file_path)
        if not path.exists() or not path.is_file():
            logger.debug("YARA : fichier inaccessible ou inexistant : %s", file_path)
            return None

        try:
            file_bytes = path.read_bytes()
        except (OSError, PermissionError) as exc:
            logger.warning("YARA : impossible de lire %s : %s", file_path, exc)
            return None

        # Hash MD5 calculé avant le scan
        file_hash = "md5:" + hashlib.md5(file_bytes).hexdigest()

        try:
            matches = self._rules.match(data=file_bytes, timeout=30)
        except yara.TimeoutError:
            logger.warning("YARA : timeout sur %s", file_path)
            return None
        except yara.Error as exc:
            logger.warning("YARA : erreur scan sur %s : %s", file_path, exc)
            return None

        if not matches:
            return None

        # On retourne le premier match — le plus significatif
        first_match = matches[0]
        return {
            "rule_name": first_match.rule,
            "file_path": file_path,
            "file_hash": file_hash,
            "ruleset":   "neo23x0/signature-base",
        }
