# reader.py
import logging
import os
import queue
import threading
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger(__name__)


class _LogFileHandler(FileSystemEventHandler):
    """Handler watchdog pour un répertoire de logs.

    Maintient un pointeur de position par fichier pour ne lire
    que les nouvelles lignes à chaque événement inotify.

    Attributes:
        _queue: Queue thread-safe partagée avec le Dispatcher.
        _positions: Dict {chemin_absolu: offset} — pointeur de lecture.
        _sources: Ensemble des noms de fichiers à surveiller.
        _maxsize: Taille maximale de la queue.
    """

    def __init__(
        self,
        shared_queue: queue.Queue,
        sources: set[str],
        maxsize: int,
    ) -> None:
        """Initialise le handler.

        Args:
            shared_queue: Queue thread-safe partagée avec le Dispatcher.
            sources: Ensemble des noms de fichiers configurés dans config.yaml.
            maxsize: Taille maximale de la queue (H-E3).
        """
        super().__init__()
        self._queue     = shared_queue
        self._positions: dict[str, int] = {}
        self._sources   = sources
        self._maxsize   = maxsize

    def on_modified(self, event) -> None:
        """Appelé par watchdog quand un fichier est modifié.

        Args:
            event: Événement watchdog (FileModifiedEvent).
        """
        if event.is_directory:
            return

        path = event.src_path
        filename = os.path.basename(path)

        if filename not in self._sources:
            return  # fichier non configuré — ignoré

        self._read_new_lines(path, filename)

    def on_created(self, event) -> None:
        """Appelé quand un nouveau fichier est créé (rotation de logs).

        Args:
            event: Événement watchdog (FileCreatedEvent).
        """
        if event.is_directory:
            return
        filename = os.path.basename(event.src_path)
        if filename in self._sources:
            # Réinitialiser le pointeur pour le nouveau fichier
            self._positions[event.src_path] = 0
            self._read_new_lines(event.src_path, filename)

    def _read_new_lines(self, path: str, filename: str) -> None:
        """Lit les nouvelles lignes depuis le pointeur courant.

        Avance le pointeur après chaque lecture pour ne pas retraiter
        les anciennes lignes lors du prochain événement inotify.

        Args:
            path: Chemin absolu du fichier de log.
            filename: Nom du fichier (clé de routing pour le Dispatcher).
        """
        pos = self._positions.get(path, 0)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(pos)
                new_lines = f.readlines()
                self._positions[path] = f.tell()
        except (OSError, PermissionError) as exc:
            logger.warning("Impossible de lire %s : %s", path, exc)
            return

        for line in new_lines:
            stripped = line.rstrip("\n")
            if not stripped:
                continue
            try:
                self._queue.put_nowait((stripped, filename))
            except queue.Full:
                # H-E3 : queue pleine — ligne rejetée, anomalie loggée
                logger.warning(
                    "Queue saturée (maxsize=%d) — ligne rejetée depuis '%s'",
                    self._maxsize, filename,
                )


class Reader:
    """Surveille /var/log/remote/ via watchdog inotify.

    Un seul _LogFileHandler surveille tout le répertoire. Les nouvelles
    lignes sont poussées dans la queue partagée sous la forme
    (ligne: str, nom_fichier: str).

    Attributes:
        log_dir: Répertoire surveillé.
        sources: Noms des fichiers configurés comme sources.
        queue: Queue thread-safe partagée avec le Dispatcher.
    """

    def __init__(
        self,
        log_dir: str,
        sources: set[str],
        shared_queue: queue.Queue,
        maxsize: int = 10_000,
    ) -> None:
        """Initialise le Reader.

        Args:
            log_dir: Chemin vers /var/log/remote/.
            sources: Ensemble des noms de fichiers à surveiller.
            shared_queue: Queue thread-safe partagée avec le Dispatcher.
            maxsize: Taille maximale de la queue pour la politique de rejet.
        """
        self.log_dir  = Path(log_dir)
        self.sources  = sources
        self.queue    = shared_queue
        self._maxsize = maxsize
        self._observer: Observer | None = None

    def start(self) -> None:
        """Démarre le watchdog Observer dans un thread daemon.

        Effectue un 'catch-up' initial : lit les lignes existantes dans
        chaque fichier source dès le démarrage pour ne pas manquer les
        logs déjà présents avant le lancement du moteur.
        """
        if not self.log_dir.exists():
            logger.error("Répertoire de logs introuvable : %s", self.log_dir)
            raise FileNotFoundError(f"log_dir introuvable : {self.log_dir}")

        handler = _LogFileHandler(self.queue, self.sources, self._maxsize)

        # Catch-up initial — lit ce qui existe déjà dans chaque fichier
        for filename in self.sources:
            candidate = self.log_dir / filename
            if candidate.exists():
                logger.info("Catch-up initial : %s", candidate)
                handler._read_new_lines(str(candidate), filename)

        self._observer = Observer()
        self._observer.schedule(handler, str(self.log_dir), recursive=False)
        self._observer.start()
        logger.info("Reader démarré — surveillance de %s", self.log_dir)

    def stop(self) -> None:
        """Arrête le watchdog proprement (appelé sur SIGTERM)."""
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join()
            logger.info("Reader arrêté")