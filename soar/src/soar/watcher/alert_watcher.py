from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from soar.models.alert import Alert
from soar.parser import AlertParser, AlertValidationError

logger = logging.getLogger("soar.watcher")

AlertHandlerFn = Callable[[Alert], None]


class AlertFileHandler(FileSystemEventHandler):
    def __init__(
        self,
        parser: AlertParser,
        on_alert: AlertHandlerFn,
        seen_ids: set[str] | None = None,
    ):
        super().__init__()
        self._parser = parser
        self._on_alert = on_alert
        self._seen_ids = seen_ids if seen_ids is not None else set()

    def on_moved(self, event):
        if not event.is_directory and event.dest_path.endswith(".json"):
            self._process(event.dest_path)

    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".json"):
            self._process(event.src_path)

    def _process(self, path_str: str):
        path = Path(path_str)
        if not path.exists():
            return

        try:
            alert = self._parser.parse_file(path)
        except AlertValidationError as e:
            logger.warning("Alerte invalide ignorée %s: %s", path.name, e)
            return
        except OSError as e:
            logger.warning("Impossible de lire %s: %s", path.name, e)
            return

        if alert.alert_id in self._seen_ids:
            logger.debug("Alerte déjà traitée, ignorée: %s", alert.alert_id)
            return

        self._seen_ids.add(alert.alert_id)
        logger.info("Nouvelle alerte: %s [%s] %s", alert.rule_id, alert.severity, alert.alert_id)

        try:
            self._on_alert(alert)
        except Exception:
            logger.exception("Erreur dans le handler pour %s", alert.alert_id)


class AlertWatcher:
    def __init__(
        self,
        watch_dir: str | Path,
        parser: AlertParser,
        on_alert: AlertHandlerFn,
    ):
        self._watch_dir = Path(watch_dir)
        self._parser = parser
        self._on_alert = on_alert
        self._seen_ids: set[str] = set()
        self._observer: Observer | None = None

    def start(self):
        self._watch_dir.mkdir(parents=True, exist_ok=True)
        self._preload_existing()

        handler = AlertFileHandler(
            parser=self._parser,
            on_alert=self._on_alert,
            seen_ids=self._seen_ids,
        )

        self._observer = Observer()
        self._observer.schedule(handler, str(self._watch_dir), recursive=False)
        self._observer.start()
        logger.info("Watcher démarré sur %s", self._watch_dir)

    def stop(self):
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            logger.info("Watcher arrêté")

    def _preload_existing(self):
        if not self._watch_dir.exists():
            return
        for f in sorted(self._watch_dir.iterdir()):
            if f.suffix == ".json" and f.is_file():
                try:
                    alert = self._parser.parse_file(f)
                    self._seen_ids.add(alert.alert_id)
                    logger.debug("Préchargée: %s (%s)", f.name, alert.alert_id)
                    self._on_alert(alert)
                except (AlertValidationError, OSError) as e:
                    logger.debug("Ignoré au préchargement %s: %s", f.name, e)
