from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from soar.config.settings import settings


def setup_soar_logging():
    log_path = settings.soar_log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger("soar")
    root.setLevel(settings.log_level)

    if root.handlers:
        return

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = RotatingFileHandler(
        filename=str(log_path),
        maxBytes=settings.rotation_max_bytes,
        backupCount=settings.rotation_backup_count,
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    root.addHandler(ch)
