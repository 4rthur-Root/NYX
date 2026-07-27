from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Optional

from soar.config.settings import settings

logger = logging.getLogger("soar.db")

_connection: Optional[sqlite3.Connection] = None
MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def get_connection() -> sqlite3.Connection:
    global _connection
    if _connection is None:
        db_path = settings.database_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _connection = sqlite3.connect(str(db_path), check_same_thread=False)
        _connection.row_factory = sqlite3.Row
        _connection.execute("PRAGMA journal_mode=WAL")
        _connection.execute("PRAGMA foreign_keys=ON")
        logger.info("Connexion SQLite ouverte: %s", db_path)
    return _connection


def close_connection():
    global _connection
    if _connection is not None:
        _connection.close()
        _connection = None
        logger.info("Connexion SQLite fermée")


def initialize_db():
    conn = get_connection()
    migration_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    for f in migration_files:
        sql = f.read_text()
        if sql.strip():
            conn.executescript(sql)
            logger.info("Migration appliquée: %s", f.name)
    conn.commit()
