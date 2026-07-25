from __future__ import annotations

import os
from pathlib import Path


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "nyxsoc-dashboard-dev")
    SOAR_DB_PATH = os.getenv(
        "SOAR_DB_PATH",
        str(Path(__file__).resolve().parent.parent.parent / "soar" / "data" / "soar.db"),
    )
    ENGINE_DB_PATH = os.getenv(
        "ENGINE_DB_PATH",
        str(Path(__file__).resolve().parent.parent.parent / "engine" / "engine.db"),
    )
    MOCK_DATA_DIR = os.getenv(
        "MOCK_DATA_DIR",
        str(Path(__file__).resolve().parent.parent / "mock_data"),
    )
    FLASK_DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
    MOCK_MODE = os.getenv("MOCK_MODE", "0") == "1"


class DevConfig(Config):
    FLASK_DEBUG = True


class ProdConfig(Config):
    FLASK_DEBUG = False


def get_config() -> type[Config]:
    if Config.FLASK_DEBUG:
        return DevConfig
    return ProdConfig
