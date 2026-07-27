import os
from pathlib import Path

from dotenv import load_dotenv
import yaml


# Chemin : soar/src/soar/config/settings.py → soar/
SOAR_ROOT = Path(__file__).resolve().parent.parent.parent.parent

# Chemin du fichier config.yaml, au même endroit que settings.py
CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"


class Settings:
    def __init__(self):
        env_path = SOAR_ROOT / ".env"
        load_dotenv(env_path)

        with open(CONFIG_PATH) as f:
            self._config = yaml.safe_load(f)

        self._validate()

    def _validate(self):
        required = {
            "ABUSEIPDB_API_KEY": "Clé API AbuseIPDB (https://www.abuseipdb.com)",
            "OPNSENSE_API_URL": "URL de l'API OPNsense (ex: https://10.0.1.1/api)",
            "OPNSENSE_API_KEY": "Clé API OPNsense",
            "OPNSENSE_API_SECRET": "Secret API OPNsense",
        }
        missing = []
        for key, desc in required.items():
            if not os.getenv(key):
                missing.append(f"  - {key}: {desc}")

        if missing:
            msg = (
                "Variables d'environnement obligatoires manquantes.\n"
                "Créez un fichier .env à la racine du module SOAR:\n"
                "  cp .env.example .env\n"
                "Et renseignez les valeurs suivantes:\n"
                + "\n".join(missing)
            )
            raise EnvironmentError(msg)

    @property
    def severity_threshold(self) -> str:
        return self._config["soar"]["severity_threshold"]

    @property
    def response_timeout_s(self) -> int:
        return self._config["soar"]["response_timeout_s"]

    @property
    def abuseipdb_score_threshold(self) -> int:
        return self._config["soar"]["abuseipdb_score_threshold"]

    @property
    def abuseipdb_circuit_breaker_cooldown_s(self) -> int:
        return self._config["soar"]["abuseipdb_circuit_breaker_cooldown_s"]

    @property
    def rule_ttl_hours(self) -> int:
        return self._config["soar"]["rule_ttl_hours"]

    @property
    def handler_mapping(self) -> dict:
        return dict(self._config["handlers"])

    def _resolve(self, raw: str) -> Path:
        p = Path(raw)
        if p.is_absolute():
            return p.resolve()
        return (SOAR_ROOT / p).resolve()

    @property
    def alerts_incoming(self) -> str:
        return self._config["paths"]["alerts_incoming"]

    @property
    def alert_schema_path(self) -> Path:
        return self._resolve(self._config["paths"]["alert_schema"])

    @property
    def fallback_list_path(self) -> Path:
        return self._resolve(self._config["paths"]["fallback_list"])

    @property
    def database_path(self) -> Path:
        return self._resolve(self._config["paths"]["database"])

    @property
    def soar_log_path(self) -> Path:
        return self._resolve(self._config["logging"]["soar_log_path"])

    @property
    def audit_log_path(self) -> Path:
        return self._resolve(self._config["logging"]["audit_log_path"])

    @property
    def rotation_max_bytes(self) -> int:
        return self._config["logging"]["rotation_max_bytes"]

    @property
    def rotation_backup_count(self) -> int:
        return self._config["logging"]["rotation_backup_count"]

    @property
    def abuseipdb_api_key(self) -> str:
        return os.environ["ABUSEIPDB_API_KEY"]

    @property
    def opnsense_api_url(self) -> str:
        return os.environ["OPNSENSE_API_URL"]

    @property
    def opnsense_api_key(self) -> str:
        return os.environ["OPNSENSE_API_KEY"]

    @property
    def opnsense_api_secret(self) -> str:
        return os.environ["OPNSENSE_API_SECRET"]

    @property
    def opnsense_verify_ssl(self) -> bool:
        return os.getenv("OPNSENSE_VERIFY_SSL", "false").lower() == "true"

    @property
    def log_level(self) -> str:
        return os.getenv("LOG_LEVEL", "INFO").upper()

    @property
    def telegram_bot_token(self) -> str | None:
        return os.getenv("TELEGRAM_BOT_TOKEN")

    @property
    def telegram_chat_id(self) -> str | None:
        return os.getenv("TELEGRAM_CHAT_ID")

    @property
    def smtp_host(self) -> str | None:
        return os.getenv("SMTP_HOST")

    @property
    def smtp_port(self) -> int:
        return int(os.getenv("SMTP_PORT", "587"))

    @property
    def smtp_user(self) -> str | None:
        return os.getenv("SMTP_USER")

    @property
    def smtp_password(self) -> str | None:
        return os.getenv("SMTP_PASSWORD")

    @property
    def smtp_to(self) -> str | None:
        return os.getenv("SMTP_TO")


settings = Settings()
