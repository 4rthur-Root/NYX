from __future__ import annotations

import logging
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

from soar.config.settings import settings
from soar.models.response import OpnsenseResult

logger = logging.getLogger("soar.integrations.opnsense")

ALIAS_NAME = "soar_blocklist"
MAX_RETRIES = 3


class OPNsenseClient:
    def __init__(self):
        self._base_url = settings.opnsense_api_url.rstrip("/")
        self._auth = HTTPBasicAuth(
            settings.opnsense_api_key,
            settings.opnsense_api_secret,
        )
        # Certificat auto-signé en lab — ne pas reproduire en production
        self._verify = settings.opnsense_verify_ssl

    def block_ip(self, ip: str) -> OpnsenseResult:
        last_code = 0
        attempts = 0

        for attempt in range(1, MAX_RETRIES + 1):
            attempts = attempt
            try:
                resp = requests.post(
                    f"{self._base_url}/api/firewall/alias/addItem",
                    json={"alias": ALIAS_NAME, "address": ip},
                    auth=self._auth,
                    verify=self._verify,
                    timeout=5,
                )
                last_code = resp.status_code

                if resp.status_code == 200:
                    self._apply()
                    return OpnsenseResult(
                        rule_id=ALIAS_NAME,
                        blocked_ip=ip,
                        api_status_code=200,
                        retry_count=attempt,
                    )

                logger.warning(
                    "Blocage %s tentative %d/%d: HTTP %d",
                    ip, attempt, MAX_RETRIES, resp.status_code,
                )

            except requests.RequestException as e:
                last_code = 0
                logger.warning(
                    "Blocage %s tentative %d/%d: %s",
                    ip, attempt, MAX_RETRIES, e,
                )

        return OpnsenseResult(
            blocked_ip=ip,
            api_status_code=last_code,
            retry_count=attempts,
        )

    def unblock_ip(self, ip: str) -> OpnsenseResult:
        last_code = 0
        attempts = 0

        for attempt in range(1, MAX_RETRIES + 1):
            attempts = attempt
            try:
                resp = requests.post(
                    f"{self._base_url}/api/firewall/alias/delItem",
                    json={"alias": ALIAS_NAME, "address": ip},
                    auth=self._auth,
                    verify=self._verify,
                    timeout=5,
                )
                last_code = resp.status_code

                if resp.status_code == 200:
                    self._apply()
                    return OpnsenseResult(
                        rule_id=ALIAS_NAME,
                        blocked_ip=ip,
                        api_status_code=200,
                        retry_count=attempt,
                    )

            except requests.RequestException as e:
                last_code = 0
                logger.warning(
                    "Déblocage %s tentative %d/%d: %s",
                    ip, attempt, MAX_RETRIES, e,
                )

        return OpnsenseResult(
            blocked_ip=ip,
            api_status_code=last_code,
            retry_count=attempts,
        )

    def list_blocked(self) -> list[str]:
        try:
            resp = requests.get(
                f"{self._base_url}/api/firewall/alias/getAlias",
                params={"name": ALIAS_NAME},
                auth=self._auth,
                verify=self._verify,
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                content = data.get("alias", {}).get("content", "")
                if not content:
                    return []
                return [addr.strip() for addr in content.split("\n") if addr.strip()]
        except requests.RequestException as e:
            logger.warning("Impossible de lister les IPs bloquées: %s", e)
        return []

    def is_already_blocked(self, ip: str) -> bool:
        blocked = self.list_blocked()
        return ip in blocked

    def _apply(self) -> bool:
        try:
            resp = requests.post(
                f"{self._base_url}/api/firewall/alias/reconfigure",
                auth=self._auth,
                verify=self._verify,
                timeout=30,
            )
            return resp.status_code == 200
        except requests.RequestException as e:
            logger.warning("Échec de l'application des règles: %s", e)
            return False
