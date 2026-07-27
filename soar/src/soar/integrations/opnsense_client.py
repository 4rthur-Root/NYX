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
        self._verify = settings.opnsense_verify_ssl

    def block_ip(self, ip: str) -> OpnsenseResult:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                current = self.list_blocked()
                if ip in current:
                    return OpnsenseResult(
                        rule_id=ALIAS_NAME,
                        blocked_ip=ip,
                        api_status_code=200,
                        retry_count=attempt,
                    )
                current.append(ip)
                if not self._import_content("\n".join(current)):
                    logger.warning(
                        "Blocage %s tentative %d/%d: échec import",
                        ip, attempt, MAX_RETRIES,
                    )
                    continue
                self._apply()
                return OpnsenseResult(
                    rule_id=ALIAS_NAME,
                    blocked_ip=ip,
                    api_status_code=200,
                    retry_count=attempt,
                )
            except requests.RequestException as e:
                logger.warning(
                    "Blocage %s tentative %d/%d: %s",
                    ip, attempt, MAX_RETRIES, e,
                )
        return OpnsenseResult(
            blocked_ip=ip,
            api_status_code=0,
            retry_count=MAX_RETRIES,
        )

    def unblock_ip(self, ip: str) -> OpnsenseResult:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                current = self.list_blocked()
                if ip not in current:
                    return OpnsenseResult(
                        rule_id=ALIAS_NAME,
                        blocked_ip=ip,
                        api_status_code=200,
                        retry_count=attempt,
                    )
                current = [addr for addr in current if addr != ip]
                if not self._import_content("\n".join(current)):
                    continue
                self._apply()
                return OpnsenseResult(
                    rule_id=ALIAS_NAME,
                    blocked_ip=ip,
                    api_status_code=200,
                    retry_count=attempt,
                )
            except requests.RequestException as e:
                logger.warning(
                    "Déblocage %s tentative %d/%d: %s",
                    ip, attempt, MAX_RETRIES, e,
                )
        return OpnsenseResult(
            blocked_ip=ip,
            api_status_code=0,
            retry_count=MAX_RETRIES,
        )

    def list_blocked(self) -> list[str]:
        try:
            resp = requests.get(
                f"{self._base_url}/api/firewall/alias/searchItem",
                auth=self._auth,
                verify=self._verify,
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                for row in data.get("rows", []):
                    if row.get("name") == ALIAS_NAME:
                        content = row.get("content", "")
                        if not content:
                            return []
                        return [
                            addr.strip()
                            for addr in content.split("\n")
                            if addr.strip()
                        ]
        except requests.RequestException as e:
            logger.warning("Impossible de lister les IPs bloquées: %s", e)
        return []

    def is_already_blocked(self, ip: str) -> bool:
        return ip in self.list_blocked()

    def _import_content(self, content: str) -> bool:
        try:
            resp = requests.post(
                f"{self._base_url}/api/firewall/alias/import",
                data={
                    "data[aliases][alias][1][name]": ALIAS_NAME,
                    "data[aliases][alias][1][type]": "host",
                    "data[aliases][alias][1][content]": content,
                },
                auth=self._auth,
                verify=self._verify,
                timeout=5,
            )
            if resp.status_code == 200:
                result = resp.json()
                return result.get("status") == "ok"
            return False
        except requests.RequestException as e:
            logger.warning("Échec de l'import du contenu: %s", e)
            return False

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
