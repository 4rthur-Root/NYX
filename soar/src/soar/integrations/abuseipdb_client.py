from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Optional

import requests
import yaml

from soar.cache import IpCache
from soar.config.settings import settings
from soar.integrations.base import ThreatIntelClient
from soar.models.decision import EnrichmentResult

logger = logging.getLogger("soar.integrations.abuseipdb")


class AbuseIPDBClient(ThreatIntelClient):
    def __init__(self, cache: Optional[IpCache] = None):
        self._cache = cache or IpCache()
        self._circuit_open_until: float = 0
        self._consecutive_failures: int = 0
        self._fallback: dict[str, int] = self._load_fallback()

    def _load_fallback(self) -> dict[str, int]:
        path: Path = settings.fallback_list_path
        if not path.exists():
            return {}
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            return {entry["ip"]: entry["score"] for entry in data.get("known_ips", [])}
        except Exception:
            logger.warning("Impossible de charger la fallback list: %s", path)
            return {}

    def get_reputation(self, ip: str) -> EnrichmentResult:
        cached = self._cache.get(ip)
        if cached is not None:
            return EnrichmentResult(
                source="cache",
                abuseipdb_score=cached,
                fallback_used=False,
            )

        if self._circuit_open():
            return self._fallback_or_default(ip)

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={
                    "Key": settings.abuseipdb_api_key,
                    "Accept": "application/json",
                },
                timeout=2,
            )
            response.raise_for_status()
            data = response.json()["data"]

            score = data.get("abuseConfidenceScore", 0)
            country_code = data.get("countryCode")
            isp = data.get("isp")

            self._cache.set(ip, score, ttl_seconds=300)
            self._consecutive_failures = 0

            return EnrichmentResult(
                source="abuseipdb",
                abuseipdb_score=score,
                country_code=country_code,
                isp=isp,
                fallback_used=False,
            )

        except requests.RequestException as e:
            self._consecutive_failures += 1
            if self._consecutive_failures >= 3:
                cooldown = settings.abuseipdb_circuit_breaker_cooldown_s
                self._circuit_open_until = time.monotonic() + cooldown
                logger.warning(
                    "Circuit breaker ouvert pour %ss (%d échecs consécutifs)",
                    cooldown, self._consecutive_failures,
                )

            logger.warning("API AbuseIPDB injoignable pour %s: %s", ip, e)
            return self._fallback_or_default(ip, fallback_used=True)

    def _circuit_open(self) -> bool:
        if time.monotonic() < self._circuit_open_until:
            return True
        if self._circuit_open_until and time.monotonic() >= self._circuit_open_until:
            self._circuit_open_until = 0
            self._consecutive_failures = 0
            logger.info("Circuit breaker refermé")
        return False

    def _fallback_or_default(
        self, ip: str, fallback_used: bool = False,
    ) -> EnrichmentResult:
        if ip in self._fallback:
            return EnrichmentResult(
                source="unavailable",
                abuseipdb_score=self._fallback[ip],
                fallback_used=True,
            )
        return EnrichmentResult(
            source="unavailable",
            abuseipdb_score=50,
            fallback_used=fallback_used,
        )
