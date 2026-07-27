from __future__ import annotations

from abc import ABC, abstractmethod

from soar.models.decision import EnrichmentResult


class ThreatIntelClient(ABC):
    @abstractmethod
    def get_reputation(self, ip: str) -> EnrichmentResult:
        ...
