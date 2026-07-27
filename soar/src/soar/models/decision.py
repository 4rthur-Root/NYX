from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from soar.models.alert import Alert


@dataclass(frozen=True)
class EnrichmentResult:
    source: str
    fallback_used: bool
    abuseipdb_score: Optional[int] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None


@dataclass(frozen=True)
class Decision:
    alert: Alert
    scenario_type: str
    action: str
    skip_reason: Optional[str] = None
    enrichment: Optional[EnrichmentResult] = None
