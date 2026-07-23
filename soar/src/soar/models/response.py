from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Optional

from soar.models.decision import EnrichmentResult


@dataclass(frozen=True)
class OpnsenseResult:
    api_status_code: int
    retry_count: int
    rule_id: Optional[str] = None
    blocked_ip: Optional[str] = None


@dataclass(frozen=True)
class Response:
    response_id: str
    alert_id: str
    alert_timestamp: int
    response_timestamp: int
    latency_ms: int
    action: str
    status: str
    skip_reason: Optional[str] = None
    enrichment: Optional[EnrichmentResult] = None
    opnsense: Optional[OpnsenseResult] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["latency_ms"] = int(d["latency_ms"])
        return d
