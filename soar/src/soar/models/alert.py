from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class EventDetail:
    timestamp: int
    event_type: str
    source_host: str
    raw_log: str
    actor_user: Optional[str] = None
    actor_role: Optional[str] = None
    target_resource: Optional[str] = None


@dataclass(frozen=True)
class YaraMatch:
    rule_name: str
    file_path: str
    file_hash: str
    ruleset: str


@dataclass(frozen=True)
class Alert:
    alert_id: str
    timestamp: int
    rule_id: str
    severity: str
    target_host: str
    target_ip: str
    mitre_tactic: str
    mitre_technique: str
    events_count: int
    events_details: list[EventDetail]
    attacker_ip: Optional[str] = None
    target_resource: Optional[str] = None
    yara_match: Optional[YaraMatch] = None
