from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

from soar.config.settings import settings
from soar.models.alert import Alert, EventDetail, YaraMatch


class AlertValidationError(ValueError):
    pass


class AlertParser:
    def __init__(self):
        schema_path: Path = settings.alert_schema_path
        with open(schema_path) as f:
            self._schema: dict[str, Any] = json.load(f)

    def parse_dict(self, data: dict[str, Any]) -> Alert:
        try:
            jsonschema.validate(data, self._schema)
        except jsonschema.ValidationError as e:
            raise AlertValidationError(str(e)) from e

        return self._build_alert(data)

    def parse_file(self, file_path: str | Path) -> Alert:
        path = Path(file_path)
        try:
            with open(path) as f:
                data: dict[str, Any] = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            raise AlertValidationError(f"Impossible de lire {path}: {e}") from e

        return self.parse_dict(data)

    def _build_alert(self, data: dict[str, Any]) -> Alert:
        events = data["events"]
        details_raw: list[dict[str, Any]] = events.get("details", [])

        details = [
            EventDetail(
                timestamp=d["timestamp"],
                event_type=d["event_type"],
                source_host=d["source_host"],
                raw_log=d["raw_log"],
                actor_user=d.get("actor_user"),
                actor_role=d.get("actor_role"),
                target_resource=d.get("target_resource"),
            )
            for d in details_raw
        ]

        yara_raw = data.get("yara_match")
        yara: YaraMatch | None = None
        if yara_raw is not None:
            yara = YaraMatch(
                rule_name=yara_raw["rule_name"],
                file_path=yara_raw["file_path"],
                file_hash=yara_raw["file_hash"],
                ruleset=yara_raw["ruleset"],
            )

        return Alert(
            alert_id=data["alert_id"],
            timestamp=data["timestamp"],
            rule_id=data["rule_id"],
            severity=data["severity"],
            target_host=data["target_host"],
            target_ip=data["target_ip"],
            mitre_tactic=data["mitre_tactic"],
            mitre_technique=data["mitre_technique"],
            events_count=events["count"],
            events_details=details,
            attacker_ip=data.get("attacker_ip"),
            target_resource=data.get("target_resource"),
            yara_match=yara,
        )
