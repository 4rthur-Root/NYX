from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

from soar.config.settings import settings
from soar.models.alert import Alert
from soar.models.decision import Decision
from soar.models.response import OpnsenseResult, Response
from soar.repositories import AuditRepository

logger = logging.getLogger("soar.logging.audit")


class AuditLogger:
    def __init__(self):
        self._repo = AuditRepository()
        audit_path = settings.audit_log_path
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._jsonl_path = audit_path

    def log(
        self,
        alert: Alert,
        decision: Decision,
        response: Optional[Response] = None,
    ):
        now_ms = int(time.time() * 1000)
        record = {
            "timestamp": now_ms,
            "event_type": "alert_processed",
            "alert_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "severity": alert.severity,
            "scenario_type": decision.scenario_type,
            "action": decision.action,
            "skip_reason": decision.skip_reason,
            "status": response.status if response else "decided",
            "latency_ms": response.latency_ms if response else None,
        }

        if response and response.error:
            record["error"] = response.error

        self._write_jsonl(record)
        self._repo.insert_event(record)

    def log_event(self, event_type: str, details: dict[str, Any]):
        now_ms = int(time.time() * 1000)
        record = {
            "timestamp": now_ms,
            "event_type": event_type,
            **details,
        }
        self._write_jsonl(record)
        self._repo.insert_event(record)

    def _write_jsonl(self, record: dict):
        try:
            with open(self._jsonl_path, "a") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except OSError as e:
            logger.error("Impossible d'écrire dans %s: %s", self._jsonl_path, e)
