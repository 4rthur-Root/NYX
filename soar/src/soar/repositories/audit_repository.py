from __future__ import annotations

import json
import logging
import time
from typing import Any

from soar.db.connection import get_connection

logger = logging.getLogger("soar.repositories.audit")


class AuditRepository:
    def insert_event(self, record: dict[str, Any]):
        conn = get_connection()
        conn.execute(
            """INSERT INTO audit_events (event_type, alert_id, details_json, timestamp)
               VALUES (?, ?, ?, ?)""",
            (
                record.get("event_type", "unknown"),
                record.get("alert_id"),
                json.dumps(record.get("details", {}), default=str),
                record.get("timestamp", int(time.time() * 1000)),
            ),
        )
        conn.commit()

    def list_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
