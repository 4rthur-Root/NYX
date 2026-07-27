from __future__ import annotations

import json
import logging
from typing import Optional

from soar.db.connection import get_connection
from soar.models.alert import Alert

logger = logging.getLogger("soar.repositories.alert")


class AlertRepository:
    def save(self, alert: Alert):
        conn = get_connection()
        conn.execute(
            """INSERT OR IGNORE INTO alerts
               (alert_id, rule_id, severity, attacker_ip, target_host, target_ip,
                mitre_tactic, mitre_technique, events_count, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.alert_id,
                alert.rule_id,
                alert.severity,
                alert.attacker_ip,
                alert.target_host,
                alert.target_ip,
                alert.mitre_tactic,
                alert.mitre_technique,
                alert.events_count,
                alert.timestamp,
            ),
        )
        conn.commit()

    def get_by_id(self, alert_id: str) -> Optional[Alert]:
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        if row is None:
            return None
        return Alert(
            alert_id=row["alert_id"],
            timestamp=row["timestamp"],
            rule_id=row["rule_id"],
            severity=row["severity"],
            attacker_ip=row["attacker_ip"],
            target_host=row["target_host"],
            target_ip=row["target_ip"],
            mitre_tactic=row["mitre_tactic"],
            mitre_technique=row["mitre_technique"],
            events_count=row["events_count"],
            events_details=[],
        )

    def exists(self, alert_id: str) -> bool:
        conn = get_connection()
        row = conn.execute(
            "SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        return row is not None

    def list_recent(self, limit: int = 50) -> list[Alert]:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            Alert(
                alert_id=r["alert_id"],
                timestamp=r["timestamp"],
                rule_id=r["rule_id"],
                severity=r["severity"],
                attacker_ip=r["attacker_ip"],
                target_host=r["target_host"],
                target_ip=r["target_ip"],
                mitre_tactic=r["mitre_tactic"],
                mitre_technique=r["mitre_technique"],
                events_count=r["events_count"],
                events_details=[],
            )
            for r in rows
        ]
