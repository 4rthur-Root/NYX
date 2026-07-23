from __future__ import annotations

import logging
import sqlite3
from typing import Optional

from soar.db.connection import get_connection
from soar.models.decision import EnrichmentResult
from soar.models.response import OpnsenseResult, Response

logger = logging.getLogger("soar.repositories.response")


class ResponseRepository:
    def save(self, response: Response):
        conn = get_connection()
        cur = conn.execute(
            """INSERT OR REPLACE INTO responses
               (response_id, alert_id, action, status, skip_reason, error,
                alert_timestamp, response_timestamp, latency_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                response.response_id,
                response.alert_id,
                response.action,
                response.status,
                response.skip_reason,
                response.error,
                response.alert_timestamp,
                response.response_timestamp,
                response.latency_ms,
            ),
        )

        if response.enrichment is not None:
            conn.execute(
                """INSERT OR REPLACE INTO enrichments
                   (response_id, source, abuseipdb_score, country_code, isp, fallback_used)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    response.response_id,
                    response.enrichment.source,
                    response.enrichment.abuseipdb_score,
                    response.enrichment.country_code,
                    response.enrichment.isp,
                    1 if response.enrichment.fallback_used else 0,
                ),
            )

        if response.opnsense is not None:
            conn.execute(
                """INSERT OR REPLACE INTO opnsense_actions
                   (response_id, rule_id, blocked_ip, api_status_code, retry_count)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    response.response_id,
                    response.opnsense.rule_id,
                    response.opnsense.blocked_ip,
                    response.opnsense.api_status_code,
                    response.opnsense.retry_count,
                ),
            )

        conn.commit()

    def get_by_alert_id(self, alert_id: str) -> Optional[Response]:
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM responses WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_response(row, conn)

    def get_by_response_id(self, response_id: str) -> Optional[Response]:
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM responses WHERE response_id = ?", (response_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_response(row, conn)

    def list_failed(self, limit: int = 50) -> list[Response]:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM responses WHERE status = 'error' ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._row_to_response(r, conn) for r in rows]

    def list_recent(self, limit: int = 50) -> list[Response]:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM responses ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_response(r, conn) for r in rows]

    def _row_to_response(
        self, row: sqlite3.Row, conn: sqlite3.Connection
    ) -> Response:
        enrichment = self._load_enrichment(row["response_id"], conn)
        opnsense = self._load_opnsense(row["response_id"], conn)

        return Response(
            response_id=row["response_id"],
            alert_id=row["alert_id"],
            alert_timestamp=row["alert_timestamp"],
            response_timestamp=row["response_timestamp"],
            latency_ms=row["latency_ms"],
            action=row["action"],
            status=row["status"],
            skip_reason=row["skip_reason"],
            error=row["error"],
            enrichment=enrichment,
            opnsense=opnsense,
        )

    def _load_enrichment(
        self, response_id: str, conn: sqlite3.Connection
    ) -> Optional[EnrichmentResult]:
        row = conn.execute(
            "SELECT * FROM enrichments WHERE response_id = ?", (response_id,)
        ).fetchone()
        if row is None:
            return None
        return EnrichmentResult(
            source=row["source"],
            abuseipdb_score=row["abuseipdb_score"],
            country_code=row["country_code"],
            isp=row["isp"],
            fallback_used=bool(row["fallback_used"]),
        )

    def _load_opnsense(
        self, response_id: str, conn: sqlite3.Connection
    ) -> Optional[OpnsenseResult]:
        row = conn.execute(
            "SELECT * FROM opnsense_actions WHERE response_id = ?",
            (response_id,),
        ).fetchone()
        if row is None:
            return None
        return OpnsenseResult(
            rule_id=row["rule_id"],
            blocked_ip=row["blocked_ip"],
            api_status_code=row["api_status_code"],
            retry_count=row["retry_count"],
        )
