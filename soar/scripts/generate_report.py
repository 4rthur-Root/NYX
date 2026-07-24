#!/usr/bin/env python3
"""Generate CSV reports from the SOAR SQLite database."""

from __future__ import annotations

import csv
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from soar.config.settings import settings
from soar.db.connection import get_connection

logger = logging.getLogger("soar.scripts.report")

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _since_cli(default_hours: int = 24) -> int | None:
    if "--since-hours" in sys.argv:
        idx = sys.argv.index("--since-hours")
        try:
            return int(sys.argv[idx + 1])
        except (IndexError, ValueError):
            pass
    return default_hours


def _report_path(name: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return REPORTS_DIR / f"{name}_{ts}.csv"


def _write_csv(path: Path, headers: list[str], rows: list[tuple]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(row)


def report_alerts(since_ms: int | None = None) -> Path:
    conn = get_connection()
    query = """
        SELECT alert_id, rule_id, severity, attacker_ip, target_host, target_ip,
               mitre_tactic, mitre_technique, events_count, timestamp, created_at
        FROM alerts
    """
    params: tuple = ()
    if since_ms is not None:
        query += " WHERE timestamp >= ?"
        params = (since_ms,)
    query += " ORDER BY created_at DESC"

    rows = conn.execute(query, params).fetchall()
    headers = [
        "alert_id", "rule_id", "severity", "attacker_ip", "target_host",
        "target_ip", "mitre_tactic", "mitre_technique", "events_count",
        "timestamp", "created_at",
    ]
    csv_rows = [tuple(r) for r in rows]
    path = _report_path("alerts")
    _write_csv(path, headers, csv_rows)
    logger.info("Alerts report written: %s (%d rows)", path, len(csv_rows))
    return path


def report_responses(since_ms: int | None = None) -> Path:
    conn = get_connection()
    query = """
        SELECT r.response_id, r.alert_id, r.action, r.status, r.skip_reason,
               r.error, r.alert_timestamp, r.response_timestamp, r.latency_ms,
               r.created_at,
               e.source, e.abuseipdb_score, e.country_code, e.isp, e.fallback_used,
               o.rule_id, o.blocked_ip, o.api_status_code, o.retry_count
        FROM responses r
        LEFT JOIN enrichments e ON e.response_id = r.response_id
        LEFT JOIN opnsense_actions o ON o.response_id = r.response_id
    """
    params: tuple = ()
    if since_ms is not None:
        query += " WHERE r.response_timestamp >= ?"
        params = (since_ms,)
    query += " ORDER BY r.created_at DESC"

    rows = conn.execute(query, params).fetchall()
    headers = [
        "response_id", "alert_id", "action", "status", "skip_reason", "error",
        "alert_timestamp", "response_timestamp", "latency_ms", "created_at",
        "enrichment_source", "abuseipdb_score", "country_code", "isp", "fallback_used",
        "opnsense_rule_id", "blocked_ip", "api_status_code", "retry_count",
    ]
    csv_rows = [tuple(r) for r in rows]
    path = _report_path("responses")
    _write_csv(path, headers, csv_rows)
    logger.info("Responses report written: %s (%d rows)", path, len(csv_rows))
    return path


def report_summary(since_ms: int | None = None) -> Path:
    conn = get_connection()

    def _count(table: str, ts_col: str) -> int:
        q = f"SELECT COUNT(*) FROM {table}"
        p: tuple = ()
        if since_ms is not None:
            q += f" WHERE {ts_col} >= ?"
            p = (since_ms,)
        row = conn.execute(q, p).fetchone()
        return row[0] if row else 0

    def _avg(field: str, table: str, where: str = "1=1") -> float | None:
        row = conn.execute(
            f"SELECT AVG({field}) FROM {table} WHERE {where}"
        ).fetchone()
        val = row[0] if row else None
        return round(val, 2) if val is not None else None

    total_alerts = _count("alerts", "timestamp")
    total_responses = _count("responses", "response_timestamp")
    total_audit = _count("audit_events", "timestamp")

    status_rows = conn.execute("""
        SELECT status, COUNT(*) as cnt, AVG(latency_ms) as avg_latency
        FROM responses GROUP BY status
    """).fetchall()
    status_counts = {str(r[0]): {"count": r[1], "avg_latency_ms": r[2]} for r in status_rows}

    action_rows = conn.execute("""
        SELECT action, COUNT(*) as cnt FROM responses GROUP BY action
    """).fetchall()
    action_counts = {str(r[0]): r[1] for r in action_rows}

    enrichment_rows = conn.execute("""
        SELECT source, COUNT(*) as cnt, AVG(abuseipdb_score) as avg_score
        FROM enrichments GROUP BY source
    """).fetchall()
    enrichment_stats = {
        str(r[0]): {"count": r[1], "avg_abuseipdb_score": round(r[2], 2)}
        for r in enrichment_rows
    }

    headers = [
        "metric", "value", "detail",
    ]
    csv_rows = [
        ("total_alerts", total_alerts, ""),
        ("total_responses", total_responses, ""),
        ("total_audit_events", total_audit, ""),
    ]
    for status, data in status_counts.items():
        csv_rows.append(
            (f"status_{status}", data["count"], f"avg_latency_ms={data['avg_latency_ms']}")
        )
    for action, count in action_counts.items():
        csv_rows.append((f"action_{action}", count, ""))
    for source, data in enrichment_stats.items():
        csv_rows.append(
            (f"enrichment_{source}", data["count"], f"avg_abuseipdb_score={data['avg_abuseipdb_score']}")
        )

    path = _report_path("summary")
    _write_csv(path, headers, csv_rows)
    logger.info("Summary report written: %s (%d rows)", path, len(csv_rows))
    return path


REPORTS: dict[str, Callable[[int | None], Path]] = {
    "alerts": report_alerts,
    "responses": report_responses,
    "summary": report_summary,
}


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    since_hours = _since_cli()
    since_ms = int((datetime.now(timezone.utc).timestamp() - since_hours * 3600) * 1000) if since_hours else None

    name = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] in REPORTS else "summary"
    path = REPORTS[name](since_ms)
    print(f"Report generated: {path}")


if __name__ == "__main__":
    main()
