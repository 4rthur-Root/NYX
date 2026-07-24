from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Blueprint, current_app, render_template

metrics_bp = Blueprint("metrics", __name__)


def _get_db_path() -> Path | None:
    db_path = Path(current_app.config["SOAR_DB_PATH"])
    return db_path if db_path.exists() else None


def _get_engine_db_path() -> Path | None:
    db_path = Path(current_app.config["ENGINE_DB_PATH"])
    return db_path if db_path.exists() else None


def _compute_stats() -> dict[str, Any]:
    soar_db = _get_db_path()
    engine_db = _get_engine_db_path()

    stats = {
        "total_alerts": 0,
        "total_responses": 0,
        "success_rate": None,
        "avg_latency_ms": None,
        "alerts_by_severity": {},
        "alerts_by_hour": {},
        "latency_by_scenario": {},
        "blocked_ips": [],
    }

    if soar_db is None:
        return stats

    conn = sqlite3.connect(soar_db)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        total_alerts = cur.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        stats["total_alerts"] = total_alerts

        total_responses = cur.execute("SELECT COUNT(*) FROM responses").fetchone()[0]
        stats["total_responses"] = total_responses

        success_row = cur.execute(
            "SELECT COUNT(*) FROM responses WHERE status = 'success'"
        ).fetchone()
        if total_responses > 0:
            stats["success_rate"] = round((success_row[0] / total_responses) * 100, 1)

        avg_latency = cur.execute("SELECT AVG(latency_ms) FROM responses").fetchone()[0]
        stats["avg_latency_ms"] = round(avg_latency, 1) if avg_latency else None

        severity_rows = cur.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
        ).fetchall()
        stats["alerts_by_severity"] = {r["severity"]: r["cnt"] for r in severity_rows}

        hour_rows = cur.execute("""
            SELECT strftime('%Y-%m-%d %H:00', timestamp / 1000, 'unixepoch') as hour,
                   COUNT(*) as cnt
            FROM alerts
            GROUP BY hour
            ORDER BY hour
        """).fetchall()
        stats["alerts_by_hour"] = {r["hour"]: r["cnt"] for r in hour_rows}

        scenario_rows = cur.execute("""
            SELECT a.rule_id, AVG(r.latency_ms) as avg_lat
            FROM responses r
            JOIN alerts a ON a.alert_id = r.alert_id
            GROUP BY a.rule_id
        """).fetchall()
        stats["latency_by_scenario"] = {r["rule_id"]: round(r["avg_lat"], 1) for r in scenario_rows}

        blocked = cur.execute("""
            SELECT DISTINCT blocked_ip FROM opnsense_actions
            WHERE blocked_ip IS NOT NULL AND api_status_code = 200
        """).fetchall()
        stats["blocked_ips"] = [r["blocked_ip"] for r in blocked]
    finally:
        conn.close()

    return stats


@metrics_bp.route("/metrics")
def metrics_index():
    stats = _compute_stats()
    return render_template("metrics/index.html", stats=stats)
