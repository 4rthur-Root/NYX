from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Blueprint, current_app, request, render_template

alerts_bp = Blueprint("alerts", __name__)


def _get_db_path() -> Path | None:
    if current_app.config.get("MOCK_MODE"):
        return None
    db_path = Path(current_app.config["SOAR_DB_PATH"])
    return db_path if db_path.exists() else None


def _load_mock_alerts() -> list[dict[str, Any]]:
    mock_dir = Path(current_app.config["MOCK_DATA_DIR"]) / "alerts"
    alerts = []
    if not mock_dir.exists():
        return alerts
    for path in sorted(mock_dir.glob("*.json")):
        try:
            alerts.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return alerts


def _fetch_alerts_from_db(
    severity: str | None = None,
    rule_id: str | None = None,
    attacker_ip: str | None = None,
    start_ts: int | None = None,
    end_ts: int | None = None,
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[dict], int]:
    db_path = _get_db_path()
    if db_path is None:
        return _load_mock_alerts(), len(_load_mock_alerts())

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    where = []
    params = []
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if rule_id:
        where.append("rule_id = ?")
        params.append(rule_id)
    if attacker_ip:
        where.append("attacker_ip = ?")
        params.append(attacker_ip)
    if start_ts is not None:
        where.append("timestamp >= ?")
        params.append(start_ts)
    if end_ts is not None:
        where.append("timestamp <= ?")
        params.append(end_ts)

    where_clause = f"WHERE {' AND '.join(where)}" if where else ""
    count_sql = f"SELECT COUNT(*) FROM alerts {where_clause}"
    total = cur.execute(count_sql, params).fetchone()[0]

    offset = (page - 1) * per_page
    rows = cur.execute(
        f"SELECT * FROM alerts {where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (*params, per_page, offset),
    ).fetchall()

    alerts = [dict(r) for r in rows]
    conn.close()
    return alerts, total


@alerts_bp.route("/")
@alerts_bp.route("/alerts")
def alerts_index():
    severity = request.args.get("severity", type=str)
    rule_id = request.args.get("rule_id", type=str)
    attacker_ip = request.args.get("attacker_ip", type=str)
    start_ts = request.args.get("start_ts", type=int)
    end_ts = request.args.get("end_ts", type=int)
    page = request.args.get("page", 1, type=int)

    alerts, total = _fetch_alerts_from_db(
        severity=severity,
        rule_id=rule_id,
        attacker_ip=attacker_ip,
        start_ts=start_ts,
        end_ts=end_ts,
        page=page,
    )
    total_pages = max(1, (total + 49) // 50)

    return render_template(
        "alerts/index.html",
        alerts=alerts,
        filters={
            "severity": severity or "",
            "rule_id": rule_id or "",
            "attacker_ip": attacker_ip or "",
            "start_ts": start_ts or "",
            "end_ts": end_ts or "",
        },
        page=page,
        total_pages=total_pages,
        total=total,
    )


@alerts_bp.route("/alerts/<alert_id>")
def alert_detail(alert_id: str):
    db_path = _get_db_path()
    alert = None
    events = []

    if db_path is not None:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        row = cur.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if row:
            alert = dict(row)
        conn.close()
    else:
        mock_alerts = _load_mock_alerts()
        for a in mock_alerts:
            if a.get("alert_id") == alert_id:
                alert = a
                break

    if alert and alert.get("events_details"):
        events = alert.get("events_details", [])

    return render_template("alerts/detail.html", alert=alert, events=events)
