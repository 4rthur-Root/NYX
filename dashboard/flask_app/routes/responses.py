from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Blueprint, current_app, request, render_template

responses_bp = Blueprint("responses", __name__)


def _get_db_path() -> Path | None:
    db_path = Path(current_app.config["SOAR_DB_PATH"])
    return db_path if db_path.exists() else None


def _fetch_responses_from_db(
    action: str | None = None,
    status: str | None = None,
    start_ts: int | None = None,
    end_ts: int | None = None,
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[dict], int]:
    db_path = _get_db_path()
    if db_path is None:
        return [], 0

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    where = ["1=1"]
    params = []
    if action:
        where.append("r.action = ?")
        params.append(action)
    if status:
        where.append("r.status = ?")
        params.append(status)
    if start_ts is not None:
        where.append("r.response_timestamp >= ?")
        params.append(start_ts)
    if end_ts is not None:
        where.append("r.response_timestamp <= ?")
        params.append(end_ts)

    where_clause = " AND ".join(where)

    count_sql = f"SELECT COUNT(*) FROM responses r WHERE {where_clause}"
    total = cur.execute(count_sql, params).fetchone()[0]

    offset = (page - 1) * per_page
    rows = cur.execute(
        f"""SELECT r.response_id, r.alert_id, r.action, r.status, r.skip_reason,
                   r.error, r.alert_timestamp, r.response_timestamp, r.latency_ms,
                   r.created_at,
                   e.source, e.abuseipdb_score, e.country_code, e.isp, e.fallback_used,
                   o.rule_id as opnsense_rule_id, o.blocked_ip, o.api_status_code, o.retry_count
            FROM responses r
            LEFT JOIN enrichments e ON e.response_id = r.response_id
            LEFT JOIN opnsense_actions o ON o.response_id = r.response_id
            WHERE {where_clause}
            ORDER BY r.created_at DESC
            LIMIT ? OFFSET ?""",
        (*params, per_page, offset),
    ).fetchall()

    responses = [dict(r) for r in rows]
    conn.close()
    return responses, total


@responses_bp.route("/responses")
def responses_index():
    action = request.args.get("action", type=str)
    status = request.args.get("status", type=str)
    start_ts = request.args.get("start_ts", type=int)
    end_ts = request.args.get("end_ts", type=int)
    page = request.args.get("page", 1, type=int)

    responses, total = _fetch_responses_from_db(
        action=action,
        status=status,
        start_ts=start_ts,
        end_ts=end_ts,
        page=page,
    )
    total_pages = max(1, (total + 49) // 50)

    return render_template(
        "responses/index.html",
        responses=responses,
        filters={
            "action": action or "",
            "status": status or "",
            "start_ts": start_ts or "",
            "end_ts": end_ts or "",
        },
        page=page,
        total_pages=total_pages,
        total=total,
    )
