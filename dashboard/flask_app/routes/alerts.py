from __future__ import annotations

from flask import Blueprint, render_template

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/")
@alerts_bp.route("/alerts")
def alerts_index():
    return render_template("alerts/index.html", alerts=[], filters={}, page=1, total_pages=1)


@alerts_bp.route("/alerts/<alert_id>")
def alert_detail(alert_id: str):
    return render_template("alerts/detail.html", alert=None)
