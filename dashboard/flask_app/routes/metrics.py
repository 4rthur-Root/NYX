from __future__ import annotations

from flask import Blueprint, render_template

metrics_bp = Blueprint("metrics", __name__)


@metrics_bp.route("/metrics")
@metrics_bp.route("/")
def metrics_index():
    return render_template("metrics/index.html", stats={})
