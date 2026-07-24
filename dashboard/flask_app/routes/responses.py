from __future__ import annotations

from flask import Blueprint, render_template

responses_bp = Blueprint("responses", __name__)


@responses_bp.route("/responses")
def responses_index():
    return render_template("responses/index.html", responses=[], filters={}, page=1, total_pages=1)
