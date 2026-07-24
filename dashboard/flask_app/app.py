from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template


def _datetimeformat(ts: int) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "nyxsoc-dashboard-dev")
    app.config["SOAR_DB_PATH"] = os.getenv(
        "SOAR_DB_PATH", str(Path(__file__).resolve().parent.parent.parent / "soar" / "data" / "soar.db")
    )
    app.config["ENGINE_DB_PATH"] = os.getenv(
        "ENGINE_DB_PATH", str(Path(__file__).resolve().parent.parent.parent / "engine" / "engine.db")
    )
    app.config["MOCK_DATA_DIR"] = os.getenv(
        "MOCK_DATA_DIR", str(Path(__file__).resolve().parent.parent / "mock_data")
    )

    from flask_app.routes.alerts import alerts_bp
    from flask_app.routes.responses import responses_bp
    from flask_app.routes.metrics import metrics_bp

    app.register_blueprint(alerts_bp)
    app.register_blueprint(responses_bp)
    app.register_blueprint(metrics_bp)

    app.jinja_env.filters["datetimeformat"] = _datetimeformat

    @app.errorhandler(404)
    def not_found(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(error):
        return render_template("errors/500.html"), 500

    @app.route("/health")
    def health():
        return {"status": "ok"}

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=5000, debug=True)
