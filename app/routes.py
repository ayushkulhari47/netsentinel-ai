"""Core web and health-check routes for NetSentinel AI."""

from flask import Blueprint, current_app, jsonify, render_template

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Render the main cybersecurity dashboard homepage."""
    return render_template(
        "dashboard.html",
        app_name=current_app.config["APP_NAME"],
        app_version=current_app.config["APP_VERSION"],
    )


@main_bp.route("/health")
def health():
    """Return application health status as JSON."""
    return jsonify(
        {
            "status": "ok",
            "app": current_app.config["APP_NAME"],
            "version": current_app.config["APP_VERSION"],
            "packet_capture": "not_configured",
        }
    ), 200
