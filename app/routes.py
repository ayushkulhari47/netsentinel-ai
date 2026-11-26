"""Core web, health-check, and alert API routes for NetSentinel AI."""

from flask import Blueprint, current_app, jsonify, render_template, request
from sqlalchemy import func
from app.extensions import db
from app.models import Alert
from app.validators import (
    ALLOWED_SEVERITIES,
    ALLOWED_STATUSES,
    validate_alert_payload,
)

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


@main_bp.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Return stored security alerts ordered from newest to oldest."""
    query = Alert.query

    severity = request.args.get("severity")
    if severity is not None:
        normalized_severity = severity.strip().lower()
        if normalized_severity not in ALLOWED_SEVERITIES:
            return jsonify(
                {
                    "error": "Invalid severity filter.",
                    "allowed": sorted(ALLOWED_SEVERITIES),
                }
            ), 400
        query = query.filter(Alert.severity == normalized_severity)

    status = request.args.get("status")
    if status is not None:
        normalized_status = status.strip().lower()
        if normalized_status not in ALLOWED_STATUSES:
            return jsonify(
                {
                    "error": "Invalid status filter.",
                    "allowed": sorted(ALLOWED_STATUSES),
                }
            ), 400
        query = query.filter(Alert.status == normalized_status)

    limit_raw = request.args.get("limit", "100")
    try:
        limit = int(limit_raw)
    except ValueError:
        return jsonify({"error": "limit must be an integer between 1 and 500."}), 400

    if limit < 1 or limit > 500:
        return jsonify({"error": "limit must be an integer between 1 and 500."}), 400

    alerts = query.order_by(Alert.timestamp.desc(), Alert.id.desc()).limit(limit).all()
    return jsonify(
        {
            "alerts": [alert.to_dict() for alert in alerts],
            "count": len(alerts),
        }
    ), 200


@main_bp.route("/api/alerts", methods=["POST"])
def create_alert():
    """Validate and persist a new security alert in SQLite."""
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Request body must contain valid JSON."}), 400

    cleaned, errors = validate_alert_payload(payload)
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400

    alert = Alert(**cleaned)
    db.session.add(alert)
    db.session.commit()

    return jsonify({"alert": alert.to_dict()}), 201


@main_bp.route("/api/summary", methods=["GET"])
def get_summary():
    """Return aggregated security alert metrics for the dashboard."""
    total_alerts = db.session.query(func.count(Alert.id)).scalar() or 0
    critical_alerts = (
        db.session.query(func.count(Alert.id))
        .filter(Alert.severity == "critical")
        .scalar()
        or 0
    )
    high_alerts = (
        db.session.query(func.count(Alert.id))
        .filter(Alert.severity == "high")
        .scalar()
        or 0
    )
    suspicious_ip_count = (
        db.session.query(func.count(func.distinct(Alert.source_ip))).scalar() or 0
    )

    return jsonify(
        {
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "suspicious_ip_count": suspicious_ip_count,
        }
    ), 200


@main_bp.route("/api/threat-intel/<ip_address>", methods=["GET"])
def get_threat_intel(ip_address):
    """Look up optional AbuseIPDB reputation metadata for an IP address."""
    service = current_app.extensions.get("threat_intel_service")
    if service is None:
        return jsonify({"error": "Threat intelligence service is not configured."}), 500

    try:
        result = service.lookup_ip(ip_address)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result), 200
