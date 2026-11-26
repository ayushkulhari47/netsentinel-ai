"""Application factory for NetSentinel AI."""

import os
from dotenv import load_dotenv
from flask import Flask
from app.extensions import db
from app.ml.predict import DEFAULT_MODEL_PATH
from app.services.llm_explainer import LLMExplainer
from app.services.threat_intel import DEFAULT_CACHE_TTL_SECONDS, ThreatIntelService


def create_app(test_config=None):
    """Create and configure the Flask application instance."""
    if test_config is None:
        load_dotenv()

    app = Flask(__name__)
    os.makedirs(app.instance_path, exist_ok=True)

    default_db_path = os.path.join(app.instance_path, "netsentinel.db")
    database_url = os.environ.get("DATABASE_URL") or f"sqlite:///{default_db_path}"

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-change-in-production"),
        APP_NAME="NetSentinel AI",
        APP_VERSION="0.1.0",
        DEBUG=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
        TESTING=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SQLALCHEMY_DATABASE_URI=database_url,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        ABUSEIPDB_API_KEY=None,
        THREAT_INTEL_CACHE_TTL=int(
            os.environ.get("THREAT_INTEL_CACHE_TTL", str(DEFAULT_CACHE_TTL_SECONDS))
        ),
        OPENAI_API_KEY=None,
        OPENAI_MODEL=None,
        ML_MODEL_PATH=os.environ.get("ML_MODEL_PATH") or str(DEFAULT_MODEL_PATH),
    )

    if test_config is not None:
        app.config.from_mapping(test_config)

    db.init_app(app)

    app.extensions["threat_intel_service"] = ThreatIntelService(
        api_key=app.config.get("ABUSEIPDB_API_KEY"),
        cache_ttl_seconds=app.config.get("THREAT_INTEL_CACHE_TTL", DEFAULT_CACHE_TTL_SECONDS),
    )
    app.extensions["llm_explainer"] = LLMExplainer(
        api_key=app.config.get("OPENAI_API_KEY"),
        model=app.config.get("OPENAI_MODEL"),
    )

    with app.app_context():
        from app import models  # noqa: F401
        db.create_all()

    from app.routes import main_bp

    app.register_blueprint(main_bp)

    @app.after_request
    def apply_security_headers(response):
        """Attach defensive HTTP security headers to all application responses."""
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            (
                "default-src 'self'; "
                "script-src 'self' https://cdn.jsdelivr.net; "
                "style-src 'self'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            ),
        )
        return response

    return app
