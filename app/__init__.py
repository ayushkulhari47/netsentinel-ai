"""Application factory for NetSentinel AI."""

import os
from dotenv import load_dotenv
from flask import Flask
from app.extensions import db
from app.services.llm_explainer import LLMExplainer
from app.services.threat_intel import DEFAULT_CACHE_TTL_SECONDS, ThreatIntelService


def create_app(test_config=None):
    """Create and configure the Flask application instance."""
    load_dotenv()

    app = Flask(__name__)
    os.makedirs(app.instance_path, exist_ok=True)

    default_db_path = os.path.join(app.instance_path, "netsentinel.db")
    database_url = os.environ.get("DATABASE_URL") or f"sqlite:///{default_db_path}"

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-change-in-production"),
        APP_NAME="NetSentinel AI",
        APP_VERSION="0.1.0",
        SQLALCHEMY_DATABASE_URI=database_url,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        ABUSEIPDB_API_KEY=None,
        THREAT_INTEL_CACHE_TTL=int(
            os.environ.get("THREAT_INTEL_CACHE_TTL", str(DEFAULT_CACHE_TTL_SECONDS))
        ),
        OPENAI_API_KEY=None,
        OPENAI_MODEL=None,
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

    return app
