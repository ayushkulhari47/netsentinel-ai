"""Application factory for NetSentinel AI."""

import os
from dotenv import load_dotenv
from flask import Flask


def create_app(test_config=None):
    """Create and configure the Flask application instance."""
    load_dotenv()

    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-change-in-production"),
        APP_NAME="NetSentinel AI",
        APP_VERSION="0.1.0",
    )

    if test_config is not None:
        app.config.from_mapping(test_config)

    from app.routes import main_bp

    app.register_blueprint(main_bp)

    return app
