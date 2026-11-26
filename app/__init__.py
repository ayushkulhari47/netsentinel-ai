"""Application factory for NetSentinel AI."""

import os
from dotenv import load_dotenv
from flask import Flask
from app.extensions import db


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
    )

    if test_config is not None:
        app.config.from_mapping(test_config)

    db.init_app(app)

    with app.app_context():
        from app import models  # noqa: F401
        db.create_all()

    from app.routes import main_bp

    app.register_blueprint(main_bp)

    return app
