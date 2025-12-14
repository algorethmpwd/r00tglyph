#!/usr/bin/env python3
"""
R00tGlyph - Advanced Web Security Training Platform
Main Application Factory Module

This module initializes the Flask application with all extensions,
configurations, and blueprints in a clean, modular architecture.
"""

import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

import redis
from flask import Flask, g, request, session
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
limiter = Limiter(key_func=get_remote_address)
cache = Cache()
socketio = SocketIO()


def create_app(config_name="development"):
    """
    Application factory pattern for creating Flask app instances

    Args:
        config_name (str): Configuration environment name

    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
        instance_relative_config=True,
    )

    # Load configuration
    load_config(app, config_name)

    # Initialize extensions
    initialize_extensions(app)

    # Register blueprints
    register_blueprints(app)

    # Set up logging
    setup_logging(app)

    # Register error handlers
    register_error_handlers(app)

    # Register context processors
    register_context_processors(app)

    # Register CLI commands
    register_cli_commands(app)

    # Create database tables
    with app.app_context():
        db.create_all()
        initialize_default_data()

    return app


def load_config(app, config_name):
    """Load configuration based on environment"""

    # Base configuration
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32)),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        WTF_CSRF_ENABLED=True,
        WTF_CSRF_TIME_LIMIT=3600,
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file upload
        UPLOAD_FOLDER=os.path.join(app.instance_path, "uploads"),
        RATELIMIT_STORAGE_URL=os.environ.get("REDIS_URL", "redis://localhost:6379/1"),
        CACHE_TYPE="redis" if os.environ.get("REDIS_URL") else "simple",
        CACHE_REDIS_URL=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        CACHE_DEFAULT_TIMEOUT=300,
    )

    if config_name == "production":
        app.config.update(
            SQLALCHEMY_DATABASE_URI=os.environ.get(
                "DATABASE_URL", "sqlite:///rootglyph_prod.db"
            ),
            DEBUG=False,
            TESTING=False,
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE="Lax",
            PERMANENT_SESSION_LIFETIME=3600,
        )
    elif config_name == "testing":
        app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///test_rootglyph.db",
            TESTING=True,
            DEBUG=True,
            WTF_CSRF_ENABLED=False,
        )
    else:  # development
        app.config.update(
            SQLALCHEMY_DATABASE_URI=os.environ.get(
                "DATABASE_URL", "sqlite:///rootglyph_dev.db"
            ),
            DEBUG=True,
            TESTING=False,
        )

    # Ensure instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass


def initialize_extensions(app):
    """Initialize Flask extensions"""
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    cache.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")


def register_blueprints(app):
    """Register application blueprints"""
    from app.controllers.admin import admin_bp
    from app.controllers.api import api_bp
    from app.controllers.auth import auth_bp
    from app.controllers.challenges.cmdi import cmdi_bp
    from app.controllers.challenges.csrf import csrf_bp
    from app.controllers.challenges.sqli import sqli_bp
    from app.controllers.challenges.ssrf import ssrf_bp
    from app.controllers.challenges.ssti import ssti_bp
    from app.controllers.challenges.xss import xss_bp
    from app.controllers.main import main_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(main_bp)
    app.register_blueprint(xss_bp, url_prefix="/xss")
    app.register_blueprint(sqli_bp, url_prefix="/sqli")
    app.register_blueprint(cmdi_bp, url_prefix="/cmdi")
    app.register_blueprint(csrf_bp, url_prefix="/csrf")
    app.register_blueprint(ssrf_bp, url_prefix="/ssrf")
    app.register_blueprint(ssti_bp, url_prefix="/ssti")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(api_bp, url_prefix="/api")


def register_error_handlers(app):
    """Register custom error handlers"""

    @app.errorhandler(404)
    def not_found(error):
        from flask import render_template

        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        from flask import render_template

        db.session.rollback()
        return render_template("errors/500.html"), 500

    @app.errorhandler(403)
    def forbidden(error):
        from flask import render_template

        return render_template("errors/403.html"), 403

    @app.errorhandler(429)
    def ratelimit_handler(e):
        from flask import jsonify, render_template

        if request.is_json:
            return jsonify(
                error="Rate limit exceeded", retry_after=str(e.retry_after)
            ), 429
        return render_template("errors/429.html", retry_after=e.retry_after), 429


def register_context_processors(app):
    """Register template context processors"""

    @app.context_processor
    def inject_user():
        from app.services.auth_service import get_current_user

        return dict(current_user=get_current_user())

    @app.context_processor
    def inject_config():
        return dict(
            app_name="R00tGlyph", app_version="2.0.0", current_year=datetime.now().year
        )

    @app.context_processor
    def inject_progress():
        from app.services.progress_service import ProgressService

        user = g.get("current_user")
        if user:
            progress_service = ProgressService()
            return dict(
                user_progress=progress_service.get_user_progress(user.id),
                global_stats=progress_service.get_global_stats(),
            )
        return dict(user_progress=None, global_stats=None)


def register_cli_commands(app):
    """Register CLI commands"""

    @app.cli.command()
    def init_db():
        """Initialize the database with default data."""
        from app.services.database_service import DatabaseService

        db_service = DatabaseService()
        db_service.initialize_challenges()
        db_service.create_admin_user()
        print("✅ Database initialized successfully!")

    @app.cli.command()
    def reset_db():
        """Reset database to clean state."""
        from app.services.database_service import DatabaseService

        db_service = DatabaseService()
        db_service.reset_database()
        print("✅ Database reset completed!")

    @app.cli.command()
    def backup_data():
        """Backup user data."""
        from app.services.backup_service import BackupService

        backup_service = BackupService()
        backup_path = backup_service.create_backup()
        print(f"✅ Backup created: {backup_path}")

    @app.cli.command()
    def restore_data():
        """Restore user data from backup."""
        from app.services.backup_service import BackupService

        backup_service = BackupService()
        if backup_service.restore_latest():
            print("✅ Data restored successfully!")
        else:
            print("❌ No backup found or restore failed!")

    @app.cli.command()
    def update_challenges():
        """Update challenge definitions."""
        from app.services.challenge_service import ChallengeService

        challenge_service = ChallengeService()
        updated_count = challenge_service.update_all_challenges()
        print(f"✅ Updated {updated_count} challenges!")


def setup_logging(app):
    """Setup application logging"""
    if not app.debug and not app.testing:
        if not os.path.exists("logs"):
            os.mkdir("logs")

        file_handler = RotatingFileHandler(
            "logs/rootglyph.log", maxBytes=10240000, backupCount=10
        )
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
            )
        )
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info("R00tGlyph startup")


def initialize_default_data():
    """Initialize default data if needed"""
    from app.models.challenge import Challenge
    from app.models.user import User

    # Check if we need to initialize data
    if Challenge.query.count() == 0:
        from app.services.database_service import DatabaseService

        db_service = DatabaseService()
        db_service.initialize_challenges()


# Global application instance (for backwards compatibility)
app = None


def get_app():
    """Get or create application instance"""
    global app
    if app is None:
        config_name = os.environ.get("FLASK_ENV", "development")
        app = create_app(config_name)
    return app
