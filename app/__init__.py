from flask import Flask
import os
from app.extensions import db

def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    app.secret_key = os.environ.get("SECRET_KEY")
    if not app.secret_key and (os.environ.get("FLASK_ENV") == "production" or os.environ.get("FLASK_DEBUG", "0") == "0"):
        raise RuntimeError("SECRET_KEY environment variable not set in production!")
    app.secret_key = app.secret_key or "r00tglyph_secret_key_change_in_production"
    
    DATABASE_URL = os.environ.get("DATABASE_URL")
    if DATABASE_URL:
        if DATABASE_URL.startswith("postgres://"):
            DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///../instance/r00tglyph.db"
    
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    db.init_app(app)
    
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect()
    csrf.init_app(app)
    
    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp)
    from app.routes.core import core_bp
    app.register_blueprint(core_bp)
    from app.routes.api import api_bp
    app.register_blueprint(api_bp)
    
    
    
    
    from app.routes.challenge_router import dynamic_router_bp
    app.register_blueprint(dynamic_router_bp)
    
    # Exempt vulnerable challenges from CSRF protection
    csrf.exempt(dynamic_router_bp)
    from app.routes.admin import admin_bp
    app.register_blueprint(admin_bp)
    from app.routes.teams import teams_bp
    app.register_blueprint(teams_bp)

    # Context processor
    from app.utils import inject_user
    app.context_processor(inject_user)
    
    # Template filter
    from app.utils import from_json_filter
    app.template_filter('from_json')(from_json_filter)
    
    return app
