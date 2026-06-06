import ast
import os
from collections import defaultdict

with open('app_monolith_backup.py', 'r') as f:
    source = f.read()

tree = ast.parse(source)

blueprints = {
    'auth': ['register', 'login', 'logout'],
    'core': ['change-theme', 'profile', 'core', 'challenges', 'scoreboard', 'team-scoreboard'],
    'api': ['submit-flag', 'api', 'solutions'],
    'admin': ['admin'],
    'teams': ['teams'],
    'xss': ['xss'],
    'sqli': ['sqli'],
    'cmdi': ['cmdi'],
    'csrf': ['csrf'],
    'ssrf': ['ssrf'],
    'xxe': ['xxe'],
    'dynamic': ['ssti', 'deserial', 'auth']
}

models = ['LocalUser', 'Challenge', 'Flag', 'Submission', 'Comment', 'Team']
utils = ['rate_limit', 'from_json_filter', 'login_required', 'get_current_user', 'get_local_user', 
         'get_machine_id', 'inject_user', 'generate_flag', 'get_or_create_flag', 
         'get_flag_if_completed', 'update_user_progress', 'safe_execute_command', 'show_help', 'admin_required']

os.makedirs('app/routes', exist_ok=True)
os.makedirs('app/routes/challenges', exist_ok=True)

with open('app/extensions.py', 'w') as f:
    f.write('''from flask_sqlalchemy import SQLAlchemy
import time
from collections import defaultdict

db = SQLAlchemy()

class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)

    def is_allowed(self, key, max_requests, window_seconds):
        now = time.time()
        self.requests[key] = [t for t in self.requests[key] if now - t < window_seconds]
        if len(self.requests[key]) >= max_requests:
            return False
        self.requests[key].append(now)
        return True

    def get_remaining(self, key, max_requests, window_seconds):
        now = time.time()
        self.requests[key] = [t for t in self.requests[key] if now - t < window_seconds]
        return max(0, max_requests - len(self.requests[key]))

rate_limiter = RateLimiter()
''')

class_nodes = {}
func_nodes = {}
route_nodes = defaultdict(list)

for node in tree.body:
    if isinstance(node, ast.ClassDef):
        class_nodes[node.name] = node
    elif isinstance(node, ast.FunctionDef):
        is_route = False
        route_path = None
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and getattr(dec.func, 'attr', '') == 'route':
                is_route = True
                route_path = dec.args[0].value
                break
            elif getattr(dec, 'attr', '') == 'route':
                is_route = True
                break
        
        if is_route:
            category = route_path.strip('/').split('/')[0]
            if category == '': category = 'core'
            
            mapped_bp = None
            for bp, cats in blueprints.items():
                if category in cats or (category == 'auth' and route_path.startswith('/auth/level')):
                    if route_path.startswith('/auth/level'):
                        mapped_bp = 'dynamic'
                    else:
                        mapped_bp = bp
                    break
            if not mapped_bp:
                mapped_bp = category
                
            route_nodes[mapped_bp].append(node)
        else:
            func_nodes[node.name] = node

with open('app/models.py', 'w') as f:
    f.write('from app.extensions import db\nfrom datetime import datetime, timezone\n\n')
    for model_name in models:
        f.write(ast.unparse(class_nodes[model_name]) + '\n\n')

with open('app/utils.py', 'w') as f:
    f.write('import json\nimport os\nimport uuid\nimport hashlib\nimport random\nimport string\nimport subprocess\nimport re\nfrom functools import wraps\nfrom flask import session, request, jsonify, flash, redirect, url_for\nfrom app.extensions import db, rate_limiter\nfrom app.models import LocalUser, Challenge, Flag\n\n')
    for func_name in utils:
        if func_name in func_nodes:
            f.write(ast.unparse(func_nodes[func_name]) + '\n\n')

with open('app/reset_db_func.py', 'w') as f:
    f.write('from app.extensions import db\nfrom app.models import Challenge, LocalUser, Flag, Submission, Comment, Team\n\n')
    if 'reset_database' in func_nodes:
        f.write(ast.unparse(func_nodes['reset_database']) + '\n')

common_imports = """import json
import os
import random
import re
import xml.etree.ElementTree as ET
import xml.parsers.expat
import hashlib
import string
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from app.extensions import db
from app.models import LocalUser, Challenge, Flag, Submission, Comment, Team
from app.utils import login_required, get_current_user, get_machine_id, generate_flag, get_or_create_flag, update_user_progress, safe_execute_command, admin_required, rate_limit

"""

blueprint_files = {}

for bp, nodes in route_nodes.items():
    if bp in ['xss', 'sqli', 'cmdi', 'csrf', 'ssrf', 'xxe', 'dynamic']:
        file_path = f'app/routes/challenges/{bp}.py'
    else:
        file_path = f'app/routes/{bp}.py'
    
    blueprint_files[bp] = file_path
    
    with open(file_path, 'w') as f:
        f.write(common_imports)
        f.write(f"{bp}_bp = Blueprint('{bp}', __name__)\n\n")
        
        for node in nodes:
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and getattr(dec.func, 'attr', '') == 'route':
                    if getattr(dec.func.value, 'id', '') == 'app':
                        dec.func.value.id = f"{bp}_bp"
            
            f.write(ast.unparse(node) + '\n\n')

with open('app/__init__.py', 'w') as f:
    f.write('''from flask import Flask
import os
from app.extensions import db

def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    app.secret_key = os.environ.get("SECRET_KEY", "r00tglyph_secret_key_change_in_production")
    
    DATABASE_URL = os.environ.get("DATABASE_URL")
    if DATABASE_URL:
        if DATABASE_URL.startswith("postgres://"):
            DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///../instance/r00tglyph.db"
    
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    db.init_app(app)
    
''')
    for bp in blueprint_files.keys():
        if bp in ['xss', 'sqli', 'cmdi', 'csrf', 'ssrf', 'xxe', 'dynamic']:
            f.write(f"    from app.routes.challenges.{bp} import {bp}_bp\n")
        else:
            f.write(f"    from app.routes.{bp} import {bp}_bp\n")
        f.write(f"    app.register_blueprint({bp}_bp)\n")
    
    f.write('''
    # Context processor
    from app.utils import inject_user
    app.context_processor(inject_user)
    
    # Template filter
    from app.utils import from_json_filter
    app.template_filter('from_json')(from_json_filter)
    
    return app
''')

print("Refactoring complete! Check the app/ directory.")
