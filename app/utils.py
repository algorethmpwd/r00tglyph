import json
import os
import uuid
import hashlib
import random
import string
import subprocess
import re
from functools import wraps
from flask import session, request, jsonify, flash, redirect, url_for
from app.extensions import db, rate_limiter
from app.models import LocalUser, Challenge, Flag

def rate_limit(max_requests=10, window_seconds=60, key_func=None):

    def decorator(f):

        @wraps(f)
        def decorated_function(*args, **kwargs):
            if key_func:
                key = key_func()
            else:
                key = request.remote_addr
            if not rate_limiter.is_allowed(key, max_requests, window_seconds):
                remaining = rate_limiter.get_remaining(key, max_requests, window_seconds)
                return (jsonify({'success': False, 'message': f'Rate limit exceeded. Try again in {window_seconds} seconds.', 'remaining_attempts': remaining}), 429)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def from_json_filter(value):
    """Parse JSON string to Python object"""
    if value:
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []
    return []

def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Get the current logged-in user"""
    if 'user_id' in session:
        return db.session.get(LocalUser, session['user_id'])
    return None

def get_local_user():
    """Get or create a local user for anonymous/session-based tracking.
    This is a compatibility function for challenges that don't require login."""
    user = get_current_user()
    if user:
        return user
    if 'anon_user_id' not in session:
        anon_username = f'anon_{uuid.uuid4().hex[:8]}'
        anon_user = LocalUser(username=anon_username, password_hash=generate_password_hash(uuid.uuid4().hex), display_name='Anonymous Hacker')
        db.session.add(anon_user)
        db.session.commit()
        session['anon_user_id'] = anon_user.id
        return anon_user
    return db.session.get(LocalUser, session['anon_user_id'])

def get_machine_id():
    """Get a unique machine identifier for session tracking.
    Returns the user ID if logged in, otherwise returns a session-based ID."""
    user = get_local_user()
    if user:
        return user.id
    if 'machine_id' not in session:
        session['machine_id'] = uuid.uuid4().hex
    return session['machine_id']

def inject_user():
    return dict(current_user=get_current_user())

def generate_flag(challenge_id, user_id):
    """Generate a unique flag for a specific challenge and user"""
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    unique_id = f'{challenge_id}_{user_id}_{random_part}'
    flag = f'R00T{{{hashlib.md5(unique_id.encode()).hexdigest()}}}'
    return flag

def get_or_create_flag(challenge_id, user_id):
    """Get an existing unused flag or create a new one"""
    existing_flag = Flag.query.filter_by(challenge_id=challenge_id, user_id=user_id, used=False).first()
    if existing_flag:
        return existing_flag.flag_value
    new_flag_value = generate_flag(challenge_id, user_id)
    new_flag = Flag(challenge_id=challenge_id, user_id=user_id, flag_value=new_flag_value)
    db.session.add(new_flag)
    db.session.commit()
    return new_flag_value

def get_flag_if_completed(challenge_name, user):
    """Retrieve the flag for a challenge if the user has completed it."""
    challenge = Challenge.query.filter_by(name=challenge_name).first()
    if not challenge:
        return None
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge.id in completed_ids:
        return get_or_create_flag(challenge.id, user.id)
    return None

def update_user_progress(user_id, challenge_id, points):
    """Update user progress after completing a challenge"""
    user = db.session.get(LocalUser, user_id)
    if user:
        completed = json.loads(user.completed_challenges) if user.completed_challenges else []
        if challenge_id not in completed:
            user.score += points
            completed.append(challenge_id)
            user.completed_challenges = json.dumps(completed)
            db.session.commit()
            return True
        else:
            return False
    return False

def safe_execute_command(cmd, timeout=5):
    """Execute a command safely with timeout and output capture for CTF challenges."""
    allowed_commands = ['whoami', 'id', 'uname', 'hostname', 'pwd', 'ls', 'cat', 'echo', 'date', 'uptime', 'w', 'ps', 'env', 'printenv', 'id', 'whoami', 'uname', 'hostname', 'pwd', 'ls', 'cat', 'echo', 'date', 'uptime', 'w', 'ps', 'env', 'printenv', 'id', 'whoami', 'uname', 'hostname', 'pwd', 'ls', 'cat', 'echo', 'date', 'uptime', 'w', 'ps', 'env', 'printenv']
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        output = result.stdout
        if result.stderr:
            output += '\n[stderr]\n' + result.stderr
        return output.strip() if output else '(empty output)'
    except subprocess.TimeoutExpired:
        return '(command timed out after {} seconds)'.format(timeout)
    except Exception as e:
        return '(error: {})'.format(str(e))

def show_help():
    """Show help information"""
    print('R00tGlyph - XSS Training Platform')
    print('\nUsage:')
    print('  python app.py [options]')
    print('\nOptions:')
    print('  -h, --help        Show this help message and exit')
    print('  -p, --port PORT   Port to bind to (default: 5000)')
    print('  --reset           Reset the database to its initial state')
    print('\nExamples:')
    print('  python app.py              Start the application on default port 5000')
    print('  python app.py -p 8080      Start the application on port 8080')
    print('  python app.py --reset      Reset the database and start the application')
    print('  python app.py -h           Show this help message')

def admin_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or not user.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

