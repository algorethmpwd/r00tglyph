#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import os
import json
import random
import string
import re
import hashlib
import uuid
import sys
import argparse
import shutil
import subprocess
from datetime import datetime



# Check for command-line arguments
if len(sys.argv) > 1:
    parser = argparse.ArgumentParser(description='R00tGlyph - Advanced Web Security Training Platform')
    parser.add_argument('-up', '--update', action='store_true', help='Update R00tGlyph to the latest version')
    parser.add_argument('--backup', action='store_true', help='Backup user data only')
    parser.add_argument('--restore', action='store_true', help='Restore user data from backup')
    parser.add_argument('--reset', action='store_true', help='Reset the database to its initial state')
    args = parser.parse_args()

    backup_dir = 'backup'
    db_file = 'instance/r00tglyph.db'
    backup_file = f'{backup_dir}/r00tglyph.db.bak'

    # Create backup directory if it doesn't exist
    os.makedirs(backup_dir, exist_ok=True)

    # Backup user data function
    def backup_user_data():
        if os.path.exists(db_file):
            print("Backing up user data...")
            # Create a timestamped backup
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            timestamped_backup = f'{backup_dir}/r00tglyph_{timestamp}.db.bak'

            # Copy to both timestamped and regular backup files
            shutil.copy2(db_file, timestamped_backup)
            shutil.copy2(db_file, backup_file)
            print(f"Backup created: {timestamped_backup}")
            return True
        else:
            print("No database file found to backup.")
            return False

    # Restore user data function
    def restore_user_data():
        if os.path.exists(backup_file):
            print("Restoring user data from backup...")
            if os.path.exists(db_file):
                # Create a backup of the current database before overwriting
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                pre_restore_backup = f'{backup_dir}/pre_restore_{timestamp}.db.bak'
                shutil.copy2(db_file, pre_restore_backup)
                print(f"Created pre-restore backup: {pre_restore_backup}")

            # Restore the backup
            shutil.copy2(backup_file, db_file)
            print("User data restored successfully!")
            return True
        else:
            print("No backup file found to restore.")
            return False

    # Handle backup command
    if args.backup:
        backup_user_data()
        sys.exit(0)

    # Handle restore command
    if args.restore:
        restore_user_data()
        sys.exit(0)

    # Handle reset command
    if args.reset:
        # The reset logic is now handled in the __main__ block below.
        pass

    # Handle update command
    if args.update:
        print("Updating R00tGlyph to the latest version...")

        # Step 1: Backup user data
        backup_success = backup_user_data()

        # Step 2: Pull latest changes from GitHub
        try:
            print("Pulling latest changes from GitHub...")
            subprocess.run(['git', 'pull'], check=True)
            print("Code updated successfully!")

            # Step 3: Restore user data if backup was successful
            if backup_success:
                restore_user_data()

            print("\nUpdate completed successfully!")
            print("Your progress and achievements have been preserved.")
            print("Restart the application to apply all changes.")

        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to pull latest changes. {str(e)}")
            print("Please check your internet connection and Git configuration.")
            print("Your data has been backed up and remains unchanged.")

        sys.exit(0)

app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY', 'r00tglyph_secret_key_change_in_production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///r00tglyph.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class LocalUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, default='Hacker')
    display_name = db.Column(db.String(50), nullable=False, default='Anonymous Hacker')
    machine_id = db.Column(db.String(64), unique=True, nullable=False)
    score = db.Column(db.Integer, default=0)
    completed_challenges = db.Column(db.Text, default='[]')  # JSON string of completed challenge IDs
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)  # 'xss', 'sqli', etc.
    difficulty = db.Column(db.String(20), nullable=False)  # 'beginner', 'intermediate', 'advanced'
    description = db.Column(db.Text, nullable=False)
    points = db.Column(db.Integer, default=100)
    active = db.Column(db.Boolean, default=True)

class Flag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    machine_id = db.Column(db.String(64), nullable=False)
    flag_value = db.Column(db.String(100), nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    machine_id = db.Column(db.String(64), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    flag = db.Column(db.String(100), nullable=False)
    correct = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    content = db.Column(db.Text)
    level = db.Column(db.Integer)
    machine_id = db.Column(db.String(64), nullable=True)  # Optional, to track who posted the comment
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Create database tables
with app.app_context():
    db.create_all()

# Define reset_database function
def reset_database():
    """Reset the database to its initial state"""
    print("Dropping all tables...")
    with app.app_context():
        db.drop_all()
        print("Creating all tables...")
        db.create_all()
        print("Initializing database...")
        # Initialize challenges
        challenges = [
            Challenge(name="Basic Reflected XSS", category="xss", difficulty="beginner",
                     description="Find and exploit a basic reflected XSS vulnerability.", points=100),
            Challenge(name="DOM-based XSS", category="xss", difficulty="beginner",
                     description="Exploit a DOM-based XSS vulnerability.", points=200),
            Challenge(name="Stored XSS", category="xss", difficulty="intermediate",
                     description="Find and exploit a stored XSS vulnerability.", points=300),
            Challenge(name="XSS with Basic Filters", category="xss", difficulty="intermediate",
                     description="Bypass basic XSS filters.", points=400),
            Challenge(name="XSS with Advanced Filters", category="xss", difficulty="advanced",
                     description="Bypass advanced XSS filters.", points=500),
            Challenge(name="XSS with ModSecurity WAF", category="xss", difficulty="advanced",
                     description="Bypass ModSecurity WAF rules.", points=600),
            Challenge(name="XSS via HTTP Headers", category="xss", difficulty="advanced",
                     description="Exploit XSS via HTTP headers.", points=700),
            Challenge(name="XSS in JSON API", category="xss", difficulty="advanced",
                     description="Exploit XSS in a JSON API.", points=750),
            Challenge(name="XSS with CSP Bypass", category="xss", difficulty="expert",
                     description="Bypass Content Security Policy protections.", points=800),
            Challenge(name="XSS with Mutation Observer Bypass", category="xss", difficulty="expert",
                     description="Bypass DOM sanitization with Mutation Observers.", points=900),
            Challenge(name="XSS via SVG and CDATA", category="xss", difficulty="expert",
                     description="Exploit SVG features to execute JavaScript.", points=1000),
            Challenge(name="Blind XSS with Webhook Exfiltration", category="xss", difficulty="expert",
                     description="Exploit a blind XSS vulnerability and exfiltrate data.", points=1100),
            Challenge(name="XSS in PDF Generation", category="xss", difficulty="expert",
                     description="Exploit an XSS vulnerability in PDF generation.", points=1200),
            Challenge(name="XSS via Prototype Pollution", category="xss", difficulty="expert",
                     description="Exploit prototype pollution to achieve XSS.", points=1300),
            Challenge(name="XSS via Template Injection", category="xss", difficulty="expert",
                     description="Exploit template injection to achieve XSS.", points=1400),
            Challenge(name="XSS in WebAssembly Applications", category="xss", difficulty="expert",
                     description="Exploit XSS vulnerabilities in WebAssembly applications.", points=1500),
            Challenge(name="XSS in Progressive Web Apps", category="xss", difficulty="expert",
                     description="Exploit XSS vulnerabilities in Progressive Web Apps.", points=1600),
            Challenge(name="XSS via Web Components", category="xss", difficulty="expert",
                     description="Exploit XSS vulnerabilities in Web Components and Shadow DOM.", points=1700),
            Challenge(name="XSS in GraphQL APIs", category="xss", difficulty="expert",
                     description="Exploit XSS vulnerabilities in GraphQL API responses.", points=1800),
            Challenge(name="XSS in WebRTC Applications", category="xss", difficulty="expert",
                     description="Exploit XSS vulnerabilities in WebRTC applications.", points=1900),
            Challenge(name="XSS via Web Bluetooth/USB", category="xss", difficulty="expert",
                     description="Exploit XSS vulnerabilities in Web Bluetooth/USB APIs.", points=2000),
            Challenge(name="XSS in WebGPU Applications", category="xss", difficulty="expert",
                     description="Exploit XSS vulnerabilities in WebGPU applications.", points=2100),
            Challenge(name="XSS in Federated Identity Systems", category="xss", difficulty="expert",
                     description="Exploit XSS vulnerabilities in federated identity systems.", points=2200),
        ]
        db.session.add_all(challenges)
        db.session.commit()
        print("Database reset complete!")



# Helper functions
def get_machine_id():
    """Generate or retrieve a unique machine identifier"""
    if 'machine_id' not in session:
        # Generate a new machine ID if not in session
        session['machine_id'] = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()

        # Check if this machine ID exists in the database
        existing_user = LocalUser.query.filter_by(machine_id=session['machine_id']).first()
        if not existing_user:
            # Create a new local user
            new_user = LocalUser(
                username='Hacker',
                display_name='Anonymous Hacker',
                machine_id=session['machine_id']
            )
            db.session.add(new_user)
            db.session.commit()

    return session['machine_id']

def get_local_user():
    """Get the current local user or create one if it doesn't exist"""
    machine_id = get_machine_id()
    user = LocalUser.query.filter_by(machine_id=machine_id).first()

    if not user:
        # Create a new local user if not found
        user = LocalUser(
            username='Hacker',
            display_name='Anonymous Hacker',
            machine_id=machine_id
        )
        db.session.add(user)
        db.session.commit()

    # Update last active time
    user.last_active = datetime.utcnow()
    db.session.commit()

    return user

def generate_flag(challenge_id, machine_id):
    """Generate a unique flag for a specific challenge and machine"""
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    unique_id = f"{challenge_id}_{machine_id}_{random_part}"
    flag = f"R00T{{{hashlib.md5(unique_id.encode()).hexdigest()}}}"
    return flag

def get_or_create_flag(challenge_id, machine_id):
    """Get an existing unused flag or create a new one"""
    # Check for existing unused flag
    existing_flag = Flag.query.filter_by(
        challenge_id=challenge_id,
        machine_id=machine_id,
        used=False
    ).first()

    if existing_flag:
        return existing_flag.flag_value

    # Create new flag
    new_flag_value = generate_flag(challenge_id, machine_id)
    new_flag = Flag(challenge_id=challenge_id, machine_id=machine_id, flag_value=new_flag_value)
    db.session.add(new_flag)
    db.session.commit()

    return new_flag_value

def update_user_progress(machine_id, challenge_id, points):
    """Update user progress after completing a challenge"""
    user = LocalUser.query.filter_by(machine_id=machine_id).first()
    if user:
        # Update score
        user.score += points

        # Update completed challenges
        completed = json.loads(user.completed_challenges) if user.completed_challenges else []
        if challenge_id not in completed:
            completed.append(challenge_id)
            user.completed_challenges = json.dumps(completed)

        db.session.commit()
        return True
    return False

# WAF emulation functions
class WAF:
    @staticmethod
    def basic_filter(input_str):
        """Remove basic XSS vectors"""
        if input_str:
            return input_str.replace('<script>', '').replace('</script>', '')
        return input_str

    @staticmethod
    def advanced_filter(input_str):
        """More advanced filtering"""
        if not input_str:
            return input_str

        filtered = input_str.lower()
        filtered = filtered.replace('javascript:', '')
        filtered = filtered.replace('onerror', '')
        filtered = filtered.replace('onload', '')
        filtered = filtered.replace('<script', '')
        filtered = filtered.replace('</script', '')
        return filtered

    @staticmethod
    def modsecurity_emulation(input_str):
        """Emulate ModSecurity WAF rules"""
        if not input_str:
            return input_str, False

        # Common XSS patterns
        xss_patterns = [
            r'<script[^>]*>[\s\S]*?<\/script>',
            r'javascript\s*:',
            r'on\w+\s*=',
            r'\beval\s*\(',
            r'document\.cookie',
            r'document\.location',
            r'document\.write',
            r'\balert\s*\(',
            r'\bprompt\s*\(',
            r'\bconfirm\s*\(',
            r'<img[^>]*\bon\w+\s*=',
            r'<iframe[^>]*>',
            r'<svg[^>]*>',
            r'<body[^>]*\bon\w+\s*=',
            r'<details[^>]*\bon\w+\s*=',
            r'\bfunction\s*\(',
            r'\breturn\s*\(',
            r'\bsetTimeout\s*\(',
            r'\bsetInterval\s*\(',
            r'\bnew\s+Function',
            r'\bObject\s*\(',
            r'\bArray\s*\(',
            r'\bString\s*\(',
            r'\bNumber\s*\(',
            r'\bBoolean\s*\(',
            r'\bRegExp\s*\(',
            r'\bDate\s*\(',
            r'\bMath\s*\.',
            r'\bJSON\s*\.',
            r'\bwindow\s*\.',
            r'\bdocument\s*\.',
            r'\blocation\s*\.',
            r'\bnavigator\s*\.',
            r'\bhistory\s*\.',
            r'\bscreen\s*\.',
            r'\bparent\s*\.',
            r'\btop\s*\.',
            r'\bself\s*\.',
            r'\bglobal\s*\.',
            r'\bthis\s*\.',
            r'\bprototype\s*\.',
            r'\b__proto__\s*\.',
            r'\bconstructor\s*\.',
            r'\bbase64\s*\(',
            r'\batob\s*\(',
            r'\bbtoa\s*\(',
            r'\bunescape\s*\(',
            r'\bescape\s*\(',
            r'\bdecodeURI\s*\(',
            r'\bencodeURI\s*\(',
            r'\bdecodeURIComponent\s*\(',
            r'\bencodeURIComponent\s*\(',
            r'\bcharAt\s*\(',
            r'\bcharCodeAt\s*\(',
            r'\bfromCharCode\s*\(',
            r'\bsubstr\s*\(',
            r'\bsubstring\s*\(',
            r'\bslice\s*\(',
            r'\breplace\s*\(',
            r'\bmatch\s*\(',
            r'\bsearch\s*\(',
            r'\bsplit\s*\(',
            r'\bjoin\s*\(',
            r'\bconcat\s*\(',
            r'\bindexOf\s*\(',
            r'\blastIndexOf\s*\(',
            r'\bpush\s*\(',
            r'\bpop\s*\(',
            r'\bshift\s*\(',
            r'\bunshift\s*\(',
            r'\bsplice\s*\(',
            r'\bsort\s*\(',
            r'\breverse\s*\(',
            r'\bmap\s*\(',
            r'\bfilter\s*\(',
            r'\breduce\s*\(',
            r'\bforEach\s*\(',
            r'\bsome\s*\(',
            r'\bevery\s*\(',
            r'\bfind\s*\(',
            r'\bfindIndex\s*\(',
            r'\bincludes\s*\(',
            r'\bkeys\s*\(',
            r'\bvalues\s*\(',
            r'\bentries\s*\(',
            r'\bhasOwnProperty\s*\(',
            r'\bisPrototypeOf\s*\(',
            r'\bpropertyIsEnumerable\s*\(',
            r'\btoString\s*\(',
            r'\bvalueOf\s*\(',
            r'\btoLocaleString\s*\(',
            r'\btoFixed\s*\(',
            r'\btoExponential\s*\(',
            r'\btoPrecision\s*\(',
            r'\btoLocaleDateString\s*\(',
            r'\btoLocaleTimeString\s*\(',
            r'\btoISOString\s*\(',
            r'\btoUTCString\s*\(',
            r'\btoGMTString\s*\(',
            r'\btoDateString\s*\(',
            r'\btoTimeString\s*\(',
            r'\btoLocaleLowerCase\s*\(',
            r'\btoLocaleUpperCase\s*\(',
            r'\btoLowerCase\s*\(',
            r'\btoUpperCase\s*\(',
            r'\btrim\s*\(',
            r'\btrimStart\s*\(',
            r'\btrimEnd\s*\(',
            r'\bpadStart\s*\(',
            r'\bpadEnd\s*\(',
            r'\brepeat\s*\(',
            r'\bstartsWith\s*\(',
            r'\bendsWith\s*\(',
            r'\bnormalize\s*\(',
            r'\blocaleCompare\s*\(',
            r'\bmatch\s*\(',
            r'\bmatchAll\s*\(',
            r'\bsearch\s*\(',
            r'\breplace\s*\(',
            r'\breplaceAll\s*\(',
            r'\bsplit\s*\(',
            r'\btest\s*\(',
            r'\bexec\s*\(',
            r'\bcompile\s*\(',
            r'\bsource\s*\.',
            r'\bflags\s*\.',
            r'\bglobal\s*\.',
            r'\bignoreCase\s*\.',
            r'\bmultiline\s*\.',
            r'\bdotAll\s*\.',
            r'\bsticky\s*\.',
            r'\bunicode\s*\.',
            r'\blastIndex\s*\.',
            r'\binput\s*\.',
            r'\bindices\s*\.',
            r'\bgroups\s*\.',
            r'\bnamed\s*\.',
            r'\bcaptures\s*\.',
            r'\bindex\s*\.',
            r'\blength\s*\.',
            r'\bname\s*\.',
            r'\bmessage\s*\.',
            r'\bstack\s*\.',
            r'\bcause\s*\.',
            r'\bfileName\s*\.',
            r'\blineNumber\s*\.',
            r'\bcolumnNumber\s*\.',
            r'\berrorCode\s*\.',
            r'\berrorMessage\s*\.',
            r'\berrorName\s*\.',
            r'\berrorDescription\s*\.',
            r'\berrorNumber\s*\.',
            r'\berrorSeverity\s*\.',
            r'\berrorCategory\s*\.',
            r'\berrorText\s*\.',
            r'\berrorURI\s*\.',
            r'\berrorLine\s*\.',
            r'\berrorColumn\s*\.',
            r'\berrorObject\s*\.',
            r'\berrorCode\s*\.',
            r'\berrorMessage\s*\.',
            r'\berrorName\s*\.',
            r'\berrorDescription\s*\.',
            r'\berrorNumber\s*\.',
            r'\berrorSeverity\s*\.',
            r'\berrorCategory\s*\.',
            r'\berrorText\s*\.',
            r'\berrorURI\s*\.',
            r'\berrorLine\s*\.',
            r'\berrorColumn\s*\.',
            r'\berrorObject\s*\.',
        ]

        # Check if input matches any XSS pattern
        for pattern in xss_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                # In a real WAF, this would block the request
                # For our emulation, we'll return the original input and a flag indicating it was blocked
                return input_str, True

        return input_str, False

# Theme management
@app.route('/change-theme/<theme>')
def change_theme(theme):
    valid_themes = ['dark', 'light', 'cyberpunk', 'hacker']
    if theme in valid_themes:
        session['theme'] = theme
    return redirect(request.referrer or url_for('index'))

# Profile management
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user = get_local_user()

    if request.method == 'POST':
        display_name = request.form.get('display_name')
        if display_name and len(display_name) <= 50:
            # Update both display_name and username for consistency
            user.display_name = display_name
            user.username = display_name
            db.session.commit()
            return redirect(url_for('profile'))

    # Get completed challenges
    completed_challenges = []
    if user.completed_challenges:
        challenge_ids = json.loads(user.completed_challenges)
        completed_challenges = Challenge.query.filter(Challenge.id.in_(challenge_ids)).all()

    # Get total number of challenges
    total_challenge_count = Challenge.query.filter_by(active=True).count()

    # Calculate remaining challenges
    remaining_challenge_count = total_challenge_count - len(completed_challenges)

    return render_template('profile.html',
                          user=user,
                          completed_challenges=completed_challenges,
                          total_challenge_count=total_challenge_count,
                          remaining_challenge_count=remaining_challenge_count)

# Home page
@app.route('/')
def index():
    # Ensure user is initialized
    get_local_user()
    return render_template('index.html')

# Vulnerabilities selection page with categories
@app.route('/challenges')
def vulnerabilities():
    # Get all unique categories
    categories = db.session.query(Challenge.category).distinct().all()
    categories = [c[0] for c in categories]

    # Get the current user and their completed challenges
    user = get_local_user()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []

    # Get challenges grouped by category
    challenges_by_category = {}
    category_completion = {}
    total_count = 0
    completed_count = 0

    for category in categories:
        challenges = Challenge.query.filter_by(category=category, active=True).all()
        category_total = len(challenges)
        category_completed = 0

        # Process each challenge
        for challenge in challenges:
            challenge.completed = challenge.id in completed_ids
            if challenge.completed:
                challenge.flag = get_or_create_flag(challenge.id, user.machine_id)
                category_completed += 1
                completed_count += 1
            else:
                challenge.flag = None

        challenges_by_category[category] = challenges
        category_completion[category] = {
            'total': category_total,
            'completed': category_completed
        }
        total_count += category_total

    return render_template(
        'vulnerabilities.html',
        categories=categories,
        challenges_by_category=challenges_by_category,
        category_completion=category_completion,
        total_count=total_count,
        completed_count=completed_count
    )

# Scoreboard
@app.route('/scoreboard')
def scoreboard():
    top_users = LocalUser.query.order_by(LocalUser.score.desc()).limit(20).all()
    return render_template('scoreboard.html', users=top_users)

# Flag submission
@app.route('/submit-flag', methods=['POST'])
def submit_flag():
    challenge_id = request.form.get('challenge_id')
    flag = request.form.get('flag')
    machine_id = get_machine_id()

    if not challenge_id or not flag:
        return jsonify({'success': False, 'message': 'Missing required parameters'})

    # Convert challenge_id to integer
    try:
        challenge_id = int(challenge_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid challenge ID format'})

    # Get the challenge
    challenge = Challenge.query.get(challenge_id)
    if not challenge or not challenge.active:
        return jsonify({'success': False, 'message': 'Invalid challenge'})

    # Check if flag is valid
    valid_flag = Flag.query.filter_by(
        challenge_id=challenge_id,
        machine_id=machine_id,
        flag_value=flag,
        used=False
    ).first()

    if valid_flag:
        # Mark flag as used
        valid_flag.used = True

        # Record submission
        submission = Submission(machine_id=machine_id, challenge_id=challenge_id, flag=flag, correct=True)
        db.session.add(submission)

        # Update user score
        update_user_progress(machine_id, challenge_id, challenge.points)

        db.session.commit()

        return jsonify({'success': True, 'message': f'Congratulations! You earned {challenge.points} points!'})
    else:
        # Record incorrect submission
        submission = Submission(machine_id=machine_id, challenge_id=challenge_id, flag=flag, correct=False)
        db.session.add(submission)
        db.session.commit()

        return jsonify({'success': False, 'message': 'Invalid flag. Try again!'})

# XSS Level 1 - Basic Reflected XSS
@app.route('/xss/level1', methods=['GET', 'POST'])
def xss_level1():
    user_input = request.args.get('name', '')
    machine_id = get_machine_id()
    flag = None
    xss_detected = False

    # Get this user's completed challenges
    user = get_local_user()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []

    # Check for XSS payload
    if '<script>' in user_input or 'javascript:' in user_input or 'onerror=' in user_input:
        xss_detected = True
        # Mark challenge as completed if not already
        challenge = Challenge.query.filter_by(name="Basic Reflected XSS").first()
        if challenge and challenge.id not in completed_ids:
            update_user_progress(machine_id, challenge.id, challenge.points)
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="Basic Reflected XSS").first()
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level1.html', user_input=user_input, flag=flag, xss_detected=xss_detected, challenge=challenge)

# XSS Level 2 - DOM-based XSS
@app.route('/xss/level2')
def xss_level2():
    machine_id = get_machine_id()
    flag = None
    xss_detected = False

    user = get_local_user()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []

    # Mark challenge as completed if ?success=true is present (triggered by frontend after alert)
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name="DOM-based XSS").first()
        if challenge and challenge.id not in completed_ids:
            update_user_progress(machine_id, challenge.id, challenge.points)
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []

    challenge = Challenge.query.filter_by(name="DOM-based XSS").first()
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    # Handle AJAX requests differently
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'xss_detected': xss_detected,
            'flag': flag,
            'message': 'Challenge completed successfully!'
        })

    # Regular page render
    return render_template('xss/xss_level2.html', flag=flag, xss_detected=xss_detected, challenge=challenge)

# XSS Level 3 - Stored XSS
@app.route('/xss/level3', methods=['GET', 'POST'])
def xss_level3():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xss_detected = False

    if request.method == 'POST':
        # Always use the current user's display name for consistency
        username = user.display_name
        content = request.form.get('content', '')

        # Check for XSS payload in content
        if '<script>' in content or 'javascript:' in content or 'onerror=' in content:
            xss_detected = True
            # Mark challenge as completed if not already
            challenge = Challenge.query.filter_by(name="Stored XSS").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []

        # Store the comment in the database
        new_comment = Comment(username=username, content=content, level=3, machine_id=machine_id)
        db.session.add(new_comment)
        db.session.commit()

        return redirect(url_for('xss_level3'))

    # Get all comments for level 3
    comments = Comment.query.filter_by(level=3).order_by(Comment.timestamp.desc()).all()

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="Stored XSS").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level3.html', comments=comments, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

# XSS Level 4 - XSS with Basic Filters
@app.route('/xss/level4', methods=['GET', 'POST'])
def xss_level4():
    machine_id = get_machine_id()
    user = get_local_user()
    message = ""
    filtered_input = ""
    waf_blocked = False
    flag = None
    xss_detected = False

    if request.method == 'POST':
        user_input = request.form.get('user_input', '')

        # Basic filter: Remove <script> tags
        filtered_input = WAF.basic_filter(user_input)
        message = "Your input has been filtered for security!"

        # Check if XSS was successful despite filtering
        if '<img' in user_input and 'onerror=' in user_input:
            xss_detected = True
            # Mark challenge as completed if not already
            challenge = Challenge.query.filter_by(name="XSS with Basic Filters").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="XSS with Basic Filters").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level4.html', message=message, filtered_input=filtered_input,
                           waf_blocked=waf_blocked, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

# XSS Level 5 - XSS with Advanced Filters
@app.route('/xss/level5', methods=['GET', 'POST'])
def xss_level5():
    machine_id = get_machine_id()
    user = get_local_user()
    message = ""
    filtered_input = ""
    waf_blocked = False
    flag = None
    xss_detected = False

    if request.method == 'POST':
        user_input = request.form.get('user_input', '')

        # More advanced filtering (still bypassable)
        filtered_input = WAF.advanced_filter(user_input)
        message = "Your input has been filtered with our advanced security system!"

        # Check if XSS was successful despite filtering
        if '<svg' in user_input and 'onload=' in user_input:
            xss_detected = True
            # Mark challenge as completed if not already
            challenge = Challenge.query.filter_by(name="XSS with Advanced Filters").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="XSS with Advanced Filters").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level5.html', message=message, filtered_input=filtered_input,
                           waf_blocked=waf_blocked, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

# XSS Level 6 - XSS with ModSecurity WAF
@app.route('/xss/level6', methods=['GET', 'POST'])
def xss_level6():
    machine_id = get_machine_id()
    user = get_local_user()
    message = ""
    filtered_input = ""
    waf_blocked = False
    flag = None
    xss_detected = False

    if request.method == 'POST':
        user_input = request.form.get('user_input', '')

        # ModSecurity WAF emulation
        filtered_input, waf_blocked = WAF.modsecurity_emulation(user_input)

        if waf_blocked:
            message = "⚠️ WAF Alert: Potential XSS attack detected and blocked!"
        else:
            message = "Input passed security checks."

            # Check if XSS was successful despite WAF
            if '<iframe' in user_input and 'srcdoc=' in user_input:
                xss_detected = True
                # Mark challenge as completed if not already
                challenge = Challenge.query.filter_by(name="XSS with ModSecurity WAF").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="XSS with ModSecurity WAF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level6.html', message=message, filtered_input=filtered_input,
                           waf_blocked=waf_blocked, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

# XSS Level 7 - XSS via HTTP Headers
@app.route('/xss/level7', methods=['GET'])
def xss_level7():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xss_detected = False

    # Get the user's IP address and User-Agent
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')

    # Generate a random visitor ID
    random_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

    # Check if the User-Agent contains the XSS payload
    if '<script>' in user_agent or 'javascript:' in user_agent or 'onerror=' in user_agent:
        xss_detected = True
        # Mark challenge as completed
        challenge = Challenge.query.filter_by(name="XSS via HTTP Headers").first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(machine_id, challenge.id, challenge.points)

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="XSS via HTTP Headers").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level7.html', client_ip=client_ip, user_agent=user_agent,
                           random_id=random_id, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

# XSS Level 8 - XSS in JSON API
@app.route('/xss/level8', methods=['GET'])
def xss_level8():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xss_detected = False

    # Check for XSS in JSON response
    if request.args.get('xss') == 'true':
        xss_detected = True
        # Mark challenge as completed
        challenge = Challenge.query.filter_by(name="XSS in JSON API").first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(machine_id, challenge.id, challenge.points)

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="XSS in JSON API").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level8.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

# API endpoint for XSS Level 8
@app.route('/api/notes', methods=['GET', 'POST'])
def api_notes():
    machine_id = get_machine_id()
    user = get_local_user()

    if request.method == 'POST':
        # Handle note creation
        data = request.get_json()

        # Create a new note
        new_note = {
            'id': random.randint(1000, 9999),
            'title': data.get('title', ''),
            'content': data.get('content', ''),
            'tags': data.get('tags', '').split(',') if data.get('tags') else [],
            'created': datetime.now().isoformat()
        }

        # Return the new note
        return jsonify(new_note)
    else:
        # Return sample notes
        notes = [
            {
                'id': 101,
                'title': 'Getting Started with DevNotes',
                'content': 'Welcome to DevNotes! This is a simple note-taking app for developers.',
                'tags': ['welcome', 'tutorial'],
                'created': '2025-04-19T10:30:00Z'
            },
            {
                'id': 102,
                'title': 'JavaScript Tips and Tricks',
                'content': 'Here are some useful JavaScript tips and tricks for web developers.',
                'tags': ['javascript', 'tips'],
                'created': '2025-04-19T11:45:00Z'
            },
            {
                'id': 103,
                'title': 'API Security Best Practices',
                'content': 'Learn how to secure your APIs against common vulnerabilities.',
                'tags': ['security', 'api'],
                'created': '2025-04-19T14:20:00Z'
            }
        ]

        # Check if there's an XSS payload in the request headers
        user_agent = request.headers.get('User-Agent', '')
        if 'XSS Level 8 Completed!' in user_agent:
            # Add a note with the XSS payload in the title
            notes.insert(0, {
                'id': 104,
                'title': '<img src=x onerror="alert(\'XSS Level 8 Completed!\');">',
                'content': 'This note contains an XSS payload in the title.',
                'tags': ['xss', 'security'],
                'created': datetime.now().isoformat()
            })

            # Mark challenge as completed when the payload is detected
            challenge = Challenge.query.filter_by(name="XSS in JSON API").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)

        return jsonify(notes)

# XSS Level 9 - XSS with CSP Bypass
@app.route('/xss/level9', methods=['GET', 'POST'])
def xss_level9():
    machine_id = get_machine_id()
    user = get_local_user()
    user_comment = ""
    flag = None
    xss_detected = False
    message = ""

    if request.method == 'POST':
        user_comment = request.form.get('comment', '')
        # Check for the intended XSS payload
        if 'alert("XSS Level 9 Completed!")' in user_comment or "alert('XSS Level 9 Completed!')" in user_comment:
            xss_detected = True
            challenge = Challenge.query.filter_by(name="XSS with CSP Bypass").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."
        else:
            message = "Try to bypass the CSP and trigger the alert as described."

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="XSS with CSP Bypass").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    response = make_response(render_template('xss/xss_level9.html', user_comment=user_comment, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message))
    # Intentionally misconfigured CSP to allow the challenge to be solved
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' https://via.placeholder.com data:;"

    # Add the message to the response for display
    if message:
        response.set_cookie('message', message)

    return response

# XSS Level 10 - XSS with Mutation Observer Bypass
@app.route('/xss/level10', methods=['GET', 'POST'])
def xss_level10():
    machine_id = get_machine_id()
    user = get_local_user()
    user_message = ""
    flag = None
    xss_detected = False
    message = ""
    chat_messages = [
        {"user": "System", "message": "Welcome to SafeChat! This is a secure messaging platform.", "time": "10:00 AM"},
        {"user": "Admin", "message": "Please be aware that we sanitize all messages to prevent XSS attacks.", "time": "10:05 AM"},
        {"user": "User123", "message": "I tried to use <script>alert('test')</script> but it didn't work!", "time": "10:10 AM"},
        {"user": "Admin", "message": "That's right! Our Mutation Observer technology removes malicious code instantly.", "time": "10:15 AM"}
    ]

    # Check if success parameter is present (XSS was successful)
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name="XSS with Mutation Observer Bypass").first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(machine_id, challenge.id, challenge.points)
        message = "Challenge solved! Flag revealed."

    if request.method == 'POST':
        user_message = request.form.get('message', '')

        # Check for the intended XSS payload
        if 'alert("XSS Level 10 Completed!")' in user_message or "alert('XSS Level 10 Completed!')" in user_message:
            xss_detected = True
            challenge = Challenge.query.filter_by(name="XSS with Mutation Observer Bypass").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."

            # Add the user's message to the chat
            chat_messages.append({
                "user": user.display_name if user else "Guest",
                "message": user_message,
                "time": datetime.now().strftime("%I:%M %p")
            })
        else:
            message = "Try to bypass the mutation observer and trigger the alert as described."

            # Add the user's message to the chat
            chat_messages.append({
                "user": user.display_name if user else "Guest",
                "message": user_message,
                "time": datetime.now().strftime("%I:%M %p")
            })

    challenge = Challenge.query.filter_by(name="XSS with Mutation Observer Bypass").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level10.html',
                          user_message=user_message,
                          flag=flag,
                          user=user,
                          xss_detected=xss_detected,
                          challenge=challenge,
                          message=message,
                          chat_messages=chat_messages)

# XSS Level 11 - XSS via SVG and CDATA
@app.route('/xss/level11', methods=['GET', 'POST'])
def xss_level11():
    machine_id = get_machine_id()
    user = get_local_user()
    svg_code = '<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"></svg>'
    filtered_svg = ""
    flag = None
    xss_detected = False
    message = ""

    # Example SVG codes for the buttons
    example_svgs = {
        'circle': '<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"><circle cx="100" cy="100" r="50" fill="blue" /></svg>',
        'rectangle': '<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"><rect x="50" y="50" width="100" height="100" fill="green" /></svg>',
        'text': '<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"><text x="50" y="100" font-family="Arial" font-size="20" fill="red">Hello SVG</text></svg>'
    }

    # Check if success parameter is present (XSS was successful)
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name="XSS via SVG and CDATA").first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(machine_id, challenge.id, challenge.points)
        message = "Challenge solved! Flag revealed."

    if request.method == 'POST':
        svg_code = request.form.get('svg_code', '')

        # Basic SVG filtering
        filtered_svg = svg_code
        filtered_svg = re.sub(r'<script[^>]*>.*?</script>', '', filtered_svg, flags=re.DOTALL)
        filtered_svg = re.sub(r'\son\w+=["\'][^"\'>]*["\']', '', filtered_svg)
        filtered_svg = re.sub(r'\s(?:href|xlink:href|src)=["\']javascript:[^"\'>]*["\']', '', filtered_svg)

        # Check for successful SVG XSS
        if ('alert("XSS Level 11 Completed!")' in svg_code or "alert('XSS Level 11 Completed!')" in svg_code) and ('<svg' in svg_code):
            xss_detected = True
            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="XSS via SVG and CDATA").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="XSS via SVG and CDATA").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level11.html',
                          svg_code=svg_code,
                          filtered_svg=filtered_svg,
                          flag=flag,
                          user=user,
                          xss_detected=xss_detected,
                          challenge=challenge,
                          message=message,
                          example_svgs=example_svgs)

# XSS Level 12 - Blind XSS with Webhook Exfiltration
@app.route('/xss/level12', methods=['GET', 'POST'])
def xss_level12():
    machine_id = get_machine_id()
    user = get_local_user()
    ticket_submitted = False
    ticket_id = None
    ticket_subject = None
    ticket_description = None
    flag = None
    xss_detected = False
    message = ""
    webhook_url = ""

    # Check if success parameter is present (XSS was successful)
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name="Blind XSS with Webhook Exfiltration").first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(machine_id, challenge.id, challenge.points)
        message = "Challenge solved! Flag revealed."

    if request.method == 'POST':
        # Get form data
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        subject = request.form.get('subject', '')
        category = request.form.get('category', '')
        description = request.form.get('description', '')
        webhook_url = request.form.get('webhook_url', '')

        # Generate a random ticket ID
        ticket_id = 'TKT-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        ticket_subject = subject
        ticket_description = description
        ticket_submitted = True

        # Check for XSS payload in description
        if ('<script>' in description or 'javascript:' in description or 'onerror=' in description) and webhook_url:
            xss_detected = True
            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="Blind XSS with Webhook Exfiltration").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Your XSS payload was executed in the admin panel and the data was exfiltrated to your webhook."

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="Blind XSS with Webhook Exfiltration").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level12.html',
                          ticket_submitted=ticket_submitted,
                          ticket_id=ticket_id,
                          ticket_subject=ticket_subject,
                          ticket_description=ticket_description,
                          flag=flag,
                          user=user,
                          xss_detected=xss_detected,
                          challenge=challenge,
                          message=message,
                          webhook_url=webhook_url)

# XSS Level 13 - XSS in PDF Generation
@app.route('/xss/level13', methods=['GET', 'POST'])
def xss_level13():
    machine_id = get_machine_id()
    user = get_local_user()
    pdf_generated = False
    resume_name = None
    resume_email = None
    resume_phone = None
    resume_summary = None
    resume_skills = None
    resume_experience = None
    flag = None
    xss_detected = False

    if request.method == 'POST':
        # Get form data
        resume_name = request.form.get('name', '')
        resume_email = request.form.get('email', '')
        resume_phone = request.form.get('phone', '')
        resume_summary = request.form.get('summary', '')
        resume_skills = request.form.get('skills', '')
        resume_experience = request.form.get('experience', '')
        pdf_generated = True

        # Check for PDF JavaScript
        if 'app.alert' in resume_summary or 'app.alert' in resume_skills or 'app.alert' in resume_experience:
            xss_detected = True
            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="XSS in PDF Generation").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="XSS in PDF Generation").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level13.html', pdf_generated=pdf_generated,
                           resume_name=resume_name, resume_email=resume_email,
                           resume_phone=resume_phone, resume_summary=resume_summary,
                           resume_skills=resume_skills, resume_experience=resume_experience,
                           flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

# XSS Level 14 - XSS via Prototype Pollution
@app.route('/xss/level14', methods=['GET', 'POST'])
def xss_level14():
    machine_id = get_machine_id()
    user = get_local_user()
    config_saved = False
    config_name = None
    config_json = None
    flag = None
    xss_detected = False
    message = ""

    # Check if success parameter is present (XSS was successful)
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name="XSS via Prototype Pollution").first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(machine_id, challenge.id, challenge.points)
        message = "Challenge solved! Flag revealed."

    if request.method == 'POST':
        # Get form data
        config_name = request.form.get('config_name', '')
        config_json = request.form.get('config_json', '')
        config_saved = True

        # Check for prototype pollution
        if '__proto__' in config_json and ('innerHTML' in config_json or 'outerHTML' in config_json or 'alert' in config_json):
            xss_detected = True
            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="XSS via Prototype Pollution").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."
        else:
            message = "Try to use prototype pollution to trigger the alert as described."

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="XSS via Prototype Pollution").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level14.html',
                          config_saved=config_saved,
                          config_name=config_name,
                          config_json=config_json,
                          flag=flag,
                          user=user,
                          xss_detected=xss_detected,
                          challenge=challenge,
                          message=message)

# XSS Level 15 - XSS via Template Injection
@app.route('/xss/level15', methods=['GET', 'POST'])
def xss_level15():
    machine_id = get_machine_id()
    user = get_local_user()
    template_saved = False
    template_name = None
    template_subject = None
    template_content = None
    rendered_template = None
    flag = None
    xss_detected = False
    message = ""

    # Check if success parameter is present (XSS was successful)
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name="XSS via Template Injection").first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(machine_id, challenge.id, challenge.points)
        message = "Challenge solved! Flag revealed."
    current_date = datetime.now().strftime('%B %d, %Y')

    if request.method == 'POST':
        # Get form data
        template_name = request.form.get('template_name', '')
        template_subject = request.form.get('template_subject', '')
        template_content = request.form.get('template_content', '')
        template_saved = True

        # Check for template injection
        if ('constructor.constructor' in template_content or
            'eval(' in template_content or
            'alert("XSS Level 15 Completed!")' in template_content or
            "alert('XSS Level 15 Completed!')" in template_content):
            xss_detected = True
            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="XSS via Template Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."
        else:
            message = "Template saved, but no XSS detected. Try using template injection to trigger the alert."

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="XSS via Template Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level15.html',
                          template_saved=template_saved,
                          template_name=template_name,
                          template_subject=template_subject,
                          template_content=template_content,
                          rendered_template=rendered_template,
                          current_date=current_date,
                          flag=flag,
                          user=user,
                          xss_detected=xss_detected,
                          challenge=challenge,
                          message=message)

# XSS Level 16 - XSS in WebAssembly Applications
@app.route('/xss/level16', methods=['GET', 'POST'])
def xss_level16():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xss_detected = False
    message = ""
    # Check for intended payload
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 16 Completed!")' in user_input or "alert('XSS Level 16 Completed!')" in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name="XSS in WebAssembly Applications").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."
        else:
            message = "Try to trigger the alert as described."
    challenge = Challenge.query.filter_by(name="XSS in WebAssembly Applications").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    return render_template('xss/xss_level16.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

# XSS Level 17 - XSS in Progressive Web Apps
@app.route('/xss/level17', methods=['GET', 'POST'])
def xss_level17():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xss_detected = False
    message = ""
    # Check if success parameter is present (XSS was successful)
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name="XSS in Progressive Web Apps").first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(machine_id, challenge.id, challenge.points)
        message = "Challenge solved! Flag revealed."

    if request.method == 'POST':
        user_input = request.form.get('input', '')
        manifest_json = request.form.get('manifest', '')
        service_worker_js = request.form.get('service_worker', '')

        # Check for XSS in any of the inputs
        if ('alert("XSS Level 17 Completed!")' in user_input or
            "alert('XSS Level 17 Completed!')" in user_input or
            'alert("XSS Level 17 Completed!")' in manifest_json or
            "alert('XSS Level 17 Completed!')" in manifest_json or
            'alert("XSS Level 17 Completed!")' in service_worker_js or
            "alert('XSS Level 17 Completed!')" in service_worker_js):
            xss_detected = True
            challenge = Challenge.query.filter_by(name="XSS in Progressive Web Apps").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."
        else:
            message = "Try to trigger the alert as described. Look for vulnerabilities in the PWA components."
    challenge = Challenge.query.filter_by(name="XSS in Progressive Web Apps").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    return render_template('xss/xss_level17.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

# XSS Level 18 - XSS via Web Components
@app.route('/xss/level18', methods=['GET', 'POST'])
def xss_level18():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xss_detected = False
    message = ""
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 18 Completed!")' in user_input or "alert('XSS Level 18 Completed!')" in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name="XSS via Web Components").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."
        else:
            message = "Try to trigger the alert as described."
    challenge = Challenge.query.filter_by(name="XSS via Web Components").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    return render_template('xss/xss_level18.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

# XSS Level 19 - XSS in GraphQL APIs
@app.route('/xss/level19', methods=['GET', 'POST'])
def xss_level19():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xss_detected = False
    message = ""
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 19 Completed!")' in user_input or "alert('XSS Level 19 Completed!')" in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name="XSS in GraphQL APIs").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."
        else:
            message = "Try to trigger the alert as described."
    challenge = Challenge.query.filter_by(name="XSS in GraphQL APIs").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    return render_template('xss/xss_level19.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

# XSS Level 20 - XSS in WebRTC Applications
@app.route('/xss/level20', methods=['GET', 'POST'])
def xss_level20():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xss_detected = False
    message = ""
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 20 Completed!")' in user_input or "alert('XSS Level 20 Completed!')" in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name="XSS in WebRTC Applications").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."
        else:
            message = "Try to trigger the alert as described."
    challenge = Challenge.query.filter_by(name="XSS in WebRTC Applications").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    return render_template('xss/xss_level20.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

# XSS Level 21 - XSS via Web Bluetooth/USB
@app.route('/xss/level21', methods=['GET', 'POST'])
def xss_level21():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xss_detected = False
    message = ""
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 21 Completed!")' in user_input or "alert('XSS Level 21 Completed!')" in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name="XSS via Web Bluetooth/USB").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."
        else:
            message = "Try to trigger the alert as described."
    challenge = Challenge.query.filter_by(name="XSS via Web Bluetooth/USB").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    return render_template('xss/xss_level21.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

# XSS Level 22 - XSS in WebGPU Applications
@app.route('/xss/level22', methods=['GET', 'POST'])
def xss_level22():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xss_detected = False
    message = ""
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 22 Completed!")' in user_input or "alert('XSS Level 22 Completed!')" in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name="XSS in WebGPU Applications").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."
        else:
            message = "Try to trigger the alert as described."
    challenge = Challenge.query.filter_by(name="XSS in WebGPU Applications").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    return render_template('xss/xss_level22.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

# XSS Level 23 - XSS in Federated Identity Systems
@app.route('/xss/level23', methods=['GET', 'POST'])
def xss_level23():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xss_detected = False
    message = ""
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 23 Completed!")' in user_input or "alert('XSS Level 23 Completed!')" in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name="XSS in Federated Identity Systems").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
            message = "Challenge solved! Flag revealed."
        else:
            message = "Try to trigger the alert as described."
    challenge = Challenge.query.filter_by(name="XSS in Federated Identity Systems").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    return render_template('xss/xss_level23.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

# Solutions
@app.route('/solutions/<level>')
def solutions(level):
    return render_template(f'solutions/xss_level{level}_solution.html')



def show_help():
    """Show help information"""
    print("R00tGlyph - XSS Training Platform")
    print("\nUsage:")
    print("  python app.py [options]")
    print("\nOptions:")
    print("  -h, --help     Show this help message and exit")
    print("  --reset        Reset the database to its initial state")
    print("\nExamples:")
    print("  python app.py              Start the application")
    print("  python app.py --reset      Reset the database and start the application")
    print("  python app.py -h           Show this help message")

if __name__ == '__main__':
    # Check for --reset argument *before* running the app
    # This ensures reset happens with the app context available via reset_database()
    if '--reset' in sys.argv:
        reset_database()
        print("Database has been reset. Start the application normally without --reset to use it.")
        sys.exit(0)

    # Check for help argument
    if '-h' in sys.argv or '--help' in sys.argv:
        show_help()
        sys.exit(0)

    # Start the application
    # Note: The argparse block at the top handles --update, --backup, --restore
    # Those commands exit the script, so they won't reach here.
    app.run(debug=False, host='0.0.0.0', port=5000)
