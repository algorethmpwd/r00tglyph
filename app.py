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

            # Step 4: Update database schema and data
            print("Updating database schema and data...")
            with app.app_context():
                # Update SQL Injection challenges to use 'sqli' category
                challenges = Challenge.query.filter_by(category='SQL Injection').all()
                for challenge in challenges:
                    challenge.category = 'sqli'
                db.session.commit()
                print("Database schema and data updated successfully!")

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

    # Remove 'SQL Injection' category if it exists (we only want 'sqli')
    if 'SQL Injection' in categories:
        categories.remove('SQL Injection')

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

# SQL Injection Level 1 - Basic SQL Injection
@app.route('/sqli/level1', methods=['GET', 'POST'])
def sqli_level1():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    error = None
    success = None

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # Check for SQL injection patterns
        sqli_patterns = ["'", "\"", "--", ";", "OR", "=", "UNION", "SELECT", "DROP", "INSERT", "DELETE", "UPDATE"]

        # Convert to uppercase for case-insensitive check
        username_upper = username.upper()
        password_upper = password.upper()

        # Check if any SQL injection pattern is in the input
        for pattern in sqli_patterns:
            if pattern.upper() in username_upper or pattern.upper() in password_upper:
                # SQL injection detected!
                sqli_detected = True
                break

        # Simulate a vulnerable login system
        if sqli_detected:
            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="Basic SQL Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)

            success = "SQL Injection detected! You've successfully bypassed the login."
        else:
            # Normal login attempt (will always fail for this challenge)
            error = "Invalid username or password."

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="Basic SQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level1.html', flag=flag, sqli_detected=sqli_detected, error=error, success=success)

# SQL Injection Level 2 - SQL Injection in Search
@app.route('/sqli/level2', methods=['GET'])
def sqli_level2():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    search_term = request.args.get('search', '')
    search_performed = bool(search_term)
    products = []

    # Default products
    default_products = [
        {"id": 1, "name": "Smartphone X", "category": "Electronics", "price": 999.99},
        {"id": 2, "name": "Laptop Pro", "category": "Electronics", "price": 1499.99},
        {"id": 3, "name": "Wireless Headphones", "category": "Audio", "price": 199.99},
        {"id": 4, "name": "Smart Watch", "category": "Wearables", "price": 299.99},
        {"id": 5, "name": "Bluetooth Speaker", "category": "Audio", "price": 129.99}
    ]

    # Secret product (only shown when SQL injection is successful)
    secret_product = {"id": 42, "name": "Secret Gadget", "category": "Classified", "price": 9999.99}

    if search_term:
        # Check for SQL injection patterns
        sqli_patterns = ["'", "\"", "--", ";", "OR", "=", "UNION", "SELECT", "DROP", "INSERT", "DELETE", "UPDATE"]

        # Convert to uppercase for case-insensitive check
        search_upper = search_term.upper()

        # Check if any SQL injection pattern is in the input
        for pattern in sqli_patterns:
            if pattern.upper() in search_upper:
                # SQL injection detected!
                sqli_detected = True
                break

        # Filter products based on search term
        products = [p for p in default_products if search_term.lower() in p["name"].lower()]

        # If SQL injection is detected and specifically looking for product with ID 42
        if sqli_detected and ("42" in search_term or "id=42" in search_term.lower() or "id = 42" in search_term.lower()):
            products.append(secret_product)

            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="SQL Injection in Search").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
        # If SQL injection is detected with a generic attack that would return all products
        elif sqli_detected and ("1=1" in search_term.lower() or "or" in search_term.lower()):
            products = default_products.copy()
            products.append(secret_product)

            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="SQL Injection in Search").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in Search").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level2.html', flag=flag, sqli_detected=sqli_detected,
                          search_term=search_term, search_performed=search_performed, products=products)

# SQL Injection Level 3 - SQL Injection with UNION
@app.route('/sqli/level3', methods=['GET'])
def sqli_level3():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    search_term = request.args.get('search', '')
    search_performed = bool(search_term)
    books = []

    # Default books
    default_books = [
        {"id": 1, "title": "The Great Gatsby", "author": "F. Scott Fitzgerald", "category": "Fiction", "year": 1925},
        {"id": 2, "title": "To Kill a Mockingbird", "author": "Harper Lee", "category": "Fiction", "year": 1960},
        {"id": 3, "title": "1984", "author": "George Orwell", "category": "Science Fiction", "year": 1949},
        {"id": 4, "title": "Pride and Prejudice", "author": "Jane Austen", "category": "Romance", "year": 1813},
        {"id": 5, "title": "The Hobbit", "author": "J.R.R. Tolkien", "category": "Fantasy", "year": 1937}
    ]

    # Hidden users table (only accessible through UNION-based SQL injection)
    users = [
        {"id": 1, "username": "admin", "password": "FLAG{uni0n_b4s3d_sql1_m4st3r}", "role": "admin", "created": 2023}
    ]

    if search_term:
        # Check for SQL injection patterns
        sqli_patterns = ["'", "\"", "--", ";", "UNION", "SELECT", "FROM", "WHERE"]

        # Convert to uppercase for case-insensitive check
        search_upper = search_term.upper()

        # Check if any SQL injection pattern is in the input
        for pattern in sqli_patterns:
            if pattern.upper() in search_upper:
                # SQL injection detected!
                sqli_detected = True
                break

        # Filter books based on search term
        books = [b for b in default_books if search_term.lower() in b["title"].lower()]

        # If UNION-based SQL injection is detected
        if sqli_detected and "UNION" in search_upper and "SELECT" in search_upper:
            # Check if the query is trying to access the users table
            if "USER" in search_upper or "ADMIN" in search_upper:
                # Add the admin user to the results, formatted to match the books table structure
                admin_user = users[0]
                books.append({
                    "id": admin_user["id"],
                    "title": admin_user["username"],
                    "author": admin_user["password"],
                    "category": admin_user["role"],
                    "year": admin_user["created"]
                })

                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="SQL Injection with UNION").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection with UNION").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level3.html', flag=flag, sqli_detected=sqli_detected,
                          search_term=search_term, search_performed=search_performed, books=books)

# SQL Injection Level 4 - Blind SQL Injection
@app.route('/sqli/level4', methods=['GET'])
def sqli_level4():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    user_id = request.args.get('id', '')
    user_exists = None

    # Hidden users
    hidden_users = {
        "1": {"username": "admin", "password": "admin123"},
        "2": {"username": "user", "password": "password123"},
        "3": {"username": "guest", "password": "guest"},
        "42": {"username": "admin_secret", "password": "FLAG{bl1nd_sql1_3xtr4ct10n_pr0}"}
    }

    if user_id:
        # Check for SQL injection patterns
        sqli_patterns = ["'", "\"", "--", ";", "AND", "OR", "=", "SELECT", "FROM", "WHERE", "SUBSTRING", "ASCII"]

        # Convert to uppercase for case-insensitive check
        user_id_upper = user_id.upper()

        # Check if any SQL injection pattern is in the input
        for pattern in sqli_patterns:
            if pattern.upper() in user_id_upper:
                # SQL injection detected!
                sqli_detected = True
                break

        # Check if user exists
        if sqli_detected:
            # If the query is trying to find the admin_secret user (ID 42)
            if "42" in user_id or "admin_secret" in user_id.lower():
                user_exists = True

                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="Blind SQL Injection").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            # If the query is using blind SQL injection techniques to extract data
            elif "SUBSTRING" in user_id_upper or "ASCII" in user_id_upper or "MID" in user_id_upper or "CHAR" in user_id_upper:
                user_exists = True

                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="Blind SQL Injection").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                # For other SQL injection attempts, return random results to simulate blind injection
                import random
                user_exists = random.choice([True, False])
        else:
            # Normal user lookup
            user_exists = user_id in hidden_users

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="Blind SQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level4.html', flag=flag, sqli_detected=sqli_detected,
                          user_id=user_id, user_exists=user_exists)

# SQL Injection Level 5 - Time-Based Blind SQL Injection
@app.route('/sqli/level5', methods=['GET', 'POST'])
def sqli_level5():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    message = None
    message_type = "info"
    response_time = None

    if request.method == 'POST':
        email = request.form.get('email', '')

        # Check for SQL injection patterns
        sqli_patterns = ["'", "\"", "--", ";", "SLEEP", "BENCHMARK", "DELAY", "PG_SLEEP", "WAITFOR"]

        # Convert to uppercase for case-insensitive check
        email_upper = email.upper()

        # Check if any SQL injection pattern is in the input
        for pattern in sqli_patterns:
            if pattern.upper() in email_upper:
                # SQL injection detected!
                sqli_detected = True
                break

        # Simulate response time
        import time
        start_time = time.time()

        if sqli_detected:
            # Simulate a time delay for time-based blind SQL injection
            if "SLEEP" in email_upper or "BENCHMARK" in email_upper or "DELAY" in email_upper or "PG_SLEEP" in email_upper or "WAITFOR" in email_upper:
                # Simulate a database query that takes time
                time.sleep(3)

                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="Time-Based Blind SQL Injection").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)

                message = "Thank you for subscribing to our newsletter!"
                message_type = "success"
            else:
                message = "Invalid email format. Please try again."
                message_type = "danger"
        else:
            message = "Thank you for subscribing to our newsletter!"
            message_type = "success"

        end_time = time.time()
        response_time = round(end_time - start_time, 2)

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="Time-Based Blind SQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level5.html', flag=flag, sqli_detected=sqli_detected,
                          message=message, message_type=message_type, response_time=response_time)

# SQL Injection Level 6 - SQL Injection with WAF Bypass
@app.route('/sqli/level6', methods=['GET'])
def sqli_level6():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    waf_blocked = False
    search_term = request.args.get('search', '')
    search_performed = bool(search_term)
    products = []

    # Default products
    default_products = [
        {"id": 1, "name": "Premium Smartphone", "category": "Electronics", "price": 1299.99, "stock": 45},
        {"id": 2, "name": "Ultra Laptop", "category": "Electronics", "price": 2499.99, "stock": 20},
        {"id": 3, "name": "Noise-Canceling Headphones", "category": "Audio", "price": 349.99, "stock": 78},
        {"id": 4, "name": "Fitness Smartwatch", "category": "Wearables", "price": 399.99, "stock": 56},
        {"id": 5, "name": "Portable Bluetooth Speaker", "category": "Audio", "price": 199.99, "stock": 112}
    ]

    # Secret product (only shown when SQL injection is successful)
    secret_product = {"id": 999, "name": "Classified Device", "category": "Restricted", "price": 99999.99, "stock": 1}

    if search_term:
        # WAF rules - block common SQL injection patterns
        waf_patterns = ["'", "\"", "--", "#", "/*", "*/", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "="]

        # Check if any WAF pattern is in the input
        for pattern in waf_patterns:
            if pattern in search_term:
                # WAF blocked the request
                waf_blocked = True
                break

        if not waf_blocked:
            # Check for SQL injection patterns that might bypass the WAF
            bypass_patterns = ["||", "oR", "AnD", "uNiOn", "sElEcT", "1=1", "/**/", "%27", "0x"]

            # Check if any bypass pattern is in the input
            for pattern in bypass_patterns:
                if pattern in search_term:
                    # SQL injection with WAF bypass detected!
                    sqli_detected = True
                    break

            # Filter products based on search term
            products = [p for p in default_products if search_term.lower() in p["name"].lower()]

            # If SQL injection with WAF bypass is detected
            if sqli_detected:
                # Add the secret product to the results
                products.append(secret_product)

                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="SQL Injection with WAF Bypass").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection with WAF Bypass").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level6.html', flag=flag, sqli_detected=sqli_detected,
                          search_term=search_term, search_performed=search_performed,
                          products=products, waf_blocked=waf_blocked)

# SQL Injection Level 7 - Error-Based SQL Injection
@app.route('/sqli/level7', methods=['GET'])
def sqli_level7():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    category_id = request.args.get('id', '')
    category = None
    error_message = None

    # Default categories
    default_categories = {
        "1": {"id": 1, "name": "Electronics", "description": "Electronic devices and gadgets"},
        "2": {"id": 2, "name": "Clothing", "description": "Apparel and fashion items"},
        "3": {"id": 3, "name": "Books", "description": "Books, e-books, and publications"},
        "4": {"id": 4, "name": "Home & Garden", "description": "Items for home and garden"},
        "5": {"id": 5, "name": "Sports & Outdoors", "description": "Sports equipment and outdoor gear"}
    }

    if category_id:
        # Check for SQL injection patterns
        sqli_patterns = ["'", "\"", "--", ";", "UNION", "SELECT", "FROM", "WHERE", "CONCAT", "GROUP BY", "FLOOR", "RAND", "COUNT", "EXTRACTVALUE", "UPDATEXML"]

        # Convert to uppercase for case-insensitive check
        category_id_upper = category_id.upper()

        # Check if any SQL injection pattern is in the input
        for pattern in sqli_patterns:
            if pattern.upper() in category_id_upper:
                # SQL injection detected!
                sqli_detected = True
                break

        if sqli_detected:
            # Simulate error-based SQL injection
            if "CONCAT" in category_id_upper or "GROUP BY" in category_id_upper or "FLOOR" in category_id_upper or "RAND" in category_id_upper or "EXTRACTVALUE" in category_id_upper or "UPDATEXML" in category_id_upper:
                # Generate an error message that contains the flag
                error_message = "Error: SQLSTATE[42000]: Syntax error or access violation: 1690 BIGINT UNSIGNED value is out of range in '(SELECT 'FLAG{3rr0r_b4s3d_sql1_3xtr4ct10n}' FROM secrets WHERE key_name = 'level7_flag')'"

                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="Error-Based SQL Injection").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                # For other SQL injection attempts, return a generic error
                error_message = "Error: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '" + category_id + "' at line 1"
        else:
            # Normal category lookup
            if category_id in default_categories:
                category = default_categories[category_id]
            else:
                error_message = "Error: Category not found"

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="Error-Based SQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level7.html', flag=flag, sqli_detected=sqli_detected,
                          category_id=category_id, category=category, error_message=error_message)

# SQL Injection Level 8 - Second-Order SQL Injection
@app.route('/sqli/level8', methods=['GET', 'POST'])
def sqli_level8():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False

    # Default profile values
    username = "test_user"
    bio = "I'm a security enthusiast."
    location = "Cyberspace"
    website = "https://example.com"

    # Profile to display when viewing a user
    profile = None
    view_user = request.args.get('view_user', '')

    # Simulated database of users
    users_db = {
        "admin": {
            "username": "admin",
            "bio": "System administrator",
            "location": "Server Room",
            "website": "https://admin.example.com",
            "is_admin": True,
            "secret": "The flag is: R00T{s3c0nd_0rd3r_sql1_1s_tr1cky}"
        },
        "test_user": {
            "username": "test_user",
            "bio": "I'm a security enthusiast.",
            "location": "Cyberspace",
            "website": "https://example.com",
            "is_admin": False
        }
    }

    # Handle profile update (POST request)
    if request.method == 'POST':
        username = request.form.get('username', '')
        bio = request.form.get('bio', '')
        location = request.form.get('location', '')
        website = request.form.get('website', '')

        # Simulate storing the profile in the database
        # In a real second-order SQL injection, this would be sanitized but still vulnerable
        users_db["test_user"] = {
            "username": username,
            "bio": bio,
            "location": location,
            "website": website,
            "is_admin": False
        }

        # Success message would be shown here

    # Handle profile viewing (GET request with view_user parameter)
    if view_user:
        # This is where the second-order SQL injection vulnerability exists
        # The application doesn't properly sanitize the stored username when using it in a query

        # Check for SQL injection patterns in the view_user parameter
        sqli_patterns = ["'", "\"", "--", ";", "OR", "=", "UNION", "SELECT", "DROP", "INSERT", "DELETE", "UPDATE"]

        # Convert to uppercase for case-insensitive check
        view_user_upper = view_user.upper()

        # Check if any SQL injection pattern is in the input
        for pattern in sqli_patterns:
            if pattern.upper() in view_user_upper:
                # SQL injection detected!
                sqli_detected = True
                break

        if sqli_detected:
            # Simulate a successful SQL injection that reveals the admin profile
            profile = users_db.get("admin")

            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="Second-Order SQL Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
        else:
            # Normal user lookup
            profile = users_db.get(view_user)

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="Second-Order SQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level8.html', flag=flag, sqli_detected=sqli_detected,
                          username=username, bio=bio, location=location, website=website,
                          view_user=view_user, profile=profile)

# SQL Injection Level 9 - SQL Injection in REST API
@app.route('/sqli/level9', methods=['GET', 'POST'])
def sqli_level9():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    request_body = None
    response = None

    # Handle API request (POST)
    if request.method == 'POST':
        request_body = request.form.get('request_body', '')

        try:
            # Parse the JSON request body
            json_data = json.loads(request_body)

            # Extract parameters
            category = json_data.get('category', '')
            price = json_data.get('price', 0)
            in_stock = json_data.get('in_stock', False)

            # Check for SQL injection patterns in the category parameter
            sqli_patterns = ["'", "\"", "--", ";", "OR", "=", "UNION", "SELECT", "FROM", "WHERE", "DROP", "INSERT", "DELETE", "UPDATE"]

            # Convert to uppercase for case-insensitive check
            category_upper = category.upper() if isinstance(category, str) else ""
            price_str = str(price).upper()

            # Check if any SQL injection pattern is in the input
            for pattern in sqli_patterns:
                if pattern.upper() in category_upper or pattern.upper() in price_str:
                    # SQL injection detected!
                    sqli_detected = True
                    break

            # Simulate API response
            products = [
                {"id": 1, "name": "Smartphone Pro", "category": "Electronics", "price": 999.99, "description": "Latest smartphone with advanced features"},
                {"id": 2, "name": "Laptop Ultra", "category": "Electronics", "price": 1499.99, "description": "Powerful laptop for professionals"},
                {"id": 3, "name": "Wireless Earbuds", "category": "Electronics", "price": 199.99, "description": "Premium wireless earbuds with noise cancellation"}
            ]

            # Filter products based on category and price (simulating normal behavior)
            filtered_products = []
            for product in products:
                if (product['category'] == category or not category) and product['price'] <= price:
                    if not in_stock or (in_stock and product.get('stock', 10) > 0):
                        filtered_products.append(product)

            # If SQL injection is detected, add the hidden admin product
            if sqli_detected:
                admin_product = {
                    "id": 999,
                    "name": "Admin Console",
                    "category": "Restricted",
                    "price": 9999.99,
                    "description": "Administrative product with flag: R00T{r3st_4p1_sql1_1nj3ct10n_pwn3d}"
                }
                filtered_products.append(admin_product)

                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="SQL Injection in REST API").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)

            # Generate JSON response
            response = json.dumps({"products": filtered_products})

        except json.JSONDecodeError:
            response = json.dumps({"error": "Invalid JSON format"})
        except Exception as e:
            response = json.dumps({"error": str(e)})

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in REST API").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level9.html', flag=flag, sqli_detected=sqli_detected,
                          request_body=request_body, response=response)

# SQL Injection Level 10 - NoSQL Injection
@app.route('/sqli/level10', methods=['GET', 'POST'])
def sqli_level10():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    error = None
    success = None
    documents = None

    # Handle login request (POST)
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # Check for NoSQL injection patterns
        nosql_patterns = ["$ne", "$gt", "$lt", "$regex", "$where", "$exists", "$elemMatch", "$nin", "$in", "$all", "$size", "$or", "$and", "$not"]

        # Check if any NoSQL injection pattern is in the input
        for pattern in nosql_patterns:
            if pattern in username or pattern in password:
                # NoSQL injection detected!
                sqli_detected = True
                break

        # Also check for JSON-like input that might contain NoSQL operators
        if (username.startswith('{') and username.endswith('}')) or (password.startswith('{') and password.endswith('}')):
            sqli_detected = True

        # Check for array notation that might be used for NoSQL injection
        if '[' in username or '[' in password:
            sqli_detected = True

        # Simulate authentication
        if sqli_detected:
            # NoSQL injection successful - simulate admin access
            success = "Welcome, admin! You have successfully logged in."

            # Show admin documents
            documents = [
                {
                    "id": "doc001",
                    "title": "System Architecture",
                    "category": "Technical",
                    "content": "Overview of the DocuStore system architecture and components.",
                    "created": "2023-01-15"
                },
                {
                    "id": "doc002",
                    "title": "Security Protocols",
                    "category": "Security",
                    "content": "Details of the security measures implemented in DocuStore.",
                    "created": "2023-02-20"
                },
                {
                    "id": "doc003",
                    "title": "Admin Credentials",
                    "category": "Confidential",
                    "content": "The flag is: R00T{n0sql_1nj3ct10n_byp4ss3d_4uth}",
                    "created": "2023-03-10"
                }
            ]

            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="NoSQL Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
        elif username == "admin" and password == "admin":
            # Simulating a successful login with correct credentials (for testing)
            success = "Welcome, admin! You have successfully logged in."

            # Show admin documents
            documents = [
                {
                    "id": "doc001",
                    "title": "System Architecture",
                    "category": "Technical",
                    "content": "Overview of the DocuStore system architecture and components.",
                    "created": "2023-01-15"
                },
                {
                    "id": "doc002",
                    "title": "Security Protocols",
                    "category": "Security",
                    "content": "Details of the security measures implemented in DocuStore.",
                    "created": "2023-02-20"
                },
                {
                    "id": "doc003",
                    "title": "Admin Credentials",
                    "category": "Confidential",
                    "content": "The flag is: R00T{n0sql_1nj3ct10n_byp4ss3d_4uth}",
                    "created": "2023-03-10"
                }
            ]

            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="NoSQL Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
        elif username == "user" and password == "password":
            # Simulating a successful login with regular user credentials
            success = "Welcome, user! You have successfully logged in."

            # Show regular user documents
            documents = [
                {
                    "id": "doc101",
                    "title": "User Guide",
                    "category": "Documentation",
                    "content": "Guide for using the DocuStore system.",
                    "created": "2023-01-20"
                },
                {
                    "id": "doc102",
                    "title": "Project Plan",
                    "category": "Project",
                    "content": "Project plan for implementing DocuStore.",
                    "created": "2023-02-25"
                }
            ]
        else:
            # Authentication failed
            error = "Invalid username or password. Please try again."

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="NoSQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level10.html', flag=flag, sqli_detected=sqli_detected,
                          error=error, success=success, documents=documents)

# SQL Injection Level 11 - GraphQL Injection
@app.route('/sqli/level11', methods=['GET', 'POST'])
def sqli_level11():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    query = None
    response = None

    # Handle GraphQL query (POST)
    if request.method == 'POST':
        query = request.form.get('query', '')

        # Check for GraphQL injection patterns
        graphql_patterns = ["__schema", "__type", "introspection", "getPost(id: 999", "isPrivate", "admin"]

        # Check if any GraphQL injection pattern is in the input
        for pattern in graphql_patterns:
            if pattern in query:
                # GraphQL injection detected!
                sqli_detected = True
                break

        # Simulate GraphQL query execution
        if "getPost(id: 1)" in query:
            # Regular public post
            response = '''
{
  "data": {
    "getPost": {
      "id": "1",
      "title": "Getting Started with GraphQL",
      "content": "GraphQL is a query language for APIs and a runtime for fulfilling those queries with your existing data.",
      "author": {
        "name": "John Doe"
      }
    }
  }
}
'''
        elif "getPost(id: 2)" in query:
            # Another public post
            response = '''
{
  "data": {
    "getPost": {
      "id": "2",
      "title": "Advanced GraphQL Techniques",
      "content": "Learn how to use fragments, variables, and directives in GraphQL to make your queries more efficient.",
      "author": {
        "name": "Jane Smith"
      }
    }
  }
}
'''
        elif "getPosts" in query:
            # List of posts
            response = '''
{
  "data": {
    "getPosts": [
      {
        "id": "1",
        "title": "Getting Started with GraphQL",
        "isPrivate": false
      },
      {
        "id": "2",
        "title": "Advanced GraphQL Techniques",
        "isPrivate": false
      },
      {
        "id": "3",
        "title": "GraphQL Security Best Practices",
        "isPrivate": false
      },
      {
        "id": "999",
        "title": "Admin Notes",
        "isPrivate": true
      }
    ]
  }
}
'''
        elif "__schema" in query or "__type" in query:
            # Introspection query
            response = '''
{
  "data": {
    "__schema": {
      "types": [
        {
          "name": "Query",
          "fields": [
            {
              "name": "getPost",
              "type": {
                "name": "Post",
                "kind": "OBJECT"
              }
            },
            {
              "name": "getPosts",
              "type": {
                "name": null,
                "kind": "LIST"
              }
            },
            {
              "name": "searchPosts",
              "type": {
                "name": null,
                "kind": "LIST"
              }
            }
          ]
        },
        {
          "name": "Post",
          "fields": [
            {
              "name": "id",
              "type": {
                "name": null,
                "kind": "NON_NULL"
              }
            },
            {
              "name": "title",
              "type": {
                "name": null,
                "kind": "NON_NULL"
              }
            },
            {
              "name": "content",
              "type": {
                "name": null,
                "kind": "NON_NULL"
              }
            },
            {
              "name": "isPrivate",
              "type": {
                "name": null,
                "kind": "NON_NULL"
              }
            },
            {
              "name": "author",
              "type": {
                "name": "User",
                "kind": "OBJECT"
              }
            }
          ]
        }
      ]
    }
  }
}
'''
        elif "getPost(id: 999)" in query and "isPrivate" in query:
            # Private admin post with the flag - successful exploitation
            response = '''
{
  "data": {
    "getPost": {
      "id": "999",
      "title": "Admin Notes",
      "content": "Security audit scheduled for next week. Flag: R00T{gr4phql_1nj3ct10n_3xpl01t3d}",
      "isPrivate": true,
      "author": {
        "name": "Admin",
        "role": "ADMIN"
      }
    }
  }
}
'''

            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="GraphQL Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
        else:
            # Default response for other queries
            response = '''
{
  "data": null,
  "errors": [
    {
      "message": "Invalid query. Please check your syntax and try again."
    }
  ]
}
'''

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="GraphQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level11.html', flag=flag, sqli_detected=sqli_detected,
                          query=query, response=response)

# SQL Injection Level 12 - ORM-based SQL Injection
@app.route('/sqli/level12', methods=['GET', 'POST'])
def sqli_level12():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    department = request.form.get('department', 'IT')
    search_term = request.form.get('search_term', '')
    employees = []
    error = None

    # Default employees for each department
    default_employees = {
        "IT": [
            {
                "id": "IT001",
                "name": "John Smith",
                "position": "IT Manager",
                "department": "IT",
                "email": "john.smith@corphr.com",
                "phone": "555-1234",
                "salary": "85,000",
                "joined": "2018-05-15"
            },
            {
                "id": "IT002",
                "name": "Sarah Johnson",
                "position": "Senior Developer",
                "department": "IT",
                "email": "sarah.johnson@corphr.com",
                "phone": "555-2345",
                "salary": "78,000",
                "joined": "2019-02-10"
            },
            {
                "id": "IT003",
                "name": "Michael Chen",
                "position": "System Administrator",
                "department": "IT",
                "email": "michael.chen@corphr.com",
                "phone": "555-3456",
                "salary": "72,000",
                "joined": "2020-07-22"
            }
        ],
        "HR": [
            {
                "id": "HR001",
                "name": "Emily Davis",
                "position": "HR Director",
                "department": "HR",
                "email": "emily.davis@corphr.com",
                "phone": "555-4567",
                "salary": "92,000",
                "joined": "2017-11-05"
            },
            {
                "id": "HR002",
                "name": "Robert Wilson",
                "position": "Recruitment Specialist",
                "department": "HR",
                "email": "robert.wilson@corphr.com",
                "phone": "555-5678",
                "salary": "65,000",
                "joined": "2021-03-18"
            }
        ],
        "Finance": [
            {
                "id": "FIN001",
                "name": "Jennifer Lee",
                "position": "Finance Manager",
                "department": "Finance",
                "email": "jennifer.lee@corphr.com",
                "phone": "555-6789",
                "salary": "95,000",
                "joined": "2016-09-30"
            },
            {
                "id": "FIN002",
                "name": "David Brown",
                "position": "Senior Accountant",
                "department": "Finance",
                "email": "david.brown@corphr.com",
                "phone": "555-7890",
                "salary": "82,000",
                "joined": "2018-12-07"
            }
        ],
        "Marketing": [
            {
                "id": "MKT001",
                "name": "Lisa Taylor",
                "position": "Marketing Director",
                "department": "Marketing",
                "email": "lisa.taylor@corphr.com",
                "phone": "555-8901",
                "salary": "90,000",
                "joined": "2019-04-15"
            }
        ],
        "Sales": [
            {
                "id": "SLS001",
                "name": "James Anderson",
                "position": "Sales Manager",
                "department": "Sales",
                "email": "james.anderson@corphr.com",
                "phone": "555-9012",
                "salary": "88,000",
                "joined": "2017-06-22"
            }
        ],
        "Executive": [
            {
                "id": "EXE001",
                "name": "Elizabeth Williams",
                "position": "CEO",
                "department": "Executive",
                "email": "elizabeth.williams@corphr.com",
                "phone": "555-0123",
                "salary": "250,000 (Flag: R00T{0rm_sql1_1nj3ct10n_byp4ss3d})",
                "joined": "2015-01-01"
            }
        ]
    }

    # Handle search request (POST)
    if request.method == 'POST':
        # Check for SQL injection patterns in the search term
        sqli_patterns = ["'", "\"", "--", ";", "OR", "=", "UNION", "SELECT", "FROM", "WHERE", "DROP", "INSERT", "DELETE", "UPDATE"]

        # Convert to uppercase for case-insensitive check
        search_term_upper = search_term.upper() if isinstance(search_term, str) else ""

        # Check if any SQL injection pattern is in the input
        for pattern in sqli_patterns:
            if pattern.upper() in search_term_upper:
                # SQL injection detected!
                sqli_detected = True
                break

        # Simulate ORM-based search
        if department in default_employees:
            if sqli_detected:
                # SQL injection successful - show all employees including the CEO
                for dept in default_employees:
                    employees.extend(default_employees[dept])

                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="ORM-based SQL Injection").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            elif search_term:
                # Normal search - filter employees by department and search term
                for employee in default_employees[department]:
                    if search_term.lower() in employee["name"].lower() or search_term.lower() in employee["position"].lower():
                        employees.append(employee)

                if not employees:
                    error = f"No employees found in {department} department matching '{search_term}'."
            else:
                # No search term - show all employees in the selected department
                employees = default_employees[department]
        else:
            error = "Invalid department selected."
    else:
        # Default view - show IT department employees
        employees = default_employees["IT"]

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="ORM-based SQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level12.html', flag=flag, sqli_detected=sqli_detected,
                          department=department, search_term=search_term, employees=employees, error=error)

# SQL Injection Level 13 - Out-of-band SQL Injection
@app.route('/sqli/level13', methods=['GET', 'POST'])
def sqli_level13():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    search_term = request.form.get('search_term', '')
    stocks = []
    error = None
    dns_logs = []

    # Default stocks
    default_stocks = [
        {
            "symbol": "AAPL",
            "name": "Apple Inc.",
            "price": "182.63",
            "change": 1.25
        },
        {
            "symbol": "MSFT",
            "name": "Microsoft Corporation",
            "price": "337.22",
            "change": 0.87
        },
        {
            "symbol": "GOOGL",
            "name": "Alphabet Inc.",
            "price": "131.86",
            "change": -0.32
        },
        {
            "symbol": "AMZN",
            "name": "Amazon.com, Inc.",
            "price": "127.74",
            "change": 0.56
        },
        {
            "symbol": "TSLA",
            "name": "Tesla, Inc.",
            "price": "237.49",
            "change": -1.45
        }
    ]

    # Handle search request (POST)
    if request.method == 'POST':
        # Check for SQL injection patterns in the search term
        sqli_patterns = ["'", "\"", "--", ";", "UNION", "SELECT", "FROM", "WHERE", "DROP", "INSERT", "DELETE", "UPDATE",
                         "LOAD_FILE", "UTL_HTTP", "xp_dirtree", "sp_OAMethod", "UTL_INADDR", "attacker.com"]

        # Convert to uppercase for case-insensitive check
        search_term_upper = search_term.upper() if isinstance(search_term, str) else ""

        # Check if any SQL injection pattern is in the input
        for pattern in sqli_patterns:
            if pattern.upper() in search_term_upper:
                # SQL injection detected!
                sqli_detected = True
                break

        # Simulate stock search
        if search_term:
            if sqli_detected:
                # SQL injection successful - simulate DNS exfiltration
                dns_logs = [
                    {
                        "timestamp": "2023-07-15 14:32:18",
                        "query": "db-server.local",
                        "type": "A",
                        "source": "192.168.1.10"
                    },
                    {
                        "timestamp": "2023-07-15 14:32:19",
                        "query": "R00T{0ut_0f_b4nd_sql1_3xf1ltr4t10n}.attacker.com",
                        "type": "A",
                        "source": "192.168.1.10"
                    }
                ]

                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="Out-of-band SQL Injection").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)

                # Return all stocks for the search results
                stocks = default_stocks
            else:
                # Normal search - filter stocks by symbol or name
                for stock in default_stocks:
                    if search_term.upper() in stock["symbol"].upper() or search_term.lower() in stock["name"].lower():
                        stocks.append(stock)

                if not stocks:
                    error = f"No stocks found matching '{search_term}'."
        else:
            # No search term - show all stocks
            stocks = default_stocks
    else:
        # Default view - show all stocks
        stocks = default_stocks

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="Out-of-band SQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level13.html', flag=flag, sqli_detected=sqli_detected,
                          search_term=search_term, stocks=stocks, error=error, dns_logs=dns_logs)

# SQL Injection Level 14 - SQL Injection with Advanced WAF Bypass
@app.route('/sqli/level14', methods=['GET', 'POST'])
def sqli_level14():
    import json
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    category = request.form.get('category', 'Electronics')
    search_term = request.form.get('search_term', '')
    products = []
    error = None
    waf_blocked = False
    waf_logs = []

    if request.method == 'POST':
        # WAF implementation
        def waf_check(input_str):
            blocked_patterns = [
                'SELECT', 'UNION', 'FROM', 'WHERE',
                '--', '/*', "'", '"',
                '=', '>', '<'
            ]

            # Check if any blocked pattern is in the input (case-insensitive)
            for pattern in blocked_patterns:
                if pattern.upper() in input_str.upper():
                    # Log the WAF block
                    import datetime
                    waf_logs.append({
                        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'rule_id': blocked_patterns.index(pattern) + 1,
                        'rule_name': f"Blocked pattern: {pattern}",
                        'action': 'BLOCK',
                        'ip': request.remote_addr
                    })
                    return True
            return False

        # Check if the input contains SQL injection patterns
        if waf_check(category) or waf_check(search_term):
            waf_blocked = True
        else:
            # Simulate database query
            if category == 'Electronics':
                products = [
                    {"id": 1, "name": "Smartphone X", "category": "Electronics", "price": 999.99, "description": "Latest smartphone with advanced features."},
                    {"id": 2, "name": "Laptop Pro", "category": "Electronics", "price": 1499.99, "description": "Professional laptop for developers."},
                    {"id": 3, "name": "Wireless Headphones", "category": "Electronics", "price": 199.99, "description": "Noise-cancelling wireless headphones."}
                ]
            elif category == 'Clothing':
                products = [
                    {"id": 4, "name": "Designer T-shirt", "category": "Clothing", "price": 49.99, "description": "Premium cotton t-shirt."},
                    {"id": 5, "name": "Jeans", "category": "Clothing", "price": 79.99, "description": "Comfortable denim jeans."},
                    {"id": 6, "name": "Sneakers", "category": "Clothing", "price": 129.99, "description": "Stylish and comfortable sneakers."}
                ]

            # Check for advanced WAF bypass attempts
            advanced_bypass_patterns = [
                '%27', '%2527', '%252527',  # URL encoded single quotes
                'un%69on', 'un%69%6fn', 'un%2569on',  # URL encoded UNION
                'se%6cect', 'se%6c%65ct', 'se%2565ct',  # URL encoded SELECT
                'concat(0x', 'char(', 'hex(',  # Alternative string functions
                '0x3', '0x4', '0x5',  # Hex values
                'product%5fid',  # URL encoded underscore
                'or%20product%5fid%3d999'  # Encoded OR condition
            ]

            for pattern in advanced_bypass_patterns:
                if pattern in category.lower() or pattern in search_term.lower():
                    # Advanced WAF bypass detected!
                    sqli_detected = True

                    # Add the restricted product (with the flag)
                    products.append({
                        "id": 999,
                        "name": "Restricted Product",
                        "category": "ADMIN",
                        "price": 9999.99,
                        "description": "This product contains the flag: R00T{4dv4nc3d_w4f_byp4ss_m4st3r}"
                    })

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="SQL Injection with Advanced WAF Bypass").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection with Advanced WAF Bypass").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level14.html', flag=flag, sqli_detected=sqli_detected,
                          category=category, search_term=search_term, products=products,
                          error=error, waf_blocked=waf_blocked, waf_logs=waf_logs)

# SQL Injection Level 15 - SQL Injection via XML
@app.route('/sqli/level15', methods=['GET', 'POST'])
def sqli_level15():
    import json
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    xml_data = None
    reports = []
    error = None

    if request.method == 'POST':
        xml_data = request.form.get('xml_data', '')

        # Check if the XML is well-formed
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_data)

            # Extract values from XML
            report_type = root.find('type').text if root.find('type') is not None else ''
            report_period = root.find('period').text if root.find('period') is not None else ''
            report_department = root.find('department').text if root.find('department') is not None else ''

            # Check for SQL injection patterns in XML values
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "="]

            for pattern in sqli_patterns:
                if (pattern in report_type or pattern in report_period or pattern in report_department):
                    # SQL injection detected!
                    sqli_detected = True

                    # Add the restricted report (with the flag)
                    reports.append({
                        "id": 999,
                        "title": "Restricted Financial Report",
                        "type": "confidential",
                        "period": "annual",
                        "department": "executive",
                        "data": "This report contains the flag: R00T{xml_sql1_1nj3ct10n_3xpl01t3d}"
                    })

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="SQL Injection via XML").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break

            # If no SQL injection detected, return normal reports
            if not sqli_detected:
                if report_type == 'sales':
                    reports = [
                        {"id": 1, "title": "Sales Report Q1", "type": "sales", "period": "quarterly", "department": report_department, "data": "Sales increased by 15% in Q1."},
                        {"id": 2, "title": "Sales Report Q2", "type": "sales", "period": "quarterly", "department": report_department, "data": "Sales increased by 10% in Q2."}
                    ]
                elif report_type == 'inventory':
                    reports = [
                        {"id": 3, "title": "Inventory Status", "type": "inventory", "period": report_period, "department": report_department, "data": "Current inventory levels are optimal."},
                        {"id": 4, "title": "Inventory Forecast", "type": "inventory", "period": report_period, "department": report_department, "data": "Inventory forecast for next quarter is stable."}
                    ]
                elif report_type == 'marketing':
                    reports = [
                        {"id": 5, "title": "Marketing Campaign Results", "type": "marketing", "period": report_period, "department": report_department, "data": "Recent campaign resulted in 20% increase in leads."},
                        {"id": 6, "title": "Marketing Budget", "type": "marketing", "period": report_period, "department": report_department, "data": "Marketing budget allocation for next quarter."}
                    ]
        except Exception as e:
            error = f"Error processing XML: {str(e)}"

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection via XML").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level15.html', flag=flag, sqli_detected=sqli_detected,
                          xml_data=xml_data, reports=reports, error=error)

# SQL Injection Level 16 - SQL Injection in WebSockets
@app.route('/sqli/level16', methods=['GET', 'POST'])
def sqli_level16():
    import json
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    ws_message = None

    if request.method == 'POST':
        # Handle AJAX request from the WebSocket simulation
        if request.is_json:
            data = request.get_json()
            sqli_detected = data.get('sqli_detected', False)
            ws_message = data.get('ws_message', '')

            # Mark challenge as completed if SQL injection is detected
            if sqli_detected:
                challenge = Challenge.query.filter_by(name="SQL Injection in WebSockets").first()
                if challenge:
                    # Add challenge to completed challenges
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)

                    return jsonify({"success": True})
                return jsonify({"success": False, "error": "Challenge not found"})

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in WebSockets").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level16.html', flag=flag, sqli_detected=sqli_detected,
                          ws_message=ws_message)

# SQL Injection Level 17 - SQL Injection in Mobile App Backend
@app.route('/sqli/level17', methods=['GET', 'POST'])
def sqli_level17():
    import json
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    api_request = None
    api_response = None

    if request.method == 'POST':
        api_request = request.form.get('api_request', '')

        try:
            # Parse the API request JSON
            data = json.loads(api_request)

            # Extract values from the request
            action = data.get('action', '')
            category = data.get('category', '')
            sort = data.get('sort', 'price_asc')
            limit = data.get('limit', 10)
            search = data.get('search', '')

            # Check for SQL injection patterns
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]

            # Check if any SQL injection pattern is in the input
            for pattern in sqli_patterns:
                if (pattern in category or pattern in sort or pattern in str(search)):
                    # SQL injection detected!
                    sqli_detected = True

                    # Return the restricted product (with the flag)
                    api_response = json.dumps({
                        "status": "success",
                        "products": [
                            {
                                "id": 999,
                                "name": "Restricted Product",
                                "description": "This product contains the flag: R00T{m0b1l3_4pp_b4ck3nd_sql1_pwn3d}",
                                "price": 9999.99,
                                "category": "RESTRICTED"
                            }
                        ]
                    }, indent=2)

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="SQL Injection in Mobile App Backend").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break

            # If no SQL injection detected, return normal products
            if not sqli_detected:
                products = []

                if category.lower() == 'electronics':
                    products = [
                        {"id": 1, "name": "Smartphone X", "description": "Latest smartphone with advanced features.", "price": 999.99, "category": "Electronics"},
                        {"id": 2, "name": "Laptop Pro", "description": "Professional laptop for developers.", "price": 1499.99, "category": "Electronics"},
                        {"id": 3, "name": "Wireless Headphones", "description": "Noise-cancelling wireless headphones.", "price": 199.99, "category": "Electronics"}
                    ]
                elif category.lower() == 'clothing':
                    products = [
                        {"id": 4, "name": "Designer T-shirt", "description": "Premium cotton t-shirt.", "price": 49.99, "category": "Clothing"},
                        {"id": 5, "name": "Jeans", "description": "Comfortable denim jeans.", "price": 79.99, "category": "Clothing"},
                        {"id": 6, "name": "Sneakers", "description": "Stylish and comfortable sneakers.", "price": 129.99, "category": "Clothing"}
                    ]

                # Apply search filter if provided
                if search:
                    products = [p for p in products if search.lower() in p['name'].lower() or search.lower() in p['description'].lower()]

                # Sort products
                if sort == 'price_asc':
                    products.sort(key=lambda p: p['price'])
                elif sort == 'price_desc':
                    products.sort(key=lambda p: p['price'], reverse=True)
                elif sort == 'name_asc':
                    products.sort(key=lambda p: p['name'])
                elif sort == 'name_desc':
                    products.sort(key=lambda p: p['name'], reverse=True)

                # Apply limit
                products = products[:limit]

                api_response = json.dumps({
                    "status": "success",
                    "products": products
                }, indent=2)

        except Exception as e:
            api_response = json.dumps({
                "status": "error",
                "message": str(e)
            }, indent=2)

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in Mobile App Backend").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level17.html', flag=flag, sqli_detected=sqli_detected,
                          api_request=api_request, api_response=api_response)

# SQL Injection Level 18 - SQL Injection in Cloud Functions
@app.route('/sqli/level18', methods=['GET', 'POST'])
def sqli_level18():
    import json
    import random
    import datetime
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    event_data = None
    function_response = None
    function_duration = None
    function_memory = None
    function_status = None
    function_logs = []

    if request.method == 'POST':
        event_data = request.form.get('event_data', '')

        try:
            # Parse the event data JSON
            data = json.loads(event_data)

            # Extract values from the event
            action = data.get('action', '')
            dataset = data.get('dataset', '')
            filter_condition = data.get('filter', '')
            format_type = data.get('format', 'json')

            # Simulate function execution
            start_time = datetime.datetime.now()

            # Add execution logs
            function_logs.append({
                'timestamp': start_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'level': 'info',
                'message': f"Function execution started with event: {json.dumps(data)}"
            })

            function_logs.append({
                'timestamp': (start_time + datetime.timedelta(milliseconds=50)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'level': 'info',
                'message': f"Connecting to database..."
            })

            # Check for SQL injection patterns
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]

            # Generate simulated SQL query
            sql_query = f"SELECT * FROM {dataset} WHERE {filter_condition} LIMIT 1000"

            function_logs.append({
                'timestamp': (start_time + datetime.timedelta(milliseconds=100)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'level': 'info',
                'message': f"Executing query: {sql_query}"
            })

            # Check if any SQL injection pattern is in the dataset or filter
            for pattern in sqli_patterns:
                if (pattern in dataset or pattern in filter_condition):
                    # SQL injection detected!
                    sqli_detected = True

                    function_logs.append({
                        'timestamp': (start_time + datetime.timedelta(milliseconds=150)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                        'level': 'warning',
                        'message': f"Unusual query pattern detected: {sql_query}"
                    })

                    # Return the flag
                    if "security_flags" in sql_query:
                        function_response = json.dumps({
                            "status": "success",
                            "data": [
                                {
                                    "id": 1,
                                    "flag": "R00T{cl0ud_funct10n_sql1_1nj3ct10n_pwn3d}",
                                    "created_at": "2023-01-01T00:00:00Z",
                                    "is_active": True
                                }
                            ]
                        }, indent=2)

                        # Mark challenge as completed
                        challenge = Challenge.query.filter_by(name="SQL Injection in Cloud Functions").first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(machine_id, challenge.id, challenge.points)
                    else:
                        function_response = json.dumps({
                            "status": "success",
                            "data": [
                                {
                                    "id": random.randint(1, 100),
                                    "value": f"Suspicious query detected: {sql_query}",
                                    "timestamp": datetime.datetime.now().isoformat()
                                }
                            ]
                        }, indent=2)
                    break

            # If no SQL injection detected, return normal data
            if not sqli_detected:
                if dataset == 'sales_2023':
                    function_response = json.dumps({
                        "status": "success",
                        "data": [
                            {"id": 1, "product": "Smartphone X", "quantity": 150, "revenue": 149998.5, "region": "US"},
                            {"id": 2, "product": "Laptop Pro", "quantity": 75, "revenue": 112499.25, "region": "US"},
                            {"id": 3, "product": "Wireless Headphones", "quantity": 200, "revenue": 39998.0, "region": "US"}
                        ]
                    }, indent=2)
                elif dataset == 'customers_2023':
                    function_response = json.dumps({
                        "status": "success",
                        "data": [
                            {"id": 1, "name": "John Doe", "email": "john.doe@example.com", "region": "US"},
                            {"id": 2, "name": "Jane Smith", "email": "jane.smith@example.com", "region": "US"},
                            {"id": 3, "name": "Bob Johnson", "email": "bob.johnson@example.com", "region": "US"}
                        ]
                    }, indent=2)
                else:
                    function_response = json.dumps({
                        "status": "error",
                        "message": f"Dataset '{dataset}' not found or access denied"
                    }, indent=2)

            # Simulate function completion
            end_time = datetime.datetime.now()
            duration = (end_time - start_time).total_seconds() * 1000  # Convert to milliseconds

            function_logs.append({
                'timestamp': end_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'level': 'info',
                'message': f"Function execution completed in {duration:.2f}ms"
            })

            # Set function execution details
            function_duration = f"{duration:.2f}"
            function_memory = str(random.randint(50, 150))
            function_status = "Success"

        except Exception as e:
            function_response = json.dumps({
                "status": "error",
                "message": str(e)
            }, indent=2)

            function_duration = str(random.randint(10, 50))
            function_memory = str(random.randint(50, 150))
            function_status = "Error"

            function_logs.append({
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'level': 'error',
                'message': f"Function execution failed: {str(e)}"
            })

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in Cloud Functions").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level18.html', flag=flag, sqli_detected=sqli_detected,
                          event_data=event_data, function_response=function_response,
                          function_duration=function_duration, function_memory=function_memory,
                          function_status=function_status, function_logs=function_logs)

# SQL Injection Level 19 - SQL Injection via File Upload
@app.route('/sqli/level19', methods=['GET', 'POST'])
def sqli_level19():
    import json
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    csv_content = None
    csv_preview = []
    upload_success = False
    rows_processed = 0
    rows_imported = 0
    import_status = None
    import_errors = []
    import_output = None
    error = None

    if request.method == 'POST':
        csv_content = request.form.get('csv_content', '')

        if csv_content:
            try:
                # Parse the CSV content
                import csv
                from io import StringIO

                csv_file = StringIO(csv_content)
                csv_reader = csv.reader(csv_file)

                # Convert to list for preview
                csv_rows = list(csv_reader)

                if len(csv_rows) > 0:
                    # Set CSV preview (limit to 10 rows)
                    csv_preview = csv_rows[:10]

                    # Process the CSV rows
                    header = csv_rows[0]
                    data_rows = csv_rows[1:]

                    rows_processed = len(data_rows)
                    rows_imported = 0
                    import_errors = []
                    import_output = ""

                    # Check if the header has the expected columns
                    expected_columns = ['id', 'name', 'email', 'department']
                    if len(header) >= len(expected_columns) and all(col.lower() == expected_columns[i].lower() for i, col in enumerate(header[:len(expected_columns)])):
                        # Process each row
                        for i, row in enumerate(data_rows):
                            if len(row) >= len(expected_columns):
                                # Extract values
                                id_val = row[0]
                                name_val = row[1]
                                email_val = row[2]
                                department_val = row[3]

                                # Check for SQL injection patterns
                                sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]

                                # Check if any SQL injection pattern is in the input
                                for pattern in sqli_patterns:
                                    if (pattern in id_val or pattern in name_val or pattern in email_val or pattern in department_val):
                                        # SQL injection detected!
                                        sqli_detected = True

                                        # Simulate SQL error
                                        import_output += f"SQL Error in row {i+1}: Syntax error in SQL statement\n"
                                        import_output += f"Attempted query: INSERT INTO employees (id, name, email, department) VALUES ('{id_val}', '{name_val}', '{email_val}', '{department_val}')\n\n"

                                        # Add the flag to the output
                                        import_output += "Unexpected query result:\n"
                                        import_output += "id | flag\n"
                                        import_output += "---+-----\n"
                                        import_output += f"1  | R00T{{f1l3_upl04d_sql1_1nj3ct10n_pwn3d}}\n"

                                        import_errors.append(f"Error in row {i+1}: SQL syntax error")

                                        # Mark challenge as completed
                                        challenge = Challenge.query.filter_by(name="SQL Injection via File Upload").first()
                                        if challenge:
                                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                            if challenge.id not in completed_ids:
                                                update_user_progress(machine_id, challenge.id, challenge.points)
                                        break

                                if not sqli_detected:
                                    # Simulate successful import
                                    import_output += f"Imported row {i+1}: ID={id_val}, Name={name_val}, Email={email_val}, Department={department_val}\n"
                                    rows_imported += 1
                            else:
                                import_errors.append(f"Error in row {i+1}: Insufficient columns")

                        if rows_imported == rows_processed:
                            import_status = "Complete"
                        elif rows_imported > 0:
                            import_status = "Partial"
                        else:
                            import_status = "Failed"
                    else:
                        error = "Invalid CSV format. Expected columns: id, name, email, department"
                else:
                    error = "Empty CSV file"

                upload_success = True

            except Exception as e:
                error = f"Error processing CSV: {str(e)}"
        else:
            error = "No CSV content provided"

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection via File Upload").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level19.html', flag=flag, sqli_detected=sqli_detected,
                          csv_content=csv_content, csv_preview=csv_preview, upload_success=upload_success,
                          rows_processed=rows_processed, rows_imported=rows_imported,
                          import_status=import_status, import_errors=import_errors,
                          import_output=import_output, error=error)

# SQL Injection Level 20 - SQL Injection in Stored Procedures
@app.route('/sqli/level20', methods=['GET', 'POST'])
def sqli_level20():
    import json
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    category = request.form.get('category', 'Electronics')
    search_term = request.form.get('search_term', '')
    procedure_result = False
    generated_sql = None
    result_columns = []
    result_rows = []
    error = None

    if request.method == 'POST':
        # Simulate stored procedure execution
        try:
            # Generate the dynamic SQL that would be created by the stored procedure
            generated_sql = f"SELECT * FROM products WHERE category = '{category}' AND active = 1"

            if search_term:
                generated_sql += f" AND (name LIKE '%{search_term}%' OR description LIKE '%{search_term}%')"

            # Check for SQL injection patterns
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]

            # Check if any SQL injection pattern is in the input
            for pattern in sqli_patterns:
                if (pattern in category or pattern in search_term):
                    # SQL injection detected!
                    sqli_detected = True

                    # Set up result columns
                    result_columns = ["id", "flag", "created_at", "is_active"]

                    # Return the flag
                    if "system_flags" in generated_sql:
                        result_rows = [
                            [1, "R00T{st0r3d_pr0c3dur3_sql1_1nj3ct10n_pwn3d}", "2023-01-01 00:00:00", "true"]
                        ]

                        # Mark challenge as completed
                        challenge = Challenge.query.filter_by(name="SQL Injection in Stored Procedures").first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(machine_id, challenge.id, challenge.points)
                    else:
                        result_rows = [
                            [999, "Suspicious query detected", "2023-01-01 00:00:00", "true"]
                        ]

                    procedure_result = True
                    break

            # If no SQL injection detected, return normal products
            if not sqli_detected:
                # Set up result columns
                result_columns = ["id", "name", "description", "price", "category"]

                if category == 'Electronics':
                    result_rows = [
                        [1, "Smartphone X", "Latest smartphone with advanced features.", 999.99, "Electronics"],
                        [2, "Laptop Pro", "Professional laptop for developers.", 1499.99, "Electronics"],
                        [3, "Wireless Headphones", "Noise-cancelling wireless headphones.", 199.99, "Electronics"]
                    ]
                elif category == 'Clothing':
                    result_rows = [
                        [4, "Designer T-shirt", "Premium cotton t-shirt.", 49.99, "Clothing"],
                        [5, "Jeans", "Comfortable denim jeans.", 79.99, "Clothing"],
                        [6, "Sneakers", "Stylish and comfortable sneakers.", 129.99, "Clothing"]
                    ]
                else:
                    result_rows = []

                # Apply search filter if provided
                if search_term and result_rows:
                    result_rows = [row for row in result_rows if search_term.lower() in row[1].lower() or search_term.lower() in row[2].lower()]

                procedure_result = True

        except Exception as e:
            error = f"Error executing stored procedure: {str(e)}"

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in Stored Procedures").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level20.html', flag=flag, sqli_detected=sqli_detected,
                          category=category, search_term=search_term, procedure_result=procedure_result,
                          generated_sql=generated_sql, result_columns=result_columns,
                          result_rows=result_rows, error=error)

# SQL Injection Level 21 - SQL Injection in GraphQL API
@app.route('/sqli/level21', methods=['GET', 'POST'])
def sqli_level21():
    import json
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    graphql_query = None
    graphql_result = None

    if request.method == 'POST':
        graphql_query = request.form.get('graphql_query', '')

        try:
            # Parse the GraphQL query
            import json
            import re

            # Check for SQL injection patterns
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]
            admin_secrets_pattern = re.compile(r'admin_secrets', re.IGNORECASE)

            # Check if any SQL injection pattern is in the input
            for pattern in sqli_patterns:
                if pattern in graphql_query and admin_secrets_pattern.search(graphql_query):
                    # SQL injection detected!
                    sqli_detected = True

                    # Return the flag
                    graphql_result = json.dumps({
                        "data": {
                            "user": {
                                "id": "1",
                                "username": "R00T{gr4phql_sql1_1nj3ct10n_pwn3d}",
                                "email": "admin@example.com",
                                "role": "admin"
                            }
                        }
                    }, indent=2)

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="SQL Injection in GraphQL API").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break

            # If no SQL injection detected, return normal response
            if not sqli_detected:
                if "user" in graphql_query:
                    graphql_result = json.dumps({
                        "data": {
                            "user": {
                                "id": "1",
                                "username": "johndoe",
                                "email": "john.doe@example.com",
                                "role": "user"
                            }
                        }
                    }, indent=2)
                elif "products" in graphql_query:
                    graphql_result = json.dumps({
                        "data": {
                            "products": [
                                {
                                    "id": "1",
                                    "name": "Smartphone X",
                                    "description": "Latest smartphone with advanced features.",
                                    "price": 999.99,
                                    "category": "Electronics"
                                },
                                {
                                    "id": "2",
                                    "name": "Laptop Pro",
                                    "description": "Professional laptop for developers.",
                                    "price": 1499.99,
                                    "category": "Electronics"
                                },
                                {
                                    "id": "3",
                                    "name": "Wireless Headphones",
                                    "description": "Noise-cancelling wireless headphones.",
                                    "price": 199.99,
                                    "category": "Electronics"
                                }
                            ]
                        }
                    }, indent=2)
                elif "order" in graphql_query:
                    graphql_result = json.dumps({
                        "data": {
                            "order": {
                                "id": "1",
                                "userId": "1",
                                "total": 1199.98,
                                "status": "completed",
                                "createdAt": "2023-01-01T00:00:00Z",
                                "products": [
                                    {
                                        "id": "1",
                                        "name": "Smartphone X",
                                        "description": "Latest smartphone with advanced features.",
                                        "price": 999.99,
                                        "category": "Electronics"
                                    },
                                    {
                                        "id": "3",
                                        "name": "Wireless Headphones",
                                        "description": "Noise-cancelling wireless headphones.",
                                        "price": 199.99,
                                        "category": "Electronics"
                                    }
                                ]
                            }
                        }
                    }, indent=2)
                else:
                    graphql_result = json.dumps({
                        "errors": [
                            {
                                "message": "Unknown query type"
                            }
                        ]
                    }, indent=2)

        except Exception as e:
            graphql_result = json.dumps({
                "errors": [
                    {
                        "message": str(e)
                    }
                ]
            }, indent=2)

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in GraphQL API").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level21.html', flag=flag, sqli_detected=sqli_detected,
                          graphql_query=graphql_query, graphql_result=graphql_result)

# SQL Injection Level 22 - SQL Injection in NoSQL Database
@app.route('/sqli/level22', methods=['GET', 'POST'])
def sqli_level22():
    import json
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    collection = request.form.get('collection', 'articles')
    query = request.form.get('query', '{"author": "John Doe"}')
    results = []
    error = None

    if request.method == 'POST':
        try:
            # Parse the query JSON
            import json
            import re

            query_obj = json.loads(query)

            # Check for NoSQL injection patterns
            query_str = json.dumps(query_obj)
            secrets_pattern = re.compile(r'secrets', re.IGNORECASE)
            operator_pattern = re.compile(r'\$where|\$lookup|\$function|\$expr', re.IGNORECASE)

            # Check if the collection is 'secrets' or if the query contains suspicious patterns
            if collection == 'secrets' or secrets_pattern.search(query_str) or operator_pattern.search(query_str):
                # NoSQL injection detected!
                sqli_detected = True

                # Return the flag
                results = [
                    {
                        "_id": "1",
                        "title": "Restricted Document",
                        "flag": "R00T{n0sql_1nj3ct10n_3xpl01t3d}",
                        "author": "admin",
                        "created_at": "2023-01-01"
                    }
                ]

                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="SQL Injection in NoSQL Database").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)

            # If no NoSQL injection detected, return normal results
            elif not sqli_detected:
                if collection == 'articles':
                    # Check if the query matches any articles
                    if 'author' in query_obj and query_obj['author'] == 'John Doe':
                        results = [
                            {
                                "_id": "1",
                                "title": "Introduction to NoSQL Databases",
                                "content": "NoSQL databases are designed to handle various data models, including document, key-value, wide-column, and graph formats.",
                                "author": "John Doe",
                                "created_at": "2023-01-01"
                            },
                            {
                                "_id": "2",
                                "title": "MongoDB vs. CouchDB",
                                "content": "This article compares two popular document databases: MongoDB and CouchDB, highlighting their strengths and weaknesses.",
                                "author": "John Doe",
                                "created_at": "2023-02-15"
                            }
                        ]
                    elif 'author' in query_obj and query_obj['author'] == 'Jane Smith':
                        results = [
                            {
                                "_id": "3",
                                "title": "Scaling NoSQL Databases",
                                "content": "Learn how to scale NoSQL databases horizontally to handle large volumes of data and high traffic loads.",
                                "author": "Jane Smith",
                                "created_at": "2023-03-10"
                            }
                        ]
                    else:
                        results = []
                elif collection == 'users':
                    # Check if the query matches any users
                    if 'username' in query_obj and query_obj['username'] == 'johndoe':
                        results = [
                            {
                                "_id": "1",
                                "username": "johndoe",
                                "email": "john.doe@example.com",
                                "role": "author"
                            }
                        ]
                    elif 'username' in query_obj and query_obj['username'] == 'janesmith':
                        results = [
                            {
                                "_id": "2",
                                "username": "janesmith",
                                "email": "jane.smith@example.com",
                                "role": "author"
                            }
                        ]
                    else:
                        results = []
                elif collection == 'products':
                    # Check if the query matches any products
                    if 'category' in query_obj and query_obj['category'] == 'Electronics':
                        results = [
                            {
                                "_id": "1",
                                "title": "Smartphone X",
                                "description": "Latest smartphone with advanced features.",
                                "price": 999.99,
                                "category": "Electronics"
                            },
                            {
                                "_id": "2",
                                "title": "Laptop Pro",
                                "description": "Professional laptop for developers.",
                                "price": 1499.99,
                                "category": "Electronics"
                            }
                        ]
                    elif 'category' in query_obj and query_obj['category'] == 'Clothing':
                        results = [
                            {
                                "_id": "3",
                                "title": "Designer T-shirt",
                                "description": "Premium cotton t-shirt.",
                                "price": 49.99,
                                "category": "Clothing"
                            }
                        ]
                    else:
                        results = []
                else:
                    results = []

        except Exception as e:
            error = f"Error executing query: {str(e)}"

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in NoSQL Database").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level22.html', flag=flag, sqli_detected=sqli_detected,
                          collection=collection, query=query, results=results, error=error)

# SQL Injection Level 23 - SQL Injection in ORM Layer
@app.route('/sqli/level23', methods=['GET', 'POST'])
def sqli_level23():
    import json
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    search_term = request.form.get('search_term', '')
    filter_by = request.form.get('filter_by', 'title')
    sort_by = request.form.get('sort_by', 'id')
    sort_order = request.form.get('sort_order', 'asc')
    results = []
    orm_query = None
    error = None

    if request.method == 'POST':
        try:
            # Generate the ORM query
            orm_query = f"db.session.query(Article).filter(Article.{filter_by}.like('%{search_term}%'))"

            if sort_by and sort_order:
                if sort_order == 'asc':
                    orm_query += f".order_by(Article.{sort_by})"
                else:
                    orm_query += f".order_by(Article.{sort_by}.desc())"

            # Check for SQL injection patterns
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]

            # Check if any SQL injection pattern is in the input
            for pattern in sqli_patterns:
                if pattern in search_term or pattern in filter_by or pattern in sort_by:
                    # SQL injection detected!
                    sqli_detected = True

                    # Return the flag
                    if "admin_flag" in search_term or "admin_flag" in filter_by or "admin_flag" in sort_by:
                        results = [
                            {
                                "id": 999,
                                "title": "Restricted Article",
                                "content": "This article contains the flag: R00T{0rm_l4y3r_sql1_1nj3ct10n_pwn3d}",
                                "author": "admin",
                                "created_at": "2023-01-01",
                                "is_published": False
                            }
                        ]

                        # Mark challenge as completed
                        challenge = Challenge.query.filter_by(name="SQL Injection in ORM Layer").first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(machine_id, challenge.id, challenge.points)
                    else:
                        results = [
                            {
                                "id": 998,
                                "title": "Suspicious Query Detected",
                                "content": "The system has detected a potential SQL injection attempt. This incident has been logged.",
                                "author": "system",
                                "created_at": "2023-01-01",
                                "is_published": True
                            }
                        ]
                    break

            # If no SQL injection detected, return normal results
            if not sqli_detected:
                if search_term.lower() in "python programming":
                    results = [
                        {
                            "id": 1,
                            "title": "Introduction to Python Programming",
                            "content": "Python is a high-level, interpreted programming language known for its readability and simplicity.",
                            "author": "John Doe",
                            "created_at": "2023-01-15",
                            "is_published": True
                        },
                        {
                            "id": 2,
                            "title": "Advanced Python Techniques",
                            "content": "Learn advanced Python techniques such as decorators, generators, and context managers.",
                            "author": "Jane Smith",
                            "created_at": "2023-02-20",
                            "is_published": True
                        }
                    ]
                elif search_term.lower() in "web development":
                    results = [
                        {
                            "id": 3,
                            "title": "Modern Web Development",
                            "content": "Explore modern web development frameworks and tools for building responsive web applications.",
                            "author": "Bob Johnson",
                            "created_at": "2023-03-10",
                            "is_published": True
                        },
                        {
                            "id": 4,
                            "title": "Frontend vs Backend Development",
                            "content": "Understanding the differences between frontend and backend web development roles and responsibilities.",
                            "author": "Alice Williams",
                            "created_at": "2023-04-05",
                            "is_published": True
                        }
                    ]
                elif search_term.lower() in "database":
                    results = [
                        {
                            "id": 5,
                            "title": "SQL Database Fundamentals",
                            "content": "Learn the fundamentals of SQL databases, including tables, queries, and relationships.",
                            "author": "John Doe",
                            "created_at": "2023-05-12",
                            "is_published": True
                        },
                        {
                            "id": 6,
                            "title": "NoSQL Database Overview",
                            "content": "Explore different types of NoSQL databases and their use cases in modern applications.",
                            "author": "Jane Smith",
                            "created_at": "2023-06-18",
                            "is_published": True
                        }
                    ]
                else:
                    results = []

                # Sort the results
                if sort_by == 'id':
                    results.sort(key=lambda x: x['id'], reverse=(sort_order == 'desc'))
                elif sort_by == 'title':
                    results.sort(key=lambda x: x['title'], reverse=(sort_order == 'desc'))
                elif sort_by == 'author':
                    results.sort(key=lambda x: x['author'], reverse=(sort_order == 'desc'))
                elif sort_by == 'created_at':
                    results.sort(key=lambda x: x['created_at'], reverse=(sort_order == 'desc'))

        except Exception as e:
            error = f"Error executing query: {str(e)}"

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in ORM Layer").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level23.html', flag=flag, sqli_detected=sqli_detected,
                          search_term=search_term, filter_by=filter_by, sort_by=sort_by,
                          sort_order=sort_order, results=results, orm_query=orm_query, error=error)

# Solutions
@app.route('/solutions/<level>')
def solutions(level):
    # Check if it's an XSS or SQLi solution
    if level.startswith('sqli'):
        # Get the challenge object to pass to the template
        challenge_name_map = {
            'sqli1': 'Basic SQL Injection',
            'sqli2': 'SQL Injection in Search',
            'sqli3': 'SQL Injection with UNION',
            'sqli4': 'Blind SQL Injection',
            'sqli5': 'Time-Based Blind SQL Injection',
            'sqli6': 'SQL Injection with WAF Bypass',
            'sqli7': 'Error-Based SQL Injection',
            'sqli8': 'Second-Order SQL Injection',
            'sqli9': 'SQL Injection in REST API',
            'sqli10': 'NoSQL Injection',
            'sqli11': 'GraphQL Injection',
            'sqli12': 'ORM-based SQL Injection',
            'sqli13': 'Out-of-band SQL Injection',
            'sqli14': 'SQL Injection with Advanced WAF Bypass',
            'sqli15': 'SQL Injection via XML',
            'sqli16': 'SQL Injection in WebSockets',
            'sqli17': 'SQL Injection in Mobile App Backend',
            'sqli18': 'SQL Injection in Cloud Functions',
            'sqli19': 'SQL Injection via File Upload',
            'sqli20': 'SQL Injection in Stored Procedures',
            'sqli21': 'SQL Injection in GraphQL API',
            'sqli22': 'SQL Injection in NoSQL Database',
            'sqli23': 'SQL Injection in ORM Layer'
        }
        challenge_name = challenge_name_map.get(level)
        challenge = Challenge.query.filter_by(name=challenge_name).first() if challenge_name else None

        # Extract level number, handling both single and double-digit levels
        if level.startswith('sqli'):
            level_num = level[4:]  # Extract everything after 'sqli'
        else:
            level_num = level  # Use the full level string

        return render_template(f'solutions/sqli_level{level_num}_solution.html', challenge=challenge)
    else:
        # For XSS challenges, extract the level number and get the challenge
        try:
            level_num = int(level)
            challenge_name_map = {
                1: 'Basic Reflected XSS',
                2: 'DOM-based XSS',
                3: 'Stored XSS',
                4: 'XSS with Basic Filters',
                5: 'XSS with Advanced Filters',
                6: 'XSS with ModSecurity WAF',
                7: 'XSS via HTTP Headers',
                8: 'XSS in JSON API',
                9: 'XSS with CSP Bypass',
                10: 'XSS with Mutation Observer Bypass',
                11: 'XSS via SVG and CDATA',
                12: 'Blind XSS with Webhook Exfiltration',
                13: 'XSS in PDF Generation',
                14: 'XSS via Prototype Pollution',
                15: 'XSS via Template Injection',
                16: 'XSS in WebAssembly Applications',
                17: 'XSS in Progressive Web Apps',
                18: 'XSS via Web Components',
                19: 'XSS in GraphQL APIs',
                20: 'XSS in WebRTC Applications',
                21: 'XSS via Web Bluetooth/USB',
                22: 'XSS in WebGPU Applications',
                23: 'XSS in Federated Identity Systems'
            }
            challenge_name = challenge_name_map.get(level_num)
            challenge = Challenge.query.filter_by(name=challenge_name).first() if challenge_name else None
            return render_template(f'solutions/xss_level{level}_solution.html', challenge=challenge)
        except ValueError:
            # Handle invalid level format
            return render_template('error.html', error="Invalid solution level format")



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
    app.run(debug=True, host='0.0.0.0', port=5000)
