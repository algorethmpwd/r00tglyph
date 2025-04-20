from flask import Flask, render_template, request, redirect, url_for, session, jsonify
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
    args = parser.parse_args()

    if args.update:
        print("Updating R00tGlyph to the latest version...")
        # Backup user data
        if os.path.exists('instance/r00tglyph.db'):
            print("Backing up user data...")
            backup_dir = 'backup'
            os.makedirs(backup_dir, exist_ok=True)
            shutil.copy2('instance/r00tglyph.db', f'{backup_dir}/r00tglyph.db.bak')

        # Pull latest changes from GitHub
        try:
            print("Pulling latest changes from GitHub...")
            subprocess.run(['git', 'pull'], check=True)

            # Restore user data
            if os.path.exists(f'{backup_dir}/r00tglyph.db.bak'):
                print("Restoring user data...")
                shutil.copy2(f'{backup_dir}/r00tglyph.db.bak', 'instance/r00tglyph.db')

            print("Update completed successfully!")
        except subprocess.CalledProcessError:
            print("Error: Failed to pull latest changes. Please check your internet connection.")
            if os.path.exists(f'{backup_dir}/r00tglyph.db.bak'):
                print("Restoring user data from backup...")
                shutil.copy2(f'{backup_dir}/r00tglyph.db.bak', 'instance/r00tglyph.db')

        sys.exit(0)

app = Flask(__name__)
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

    # Initialize challenges if they don't exist
    if Challenge.query.count() == 0:
        challenges = [
            Challenge(name="Basic Reflected XSS", category="xss", difficulty="beginner",
                     description="A simple search page that reflects user input directly in the response.", points=100),
            Challenge(name="DOM-based XSS", category="xss", difficulty="beginner",
                     description="Exploit a vulnerability in client-side JavaScript code.", points=150),
            Challenge(name="Stored XSS", category="xss", difficulty="intermediate",
                     description="Inject persistent JavaScript that affects all visitors.", points=200),
            Challenge(name="XSS with Basic Filters", category="xss", difficulty="intermediate",
                     description="Bypass simple XSS protection mechanisms.", points=250),
            Challenge(name="XSS with Advanced Filters", category="xss", difficulty="advanced",
                     description="Bypass complex WAF-like protections.", points=350),
            Challenge(name="XSS with ModSecurity WAF", category="xss", difficulty="advanced",
                     description="Bypass industry-standard WAF rules.", points=500),
        ]
        db.session.add_all(challenges)
        db.session.commit()

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
        completed = json.loads(user.completed_challenges)
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
            user.display_name = display_name
            db.session.commit()
            return redirect(url_for('profile'))

    # Get completed challenges
    completed_challenges = []
    if user.completed_challenges:
        challenge_ids = json.loads(user.completed_challenges)
        completed_challenges = Challenge.query.filter(Challenge.id.in_(challenge_ids)).all()

    return render_template('profile.html', user=user, completed_challenges=completed_challenges)

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

    # Get challenges grouped by category
    challenges_by_category = {}
    for category in categories:
        challenges_by_category[category] = Challenge.query.filter_by(category=category, active=True).all()

    return render_template('vulnerabilities.html', categories=categories, challenges=challenges_by_category)

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
        challenge = Challenge.query.get(challenge_id)
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

    # Generate a flag for this challenge
    challenge = Challenge.query.filter_by(name="Basic Reflected XSS").first()
    if challenge:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level1.html', user_input=user_input, flag=flag)

# XSS Level 2 - DOM-based XSS
@app.route('/xss/level2')
def xss_level2():
    machine_id = get_machine_id()
    flag = None

    # Generate a flag for this challenge
    challenge = Challenge.query.filter_by(name="DOM-based XSS").first()
    if challenge:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level2.html', flag=flag)

# XSS Level 3 - Stored XSS
@app.route('/xss/level3', methods=['GET', 'POST'])
def xss_level3():
    machine_id = get_machine_id()
    user = get_local_user()

    if request.method == 'POST':
        username = request.form.get('username', user.display_name)
        content = request.form.get('content', '')

        # Store the comment in the database
        new_comment = Comment(username=username, content=content, level=3, machine_id=machine_id)
        db.session.add(new_comment)
        db.session.commit()

        return redirect(url_for('xss_level3'))

    # Get all comments for level 3
    comments = Comment.query.filter_by(level=3).order_by(Comment.timestamp.desc()).all()

    flag = None
    # Generate a flag for this challenge
    challenge = Challenge.query.filter_by(name="Stored XSS").first()
    if challenge:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level3.html', comments=comments, flag=flag, user=user)

# XSS Level 4 - XSS with Basic Filters
@app.route('/xss/level4', methods=['GET', 'POST'])
def xss_level4():
    machine_id = get_machine_id()
    message = ""
    filtered_input = ""
    waf_blocked = False

    if request.method == 'POST':
        user_input = request.form.get('user_input', '')

        # Basic filter: Remove <script> tags
        filtered_input = WAF.basic_filter(user_input)
        message = "Your input has been filtered for security!"

    flag = None
    # Generate a flag for this challenge
    challenge = Challenge.query.filter_by(name="XSS with Basic Filters").first()
    if challenge:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level4.html', message=message, filtered_input=filtered_input,
                           waf_blocked=waf_blocked, flag=flag)

# XSS Level 5 - XSS with Advanced Filters
@app.route('/xss/level5', methods=['GET', 'POST'])
def xss_level5():
    machine_id = get_machine_id()
    message = ""
    filtered_input = ""
    waf_blocked = False

    if request.method == 'POST':
        user_input = request.form.get('user_input', '')

        # More advanced filtering (still bypassable)
        filtered_input = WAF.advanced_filter(user_input)
        message = "Your input has been filtered with our advanced security system!"

    flag = None
    # Generate a flag for this challenge
    challenge = Challenge.query.filter_by(name="XSS with Advanced Filters").first()
    if challenge:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level5.html', message=message, filtered_input=filtered_input,
                           waf_blocked=waf_blocked, flag=flag)

# XSS Level 6 - XSS with ModSecurity WAF
@app.route('/xss/level6', methods=['GET', 'POST'])
def xss_level6():
    machine_id = get_machine_id()
    message = ""
    filtered_input = ""
    waf_blocked = False

    if request.method == 'POST':
        user_input = request.form.get('user_input', '')

        # ModSecurity WAF emulation
        filtered_input, waf_blocked = WAF.modsecurity_emulation(user_input)

        if waf_blocked:
            message = "⚠️ WAF Alert: Potential XSS attack detected and blocked!"
        else:
            message = "Input passed security checks."

    flag = None
    # Generate a flag for this challenge
    challenge = Challenge.query.filter_by(name="XSS with ModSecurity WAF").first()
    if challenge:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xss/xss_level6.html', message=message, filtered_input=filtered_input,
                           waf_blocked=waf_blocked, flag=flag)

# Solutions
@app.route('/solutions/<level>')
def solutions(level):
    return render_template(f'solutions/xss_level{level}_solution.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
