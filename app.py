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
        # We'll handle this later after app is defined
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

    # Create new flag with improved uniqueness and validation
    new_flag_value = generate_flag(challenge_id, machine_id)
    
    # Ensure flag doesn't exist (additional verification)
    existing = Flag.query.filter_by(flag_value=new_flag_value).first()
    if existing:
        # Very unlikely but regenerate if collision occurs
        new_flag_value = generate_flag(challenge_id, machine_id)
    
    # Store flag with creation timestamp
    new_flag = Flag(
        challenge_id=challenge_id, 
        machine_id=machine_id, 
        flag_value=new_flag_value,
        created_at=datetime.utcnow()
    )
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
            # Enhanced basic filter with more tag variants
            filtered = input_str
            for tag in ['script', 'img', 'iframe', 'svg', 'object', 'embed']:
                filtered = re.sub(f'<{tag}[^>]*>|</{tag}>', '', filtered, flags=re.IGNORECASE)
            return filtered
        return input_str

    @staticmethod
    def advanced_filter(input_str):
        """More advanced filtering - similar to common XSS protections"""
        if not input_str:
            return input_str

        filtered = input_str
        # Event handlers
        event_handlers = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur', 'oncut', 'oncopy', 
                          'onpaste', 'ondrag', 'ondrop', 'onkeyup', 'onkeydown', 'onkeypress', 'onmouseup',
                          'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'ontouchstart', 'ontouchend',
                          'ontouchmove', 'onabort', 'onbeforeunload', 'onhashchange', 'onpageshow', 'onpagehide']
        
        # Replace dangerous attributes/protocols
        for handler in event_handlers:
            filtered = re.sub(f'{handler}\\s*=', '', filtered, flags=re.IGNORECASE)
        
        # Block dangerous protocols and JS execution paths
        dangerous_protocols = ['javascript:', 'data:', 'vbscript:', 'file:']
        for protocol in dangerous_protocols:
            filtered = filtered.replace(protocol, '')
            
        # Block script and iframe tags more thoroughly
        for tag in ['script', 'iframe', 'object', 'embed', 'base']:
            filtered = re.sub(f'<{tag}[^>]*>([\\s\\S]*?)</{tag}>', '', filtered, flags=re.IGNORECASE)
        
        return filtered

    @staticmethod
    def modsecurity_emulation(input_str):
        """Emulate ModSecurity WAF rules with realistic behaviors from modern WAFs"""
        if not input_str:
            return input_str, False

        # Real ModSecurity-inspired rules - organized by attack category
        xss_patterns = [
            # Script tag variations
            r'<script[^>]*>[\s\S]*?<\/script>',
            r'<\s*script\s*>',
            r'<\s*script\s*[\s\S]*?>',
            r'<\s*\/\s*script\s*>',
            
            # JS protocol
            r'javascript\s*:',
            r'data\s*:\s*text\/html',
            r'vbscript\s*:',
            
            # Event handlers
            r'on\w+\s*=',
            r'\bon\w+\s*=\s*(["\'])(?:(?!\1).)*\1',
            
            # JS functions
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'\bFunction\s*\(',
            
            # DOM manipulation
            r'document\.(?:cookie|location|write|createE)',
            r'(?:window|document|location|history)\.(?:href|host|pathname|replace|assign|reload)',
            
            # JS dialog functions
            r'\b(?:alert|confirm|prompt)\s*\(',
            
            # Tag attribute exploits
            r'<img[^>]*\b(?:on\w+|src|style)\s*=',
            r'<(?:iframe|frame|embed|object|svg)[^>]*>',
            
            # HTML5 elements with event handlers
            r'<(?:audio|video|body|details|form)[^>]*\bon\w+\s*=',
            
            # Advanced JS functions
            r'\b(?:setTimeout|setInterval|fetch|XMLHttpRequest)\s*\(',
            
            # ES6+ features potentially used in exploits
            r'(?:=>|\`|\${)',
            r'(?:class|extends|super|constructor)',
            
            # CSP bypass techniques
            r'(?:<base|data:image\/svg|blob:)',
            
            # Advanced encoding bypasses
            r'(?:fromCharCode|String\.raw|decodeURI|\\u00[0-9a-f]{2}|\\x[0-9a-f]{2})',
            
            # Attribute context breaking 
            r'["\']\s*[+>]\s*["\']\s*[+>]',
            
            # New WAF bypass techniques from 2023-2025
            r'(?:navigator\.sendBeacon|trustedTypes|Proxy\s*\(|import\s*\()',
            r'import(?:\s*\(|\s+from)',
            r'\[\s*Symbol\s*\.',
            r'Element\.prototype\.',
            r'(?:ServiceWorker|SharedWorker|Worker)(?:\s*\.\s*prototype|\s*\[\s*\w+\s*\])',
        ]

@app.route('/submit-flag', methods=['POST'])
def submit_flag():
    challenge_id = request.form.get('challenge_id')
    flag = request.form.get('flag')
    machine_id = get_machine_id()
    
    # Enhanced logging for security auditing
    request_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
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
        
        # Get challenge details for enhanced response
        challenge = Challenge.query.get(challenge_id)
        if not challenge:
            return jsonify({'success': False, 'message': 'Challenge not found'})
            
        # Get user information
        user = get_local_user()
        
        # Calculate skill progression metrics
        completed_challenges = json.loads(user.completed_challenges)
        category_completion = {
            'xss': 0,
            'sqli': 0,
            'csrf': 0,
            'other': 0
        }
        
        # Count completed challenges by category
        all_challenges = Challenge.query.all()
        category_totals = {cat: 0 for cat in category_completion.keys()}
        
        for c in all_challenges:
            cat = c.category.lower()
            if cat not in category_totals:
                cat = 'other'
            category_totals[cat] += 1
            
            if str(c.id) in completed_challenges:
                if cat in category_completion:
                    category_completion[cat] += 1
                else:
                    category_completion['other'] += 1
        
        # Calculate percentages
        for cat in category_completion.keys():
            if category_totals.get(cat, 0) > 0:
                category_completion[cat] = round((category_completion[cat] / category_totals[cat]) * 100)
        
        # Record submission with comprehensive metadata
        submission = Submission(
            machine_id=machine_id, 
            challenge_id=challenge_id, 
            flag=flag, 
            correct=True,
            timestamp=datetime.utcnow()
        )
        db.session.add(submission)

        # Update user score and progress
        previous_score = user.score
        update_user_progress(machine_id, challenge_id, challenge.points)
        
        # Log the successful completion with detailed information
        print(f"[SUCCESS] Challenge {challenge_id} ({challenge.name}) completed by {machine_id} - {datetime.utcnow()} - IP: {request_ip}")
        
        # Generate achievement data
        solved_count = len(json.loads(user.completed_challenges))
        total_challenges = Challenge.query.count()
        completion_percentage = round((solved_count / total_challenges) * 100) if total_challenges > 0 else 0
        
        # Determine if this is their first completion of this category
        first_of_category = False
        category_challenges = Challenge.query.filter_by(category=challenge.category).all()
        category_ids = [str(c.id) for c in category_challenges]
        if len(set(completed_challenges).intersection(set(category_ids))) == 1 and str(challenge_id) in completed_challenges:
            first_of_category = True
            
        # Determine if this completes a difficulty level
        difficulty_completion = False
        difficulty_challenges = Challenge.query.filter_by(difficulty=challenge.difficulty).all()
        difficulty_ids = [str(c.id) for c in difficulty_challenges]
        if set(difficulty_ids).issubset(set(completed_challenges)):
            difficulty_completion = True
        
        db.session.commit()
        
        # Return enhanced success response with comprehensive metrics
        return jsonify({
            'success': True,
            'message': f'Congratulations! You earned {challenge.points} points!',
            'challenge': {
                'id': challenge.id,
                'name': challenge.name,
                'category': challenge.category,
                'difficulty': challenge.difficulty,
                'points': challenge.points
            },
            'user': {
                'username': user.username,
                'previousScore': previous_score,
                'newScore': user.score,
                'scoreIncrease': challenge.points,
                'completedChallenges': solved_count,
                'totalChallenges': total_challenges,
                'progressPercentage': completion_percentage
            },
            'skill_metrics': {
                'categoryProgress': category_completion,
                'isFirstCategoryCompletion': first_of_category,
                'isDifficultyCompleted': difficulty_completion
            },
            'timestamp': datetime.utcnow().isoformat()
        })
    else:
        # Record incorrect submission with enhanced auditing
        submission = Submission(
            machine_id=machine_id, 
            challenge_id=challenge_id, 
            flag=flag, 
            correct=False,
            timestamp=datetime.utcnow()
        )
        db.session.add(submission)
        
        # Log the failed attempt for security monitoring
        print(f"[FAIL] Invalid flag attempt for challenge {challenge_id} by {machine_id} - {datetime.utcnow()} - IP: {request_ip}")
        
        db.session.commit()

        return jsonify({
            'success': False, 
            'message': 'Invalid flag. Try again!',
            'timestamp': datetime.utcnow().isoformat()
        })
