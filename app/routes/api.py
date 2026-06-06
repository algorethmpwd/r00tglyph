import json
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

api_bp = Blueprint('api', __name__)

@api_bp.route('/submit-flag', methods=['POST'])
@login_required
@rate_limit(max_requests=30, window_seconds=60, key_func=lambda: str(session.get('user_id', '')))
def submit_flag():
    challenge_id = request.form.get('challenge_id')
    flag = request.form.get('flag')
    user_id = session.get('user_id')
    if not challenge_id or not flag:
        return jsonify({'success': False, 'message': 'Missing required parameters'})
    try:
        challenge_id = int(challenge_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid challenge ID format'})
    challenge = db.session.get(Challenge, challenge_id)
    if not challenge or not challenge.active:
        return jsonify({'success': False, 'message': 'Invalid challenge'})
    valid_flag = Flag.query.filter_by(challenge_id=challenge_id, user_id=user_id, flag_value=flag, used=False).first()
    if valid_flag:
        valid_flag.used = True
        submission = Submission(user_id=user_id, challenge_id=challenge_id, flag=flag, correct=True)
        db.session.add(submission)
        update_user_progress(user_id, challenge_id, challenge.points)
        db.session.commit()
        return jsonify({'success': True, 'message': f'Congratulations! You earned {challenge.points} points!'})
    else:
        submission = Submission(user_id=user_id, challenge_id=challenge_id, flag=flag, correct=False)
        db.session.add(submission)
        db.session.commit()
        return jsonify({'success': False, 'message': 'Invalid flag. Try again!'})

@api_bp.route('/api/notes', methods=['GET', 'POST'])
def api_notes():
    user = get_current_user()
    if not user:
        return (jsonify({'error': 'Unauthorized'}), 401)
    if request.method == 'POST':
        data = request.get_json()
        new_note = {'id': random.randint(1000, 9999), 'title': data.get('title', ''), 'content': data.get('content', ''), 'tags': data.get('tags', '').split(',') if data.get('tags') else [], 'created': datetime.now().isoformat()}
        return jsonify(new_note)
    else:
        notes = [{'id': 101, 'title': 'Getting Started with DevNotes', 'content': 'Welcome to DevNotes! This is a simple note-taking app for developers.', 'tags': ['welcome', 'tutorial'], 'created': '2025-04-19T10:30:00Z'}, {'id': 102, 'title': 'JavaScript Tips and Tricks', 'content': 'Here are some useful JavaScript tips and tricks for web developers.', 'tags': ['javascript', 'tips'], 'created': '2025-04-19T11:45:00Z'}, {'id': 103, 'title': 'API Security Best Practices', 'content': 'Learn how to secure your APIs against common vulnerabilities.', 'tags': ['security', 'api'], 'created': '2025-04-19T14:20:00Z'}]
        user_agent = request.headers.get('User-Agent', '')
        if 'XSS Level 8 Completed!' in user_agent:
            notes.insert(0, {'id': 104, 'title': '<img src=x onerror="alert(\'XSS Level 8 Completed!\');">', 'content': 'This note contains an XSS payload in the title.', 'tags': ['xss', 'security'], 'created': datetime.now().isoformat()})
            challenge = Challenge.query.filter_by(name='XSS in JSON API').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
        return jsonify(notes)

@api_bp.route('/solutions/<level>')
def solutions(level):
    if level.startswith('cmdi'):
        challenge_name_map = {'cmdi1': 'Basic Command Injection', 'cmdi2': 'Command Injection with Filters', 'cmdi3': 'Blind Command Injection', 'cmdi4': 'Command Injection via File Upload', 'cmdi5': 'Command Injection in API Parameters', 'cmdi6': 'Command Injection with WAF Bypass', 'cmdi7': 'Time-Based Blind Command Injection', 'cmdi8': 'Command Injection in Log Processing', 'cmdi9': 'Command Injection in JSON APIs', 'cmdi10': 'Command Injection in XML Processing', 'cmdi11': 'Command Injection with WAF Bypass', 'cmdi12': 'Command Injection in DevOps Tools', 'cmdi13': 'Command Injection in GraphQL APIs', 'cmdi14': 'Command Injection in WebSocket Connections', 'cmdi15': 'Command Injection in Serverless Functions', 'cmdi16': 'Advanced Shell Features Command Injection', 'cmdi17': 'Command Injection in Container Environments', 'cmdi18': 'Command Injection via Template Engines', 'cmdi19': 'Command Injection in Message Queues', 'cmdi20': 'Out-of-Band Command Injection', 'cmdi21': 'Command Injection in Cloud Functions', 'cmdi22': 'Command Injection in SSH Commands', 'cmdi23': 'Advanced Command Injection Chaining'}
        challenge_name = challenge_name_map.get(level)
        challenge = Challenge.query.filter_by(name=challenge_name).first() if challenge_name else None
        if level.startswith('cmdi'):
            level_num = level[4:]
        else:
            level_num = level
        return render_template(f'solutions/cmdi_level{level_num}_solution.html', challenge=challenge)
    elif level.startswith('ssrf'):
        challenge_name_map = {'ssrf1': 'Basic SSRF', 'ssrf2': 'SSRF with Internal Network Scanning', 'ssrf3': 'Cloud Metadata SSRF', 'ssrf4': 'Blind SSRF with DNS Exfiltration', 'ssrf5': 'SSRF with Basic Filters', 'ssrf6': 'SSRF via File Upload', 'ssrf7': 'SSRF in Webhooks', 'ssrf8': 'SSRF with WAF Bypass', 'ssrf9': 'SSRF via XXE', 'ssrf10': 'SSRF with DNS Rebinding', 'ssrf11': 'SSRF in GraphQL', 'ssrf12': 'SSRF via Redis Protocol', 'ssrf13': 'SSRF in WebSocket Upgrade', 'ssrf14': 'SSRF via SMTP Protocol', 'ssrf15': 'SSRF in OAuth Callbacks', 'ssrf16': 'SSRF via LDAP Protocol', 'ssrf17': 'SSRF in Container Metadata', 'ssrf18': 'SSRF via FTP Protocol', 'ssrf19': 'SSRF in API Gateway', 'ssrf20': 'SSRF via Time-based Attacks', 'ssrf21': 'SSRF in Microservices', 'ssrf22': 'SSRF via Protocol Smuggling', 'ssrf23': 'SSRF in Serverless Functions'}
        challenge_name = challenge_name_map.get(level)
        challenge = Challenge.query.filter_by(name=challenge_name).first() if challenge_name else None
        if level.startswith('ssrf'):
            level_num = level[4:]
        else:
            level_num = level
        return render_template(f'solutions/ssrf_level{level_num}_solution.html', challenge=challenge)
    elif level.startswith('sqli'):
        challenge_name_map = {'sqli1': 'Basic SQL Injection', 'sqli2': 'SQL Injection in Search', 'sqli3': 'SQL Injection with UNION', 'sqli4': 'Blind SQL Injection', 'sqli5': 'Time-Based Blind SQL Injection', 'sqli6': 'SQL Injection with WAF Bypass', 'sqli7': 'Error-Based SQL Injection', 'sqli8': 'Second-Order SQL Injection', 'sqli9': 'SQL Injection in REST API', 'sqli10': 'NoSQL Injection', 'sqli11': 'GraphQL Injection', 'sqli12': 'ORM-based SQL Injection', 'sqli13': 'Out-of-band SQL Injection', 'sqli14': 'SQL Injection with Advanced WAF Bypass', 'sqli15': 'SQL Injection via XML', 'sqli16': 'SQL Injection in WebSockets', 'sqli17': 'SQL Injection in Mobile App Backend', 'sqli18': 'SQL Injection in Cloud Functions', 'sqli19': 'SQL Injection via File Upload', 'sqli20': 'SQL Injection in Stored Procedures', 'sqli21': 'SQL Injection in GraphQL API', 'sqli22': 'SQL Injection in NoSQL Database', 'sqli23': 'SQL Injection in ORM Layer'}
        challenge_name = challenge_name_map.get(level)
        challenge = Challenge.query.filter_by(name=challenge_name).first() if challenge_name else None
        if level.startswith('sqli'):
            level_num = level[4:]
        else:
            level_num = level
        return render_template(f'solutions/sqli_level{level_num}_solution.html', challenge=challenge)
    elif level.startswith('xxe'):
        challenge_name_map = {'xxe1': 'Basic XXE File Disclosure', 'xxe2': 'XXE with DOCTYPE Restrictions', 'xxe3': 'XXE SYSTEM Entity Exploitation', 'xxe4': 'XXE Internal Network Scanning', 'xxe5': 'XXE Data Exfiltration via HTTP', 'xxe6': 'XXE with Parameter Entities', 'xxe7': 'Blind XXE via Error Messages', 'xxe8': 'XXE with CDATA Injection', 'xxe9': 'XXE via SVG File Upload', 'xxe10': 'XXE with XInclude Attacks', 'xxe11': 'XXE Billion Laughs DoS', 'xxe12': 'XXE SSRF Combination Attack', 'xxe13': 'XXE with WAF Bypass Techniques', 'xxe14': 'XXE via SOAP Web Services', 'xxe15': 'Advanced XXE with OOB Data Retrieval', 'xxe16': 'XXE in JSON-XML Conversion', 'xxe17': 'XXE with Custom Entity Resolvers', 'xxe18': 'XXE in Microsoft Office Documents', 'xxe19': 'XXE with Protocol Handler Exploitation', 'xxe20': 'XXE in XML Signature Verification', 'xxe21': 'XXE with Time-Based Blind Techniques', 'xxe22': 'XXE in Cloud XML Processing', 'xxe23': 'Advanced XXE Attack Chaining'}
        challenge_name = challenge_name_map.get(level)
        challenge = Challenge.query.filter_by(name=challenge_name).first() if challenge_name else None
        if level.startswith('xxe'):
            level_num = level[3:]
        else:
            level_num = level
        return render_template(f'solutions/xxe_level{level_num}_solution.html', challenge=challenge)
    elif level.startswith('csrf'):
        challenge_name_map = {'csrf1': 'Basic Form CSRF', 'csrf2': 'GET-based CSRF', 'csrf3': 'JSON CSRF', 'csrf4': 'File Upload CSRF', 'csrf5': 'CSRF with Weak Tokens', 'csrf6': 'Referrer-based Protection Bypass', 'csrf7': 'CSRF in AJAX Requests', 'csrf8': 'SameSite Cookie Bypass', 'csrf9': 'CSRF with Custom Headers', 'csrf10': 'Multi-step CSRF', 'csrf11': 'CSRF in Password Change', 'csrf12': 'CSRF with CAPTCHA Bypass', 'csrf13': 'CSRF with CORS Exploitation', 'csrf14': 'WebSocket CSRF', 'csrf15': 'CSRF in OAuth Flows', 'csrf16': 'CSRF with CSP Bypass', 'csrf17': 'CSRF via XSS Chain', 'csrf18': 'GraphQL CSRF', 'csrf19': 'JWT-based CSRF', 'csrf20': 'Mobile API CSRF', 'csrf21': 'Microservices CSRF', 'csrf22': 'CSRF with Subdomain Takeover', 'csrf23': 'Serverless Function CSRF'}
        challenge_name = challenge_name_map.get(level)
        challenge = Challenge.query.filter_by(name=challenge_name).first() if challenge_name else None
        if level.startswith('csrf'):
            level_num = level[4:]
        else:
            level_num = level
        return render_template(f'solutions/csrf_level{level_num}_solution.html', challenge=challenge)
    else:
        try:
            level_num = int(level)
            challenge_name_map = {1: 'Basic Reflected XSS', 2: 'DOM-based XSS', 3: 'Stored XSS', 4: 'XSS with Basic Filters', 5: 'XSS with Advanced Filters', 6: 'XSS with ModSecurity WAF', 7: 'XSS via HTTP Headers', 8: 'XSS in JSON API', 9: 'XSS with CSP Bypass', 10: 'XSS with Mutation Observer Bypass', 11: 'XSS via SVG and CDATA', 12: 'Blind XSS with Webhook Exfiltration', 13: 'XSS in PDF Generation', 14: 'XSS via Prototype Pollution', 15: 'XSS via Template Injection', 16: 'XSS in WebAssembly Applications', 17: 'XSS in Progressive Web Apps', 18: 'XSS via Web Components', 19: 'XSS in GraphQL APIs', 20: 'XSS in WebRTC Applications', 21: 'XSS via Web Bluetooth/USB', 22: 'XSS in WebGPU Applications', 23: 'XSS in Federated Identity Systems'}
            challenge_name = challenge_name_map.get(level_num)
            challenge = Challenge.query.filter_by(name=challenge_name).first() if challenge_name else None
            return render_template(f'solutions/xss_level{level}_solution.html', challenge=challenge)
        except ValueError:
            return render_template('error.html', error='Invalid solution level format')

@api_bp.route('/api/hints/<category>/<int:level>')
@login_required
def get_hint(category, level):
    hint_file = f'data/hints/{category}_level{level}.json'
    if os.path.exists(hint_file):
        with open(hint_file, 'r') as f:
            return jsonify(json.load(f))
    return (jsonify({'error': 'Hint not found'}), 404)

@api_bp.route('/api/solutions/<category>/<int:level>')
@login_required
def get_solution(category, level):
    user = get_current_user()
    challenge = Challenge.query.filter_by(category=category).filter(Challenge.name.like(f'%Level {level}%') if level > 1 else Challenge.name.like(f'%{category.title()}%')).first()
    if not challenge:
        challenge = Challenge.query.filter_by(category=category).first()
    if challenge:
        completed = json.loads(user.completed_challenges) if user.completed_challenges else []
        if challenge.id not in completed and (not user.is_admin):
            return (jsonify({'error': 'Complete the challenge to view the solution'}), 403)
    solution_file = f'data/solutions/{category}_level{level}.json'
    if os.path.exists(solution_file):
        with open(solution_file, 'r') as f:
            return jsonify(json.load(f))
    return (jsonify({'error': 'Solution not found'}), 404)

