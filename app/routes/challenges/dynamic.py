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

dynamic_bp = Blueprint('dynamic', __name__)

@dynamic_bp.route('/ssti/level1', methods=['GET', 'POST'])
@login_required
def ssti_level1():
    user = get_current_user()
    challenge = Challenge.query.filter_by(category='ssti', name='SSTI Level 1').first()
    if not challenge:
        return ('Challenge not found. Please run add_challenges_to_db.py first.', 404)
    vulnerability_detected = False
    flag = None
    result = None
    if request.method == 'POST':
        payload = request.form.get('payload', '')
        if any((p in payload for p in ['{{', '}}', '{%', '%}', 'config', 'self', '__class__'])):
            vulnerability_detected = True
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
            flag = get_or_create_flag(challenge.id, user.id)
        result = 'Template processed: ' + payload[:100] if payload else None
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssti/ssti_level1.html', user=user, vulnerability_detected=vulnerability_detected, flag=flag, result=result, challenge=challenge)

@dynamic_bp.route('/ssti/level<int:level>', methods=['GET', 'POST'])
@login_required
def ssti_level_dynamic(level):
    if level < 2 or level > 23:
        return ('Invalid level', 404)
    user = get_current_user()
    challenge = Challenge.query.filter_by(category='ssti', name=f'SSTI Level {level}').first()
    if not challenge:
        return (f'Challenge not found. Please run add_challenges_to_db.py first.', 404)
    vulnerability_detected = False
    flag = None
    result = None
    if request.method == 'POST':
        payload = request.form.get('payload', '')
        ssti_patterns = ['{{', '}}', '{%', '%}', 'config', 'self', '__class__', '__mro__', '__globals__']
        if any((p in payload for p in ssti_patterns)):
            vulnerability_detected = True
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
            flag = get_or_create_flag(challenge.id, user.id)
        result = f'Template processed: {payload[:100]}' if payload else None
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template(f'ssti/ssti_level{level}.html', user=user, vulnerability_detected=vulnerability_detected, flag=flag, result=result, challenge=challenge)

@dynamic_bp.route('/deserial/level<int:level>', methods=['GET', 'POST'])
@login_required
def deserial_level(level):
    if level < 1 or level > 10:
        return ('Invalid level', 404)
    user = get_current_user()
    challenge = Challenge.query.filter_by(category='deserial', name=f'Deserialization Level {level}').first()
    if not challenge:
        return ('Challenge not found. Please run add_challenges_to_db.py first.', 404)
    vulnerability_detected = False
    flag = None
    result = None
    if request.method == 'POST':
        payload = request.form.get('payload', '')
        deserial_patterns = ['pickle', '__reduce__', 'os.system', 'O:', 'a:', 's:', 'rO0', 'AAEAA', 'yaml', 'SOAP', 'MessagePack', 'gadget']
        if any((p in payload for p in deserial_patterns)):
            vulnerability_detected = True
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
            flag = get_or_create_flag(challenge.id, user.id)
        result = f'Deserialization attempted: {payload[:100]}' if payload else None
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template(f'deserial/deserial_level{level}.html', user=user, vulnerability_detected=vulnerability_detected, flag=flag, result=result, challenge=challenge)

@dynamic_bp.route('/auth/level<int:level>', methods=['GET', 'POST'])
@login_required
def auth_level(level):
    if level < 1 or level > 10:
        return ('Invalid level', 404)
    user = get_current_user()
    challenge = Challenge.query.filter_by(category='auth', name=f'Auth Bypass Level {level}').first()
    if not challenge:
        return ('Challenge not found. Please run add_challenges_to_db.py first.', 404)
    vulnerability_detected = False
    flag = None
    result = None
    if request.method == 'POST':
        payload = request.form.get('payload', '')
        auth_patterns = ["' OR '1'='1", "' OR 1=1--", "admin' --", '"alg": "none"', 'sessionid=', 'jwt', 'saml', 'kerberos', 'reset', 'token']
        if any((p.lower() in payload.lower() for p in auth_patterns)):
            vulnerability_detected = True
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
            flag = get_or_create_flag(challenge.id, user.id)
        result = f'Authentication check: {payload[:100]}' if payload else None
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template(f'auth/auth_level{level}.html', user=user, vulnerability_detected=vulnerability_detected, flag=flag, result=result, challenge=challenge)

