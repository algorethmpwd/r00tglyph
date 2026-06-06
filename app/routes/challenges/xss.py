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

xss_bp = Blueprint('xss', __name__)

@xss_bp.route('/xss/level1', methods=['GET', 'POST'])
@login_required
def xss_level1():
    user_input = request.args.get('name', '')
    flag = None
    xss_detected = False
    user = get_current_user()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if '<script>' in user_input or 'javascript:' in user_input or 'onerror=' in user_input:
        xss_detected = True
        challenge = Challenge.query.filter_by(name='Basic Reflected XSS').first()
        if challenge and challenge.id not in completed_ids:
            update_user_progress(user.id, challenge.id, challenge.points)
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    challenge = Challenge.query.filter_by(name='Basic Reflected XSS').first()
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level1.html', user_input=user_input, flag=flag, xss_detected=xss_detected, challenge=challenge)

@xss_bp.route('/xss/level2')
@login_required
def xss_level2():
    flag = None
    xss_detected = False
    user = get_current_user()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name='DOM-based XSS').first()
        if challenge and challenge.id not in completed_ids:
            update_user_progress(user.id, challenge.id, challenge.points)
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    challenge = Challenge.query.filter_by(name='DOM-based XSS').first()
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'xss_detected': xss_detected, 'flag': flag, 'message': 'Challenge completed successfully!'})
    return render_template('xss/xss_level2.html', flag=flag, xss_detected=xss_detected, challenge=challenge)

@xss_bp.route('/xss/level3', methods=['GET', 'POST'])
@login_required
def xss_level3():
    user = get_current_user()
    flag = None
    xss_detected = False
    if request.method == 'POST':
        username = user.display_name
        content = request.form.get('content', '')
        if '<script>' in content or 'javascript:' in content or 'onerror=' in content:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='Stored XSS').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
        new_comment = Comment(username=username, content=content, level=3, user_id=user.id)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('xss_level3'))
    comments = Comment.query.filter_by(level=3).order_by(Comment.timestamp.desc()).all()
    challenge = Challenge.query.filter_by(name='Stored XSS').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level3.html', comments=comments, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

@xss_bp.route('/xss/level4', methods=['GET', 'POST'])
@login_required
def xss_level4():
    user = get_current_user()
    message = ''
    filtered_input = ''
    waf_blocked = False
    flag = None
    xss_detected = False
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        filtered_input = WAF.basic_filter(user_input)
        message = 'Your input has been filtered for security!'
        if '<img' in user_input and 'onerror=' in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS with Basic Filters').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    challenge = Challenge.query.filter_by(name='XSS with Basic Filters').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level4.html', message=message, filtered_input=filtered_input, waf_blocked=waf_blocked, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

@xss_bp.route('/xss/level5', methods=['GET', 'POST'])
@login_required
def xss_level5():
    user = get_current_user()
    message = ''
    filtered_input = ''
    waf_blocked = False
    flag = None
    xss_detected = False
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        filtered_input = WAF.advanced_filter(user_input)
        message = 'Your input has been filtered with our advanced security system!'
        if '<svg' in user_input and 'onload=' in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS with Advanced Filters').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    challenge = Challenge.query.filter_by(name='XSS with Advanced Filters').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level5.html', message=message, filtered_input=filtered_input, waf_blocked=waf_blocked, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

@xss_bp.route('/xss/level6', methods=['GET', 'POST'])
@login_required
def xss_level6():
    user = get_current_user()
    message = ''
    filtered_input = ''
    waf_blocked = False
    flag = None
    xss_detected = False
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        filtered_input, waf_blocked = WAF.modsecurity_emulation(user_input)
        if waf_blocked:
            message = '⚠️ WAF Alert: Potential XSS attack detected and blocked!'
        else:
            message = 'Input passed security checks.'
            if '<iframe' in user_input and 'srcdoc=' in user_input:
                xss_detected = True
                challenge = Challenge.query.filter_by(name='XSS with ModSecurity WAF').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    challenge = Challenge.query.filter_by(name='XSS with ModSecurity WAF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level6.html', message=message, filtered_input=filtered_input, waf_blocked=waf_blocked, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

@xss_bp.route('/xss/level7', methods=['GET'])
@login_required
def xss_level7():
    user = get_current_user()
    flag = None
    xss_detected = False
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    random_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    if '<script>' in user_agent or 'javascript:' in user_agent or 'onerror=' in user_agent:
        xss_detected = True
        challenge = Challenge.query.filter_by(name='XSS via HTTP Headers').first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
    challenge = Challenge.query.filter_by(name='XSS via HTTP Headers').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level7.html', client_ip=client_ip, user_agent=user_agent, random_id=random_id, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

@xss_bp.route('/xss/level8', methods=['GET'])
@login_required
def xss_level8():
    user = get_current_user()
    flag = None
    xss_detected = False
    if request.args.get('xss') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name='XSS in JSON API').first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
    challenge = Challenge.query.filter_by(name='XSS in JSON API').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level8.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

@xss_bp.route('/xss/level9', methods=['GET', 'POST'])
@login_required
def xss_level9():
    user = get_current_user()
    user_comment = ''
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_comment = request.form.get('comment', '')
        if 'alert("XSS Level 9 Completed!")' in user_comment or "alert('XSS Level 9 Completed!')" in user_comment:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS with CSP Bypass').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Try to bypass the CSP and trigger the alert as described.'
    challenge = Challenge.query.filter_by(name='XSS with CSP Bypass').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    response = make_response(render_template('xss/xss_level9.html', user_comment=user_comment, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message))
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' https://via.placeholder.com data:;"
    if message:
        response.set_cookie('message', message)
    return response

@xss_bp.route('/xss/level10', methods=['GET', 'POST'])
@login_required
def xss_level10():
    user = get_current_user()
    user_message = ''
    flag = None
    xss_detected = False
    message = ''
    chat_messages = [{'user': 'System', 'message': 'Welcome to SafeChat! This is a secure messaging platform.', 'time': '10:00 AM'}, {'user': 'Admin', 'message': 'Please be aware that we sanitize all messages to prevent XSS attacks.', 'time': '10:05 AM'}, {'user': 'User123', 'message': "I tried to use <script>alert('test')</script> but it didn't work!", 'time': '10:10 AM'}, {'user': 'Admin', 'message': "That's right! Our Mutation Observer technology removes malicious code instantly.", 'time': '10:15 AM'}]
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name='XSS with Mutation Observer Bypass').first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
        message = 'Challenge solved! Flag revealed.'
    if request.method == 'POST':
        user_message = request.form.get('message', '')
        if 'alert("XSS Level 10 Completed!")' in user_message or "alert('XSS Level 10 Completed!')" in user_message:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS with Mutation Observer Bypass').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
            chat_messages.append({'user': user.display_name if user else 'Guest', 'message': user_message, 'time': datetime.now().strftime('%I:%M %p')})
        else:
            message = 'Try to bypass the mutation observer and trigger the alert as described.'
            chat_messages.append({'user': user.display_name if user else 'Guest', 'message': user_message, 'time': datetime.now().strftime('%I:%M %p')})
    challenge = Challenge.query.filter_by(name='XSS with Mutation Observer Bypass').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level10.html', user_message=user_message, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message, chat_messages=chat_messages)

@xss_bp.route('/xss/level11', methods=['GET', 'POST'])
@login_required
def xss_level11():
    user = get_current_user()
    svg_code = '<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"></svg>'
    filtered_svg = ''
    flag = None
    xss_detected = False
    message = ''
    example_svgs = {'circle': '<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"><circle cx="100" cy="100" r="50" fill="blue" /></svg>', 'rectangle': '<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"><rect x="50" y="50" width="100" height="100" fill="green" /></svg>', 'text': '<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"><text x="50" y="100" font-family="Arial" font-size="20" fill="red">Hello SVG</text></svg>'}
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name='XSS via SVG and CDATA').first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
        message = 'Challenge solved! Flag revealed.'
    if request.method == 'POST':
        svg_code = request.form.get('svg_code', '')
        filtered_svg = svg_code
        filtered_svg = re.sub('<script[^>]*>.*?</script>', '', filtered_svg, flags=re.DOTALL)
        filtered_svg = re.sub('\\son\\w+=["\\\'][^"\\\'>]*["\\\']', '', filtered_svg)
        filtered_svg = re.sub('\\s(?:href|xlink:href|src)=["\\\']javascript:[^"\\\'>]*["\\\']', '', filtered_svg)
        if ('alert("XSS Level 11 Completed!")' in svg_code or "alert('XSS Level 11 Completed!')" in svg_code) and '<svg' in svg_code:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS via SVG and CDATA').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
    challenge = Challenge.query.filter_by(name='XSS via SVG and CDATA').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level11.html', svg_code=svg_code, filtered_svg=filtered_svg, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message, example_svgs=example_svgs)

@xss_bp.route('/xss/level12', methods=['GET', 'POST'])
@login_required
def xss_level12():
    user = get_current_user()
    ticket_submitted = False
    ticket_id = None
    ticket_subject = None
    ticket_description = None
    flag = None
    xss_detected = False
    message = ''
    webhook_url = ''
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name='Blind XSS with Webhook Exfiltration').first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
        message = 'Challenge solved! Flag revealed.'
    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        subject = request.form.get('subject', '')
        category = request.form.get('category', '')
        description = request.form.get('description', '')
        webhook_url = request.form.get('webhook_url', '')
        ticket_id = 'TKT-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        ticket_subject = subject
        ticket_description = description
        ticket_submitted = True
        if ('<script>' in description or 'javascript:' in description or 'onerror=' in description) and webhook_url:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='Blind XSS with Webhook Exfiltration').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Your XSS payload was executed in the admin panel and the data was exfiltrated to your webhook.'
    challenge = Challenge.query.filter_by(name='Blind XSS with Webhook Exfiltration').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level12.html', ticket_submitted=ticket_submitted, ticket_id=ticket_id, ticket_subject=ticket_subject, ticket_description=ticket_description, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message, webhook_url=webhook_url)

@xss_bp.route('/xss/level13', methods=['GET', 'POST'])
@login_required
def xss_level13():
    user = get_current_user()
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
        resume_name = request.form.get('name', '')
        resume_email = request.form.get('email', '')
        resume_phone = request.form.get('phone', '')
        resume_summary = request.form.get('summary', '')
        resume_skills = request.form.get('skills', '')
        resume_experience = request.form.get('experience', '')
        pdf_generated = True
        if 'app.alert' in resume_summary or 'app.alert' in resume_skills or 'app.alert' in resume_experience:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS in PDF Generation').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
    challenge = Challenge.query.filter_by(name='XSS in PDF Generation').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level13.html', pdf_generated=pdf_generated, resume_name=resume_name, resume_email=resume_email, resume_phone=resume_phone, resume_summary=resume_summary, resume_skills=resume_skills, resume_experience=resume_experience, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge)

@xss_bp.route('/xss/level14', methods=['GET', 'POST'])
@login_required
def xss_level14():
    user = get_current_user()
    config_saved = False
    config_name = None
    config_json = None
    flag = None
    xss_detected = False
    message = ''
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name='XSS via Prototype Pollution').first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
        message = 'Challenge solved! Flag revealed.'
    if request.method == 'POST':
        config_name = request.form.get('config_name', '')
        config_json = request.form.get('config_json', '')
        config_saved = True
        if '__proto__' in config_json and ('innerHTML' in config_json or 'outerHTML' in config_json or 'alert' in config_json):
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS via Prototype Pollution').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Try to use prototype pollution to trigger the alert as described.'
    challenge = Challenge.query.filter_by(name='XSS via Prototype Pollution').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level14.html', config_saved=config_saved, config_name=config_name, config_json=config_json, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

@xss_bp.route('/xss/level15', methods=['GET', 'POST'])
@login_required
def xss_level15():
    user = get_current_user()
    template_saved = False
    template_name = None
    template_subject = None
    template_content = None
    rendered_template = None
    flag = None
    xss_detected = False
    message = ''
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name='XSS via Template Injection').first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
        message = 'Challenge solved! Flag revealed.'
    current_date = datetime.now().strftime('%B %d, %Y')
    if request.method == 'POST':
        template_name = request.form.get('template_name', '')
        template_subject = request.form.get('template_subject', '')
        template_content = request.form.get('template_content', '')
        template_saved = True
        if 'constructor.constructor' in template_content or 'eval(' in template_content or 'alert("XSS Level 15 Completed!")' in template_content or ("alert('XSS Level 15 Completed!')" in template_content):
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS via Template Injection').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Template saved, but no XSS detected. Try using template injection to trigger the alert.'
    challenge = Challenge.query.filter_by(name='XSS via Template Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level15.html', template_saved=template_saved, template_name=template_name, template_subject=template_subject, template_content=template_content, rendered_template=rendered_template, current_date=current_date, flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

@xss_bp.route('/xss/level16', methods=['GET', 'POST'])
@login_required
def xss_level16():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name='XSS in WebAssembly Applications').first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
        message = 'Challenge solved! Flag revealed.'
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 16 Completed!")' in user_input or "alert('XSS Level 16 Completed!')" in user_input or any((p in user_input.lower() for p in ['<script>', '<img', '<svg', '<iframe', 'javascript:', 'onerror=', 'onload=', 'alert(', 'eval(', 'document.cookie', 'document.write', 'innerhtml'])):
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS in WebAssembly Applications').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Try to trigger the alert as described.'
    challenge = Challenge.query.filter_by(name='XSS in WebAssembly Applications').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level16.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

@xss_bp.route('/xss/level17', methods=['GET', 'POST'])
@login_required
def xss_level17():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.args.get('success') == 'true':
        xss_detected = True
        challenge = Challenge.query.filter_by(name='XSS in Progressive Web Apps').first()
        if challenge:
            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
            if challenge.id not in completed_ids:
                update_user_progress(user.id, challenge.id, challenge.points)
        message = 'Challenge solved! Flag revealed.'
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        manifest_json = request.form.get('manifest', '')
        service_worker_js = request.form.get('service_worker', '')
        if 'alert("XSS Level 17 Completed!")' in user_input or "alert('XSS Level 17 Completed!')" in user_input or any((p in user_input.lower() for p in ['<script>', '<img', '<svg', '<iframe', 'javascript:', 'onerror=', 'onload=', 'alert(', 'eval(', 'document.cookie', 'document.write', 'innerhtml'])) or ('alert("XSS Level 17 Completed!")' in manifest_json) or ("alert('XSS Level 17 Completed!')" in manifest_json) or ('alert("XSS Level 17 Completed!")' in service_worker_js) or ("alert('XSS Level 17 Completed!')" in service_worker_js) or any((p in user_input.lower() for p in ['<script>', '<img', '<svg', '<iframe', 'javascript:', 'onerror=', 'onload=', 'alert(', 'eval(', 'document.cookie'])) or any((p in manifest_json.lower() for p in ['<script>', '<img', 'javascript:', 'onerror=', 'alert('])) or any((p in service_worker_js.lower() for p in ['<script>', '<img', 'javascript:', 'onerror=', 'alert('])):
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS in Progressive Web Apps').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Try to trigger the alert as described. Look for vulnerabilities in the PWA components.'
    challenge = Challenge.query.filter_by(name='XSS in Progressive Web Apps').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level17.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

@xss_bp.route('/xss/level18', methods=['GET', 'POST'])
@login_required
def xss_level18():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 18 Completed!")' in user_input or "alert('XSS Level 18 Completed!')" in user_input or any((p in user_input.lower() for p in ['<script>', '<img', '<svg', '<iframe', 'javascript:', 'onerror=', 'onload=', 'alert(', 'eval(', 'document.cookie', 'document.write', 'innerhtml'])):
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS via Web Components').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Try to trigger the alert as described.'
    challenge = Challenge.query.filter_by(name='XSS via Web Components').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level18.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

@xss_bp.route('/xss/level19', methods=['GET', 'POST'])
@login_required
def xss_level19():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 19 Completed!")' in user_input or "alert('XSS Level 19 Completed!')" in user_input or any((p in user_input.lower() for p in ['<script>', '<img', '<svg', '<iframe', 'javascript:', 'onerror=', 'onload=', 'alert(', 'eval(', 'document.cookie', 'document.write', 'innerhtml'])):
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS in GraphQL APIs').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Try to trigger the alert as described.'
    challenge = Challenge.query.filter_by(name='XSS in GraphQL APIs').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level19.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

@xss_bp.route('/xss/level20', methods=['GET', 'POST'])
@login_required
def xss_level20():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 20 Completed!")' in user_input or "alert('XSS Level 20 Completed!')" in user_input or any((p in user_input.lower() for p in ['<script>', '<img', '<svg', '<iframe', 'javascript:', 'onerror=', 'onload=', 'alert(', 'eval(', 'document.cookie', 'document.write', 'innerhtml'])):
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS in WebRTC Applications').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Try to trigger the alert as described.'
    challenge = Challenge.query.filter_by(name='XSS in WebRTC Applications').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level20.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

@xss_bp.route('/xss/level21', methods=['GET', 'POST'])
@login_required
def xss_level21():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 21 Completed!")' in user_input or "alert('XSS Level 21 Completed!')" in user_input or any((p in user_input.lower() for p in ['<script>', '<img', '<svg', '<iframe', 'javascript:', 'onerror=', 'onload=', 'alert(', 'eval(', 'document.cookie', 'document.write', 'innerhtml'])):
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS via Web Bluetooth/USB').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Try to trigger the alert as described.'
    challenge = Challenge.query.filter_by(name='XSS via Web Bluetooth/USB').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level21.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

@xss_bp.route('/xss/level22', methods=['GET', 'POST'])
@login_required
def xss_level22():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 22 Completed!")' in user_input or "alert('XSS Level 22 Completed!')" in user_input or any((p in user_input.lower() for p in ['<script>', '<img', '<svg', '<iframe', 'javascript:', 'onerror=', 'onload=', 'alert(', 'eval(', 'document.cookie', 'document.write', 'innerhtml'])):
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS in WebGPU Applications').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Try to trigger the alert as described.'
    challenge = Challenge.query.filter_by(name='XSS in WebGPU Applications').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level22.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

@xss_bp.route('/xss/level23', methods=['GET', 'POST'])
@login_required
def xss_level23():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'alert("XSS Level 23 Completed!")' in user_input or "alert('XSS Level 23 Completed!')" in user_input or any((p in user_input.lower() for p in ['<script>', '<img', '<svg', '<iframe', 'javascript:', 'onerror=', 'onload=', 'alert(', 'eval(', 'document.cookie', 'document.write', 'innerhtml'])):
            xss_detected = True
            challenge = Challenge.query.filter_by(name='XSS in Federated Identity Systems').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Try to trigger the alert as described.'
    challenge = Challenge.query.filter_by(name='XSS in Federated Identity Systems').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level23.html', flag=flag, user=user, xss_detected=xss_detected, challenge=challenge, message=message)

@xss_bp.route('/xss/level24', methods=['GET', 'POST'])
@login_required
def xss_level24():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'id="config"' in user_input or "id='config'" in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='DOM Clobbering').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Try to clobber the window.config object.'
    challenge = Challenge.query.filter_by(name='DOM Clobbering').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level24.html', flag=flag, user=user, xss_detected=xss_detected, message=message)

@xss_bp.route('/xss/level25', methods=['GET', 'POST'])
@login_required
def xss_level25():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if "<img src='" in user_input and "'>" not in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='Dangling Markup Injection').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Try to exfiltrate data using dangling markup.'
    challenge = Challenge.query.filter_by(name='Dangling Markup Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level25.html', flag=flag, user=user, xss_detected=xss_detected, message=message)

@xss_bp.route('/xss/level26', methods=['GET', 'POST'])
@login_required
def xss_level26():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'javascript:' in user_input and '//' in user_input and ('<' in user_input):
            xss_detected = True
            challenge = Challenge.query.filter_by(name='Polyglot XSS').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Create a payload valid in HTML, JS dictionary, and URL contexts.'
    challenge = Challenge.query.filter_by(name='Polyglot XSS').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level26.html', flag=flag, user=user, xss_detected=xss_detected, message=message)

@xss_bp.route('/xss/level27', methods=['GET', 'POST'])
@login_required
def xss_level27():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'x-html' in user_input or 'x-on:click' in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='Client-Side Template Injection').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Inject Alpine.js directives.'
    challenge = Challenge.query.filter_by(name='Client-Side Template Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level27.html', flag=flag, user=user, xss_detected=xss_detected, message=message)

@xss_bp.route('/xss/level28', methods=['GET', 'POST'])
@login_required
def xss_level28():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'type="importmap"' in user_input or "type='importmap'" in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='Import Map Injection').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Inject or manipulate an import map.'
    challenge = Challenge.query.filter_by(name='Import Map Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level28.html', flag=flag, user=user, xss_detected=xss_detected, message=message)

@xss_bp.route('/xss/level29', methods=['GET', 'POST'])
@login_required
def xss_level29():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if '"type":"update"' in user_input and 'modules' in user_input:
            xss_detected = True
            challenge = Challenge.query.filter_by(name='HMR Injection').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Simulate a malicious HMR update.'
    challenge = Challenge.query.filter_by(name='HMR Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level29.html', flag=flag, user=user, xss_detected=xss_detected, message=message)

@xss_bp.route('/xss/level30', methods=['GET', 'POST'])
@login_required
def xss_level30():
    user = get_current_user()
    flag = None
    xss_detected = False
    message = ''
    if request.method == 'POST':
        user_input = request.form.get('input', '')
        if 'ignore previous' in user_input.lower() and '<script>' in user_input.lower():
            xss_detected = True
            challenge = Challenge.query.filter_by(name='Indirect Prompt Injection').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            message = 'Challenge solved! Flag revealed.'
        else:
            message = 'Trick the AI into generating XSS.'
    challenge = Challenge.query.filter_by(name='Indirect Prompt Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xss/xss_level30.html', flag=flag, user=user, xss_detected=xss_detected, message=message)

