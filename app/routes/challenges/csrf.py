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

csrf_bp = Blueprint('csrf', __name__)

@csrf_bp.route('/csrf/level1', methods=['GET', 'POST'])
@login_required
def csrf_level1():
    user = get_current_user()
    flag = None
    csrf_detected = False
    recipient = request.form.get('recipient', '')
    amount = request.form.get('amount', '')
    memo = request.form.get('memo', '')
    transfer_result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if recipient and amount:
            csrf_token = request.form.get('csrf_token', '')
            if not csrf_token or len(csrf_token) < 10:
                csrf_detected = True
                transfer_result = f'Transfer Request Processed:\nFrom: John Doe (Account: 1234567890)\nTo: {recipient}\nAmount: ${amount}\nMemo: {memo}\n\nTransaction Details:\n- Transaction ID: TXN_{user.username[:8]}\n- Status: COMPLETED\n- Timestamp: 2024-01-15 14:30:25\n- Method: Online Banking Transfer\n\nSecurity Notice:\nNo CSRF protection detected on this form.\nThis transfer was executed without any cross-site request forgery protection.\n\nBank Response:\n{{\n  "status": "success",\n  "transaction_id": "TXN_{user.username[:8]}",\n  "amount_transferred": "{amount}",\n  "recipient_account": "{recipient}",\n  "remaining_balance": "$4,{(5000 - int(amount) if amount.isdigit() else 5000)}",\n  "csrf_vulnerability": "detected"\n}}'
                challenge = Challenge.query.filter_by(name='Basic Form CSRF').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                transfer_result = f'Transfer Request:\nFrom: John Doe (Account: 1234567890)\nTo: {recipient}\nAmount: ${amount}\nMemo: {memo}\n\nStatus: Processing...\nPlease wait while we verify the transaction details.'
    challenge = Challenge.query.filter_by(name='Basic Form CSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level1.html', flag=flag, csrf_detected=csrf_detected, recipient=recipient, amount=amount, memo=memo, transfer_result=transfer_result, challenge=challenge)

@csrf_bp.route('/csrf/level2', methods=['GET', 'POST'])
@login_required
def csrf_level2():
    user = get_current_user()
    flag = None
    csrf_detected = False
    action = request.args.get('action', '')
    user_id = request.args.get('user_id', '')
    action_result = ''
    if action and user_id:
        csrf_actions = ['delete', 'promote', 'demote']
        if action in csrf_actions and user_id:
            csrf_detected = True
            action_result = f'''Administrative Action Executed:\nAction: {action.upper()}\nTarget User ID: {user_id}\nExecuted By: System Administrator\nTimestamp: 2024-01-15 14:35:10\n\nAction Details:\n- HTTP Method: GET (Vulnerable to CSRF)\n- Referrer: {request.headers.get('Referer', 'Not provided')}\n- User Agent: {request.headers.get('User-Agent', 'Unknown')}\n\nAdmin Panel Response:\n{{\n  "action": "{action}",\n  "target_user_id": "{user_id}",\n  "status": "completed",\n  "vulnerability": "GET-based state change",\n  "impact": "Administrative action performed via CSRF",\n}}\n\nSecurity Warning:\nThis action was performed using a GET request, making it vulnerable to CSRF attacks.\nState-changing operations should never use GET requests.'''
            challenge = Challenge.query.filter_by(name='GET-based CSRF').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
    challenge = Challenge.query.filter_by(name='GET-based CSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level2.html', flag=flag, csrf_detected=csrf_detected, action=action, user_id=user_id, action_result=action_result, challenge=challenge)

@csrf_bp.route('/csrf/level3', methods=['GET', 'POST'])
@login_required
def csrf_level3():
    user = get_current_user()
    flag = None
    csrf_detected = False
    api_endpoint = request.form.get('api_endpoint', '')
    json_payload = request.form.get('json_payload', '')
    content_type = request.form.get('content_type', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if api_endpoint and json_payload:
            csrf_patterns = ['create', 'delete', 'admin', 'user', 'malicious']
            if any((pattern in json_payload.lower() or pattern in api_endpoint.lower() for pattern in csrf_patterns)):
                csrf_detected = True
                result = f'JSON API Request Processed:\nEndpoint: {api_endpoint}\nContent-Type: {content_type}\nPayload: {json_payload}\n\nAPI Response:\n{{\n  "request_method": "POST",\n  "content_type": "{content_type}",\n  "endpoint": "{api_endpoint}",\n  "payload_received": {json_payload},\n  "csrf_protection": "none",\n  "vulnerability": "JSON CSRF without proper validation",\n  "execution_status": "success",\n}}\n\nSecurity Analysis:\n- Content-Type manipulation successful\n- JSON payload executed without CSRF token validation\n- API endpoint vulnerable to cross-origin requests'
                challenge = Challenge.query.filter_by(name='JSON CSRF').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'JSON API Request:\nEndpoint: {api_endpoint}\nContent-Type: {content_type}\nPayload: {json_payload}\n\nStatus: Validating request...\nPlease ensure your JSON payload contains valid API operations.'
    challenge = Challenge.query.filter_by(name='JSON CSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level3.html', flag=flag, csrf_detected=csrf_detected, api_endpoint=api_endpoint, json_payload=json_payload, content_type=content_type, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level4', methods=['GET', 'POST'])
@login_required
def csrf_level4():
    user = get_current_user()
    flag = None
    csrf_detected = False
    file_category = request.form.get('file_category', '')
    file_description = request.form.get('file_description', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if 'upload_file' in request.files:
            file = request.files['upload_file']
            if file and file.filename:
                csrf_patterns = ['malicious', 'shell', 'backdoor', 'exploit', 'payload']
                if any((pattern in file.filename.lower() or pattern in file_description.lower() for pattern in csrf_patterns)):
                    csrf_detected = True
                    result = f'File Upload Processed:\nFilename: {file.filename}\nCategory: {file_category}\nDescription: {file_description}\nSize: {(len(file.read()) if file else 0)} bytes\n\nUpload Response:\n{{\n  "upload_status": "success",\n  "filename": "{file.filename}",\n  "category": "{file_category}",\n  "description": "{file_description}",\n  "upload_path": "/uploads/documents/{file.filename}",\n  "csrf_protection": "none",\n  "vulnerability": "File upload CSRF without validation",\n  "security_risk": "Malicious file uploaded via CSRF",\n}}\n\nSecurity Warning:\nFile upload completed without CSRF protection.\nThis could allow attackers to upload malicious files via cross-site requests.'
                    challenge = Challenge.query.filter_by(name='File Upload CSRF').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                else:
                    result = f'File Upload Request:\nFilename: {file.filename}\nCategory: {file_category}\nDescription: {file_description}\n\nStatus: Processing upload...\nPlease wait while we validate the file.'
    challenge = Challenge.query.filter_by(name='File Upload CSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level4.html', flag=flag, csrf_detected=csrf_detected, file_category=file_category, file_description=file_description, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level5', methods=['GET', 'POST'])
@login_required
def csrf_level5():
    user = get_current_user()
    flag = None
    csrf_detected = False
    csrf_token = request.form.get('csrf_token', '')
    form_data = request.form.get('form_data', '')
    submit_action = request.form.get('submit_action', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if csrf_token and form_data and submit_action:
            weak_tokens = ['123456', 'token', 'csrf', 'weak', 'predictable', '000000']
            if any((weak in csrf_token.lower() for weak in weak_tokens)) or len(csrf_token) < 10:
                csrf_detected = True
                result = f'Form Submission Processed:\nCSRF Token: {csrf_token}\nForm Data: {form_data}\nAction: {submit_action}\n\nToken Validation Result:\n{{\n  "token_provided": "{csrf_token}",\n  "token_validation": "bypassed",\n  "token_weakness": "predictable/weak token detected",\n  "form_data": "{form_data}",\n  "action_executed": "{submit_action}",\n  "vulnerability": "Weak CSRF token implementation",\n  "bypass_method": "Token prediction/brute force",\n}}\n\nSecurity Analysis:\n- CSRF token is weak and predictable\n- Token validation can be bypassed\n- Form submission executed despite weak protection'
                challenge = Challenge.query.filter_by(name='CSRF with Weak Tokens').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'Form Submission:\nCSRF Token: {csrf_token}\nForm Data: {form_data}\nAction: {submit_action}\n\nStatus: Validating CSRF token...\nPlease ensure you have a valid token.'
    challenge = Challenge.query.filter_by(name='CSRF with Weak Tokens').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level5.html', flag=flag, csrf_detected=csrf_detected, csrf_token=csrf_token, form_data=form_data, submit_action=submit_action, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level6', methods=['GET', 'POST'])
@login_required
def csrf_level6():
    user = get_current_user()
    flag = None
    csrf_detected = False
    referrer_url = request.form.get('referrer_url', '')
    target_action = request.form.get('target_action', '')
    payload_data = request.form.get('payload_data', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if referrer_url and target_action:
            bypass_patterns = ['trusted-domain', 'internal', 'admin', 'secure']
            actual_referrer = request.headers.get('Referer', '')
            if any((pattern in referrer_url.lower() for pattern in bypass_patterns)) or not actual_referrer:
                csrf_detected = True
                result = f'''Referrer-based Protection Bypass:\nProvided Referrer: {referrer_url}\nActual Referrer: {actual_referrer or 'None (bypassed)'}\nTarget Action: {target_action}\nPayload Data: {payload_data}\n\nSecurity Analysis:\n{{\n  "referrer_validation": "bypassed",\n  "provided_referrer": "{referrer_url}",\n  "actual_referrer": "{actual_referrer or 'missing'}",\n  "target_action": "{target_action}",\n  "payload_data": "{payload_data}",\n  "bypass_method": "referrer_spoofing_or_removal",\n  "vulnerability": "Weak referrer-based CSRF protection",\n  "execution_status": "success",\n}}\n\nProtection Bypass Details:\n- Referrer header validation circumvented\n- Action executed despite referrer-based protection\n- Demonstrates weakness of referrer-only CSRF protection'''
                challenge = Challenge.query.filter_by(name='Referrer-based Protection Bypass').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'Referrer Validation:\nProvided Referrer: {referrer_url}\nActual Referrer: {actual_referrer}\nTarget Action: {target_action}\n\nStatus: Referrer validation failed.\nPlease provide a trusted referrer URL.'
    challenge = Challenge.query.filter_by(name='Referrer-based Protection Bypass').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level6.html', flag=flag, csrf_detected=csrf_detected, referrer_url=referrer_url, target_action=target_action, payload_data=payload_data, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level7', methods=['GET', 'POST'])
@login_required
def csrf_level7():
    user = get_current_user()
    flag = None
    csrf_detected = False
    ajax_endpoint = request.form.get('ajax_endpoint', '')
    request_method = request.form.get('request_method', '')
    ajax_data = request.form.get('ajax_data', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if ajax_endpoint and request_method and ajax_data:
            csrf_patterns = ['api', 'admin', 'delete', 'update', 'create']
            ajax_headers = request.headers.get('X-Requested-With', '')
            if any((pattern in ajax_endpoint.lower() or pattern in ajax_data.lower() for pattern in csrf_patterns)):
                csrf_detected = True
                result = f'''AJAX CSRF Attack Executed:\nEndpoint: {ajax_endpoint}\nMethod: {request_method}\nData: {ajax_data}\nX-Requested-With: {ajax_headers or 'Not provided'}\n\nAJAX Response:\n{{\n  "endpoint": "{ajax_endpoint}",\n  "method": "{request_method}",\n  "data_received": "{ajax_data}",\n  "x_requested_with": "{ajax_headers or 'missing'}",\n  "csrf_protection": "insufficient",\n  "vulnerability": "AJAX CSRF without proper validation",\n  "content_type": "{request.content_type}",\n  "origin": "{request.headers.get('Origin', 'not_provided')}",\n  "execution_status": "success",\n}}\n\nAJAX Security Analysis:\n- XMLHttpRequest/fetch API CSRF successful\n- Custom headers can be bypassed with simple requests\n- CORS preflight not triggered for simple content types\n- Modern SPA applications vulnerable to CSRF'''
                challenge = Challenge.query.filter_by(name='CSRF in AJAX Requests').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'AJAX Request:\nEndpoint: {ajax_endpoint}\nMethod: {request_method}\nData: {ajax_data}\n\nStatus: Processing AJAX request...\nPlease ensure valid API endpoint and data.'
    challenge = Challenge.query.filter_by(name='CSRF in AJAX Requests').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level7.html', flag=flag, csrf_detected=csrf_detected, ajax_endpoint=ajax_endpoint, request_method=request_method, ajax_data=ajax_data, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level8', methods=['GET', 'POST'])
@login_required
def csrf_level8():
    user = get_current_user()
    flag = None
    csrf_detected = False
    samesite_mode = request.form.get('samesite_mode', '')
    navigation_type = request.form.get('navigation_type', '')
    csrf_payload = request.form.get('csrf_payload', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if samesite_mode and navigation_type and csrf_payload:
            bypass_conditions = [samesite_mode == 'Lax' and navigation_type == 'top_level', samesite_mode == 'None', 'bypass' in csrf_payload.lower() or 'samesite' in csrf_payload.lower()]
            if any(bypass_conditions):
                csrf_detected = True
                result = f'SameSite Cookie Bypass:\nSameSite Mode: {samesite_mode}\nNavigation Type: {navigation_type}\nCSRF Payload: {csrf_payload}\n\nCookie Analysis:\n{{\n  "samesite_attribute": "{samesite_mode}",\n  "navigation_context": "{navigation_type}",\n  "csrf_payload": "{csrf_payload}",\n  "bypass_successful": true,\n  "bypass_method": "samesite_lax_top_level_navigation",\n  "vulnerability": "SameSite=Lax bypass via top-level navigation",\n  "cookie_sent": true,\n  "authentication_bypassed": true,\n}}\n\nSameSite Bypass Techniques:\n- SameSite=Lax allows cookies on top-level navigation\n- SameSite=None requires Secure attribute\n- Popup windows and iframe techniques\n- Navigation-based CSRF attacks still possible'
                challenge = Challenge.query.filter_by(name='SameSite Cookie Bypass').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'SameSite Protection:\nSameSite Mode: {samesite_mode}\nNavigation Type: {navigation_type}\nCSRF Payload: {csrf_payload}\n\nStatus: SameSite protection active.\nCookies not sent due to SameSite restrictions.'
    challenge = Challenge.query.filter_by(name='SameSite Cookie Bypass').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level8.html', flag=flag, csrf_detected=csrf_detected, samesite_mode=samesite_mode, navigation_type=navigation_type, csrf_payload=csrf_payload, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level9', methods=['GET', 'POST'])
@login_required
def csrf_level9():
    user = get_current_user()
    flag = None
    csrf_detected = False
    custom_header = request.form.get('custom_header', '')
    header_value = request.form.get('header_value', '')
    api_action = request.form.get('api_action', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if custom_header and header_value and api_action:
            bypass_patterns = ['XMLHttpRequest', 'application/json', 'bypass', 'custom']
            actual_header = request.headers.get('X-Requested-With', '')
            if any((pattern in header_value for pattern in bypass_patterns)) or not actual_header:
                csrf_detected = True
                result = f'''Custom Header CSRF Bypass:\nExpected Header: {custom_header}\nExpected Value: {header_value}\nActual X-Requested-With: {actual_header or 'Not provided'}\nAPI Action: {api_action}\n\nHeader Bypass Analysis:\n{{\n  "expected_header": "{custom_header}",\n  "expected_value": "{header_value}",\n  "actual_header": "{actual_header or 'missing'}",\n  "api_action": "{api_action}",\n  "bypass_method": "custom_header_omission",\n  "vulnerability": "Custom header-based CSRF protection bypass",\n  "content_type": "{request.content_type}",\n  "simple_request": true,\n  "cors_preflight_avoided": true,\n  "execution_status": "success",\n}}\n\nCustom Header Protection Weaknesses:\n- Simple requests don't trigger CORS preflight\n- Custom headers can be omitted in CSRF attacks\n- Content-Type manipulation avoids preflight checks\n- Form-based requests bypass header requirements'''
                challenge = Challenge.query.filter_by(name='CSRF with Custom Headers').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'Custom Header Validation:\nExpected Header: {custom_header}\nExpected Value: {header_value}\nAPI Action: {api_action}\n\nStatus: Custom header validation failed.\nRequired headers not provided.'
    challenge = Challenge.query.filter_by(name='CSRF with Custom Headers').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level9.html', flag=flag, csrf_detected=csrf_detected, custom_header=custom_header, header_value=header_value, api_action=api_action, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level10', methods=['GET', 'POST'])
@login_required
def csrf_level10():
    user = get_current_user()
    flag = None
    csrf_detected = False
    step_number = request.form.get('step_number', '')
    step_data = request.form.get('step_data', '')
    workflow_id = request.form.get('workflow_id', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if step_number and step_data and workflow_id:
            attack_patterns = ['workflow', 'admin', 'delete', 'transfer', 'approve']
            if any((pattern in step_data.lower() or pattern in workflow_id.lower() for pattern in attack_patterns)):
                csrf_detected = True
                result = f'Multi-step CSRF Attack Chain:\nWorkflow Step: {step_number}/4\nStep Data: {step_data}\nWorkflow ID: {workflow_id}\n\nWorkflow Execution:\n{{\n  "workflow_id": "{workflow_id}",\n  "current_step": {step_number},\n  "total_steps": 4,\n  "step_data": "{step_data}",\n  "step_status": "completed",\n  "csrf_protection": "none",\n  "vulnerability": "Multi-step workflow CSRF",\n  "business_logic_bypass": true,\n  "workflow_state": {{\n    "step_1": "user_verification_bypassed",\n    "step_2": "approval_process_skipped",\n    "step_3": "security_checks_bypassed",\n    "step_4": "final_execution_ready"\n  }},\n  "execution_status": "success",\n}}\n\nMulti-step Attack Analysis:\n- Complex business workflows vulnerable to CSRF\n- Each step can be individually exploited\n- State management weaknesses exploited\n- Approval processes bypassed via CSRF chain'
                challenge = Challenge.query.filter_by(name='Multi-step CSRF').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'Workflow Processing:\nWorkflow Step: {step_number}/4\nStep Data: {step_data}\nWorkflow ID: {workflow_id}\n\nStatus: Processing workflow step...\nPlease ensure valid workflow data.'
    challenge = Challenge.query.filter_by(name='Multi-step CSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level10.html', flag=flag, csrf_detected=csrf_detected, step_number=step_number, step_data=step_data, workflow_id=workflow_id, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level11', methods=['GET', 'POST'])
@login_required
def csrf_level11():
    user = get_current_user()
    flag = None
    csrf_detected = False
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if current_password and new_password and confirm_password:
            csrf_patterns = ['admin', 'password123', 'hacker', 'pwned', 'bypass']
            if any((pattern in new_password.lower() for pattern in csrf_patterns)) or new_password == confirm_password:
                csrf_detected = True
                result = f'Password Change CSRF Attack:\nCurrent Password: {current_password}\nNew Password: {new_password}\nConfirm Password: {confirm_password}\n\nSecurity Breach Analysis:\n{{\n  "attack_type": "password_change_csrf",\n  "current_password": "{current_password}",\n  "new_password": "{new_password}",\n  "password_match": {str(new_password == confirm_password).lower()},\n  "csrf_protection": "none",\n  "vulnerability": "Critical password change without CSRF protection",\n  "account_compromised": true,\n  "session_hijacked": true,\n  "impact": "Complete account takeover possible",\n}}\n\nCritical Security Impact:\n- User password changed without authorization\n- Account takeover achieved via CSRF\n- No validation of password change origin\n- Session management bypassed'
                challenge = Challenge.query.filter_by(name='CSRF in Password Change').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'Password Change Request:\nCurrent Password: {current_password}\nNew Password: {new_password}\nConfirm Password: {confirm_password}\n\nStatus: Validating password change request...\nPlease ensure passwords match and meet security requirements.'
    challenge = Challenge.query.filter_by(name='CSRF in Password Change').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level11.html', flag=flag, csrf_detected=csrf_detected, current_password=current_password, new_password=new_password, confirm_password=confirm_password, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level12', methods=['GET', 'POST'])
@login_required
def csrf_level12():
    user = get_current_user()
    flag = None
    csrf_detected = False
    captcha_response = request.form.get('captcha_response', '')
    captcha_token = request.form.get('captcha_token', '')
    protected_action = request.form.get('protected_action', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if captcha_response and captcha_token and protected_action:
            bypass_patterns = ['bypass', 'automated', 'bot', 'script', '12345']
            if any((pattern in captcha_response.lower() or pattern in captcha_token.lower() for pattern in bypass_patterns)):
                csrf_detected = True
                result = f'CAPTCHA Bypass CSRF Attack:\nCAPTCHA Response: {captcha_response}\nCAPTCHA Token: {captcha_token}\nProtected Action: {protected_action}\n\nCAPTCHA Bypass Analysis:\n{{\n  "captcha_response": "{captcha_response}",\n  "captcha_token": "{captcha_token}",\n  "protected_action": "{protected_action}",\n  "captcha_bypassed": true,\n  "bypass_method": "automated_solving_or_reuse",\n  "vulnerability": "CAPTCHA protection insufficient for CSRF",\n  "csrf_protection": "weak",\n  "automation_successful": true,\n}}\n\nCAPTCHA Bypass Techniques:\n- Token reuse from previous sessions\n- Automated CAPTCHA solving services\n- CAPTCHA sharing across requests\n- Time-based token prediction'
                challenge = Challenge.query.filter_by(name='CSRF with CAPTCHA Bypass').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'CAPTCHA Validation:\nCAPTCHA Response: {captcha_response}\nCAPTCHA Token: {captcha_token}\nProtected Action: {protected_action}\n\nStatus: Validating CAPTCHA response...\nPlease solve the CAPTCHA correctly.'
    challenge = Challenge.query.filter_by(name='CSRF with CAPTCHA Bypass').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level12.html', flag=flag, csrf_detected=csrf_detected, captcha_response=captcha_response, captcha_token=captcha_token, protected_action=protected_action, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level13', methods=['GET', 'POST'])
@login_required
def csrf_level13():
    user = get_current_user()
    flag = None
    csrf_detected = False
    origin_header = request.form.get('origin_header', '')
    cors_endpoint = request.form.get('cors_endpoint', '')
    credentials_mode = request.form.get('credentials_mode', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if origin_header and cors_endpoint and credentials_mode:
            cors_patterns = ['attacker.com', 'evil.com', 'malicious', 'cors', 'api']
            actual_origin = request.headers.get('Origin', '')
            if any((pattern in origin_header.lower() or pattern in cors_endpoint.lower() for pattern in cors_patterns)):
                csrf_detected = True
                result = f'''CORS Exploitation CSRF Attack:\nOrigin Header: {origin_header}\nCORS Endpoint: {cors_endpoint}\nCredentials Mode: {credentials_mode}\nActual Origin: {actual_origin or 'Not provided'}\n\nCORS Misconfiguration Exploit:\n{{\n  "origin_header": "{origin_header}",\n  "cors_endpoint": "{cors_endpoint}",\n  "credentials_mode": "{credentials_mode}",\n  "actual_origin": "{actual_origin or 'missing'}",\n  "cors_misconfigured": true,\n  "wildcard_origin": true,\n  "credentials_allowed": true,\n  "vulnerability": "CORS misconfiguration enables CSRF",\n  "cross_origin_request": "successful",\n}}\n\nCORS Exploitation Details:\n- Wildcard origin (*) with credentials\n- Cross-origin requests allowed\n- CSRF protection bypassed via CORS\n- Sensitive data accessible cross-origin'''
                challenge = Challenge.query.filter_by(name='CSRF with CORS Exploitation').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'CORS Request:\nOrigin Header: {origin_header}\nCORS Endpoint: {cors_endpoint}\nCredentials Mode: {credentials_mode}\n\nStatus: Processing CORS request...\nChecking origin validation.'
    challenge = Challenge.query.filter_by(name='CSRF with CORS Exploitation').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level13.html', flag=flag, csrf_detected=csrf_detected, origin_header=origin_header, cors_endpoint=cors_endpoint, credentials_mode=credentials_mode, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level14', methods=['GET', 'POST'])
@login_required
def csrf_level14():
    user = get_current_user()
    flag = None
    csrf_detected = False
    websocket_url = request.form.get('websocket_url', '')
    ws_protocol = request.form.get('ws_protocol', '')
    ws_message = request.form.get('ws_message', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if websocket_url and ws_protocol and ws_message:
            ws_patterns = ['ws://', 'wss://', 'chat', 'admin', 'delete', 'malicious']
            if any((pattern in websocket_url.lower() or pattern in ws_message.lower() for pattern in ws_patterns)):
                csrf_detected = True
                result = f'WebSocket CSRF Attack:\nWebSocket URL: {websocket_url}\nProtocol: {ws_protocol}\nMessage: {ws_message}\n\nWebSocket Security Analysis:\n{{\n  "websocket_url": "{websocket_url}",\n  "protocol": "{ws_protocol}",\n  "message_payload": "{ws_message}",\n  "origin_validation": "bypassed",\n  "csrf_protection": "none",\n  "vulnerability": "WebSocket CSRF without origin validation",\n  "real_time_exploit": true,\n  "connection_hijacked": true,\n}}\n\nWebSocket CSRF Techniques:\n- Origin header manipulation\n- Cross-origin WebSocket connections\n- Real-time message injection\n- Session hijacking via WebSocket'
                challenge = Challenge.query.filter_by(name='WebSocket CSRF').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'WebSocket Connection:\nWebSocket URL: {websocket_url}\nProtocol: {ws_protocol}\nMessage: {ws_message}\n\nStatus: Establishing WebSocket connection...\nValidating protocol and message format.'
    challenge = Challenge.query.filter_by(name='WebSocket CSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level14.html', flag=flag, csrf_detected=csrf_detected, websocket_url=websocket_url, ws_protocol=ws_protocol, ws_message=ws_message, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level15', methods=['GET', 'POST'])
@login_required
def csrf_level15():
    user = get_current_user()
    flag = None
    csrf_detected = False
    client_id = request.form.get('client_id', '')
    redirect_uri = request.form.get('redirect_uri', '')
    state_parameter = request.form.get('state_parameter', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if client_id and redirect_uri and state_parameter:
            oauth_patterns = ['attacker', 'malicious', 'bypass', 'oauth', 'redirect']
            if any((pattern in redirect_uri.lower() or pattern in state_parameter.lower() for pattern in oauth_patterns)):
                csrf_detected = True
                result = f'OAuth Flow CSRF Attack:\nClient ID: {client_id}\nRedirect URI: {redirect_uri}\nState Parameter: {state_parameter}\n\nOAuth Security Breach:\n{{\n  "client_id": "{client_id}",\n  "redirect_uri": "{redirect_uri}",\n  "state_parameter": "{state_parameter}",\n  "state_validation": "bypassed",\n  "csrf_protection": "insufficient",\n  "vulnerability": "OAuth state parameter CSRF",\n  "authorization_hijacked": true,\n  "account_linking_attack": true,\n}}\n\nOAuth CSRF Attack Details:\n- State parameter manipulation\n- Authorization code interception\n- Account linking attacks\n- Cross-site authorization'
                challenge = Challenge.query.filter_by(name='CSRF in OAuth Flows').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'OAuth Authorization:\nClient ID: {client_id}\nRedirect URI: {redirect_uri}\nState Parameter: {state_parameter}\n\nStatus: Processing OAuth authorization...\nValidating client and redirect URI.'
    challenge = Challenge.query.filter_by(name='CSRF in OAuth Flows').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level15.html', flag=flag, csrf_detected=csrf_detected, client_id=client_id, redirect_uri=redirect_uri, state_parameter=state_parameter, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level16', methods=['GET', 'POST'])
@login_required
def csrf_level16():
    user = get_current_user()
    flag = None
    csrf_detected = False
    csp_header = request.form.get('csp_header', '')
    payload_method = request.form.get('payload_method', '')
    bypass_technique = request.form.get('bypass_technique', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if csp_header and payload_method and bypass_technique:
            bypass_patterns = ['jsonp', 'angular', 'meta', 'base', 'iframe', 'form-action']
            if any((pattern in bypass_technique.lower() for pattern in bypass_patterns)):
                csrf_detected = True
                result = f'CSP Bypass CSRF Attack:\nCSP Header: {csp_header}\nPayload Method: {payload_method}\nBypass Technique: {bypass_technique}\n\nCSP Analysis:\n{{\n  "csp_header": "{csp_header}",\n  "payload_method": "{payload_method}",\n  "bypass_technique": "{bypass_technique}",\n  "bypass_successful": true,\n  "vulnerability": "CSP misconfiguration allows CSRF",\n  "attack_vector": "CSP bypass via {bypass_technique}",\n  "impact": "CSRF protection circumvented",\n}}\n\nSecurity Analysis:\n- Content Security Policy bypassed\n- CSRF attack executed despite CSP protection\n- Demonstrates importance of proper CSP configuration'
                challenge = Challenge.query.filter_by(name='CSRF with CSP Bypass').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'CSP Bypass Attempt:\nCSP Header: {csp_header}\nPayload Method: {payload_method}\nBypass Technique: {bypass_technique}\n\nStatus: CSP protection active.\nTry different bypass techniques.'
    challenge = Challenge.query.filter_by(name='CSRF with CSP Bypass').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level16.html', flag=flag, csrf_detected=csrf_detected, csp_header=csp_header, payload_method=payload_method, bypass_technique=bypass_technique, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level17', methods=['GET', 'POST'])
@login_required
def csrf_level17():
    user = get_current_user()
    flag = None
    csrf_detected = False
    xss_payload = request.form.get('xss_payload', '')
    csrf_action = request.form.get('csrf_action', '')
    target_endpoint = request.form.get('target_endpoint', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if xss_payload and csrf_action and target_endpoint:
            xss_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=', 'fetch(', 'XMLHttpRequest']
            csrf_patterns = ['transfer', 'delete', 'admin', 'password', 'email']
            has_xss = any((pattern in xss_payload.lower() for pattern in xss_patterns))
            has_csrf = any((pattern in csrf_action.lower() for pattern in csrf_patterns))
            if has_xss and has_csrf:
                csrf_detected = True
                result = f'''XSS + CSRF Chain Attack:\nXSS Payload: {xss_payload}\nCSRF Action: {csrf_action}\nTarget Endpoint: {target_endpoint}\n\nAttack Chain Analysis:\n{{\n  "xss_payload": "{xss_payload}",\n  "csrf_action": "{csrf_action}",\n  "target_endpoint": "{target_endpoint}",\n  "attack_successful": true,\n  "vulnerability": "XSS enables CSRF bypass",\n  "attack_vector": "Stored/Reflected XSS + CSRF",\n  "impact": "Complete account takeover possible",\n}}\n\nSecurity Analysis:\n- XSS vulnerability exploited to bypass CSRF protection\n- JavaScript executed in victim's browser context\n- CSRF tokens extracted and reused automatically\n- Demonstrates why XSS is critical for modern CSRF attacks'''
                challenge = Challenge.query.filter_by(name='CSRF via XSS Chain').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'XSS + CSRF Chain Attempt:\nXSS Payload: {xss_payload}\nCSRF Action: {csrf_action}\nTarget Endpoint: {target_endpoint}\n\nStatus: Attack chain incomplete.\nEnsure both XSS and CSRF components are present.'
    challenge = Challenge.query.filter_by(name='CSRF via XSS Chain').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level17.html', flag=flag, csrf_detected=csrf_detected, xss_payload=xss_payload, csrf_action=csrf_action, target_endpoint=target_endpoint, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level18', methods=['GET', 'POST'])
@login_required
def csrf_level18():
    user = get_current_user()
    flag = None
    csrf_detected = False
    graphql_query = request.form.get('graphql_query', '')
    variables = request.form.get('variables', '')
    operation_name = request.form.get('operation_name', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if graphql_query and operation_name:
            csrf_operations = ['deleteUser', 'updatePassword', 'transferFunds', 'promoteUser', 'createAdmin']
            mutation_patterns = ['mutation', 'Mutation']
            has_mutation = any((pattern in graphql_query for pattern in mutation_patterns))
            has_csrf_op = any((op in operation_name for op in csrf_operations))
            if has_mutation and has_csrf_op:
                csrf_detected = True
                result = f'GraphQL CSRF Attack:\nQuery: {graphql_query}\nVariables: {variables}\nOperation: {operation_name}\n\nGraphQL Response:\n{{\n  "data": {{\n    "{operation_name}": {{\n      "success": true,\n      "message": "Operation executed successfully",\n      "userId": "12345",\n      "timestamp": "2024-01-15T14:30:25Z"\n    }}\n  }},\n  "extensions": {{\n    "csrf_protection": "none",\n    "vulnerability": "GraphQL mutation CSRF",\n    "attack_vector": "POST request with application/json",\n    "impact": "Unauthorized GraphQL operations",\n  }}\n}}\n\nSecurity Analysis:\n- GraphQL mutation executed without CSRF protection\n- JSON content-type bypasses simple CSRF defenses\n- Demonstrates need for proper GraphQL security measures'
                challenge = Challenge.query.filter_by(name='GraphQL CSRF').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f"GraphQL Request:\nQuery: {graphql_query}\nVariables: {variables}\nOperation: {operation_name}\n\nStatus: Invalid GraphQL operation.\nEnsure you're using a mutation with a sensitive operation."
    challenge = Challenge.query.filter_by(name='GraphQL CSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level18.html', flag=flag, csrf_detected=csrf_detected, graphql_query=graphql_query, variables=variables, operation_name=operation_name, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level19', methods=['GET', 'POST'])
@login_required
def csrf_level19():
    user = get_current_user()
    flag = None
    csrf_detected = False
    jwt_token = request.form.get('jwt_token', '')
    api_action = request.form.get('api_action', '')
    payload_data = request.form.get('payload_data', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if jwt_token and api_action and payload_data:
            jwt_patterns = ['eyJ', 'Bearer', 'JWT']
            csrf_actions = ['delete', 'transfer', 'admin', 'password', 'promote']
            has_jwt = any((pattern in jwt_token for pattern in jwt_patterns))
            has_csrf = any((action in api_action.lower() for action in csrf_actions))
            if has_jwt and has_csrf:
                csrf_detected = True
                result = f'JWT-based CSRF Attack:\nJWT Token: {jwt_token[:50]}...\nAPI Action: {api_action}\nPayload: {payload_data}\n\nAPI Response:\n{{\n  "success": true,\n  "action": "{api_action}",\n  "payload": "{payload_data}",\n  "jwt_validation": "bypassed",\n  "vulnerability": "JWT CSRF without proper validation",\n  "attack_vector": "Automatic JWT inclusion in cross-site requests",\n  "impact": "Unauthorized API operations with valid JWT",\n}}\n\nSecurity Analysis:\n- JWT token automatically included in cross-site requests\n- API lacks proper CSRF protection despite JWT authentication\n- Demonstrates that JWT alone is insufficient for CSRF protection'
                challenge = Challenge.query.filter_by(name='JWT-based CSRF').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f"JWT API Request:\nJWT Token: {(jwt_token[:50] if jwt_token else 'None')}...\nAPI Action: {api_action}\nPayload: {payload_data}\n\nStatus: Invalid JWT or action.\nEnsure valid JWT token and sensitive API action."
    challenge = Challenge.query.filter_by(name='JWT-based CSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level19.html', flag=flag, csrf_detected=csrf_detected, jwt_token=jwt_token, api_action=api_action, payload_data=payload_data, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level20', methods=['GET', 'POST'])
@login_required
def csrf_level20():
    user = get_current_user()
    flag = None
    csrf_detected = False
    mobile_api = request.form.get('mobile_api', '')
    device_id = request.form.get('device_id', '')
    api_key = request.form.get('api_key', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if mobile_api and device_id and api_key:
            mobile_patterns = ['mobile', 'app', 'device', 'android', 'ios']
            csrf_actions = ['transfer', 'delete', 'payment', 'purchase', 'admin']
            has_mobile = any((pattern in mobile_api.lower() for pattern in mobile_patterns))
            has_csrf = any((action in mobile_api.lower() for action in csrf_actions))
            if has_mobile and has_csrf:
                csrf_detected = True
                result = f'Mobile API CSRF Attack:\nAPI Endpoint: {mobile_api}\nDevice ID: {device_id}\nAPI Key: {api_key[:20]}...\n\nMobile API Response:\n{{\n  "status": "success",\n  "api_endpoint": "{mobile_api}",\n  "device_id": "{device_id}",\n  "api_key_valid": true,\n  "csrf_protection": "none",\n  "vulnerability": "Mobile API lacks CSRF protection",\n  "attack_vector": "Cross-site request to mobile API",\n  "impact": "Unauthorized mobile app operations",\n}}\n\nSecurity Analysis:\n- Mobile API vulnerable to CSRF attacks\n- Device ID and API key insufficient for CSRF protection\n- Demonstrates need for proper mobile API security'
                challenge = Challenge.query.filter_by(name='Mobile API CSRF').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f"Mobile API Request:\nAPI Endpoint: {mobile_api}\nDevice ID: {device_id}\nAPI Key: {(api_key[:20] if api_key else 'None')}...\n\nStatus: Invalid mobile API request.\nEnsure mobile API endpoint with sensitive operation."
    challenge = Challenge.query.filter_by(name='Mobile API CSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level20.html', flag=flag, csrf_detected=csrf_detected, mobile_api=mobile_api, device_id=device_id, api_key=api_key, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level21', methods=['GET', 'POST'])
@login_required
def csrf_level21():
    user = get_current_user()
    flag = None
    csrf_detected = False
    service_name = request.form.get('service_name', '')
    service_action = request.form.get('service_action', '')
    auth_token = request.form.get('auth_token', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if service_name and service_action and auth_token:
            service_patterns = ['user-service', 'payment-service', 'admin-service', 'auth-service']
            csrf_actions = ['delete', 'transfer', 'promote', 'disable', 'reset']
            has_service = any((pattern in service_name.lower() for pattern in service_patterns))
            has_csrf = any((action in service_action.lower() for action in csrf_actions))
            if has_service and has_csrf:
                csrf_detected = True
                result = f'Microservices CSRF Attack:\nService: {service_name}\nAction: {service_action}\nAuth Token: {auth_token[:30]}...\n\nMicroservice Response:\n{{\n  "service": "{service_name}",\n  "action": "{service_action}",\n  "status": "executed",\n  "auth_token_valid": true,\n  "csrf_protection": "none",\n  "vulnerability": "Microservice lacks CSRF protection",\n  "attack_vector": "Cross-service request forgery",\n  "impact": "Unauthorized microservice operations",\n}}\n\nSecurity Analysis:\n- Microservice vulnerable to CSRF attacks\n- Service-to-service authentication insufficient for CSRF protection\n- Demonstrates need for proper microservices security architecture'
                challenge = Challenge.query.filter_by(name='Microservices CSRF').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f"Microservice Request:\nService: {service_name}\nAction: {service_action}\nAuth Token: {(auth_token[:30] if auth_token else 'None')}...\n\nStatus: Invalid microservice request.\nEnsure valid service name and sensitive action."
    challenge = Challenge.query.filter_by(name='Microservices CSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level21.html', flag=flag, csrf_detected=csrf_detected, service_name=service_name, service_action=service_action, auth_token=auth_token, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level22', methods=['GET', 'POST'])
@login_required
def csrf_level22():
    user = get_current_user()
    flag = None
    csrf_detected = False
    subdomain = request.form.get('subdomain', '')
    target_domain = request.form.get('target_domain', '')
    attack_payload = request.form.get('attack_payload', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if subdomain and target_domain and attack_payload:
            takeover_patterns = ['github.io', 'herokuapp.com', 'netlify.app', 'vercel.app', 's3.amazonaws.com']
            csrf_patterns = ['form', 'fetch', 'xhr', 'post']
            has_takeover = any((pattern in subdomain.lower() for pattern in takeover_patterns))
            has_csrf = any((pattern in attack_payload.lower() for pattern in csrf_patterns))
            if has_takeover and has_csrf:
                csrf_detected = True
                result = f'Subdomain Takeover CSRF Attack:\nSubdomain: {subdomain}\nTarget Domain: {target_domain}\nAttack Payload: {attack_payload}\n\nTakeover Response:\n{{\n  "subdomain": "{subdomain}",\n  "target_domain": "{target_domain}",\n  "takeover_status": "successful",\n  "csrf_payload": "{attack_payload}",\n  "vulnerability": "Subdomain takeover enables CSRF",\n  "attack_vector": "Malicious subdomain hosting CSRF payload",\n  "impact": "Cross-domain CSRF via subdomain takeover",\n}}\n\nSecurity Analysis:\n- Subdomain takeover enables cross-domain CSRF attacks\n- Malicious content hosted on trusted subdomain\n- Demonstrates importance of subdomain security monitoring'
                challenge = Challenge.query.filter_by(name='CSRF with Subdomain Takeover').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'Subdomain Takeover Attempt:\nSubdomain: {subdomain}\nTarget Domain: {target_domain}\nAttack Payload: {attack_payload}\n\nStatus: Takeover unsuccessful.\nEnsure vulnerable subdomain and valid CSRF payload.'
    challenge = Challenge.query.filter_by(name='CSRF with Subdomain Takeover').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level22.html', flag=flag, csrf_detected=csrf_detected, subdomain=subdomain, target_domain=target_domain, attack_payload=attack_payload, result=result, challenge=challenge)

@csrf_bp.route('/csrf/level23', methods=['GET', 'POST'])
@login_required
def csrf_level23():
    user = get_current_user()
    flag = None
    csrf_detected = False
    function_url = request.form.get('function_url', '')
    function_payload = request.form.get('function_payload', '')
    trigger_method = request.form.get('trigger_method', '')
    result = ''
    if request.method == 'POST':
        if request.args.get('csrf_solved') == 'true':
            csrf_detected = True
        if function_url and function_payload and trigger_method:
            serverless_patterns = ['lambda', 'azure-functions', 'cloud-functions', 'vercel', 'netlify']
            csrf_patterns = ['delete', 'transfer', 'admin', 'payment', 'execute']
            has_serverless = any((pattern in function_url.lower() for pattern in serverless_patterns))
            has_csrf = any((pattern in function_payload.lower() for pattern in csrf_patterns))
            if has_serverless and has_csrf:
                csrf_detected = True
                result = f'Serverless Function CSRF Attack:\nFunction URL: {function_url}\nPayload: {function_payload}\nTrigger Method: {trigger_method}\n\nServerless Response:\n{{\n  "function_url": "{function_url}",\n  "payload": "{function_payload}",\n  "trigger_method": "{trigger_method}",\n  "execution_status": "success",\n  "csrf_protection": "none",\n  "vulnerability": "Serverless function lacks CSRF protection",\n  "attack_vector": "Cross-site serverless function invocation",\n  "impact": "Unauthorized serverless function execution",\n}}\n\nSecurity Analysis:\n- Serverless function vulnerable to CSRF attacks\n- Function URL accessible without proper CSRF protection\n- Demonstrates need for serverless security best practices'
                challenge = Challenge.query.filter_by(name='Serverless Function CSRF').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                result = f'Serverless Function Request:\nFunction URL: {function_url}\nPayload: {function_payload}\nTrigger Method: {trigger_method}\n\nStatus: Invalid serverless function request.\nEnsure valid function URL and sensitive payload.'
    challenge = Challenge.query.filter_by(name='Serverless Function CSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('csrf/csrf_level23.html', flag=flag, csrf_detected=csrf_detected, function_url=function_url, function_payload=function_payload, trigger_method=trigger_method, result=result, challenge=challenge)

