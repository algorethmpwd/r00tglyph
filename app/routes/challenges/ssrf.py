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

ssrf_bp = Blueprint('ssrf', __name__)

@ssrf_bp.route('/ssrf/level1', methods=['GET', 'POST'])
@login_required
def ssrf_level1():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    url = request.form.get('url', '')
    fetch_result = ''
    if request.method == 'POST':
        if url:
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
            for pattern in ssrf_patterns:
                if pattern in url.lower():
                    ssrf_detected = True
                    fetch_result = f'Fetching URL: {url}\n'
                    fetch_result += 'Connection established...\n'
                    fetch_result += 'Response received:\n\n'
                    if 'localhost' in url.lower() or '127.0.0.1' in url:
                        fetch_result += 'HTTP/1.1 200 OK\n'
                        fetch_result += 'Server: Apache/2.4.41\n'
                        fetch_result += 'Content-Type: text/html\n\n'
                        fetch_result += '<h1>Internal Admin Panel</h1>\n'
                        fetch_result += '<p>Welcome to the internal administration interface</p>\n'
                        fetch_result += '<p>Internal system access successful</p>\n'
                    elif '192.168.' in url or '10.' in url:
                        fetch_result += 'HTTP/1.1 200 OK\n'
                        fetch_result += 'Server: nginx/1.18.0\n'
                        fetch_result += 'Content-Type: application/json\n\n'
                        fetch_result += '{"status": "success", "message": "Internal API accessed", "data": "sensitive_internal_info"}\n'
                    challenge = Challenge.query.filter_by(name='Basic SSRF').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                fetch_result = f'Fetching URL: {url}\n'
                fetch_result += 'Connection established...\n'
                fetch_result += 'Response received:\n\n'
                fetch_result += 'HTTP/1.1 200 OK\n'
                fetch_result += 'Content-Type: text/html\n\n'
                fetch_result += '<html><body><h1>External Website</h1><p>This is a normal external website.</p></body></html>\n'
    challenge = Challenge.query.filter_by(name='Basic SSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level1.html', flag=flag, ssrf_detected=ssrf_detected, url=url, fetch_result=fetch_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level2', methods=['GET', 'POST'])
@login_required
def ssrf_level2():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    target_url = request.form.get('target_url', '')
    scan_result = ''
    if request.method == 'POST':
        if target_url:
            internal_patterns = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', 'localhost', '127.0.0.1']
            for pattern in internal_patterns:
                if pattern in target_url.lower():
                    ssrf_detected = True
                    scan_result = f'Taking screenshot of: {target_url}\n'
                    scan_result += 'Scanning internal network...\n\n'
                    if ':22' in target_url:
                        scan_result += 'Port 22 (SSH): Open\n'
                        scan_result += 'Service: OpenSSH 8.2\n'
                        scan_result += 'SSH service detected successfully\n'
                    elif ':80' in target_url or ':8080' in target_url:
                        scan_result += 'Port 80/8080 (HTTP): Open\n'
                        scan_result += 'Service: Internal Web Server\n'
                        scan_result += 'Response: Internal API Documentation\n'
                        scan_result += 'Web server access granted\n'
                    elif ':3306' in target_url:
                        scan_result += 'Port 3306 (MySQL): Open\n'
                        scan_result += 'Service: MySQL Database\n'
                        scan_result += 'Database service discovered\n'
                    else:
                        scan_result += 'Internal service discovered!\n'
                        scan_result += 'Network scan successful\n'
                        scan_result += 'Internal network enumeration completed\n'
                    challenge = Challenge.query.filter_by(name='SSRF with Internal Network Scanning').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                scan_result = f'Taking screenshot of: {target_url}\n'
                scan_result += 'Screenshot captured successfully\n'
                scan_result += 'External website processed\n'
    challenge = Challenge.query.filter_by(name='SSRF with Internal Network Scanning').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level2.html', flag=flag, ssrf_detected=ssrf_detected, target_url=target_url, scan_result=scan_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level3', methods=['GET', 'POST'])
@login_required
def ssrf_level3():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    webhook_url = request.form.get('webhook_url', '')
    metadata_result = ''
    if request.method == 'POST':
        if webhook_url:
            metadata_patterns = ['169.254.169.254', 'metadata.google.internal', 'metadata.azure.com', 'metadata.tencentyun.com']
            for pattern in metadata_patterns:
                if pattern in webhook_url.lower():
                    ssrf_detected = True
                    metadata_result = f'Sending webhook to: {webhook_url}\n'
                    metadata_result += 'Accessing cloud metadata service...\n\n'
                    if '169.254.169.254' in webhook_url:
                        metadata_result += 'AWS EC2 Metadata Service Response:\n'
                        metadata_result += '{\n'
                        metadata_result += '  "instance-id": "i-1234567890abcdef0",\n'
                        metadata_result += '  "instance-type": "t3.medium",\n'
                        metadata_result += '  "security-credentials": {\n'
                        metadata_result += '    "AccessKeyId": "AKIA...",\n'
                        metadata_result += '    "SecretAccessKey": "...",\n'
                        metadata_result += '    "Token": "..."\n'
                        metadata_result += '  }\n'
                        metadata_result += '}\n'
                        metadata_result += 'AWS metadata access successful\n'
                    elif 'metadata.google.internal' in webhook_url:
                        metadata_result += 'GCP Metadata Service Response:\n'
                        metadata_result += '{\n'
                        metadata_result += '  "project-id": "my-project-123",\n'
                        metadata_result += '  "service-accounts": {\n'
                        metadata_result += '    "default": {\n'
                        metadata_result += '      "token": "ya29.c.Kp6B9n..."\n'
                        metadata_result += '    }\n'
                        metadata_result += '  }\n'
                        metadata_result += '}\n'
                        metadata_result += 'GCP metadata access successful\n'
                    elif 'metadata.azure.com' in webhook_url:
                        metadata_result += 'Azure Metadata Service Response:\n'
                        metadata_result += '{\n'
                        metadata_result += '  "compute": {\n'
                        metadata_result += '    "vmId": "02aab8a4-74ef-476e-8182-f6d2ba4166a6",\n'
                        metadata_result += '    "subscriptionId": "8d10da13-8125-4ba9-a717-bf7490507b3d"\n'
                        metadata_result += '  },\n'
                        metadata_result += '  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik..."\n'
                        metadata_result += '}\n'
                        metadata_result += 'Azure metadata access successful\n'
                    challenge = Challenge.query.filter_by(name='Cloud Metadata SSRF').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                metadata_result = f'Sending webhook to: {webhook_url}\n'
                metadata_result += 'Webhook sent successfully\n'
                metadata_result += 'External service notified\n'
    challenge = Challenge.query.filter_by(name='Cloud Metadata SSRF').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level3.html', flag=flag, ssrf_detected=ssrf_detected, webhook_url=webhook_url, metadata_result=metadata_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level4', methods=['GET', 'POST'])
@login_required
def ssrf_level4():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    callback_url = request.form.get('callback_url', '')
    dns_result = ''
    if request.method == 'POST':
        if callback_url:
            dns_patterns = ['.burpcollaborator.net', '.oastify.com', '.dnslog.cn', '.requestbin.net', '.webhook.site']
            for pattern in dns_patterns:
                if pattern in callback_url.lower():
                    ssrf_detected = True
                    dns_result = f'Generating PDF with callback: {callback_url}\n'
                    dns_result += 'PDF generation initiated...\n'
                    dns_result += 'Making callback request...\n\n'
                    dns_result += 'DNS Query Detected:\n'
                    dns_result += f'Query: {callback_url}\n'
                    dns_result += 'Type: A\n'
                    dns_result += 'Source: Internal PDF Service\n'
                    dns_result += 'Status: DNS exfiltration successful!\n'
                    dns_result += 'Blind SSRF exploitation confirmed\n'
                    challenge = Challenge.query.filter_by(name='Blind SSRF with DNS Exfiltration').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                dns_result = f'Generating PDF with callback: {callback_url}\n'
                dns_result += 'PDF generation completed\n'
                dns_result += 'No callback made\n'
    challenge = Challenge.query.filter_by(name='Blind SSRF with DNS Exfiltration').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level4.html', flag=flag, ssrf_detected=ssrf_detected, callback_url=callback_url, dns_result=dns_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level5', methods=['GET', 'POST'])
@login_required
def ssrf_level5():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    image_url = request.form.get('image_url', '')
    filter_result = ''
    if request.method == 'POST':
        if image_url:
            blacklist = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
            bypass_detected = False
            if any((blocked in image_url.lower() for blocked in blacklist)):
                filter_result = f'Processing image: {image_url}\n'
                filter_result += 'ERROR: Blocked by security filter\n'
                filter_result += 'Reason: Internal address detected\n'
            else:
                bypass_patterns = ['127.1', '127.0.1', '2130706433', '0x7f000001', '0177.0.0.1', 'localtest.me', '127.0.0.1.nip.io']
                for pattern in bypass_patterns:
                    if pattern in image_url.lower():
                        bypass_detected = True
                        ssrf_detected = True
                        filter_result = f'Processing image: {image_url}\n'
                        filter_result += 'Filter bypass detected!\n'
                        filter_result += 'Accessing internal service...\n\n'
                        filter_result += 'Internal Service Response:\n'
                        filter_result += 'HTTP/1.1 200 OK\n'
                        filter_result += 'Content-Type: application/json\n\n'
                        filter_result += '{"message": "Internal admin API", "status": "access_granted"}\n'
                        challenge = Challenge.query.filter_by(name='SSRF with Basic Filters').first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(user.id, challenge.id, challenge.points)
                        break
                if not bypass_detected:
                    filter_result = f'Processing image: {image_url}\n'
                    filter_result += 'Image downloaded successfully\n'
                    filter_result += 'External image processed\n'
    challenge = Challenge.query.filter_by(name='SSRF with Basic Filters').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level5.html', flag=flag, ssrf_detected=ssrf_detected, image_url=image_url, filter_result=filter_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level6', methods=['GET', 'POST'])
@login_required
def ssrf_level6():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    svg_content = request.form.get('svg_content', '')
    upload_result = ''
    if request.method == 'POST':
        if svg_content:
            if '<image' in svg_content and 'href=' in svg_content:
                import re
                href_match = re.search('href=["\\\']([^"\\\']+)["\\\']', svg_content)
                if href_match:
                    href_url = href_match.group(1)
                    internal_patterns = ['localhost', '127.0.0.1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
                    for pattern in internal_patterns:
                        if pattern in href_url.lower():
                            ssrf_detected = True
                            upload_result = f'Processing SVG file...\n'
                            upload_result += f'Loading image from: {href_url}\n'
                            upload_result += 'SVG processing complete\n\n'
                            upload_result += 'Internal Service Response:\n'
                            upload_result += 'HTTP/1.1 200 OK\n'
                            upload_result += 'Content-Type: application/json\n\n'
                            upload_result += '{"message": "Internal file server", "access": "granted"}\n'
                            challenge = Challenge.query.filter_by(name='SSRF via File Upload').first()
                            if challenge:
                                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                if challenge.id not in completed_ids:
                                    update_user_progress(user.id, challenge.id, challenge.points)
                            break
                    else:
                        upload_result = f'Processing SVG file...\n'
                        upload_result += f'Loading image from: {href_url}\n'
                        upload_result += 'External image loaded successfully\n'
                else:
                    upload_result = 'Processing SVG file...\n'
                    upload_result += 'SVG processed successfully\n'
            else:
                upload_result = 'Processing SVG file...\n'
                upload_result += 'SVG processed successfully\n'
    challenge = Challenge.query.filter_by(name='SSRF via File Upload').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level6.html', flag=flag, ssrf_detected=ssrf_detected, svg_content=svg_content, upload_result=upload_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level7', methods=['GET', 'POST'])
@login_required
def ssrf_level7():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    notification_url = request.form.get('notification_url', '')
    webhook_result = ''
    if request.method == 'POST':
        if notification_url:
            internal_patterns = ['localhost', '127.0.0.1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
            for pattern in internal_patterns:
                if pattern in notification_url.lower():
                    ssrf_detected = True
                    webhook_result = f'Sending payment notification to: {notification_url}\n'
                    webhook_result += 'Payment processed successfully\n'
                    webhook_result += 'Sending webhook notification...\n\n'
                    webhook_result += 'Webhook Response:\n'
                    webhook_result += 'HTTP/1.1 200 OK\n'
                    webhook_result += 'Content-Type: application/json\n\n'
                    webhook_result += '{"status": "received", "internal_api": true, "access": "successful"}\n'
                    challenge = Challenge.query.filter_by(name='SSRF in Webhooks').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                webhook_result = f'Sending payment notification to: {notification_url}\n'
                webhook_result += 'Payment processed successfully\n'
                webhook_result += 'Webhook sent to external service\n'
    challenge = Challenge.query.filter_by(name='SSRF in Webhooks').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level7.html', flag=flag, ssrf_detected=ssrf_detected, notification_url=notification_url, webhook_result=webhook_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level8', methods=['GET', 'POST'])
@login_required
def ssrf_level8():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    fetch_url = request.form.get('fetch_url', '')
    waf_result = ''
    if request.method == 'POST':
        if fetch_url:
            waf_blacklist = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
            if any((blocked in fetch_url.lower() for blocked in waf_blacklist)):
                waf_result = f'Fetching URL: {fetch_url}\n'
                waf_result += 'WAF BLOCKED: Internal address detected\n'
                waf_result += 'Request denied by security policy\n'
            else:
                bypass_patterns = ['127.1', '127.0.1', '2130706433', '0x7f000001', '0177.0.0.1', 'localtest.me', '127.0.0.1.nip.io', 'spoofed.burpcollaborator.net', 'localhost.localdomain']
                for pattern in bypass_patterns:
                    if pattern in fetch_url.lower():
                        ssrf_detected = True
                        waf_result = f'Fetching URL: {fetch_url}\n'
                        waf_result += 'WAF bypass successful!\n'
                        waf_result += 'Accessing internal service...\n\n'
                        waf_result += 'Internal Service Response:\n'
                        waf_result += 'HTTP/1.1 200 OK\n'
                        waf_result += 'Content-Type: application/json\n\n'
                        waf_result += '{"message": "Internal admin panel", "access": "waf_bypassed"}\n'
                        challenge = Challenge.query.filter_by(name='SSRF with WAF Bypass').first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(user.id, challenge.id, challenge.points)
                        break
                else:
                    waf_result = f'Fetching URL: {fetch_url}\n'
                    waf_result += 'External URL fetched successfully\n'
                    waf_result += 'Content retrieved from external source\n'
    challenge = Challenge.query.filter_by(name='SSRF with WAF Bypass').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level8.html', flag=flag, ssrf_detected=ssrf_detected, fetch_url=fetch_url, waf_result=waf_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level9', methods=['GET', 'POST'])
@login_required
def ssrf_level9():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    xml_data = request.form.get('xml_data', '')
    xxe_result = ''
    if request.method == 'POST':
        if xml_data:
            if '<!ENTITY' in xml_data and 'SYSTEM' in xml_data:
                import re
                system_matches = re.findall('SYSTEM\\s+["\\\']([^"\\\']+)["\\\']', xml_data)
                for system_url in system_matches:
                    internal_patterns = ['localhost', '127.0.0.1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', 'file://', 'gopher://']
                    for pattern in internal_patterns:
                        if pattern in system_url.lower():
                            ssrf_detected = True
                            xxe_result = f'Processing XML data...\n'
                            xxe_result += f'Loading external entity: {system_url}\n'
                            xxe_result += 'XXE processing complete\n\n'
                            if 'file://' in system_url:
                                xxe_result += 'File System Access:\n'
                                xxe_result += '/etc/passwd:\n'
                                xxe_result += 'root:x:0:0:root:/root:/bin/bash\n'
                                xxe_result += 'File system access successful\n'
                            elif 'gopher://' in system_url:
                                xxe_result += 'Gopher Protocol SSRF:\n'
                                xxe_result += 'Internal service accessed via Gopher\n'
                                xxe_result += 'Gopher protocol exploitation successful\n'
                            else:
                                xxe_result += 'Internal Service Response:\n'
                                xxe_result += 'HTTP/1.1 200 OK\n'
                                xxe_result += 'Content-Type: application/json\n\n'
                                xxe_result += '{"message": "Internal API via XXE", "access": "granted"}\n'
                            challenge = Challenge.query.filter_by(name='SSRF via XXE').first()
                            if challenge:
                                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                if challenge.id not in completed_ids:
                                    update_user_progress(user.id, challenge.id, challenge.points)
                            break
                    if ssrf_detected:
                        break
                if not ssrf_detected:
                    xxe_result = f'Processing XML data...\n'
                    xxe_result += 'External entities processed\n'
                    xxe_result += 'XML parsing complete\n'
            else:
                xxe_result = 'Processing XML data...\n'
                xxe_result += 'XML parsed successfully\n'
    challenge = Challenge.query.filter_by(name='SSRF via XXE').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level9.html', flag=flag, ssrf_detected=ssrf_detected, xml_data=xml_data, xxe_result=xxe_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level10', methods=['GET', 'POST'])
@login_required
def ssrf_level10():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    target_domain = request.form.get('target_domain', '')
    rebinding_result = ''
    if request.method == 'POST':
        if target_domain:
            rebinding_patterns = ['rebind.network', 'rebind.it', '1u.ms', 'rebind.talos-sec.com', 'rbndr.us']
            for pattern in rebinding_patterns:
                if pattern in target_domain.lower():
                    ssrf_detected = True
                    rebinding_result = f'Checking website health: {target_domain}\n'
                    rebinding_result += 'DNS resolution in progress...\n'
                    rebinding_result += 'First resolution: 8.8.8.8 (external)\n'
                    rebinding_result += 'Second resolution: 127.0.0.1 (internal)\n'
                    rebinding_result += 'DNS rebinding attack detected!\n\n'
                    rebinding_result += 'Internal Service Response:\n'
                    rebinding_result += 'HTTP/1.1 200 OK\n'
                    rebinding_result += 'Content-Type: application/json\n\n'
                    rebinding_result += '{"message": "Internal admin interface", "rebinding": true, "access": "granted"}\n'
                    challenge = Challenge.query.filter_by(name='SSRF with DNS Rebinding').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                rebinding_result = f'Checking website health: {target_domain}\n'
                rebinding_result += 'DNS resolution successful\n'
                rebinding_result += 'Website is healthy\n'
    challenge = Challenge.query.filter_by(name='SSRF with DNS Rebinding').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level10.html', flag=flag, ssrf_detected=ssrf_detected, target_domain=target_domain, rebinding_result=rebinding_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level11', methods=['GET', 'POST'])
@login_required
def ssrf_level11():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    graphql_query = request.form.get('graphql_query', '')
    graphql_result = ''
    if request.method == 'POST':
        if graphql_query:
            if 'query' in graphql_query.lower() and ('http://' in graphql_query or 'https://' in graphql_query):
                import re
                url_matches = re.findall('https?://[^\\s"\\\']+', graphql_query)
                for url in url_matches:
                    internal_patterns = ['localhost', '127.0.0.1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
                    for pattern in internal_patterns:
                        if pattern in url.lower():
                            ssrf_detected = True
                            graphql_result = f'Executing GraphQL query...\n'
                            graphql_result += f'Fetching data from: {url}\n'
                            graphql_result += 'GraphQL introspection complete\n\n'
                            graphql_result += 'Internal GraphQL API Response:\n'
                            graphql_result += '{\n'
                            graphql_result += '  "data": {\n'
                            graphql_result += '    "internal": true,\n'
                            graphql_result += '    "access": "internal_granted"\n'
                            graphql_result += '  }\n'
                            graphql_result += '}\n'
                            challenge = Challenge.query.filter_by(name='SSRF in GraphQL').first()
                            if challenge:
                                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                if challenge.id not in completed_ids:
                                    update_user_progress(user.id, challenge.id, challenge.points)
                            break
                    if ssrf_detected:
                        break
                if not ssrf_detected:
                    graphql_result = f'Executing GraphQL query...\n'
                    graphql_result += 'External GraphQL API accessed\n'
                    graphql_result += 'Query executed successfully\n'
            else:
                graphql_result = 'Executing GraphQL query...\n'
                graphql_result += 'Query processed\n'
    challenge = Challenge.query.filter_by(name='SSRF in GraphQL').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level11.html', flag=flag, ssrf_detected=ssrf_detected, graphql_query=graphql_query, graphql_result=graphql_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level12', methods=['GET', 'POST'])
@login_required
def ssrf_level12():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    gopher_url = request.form.get('gopher_url', '')
    redis_result = ''
    if request.method == 'POST':
        if gopher_url:
            if 'gopher://' in gopher_url.lower():
                internal_patterns = ['localhost', '127.0.0.1', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
                for pattern in internal_patterns:
                    if pattern in gopher_url.lower():
                        ssrf_detected = True
                        redis_result = f'Processing Gopher request: {gopher_url}\n'
                        redis_result += 'Connecting to Redis server...\n'
                        redis_result += 'Redis protocol exploitation successful\n\n'
                        redis_result += 'Redis Server Response:\n'
                        redis_result += '+OK\n'
                        redis_result += '$64\n'
                        redis_result += 'Internal_Redis_Access_Successful\n'
                        challenge = Challenge.query.filter_by(name='SSRF via Redis Protocol').first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(user.id, challenge.id, challenge.points)
                        break
                else:
                    redis_result = f'Processing Gopher request: {gopher_url}\n'
                    redis_result += 'External Gopher service accessed\n'
            else:
                redis_result = 'Invalid protocol. Only Gopher protocol supported.\n'
    challenge = Challenge.query.filter_by(name='SSRF via Redis Protocol').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level12.html', flag=flag, ssrf_detected=ssrf_detected, gopher_url=gopher_url, redis_result=redis_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level13', methods=['GET', 'POST'])
@login_required
def ssrf_level13():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    websocket_url = request.form.get('websocket_url', '')
    upgrade_headers = request.form.get('upgrade_headers', '')
    websocket_result = ''
    if request.method == 'POST':
        if websocket_url and upgrade_headers:
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'admin.', 'management.']
            if any((pattern in websocket_url.lower() or pattern in upgrade_headers.lower() for pattern in ssrf_patterns)):
                ssrf_detected = True
                websocket_result = f'WebSocket Handshake Request:\nGET {websocket_url} HTTP/1.1\nUpgrade: websocket\nConnection: Upgrade\n{upgrade_headers}\n\nResponse from internal service:\nHTTP/1.1 101 Switching Protocols\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\n\nInternal WebSocket Service Response:\n{{\n  "service": "internal-websocket-gateway",\n  "status": "connected",\n  "internal_data": "sensitive_websocket_data",\n  "access": "websocket_ssrf_successful"\n}}'
                challenge = Challenge.query.filter_by(name='SSRF in WebSocket Upgrade').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                websocket_result = f'WebSocket Handshake Request:\nGET {websocket_url} HTTP/1.1\nUpgrade: websocket\nConnection: Upgrade\n{upgrade_headers}\n\nResponse:\nHTTP/1.1 400 Bad Request\nContent-Type: text/plain\n\nInvalid WebSocket upgrade request. Try targeting internal services.'
    challenge = Challenge.query.filter_by(name='SSRF in WebSocket Upgrade').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level13.html', flag=flag, ssrf_detected=ssrf_detected, websocket_url=websocket_url, upgrade_headers=upgrade_headers, websocket_result=websocket_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level14', methods=['GET', 'POST'])
@login_required
def ssrf_level14():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    smtp_server = request.form.get('smtp_server', '')
    test_email = request.form.get('test_email', '')
    smtp_result = ''
    if request.method == 'POST':
        if smtp_server and test_email:
            gopher_patterns = ['gopher://', 'localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', ':25', ':587']
            if any((pattern in smtp_server.lower() for pattern in gopher_patterns)):
                ssrf_detected = True
                smtp_result = f'SMTP Connection Test:\nTarget: {smtp_server}\nTest Email: {test_email}\n\nGopher Protocol SMTP Injection:\n{smtp_server}\n\nSMTP Server Response:\n220 internal-mail.company.local ESMTP Postfix\nEHLO attacker.com\n250-internal-mail.company.local\n250-PIPELINING\n250-SIZE 10240000\n250-VRFY\n250-ETRN\n250-STARTTLS\n250-AUTH PLAIN LOGIN\n250-AUTH=PLAIN LOGIN\n250-ENHANCEDSTATUSCODES\n250-8BITMIME\n250 DSN\n\nVRFY admin\n252 2.0.0 admin@company.local\n\nInternal SMTP Data Leaked:\n{{\n  "smtp_server": "internal-mail.company.local",\n  "valid_users": ["admin", "root", "postmaster"],\n  "internal_domains": ["company.local", "internal.local"],\n  "access": "smtp_internal_enumeration_successful"\n}}'
                challenge = Challenge.query.filter_by(name='SSRF via SMTP Protocol').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                smtp_result = f'SMTP Connection Test:\nTarget: {smtp_server}\nTest Email: {test_email}\n\nConnection Result:\nFailed to connect to SMTP server.\nError: Connection refused or invalid server.\n\nTry using Gopher protocol to target internal SMTP servers.'
    challenge = Challenge.query.filter_by(name='SSRF via SMTP Protocol').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level14.html', flag=flag, ssrf_detected=ssrf_detected, smtp_server=smtp_server, test_email=test_email, smtp_result=smtp_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level15', methods=['GET', 'POST'])
@login_required
def ssrf_level15():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    client_id = request.form.get('client_id', '')
    redirect_uri = request.form.get('redirect_uri', '')
    scope = request.form.get('scope', '')
    oauth_result = ''
    if request.method == 'POST':
        if client_id and redirect_uri and scope:
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'admin.', 'file://', 'gopher://']
            if any((pattern in redirect_uri.lower() for pattern in ssrf_patterns)):
                ssrf_detected = True
                oauth_result = f'OAuth Authorization Request:\nClient ID: {client_id}\nRedirect URI: {redirect_uri}\nScope: {scope}\n\nOAuth Server Processing:\nValidating redirect_uri: {redirect_uri}\nCallback validation bypassed!\n\nInternal OAuth Service Response:\n{{\n  "access_token": "internal_oauth_token_12345",\n  "token_type": "Bearer",\n  "expires_in": 3600,\n  "scope": "{scope}",\n  "internal_data": {{\n    "user_id": "admin",\n    "internal_services": ["user-api", "admin-panel", "billing-service"],\n    "access": "oauth_internal_token_granted"\n  }}\n}}'
                challenge = Challenge.query.filter_by(name='SSRF in OAuth Callbacks').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                oauth_result = f'OAuth Authorization Request:\nClient ID: {client_id}\nRedirect URI: {redirect_uri}\nScope: {scope}\n\nOAuth Server Response:\nError: invalid_redirect_uri\nDescription: The redirect_uri is not whitelisted for this client.\n\nTry targeting internal services through redirect_uri manipulation.'
    challenge = Challenge.query.filter_by(name='SSRF in OAuth Callbacks').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level15.html', flag=flag, ssrf_detected=ssrf_detected, client_id=client_id, redirect_uri=redirect_uri, scope=scope, oauth_result=oauth_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level16', methods=['GET', 'POST'])
@login_required
def ssrf_level16():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    ldap_query = request.form.get('ldap_query', '')
    ldap_server = request.form.get('ldap_server', '')
    ldap_result = ''
    if request.method == 'POST':
        if ldap_query and ldap_server:
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'ldap://', 'ldaps://']
            if any((pattern in ldap_server.lower() for pattern in ssrf_patterns)):
                ssrf_detected = True
                ldap_result = f'LDAP Directory Search:\nServer: {ldap_server}\nQuery: {ldap_query}\n\nLDAP Connection Established:\nBinding to {ldap_server}...\nBind successful as anonymous user\n\nSearch Results:\ndn: cn=admin,ou=users,dc=internal,dc=local\nobjectClass: person\nobjectClass: organizationalPerson\ncn: admin\nsn: Administrator\nmail: admin@internal.local\nuserPassword: {{SSHA}}encrypted_password_hash\n\ndn: cn=service-account,ou=services,dc=internal,dc=local\nobjectClass: person\ncn: service-account\ndescription: Internal service authentication\nuserPassword: {{SSHA}}service_password_hash\n\nInternal LDAP Data:\n{{\n  "ldap_server": "ldap://directory.internal.local:389",\n  "base_dn": "dc=internal,dc=local",\n  "admin_users": ["admin", "ldapadmin", "service-account"],\n  "internal_groups": ["Domain Admins", "Service Accounts"],\n  "access": "ldap_internal_directory_enumerated"\n}}'
                challenge = Challenge.query.filter_by(name='SSRF via LDAP Protocol').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                ldap_result = f'LDAP Directory Search:\nServer: {ldap_server}\nQuery: {ldap_query}\n\nConnection Result:\nFailed to connect to LDAP server.\nError: Connection refused or server unreachable.\n\nTry targeting internal LDAP servers.'
    challenge = Challenge.query.filter_by(name='SSRF via LDAP Protocol').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level16.html', flag=flag, ssrf_detected=ssrf_detected, ldap_query=ldap_query, ldap_server=ldap_server, ldap_result=ldap_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level17', methods=['GET', 'POST'])
@login_required
def ssrf_level17():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    container_id = request.form.get('container_id', '')
    metadata_endpoint = request.form.get('metadata_endpoint', '')
    container_result = ''
    if request.method == 'POST':
        if container_id and metadata_endpoint:
            ssrf_patterns = ['169.254.169.254', 'localhost', '127.0.0.1', 'docker.sock', 'kubernetes', 'metadata']
            if any((pattern in metadata_endpoint.lower() for pattern in ssrf_patterns)):
                ssrf_detected = True
                container_result = f'Container Metadata Request:\nContainer ID: {container_id}\nMetadata Endpoint: {metadata_endpoint}\n\nDocker Daemon API Response:\n{{\n  "Id": "{container_id}",\n  "Created": "2024-01-15T10:30:00.000000000Z",\n  "Path": "/app/server",\n  "Args": ["--config", "/etc/app/config.json"],\n  "State": {{\n    "Status": "running",\n    "Running": true,\n    "Pid": 12345\n  }},\n  "Image": "internal-registry.company.local/app:latest",\n  "NetworkSettings": {{\n    "IPAddress": "172.17.0.2",\n    "Gateway": "172.17.0.1",\n    "Networks": {{\n      "internal-network": {{\n        "IPAddress": "10.0.1.100",\n        "Gateway": "10.0.1.1"\n      }}\n    }}\n  }},\n  "Mounts": [\n    {{\n      "Source": "/var/secrets",\n      "Destination": "/app/secrets",\n      "Mode": "ro"\n    }}\n  ],\n  "Config": {{\n    "Env": [\n      "DATABASE_URL=postgresql://admin:secret@db.internal.local:5432/app",\n      "API_KEY=sk-1234567890abcdef",\n      "INTERNAL_SECRET=container_metadata_exposed"\n    ]\n  }}\n}}'
                challenge = Challenge.query.filter_by(name='SSRF in Container Metadata').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                container_result = f'Container Metadata Request:\nContainer ID: {container_id}\nMetadata Endpoint: {metadata_endpoint}\n\nConnection Result:\nFailed to access container metadata.\nError: Endpoint not accessible or invalid.\n\nTry targeting container metadata services.'
    challenge = Challenge.query.filter_by(name='SSRF in Container Metadata').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level17.html', flag=flag, ssrf_detected=ssrf_detected, container_id=container_id, metadata_endpoint=metadata_endpoint, container_result=container_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level18', methods=['GET', 'POST'])
@login_required
def ssrf_level18():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    ftp_server = request.form.get('ftp_server', '')
    ftp_path = request.form.get('ftp_path', '')
    ftp_result = ''
    if request.method == 'POST':
        if ftp_server and ftp_path:
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'ftp://', ':21']
            if any((pattern in ftp_server.lower() for pattern in ssrf_patterns)):
                ssrf_detected = True
                ftp_result = f'FTP Connection Test:\nServer: {ftp_server}\nPath: {ftp_path}\n\nFTP Session:\n220 internal-ftp.company.local FTP server ready\nUSER anonymous\n331 Please specify the password\nPASS anonymous@\n230 Login successful\nPWD\n257 "/" is the current directory\nCWD {ftp_path}\n250 Directory successfully changed\nPASV\n227 Entering Passive Mode (192,168,1,100,20,21)\nLIST\n150 Here comes the directory listing\n-rw-r--r--    1 ftp      ftp          1024 Jan 15 10:30 sensitive_data.txt\n-rw-r--r--    1 ftp      ftp          2048 Jan 15 10:31 internal_config.conf\n-rw-r--r--    1 ftp      ftp           512 Jan 15 10:32 flag.txt\n226 Directory send OK\n\nRETR flag.txt\n150 Opening BINARY mode data connection for flag.txt (512 bytes)\nInternal_FTP_Access_Successful\n226 Transfer complete\n\nInternal FTP Data:\n{{\n  "ftp_server": "internal-ftp.company.local",\n  "accessible_paths": ["/sensitive", "/config", "/backups"],\n  "internal_files": ["database_backup.sql", "api_keys.txt", "user_data.csv"],\n  "flag": "Internal_FTP_Access_Successful"\n}}'
                challenge = Challenge.query.filter_by(name='SSRF via FTP Protocol').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                ftp_result = f'FTP Connection Test:\nServer: {ftp_server}\nPath: {ftp_path}\n\nConnection Result:\nFailed to connect to FTP server.\nError: Connection refused or server unreachable.\n\nTry targeting internal FTP servers.'
    challenge = Challenge.query.filter_by(name='SSRF via FTP Protocol').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level18.html', flag=flag, ssrf_detected=ssrf_detected, ftp_server=ftp_server, ftp_path=ftp_path, ftp_result=ftp_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level19', methods=['GET', 'POST'])
@login_required
def ssrf_level19():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    api_endpoint = request.form.get('api_endpoint', '')
    upstream_url = request.form.get('upstream_url', '')
    gateway_result = ''
    if request.method == 'POST':
        if api_endpoint and upstream_url:
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'admin.', 'management.']
            if any((pattern in upstream_url.lower() for pattern in ssrf_patterns)):
                ssrf_detected = True
                gateway_result = f'API Gateway Request:\nEndpoint: {api_endpoint}\nUpstream: {upstream_url}\n\nGateway Routing:\nProxying request to: {upstream_url}\nRoute configuration bypassed!\n\nInternal Microservice Response:\nHTTP/1.1 200 OK\nContent-Type: application/json\nX-Internal-Service: user-management-api\nX-Service-Version: 2.1.0\n\n{{\n  "service": "internal-user-api",\n  "version": "2.1.0",\n  "environment": "production",\n  "database": "postgresql://admin:secret@db.internal.local:5432/users",\n  "internal_endpoints": [\n    "/admin/users",\n    "/admin/permissions",\n    "/internal/health",\n    "/internal/metrics"\n  ],\n  "service_mesh": {{\n    "istio_version": "1.18.0",\n    "envoy_config": "/etc/envoy/envoy.yaml",\n    "internal_services": ["billing-api", "notification-service", "audit-service"]\n  }},\n  "access": "api_gateway_internal_routing_successful"\n}}'
                challenge = Challenge.query.filter_by(name='SSRF in API Gateway').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                gateway_result = f'API Gateway Request:\nEndpoint: {api_endpoint}\nUpstream: {upstream_url}\n\nGateway Response:\nError: Invalid upstream URL\nDescription: The upstream service is not accessible or not whitelisted.\n\nTry targeting internal microservices.'
    challenge = Challenge.query.filter_by(name='SSRF in API Gateway').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level19.html', flag=flag, ssrf_detected=ssrf_detected, api_endpoint=api_endpoint, upstream_url=upstream_url, gateway_result=gateway_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level20', methods=['GET', 'POST'])
@login_required
def ssrf_level20():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    target_url = request.form.get('target_url', '')
    timeout_ms = request.form.get('timeout_ms', '')
    timing_result = ''
    if request.method == 'POST':
        if target_url and timeout_ms:
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'admin.']
            if any((pattern in target_url.lower() for pattern in ssrf_patterns)):
                ssrf_detected = True
                timing_result = f'Time-based SSRF Analysis:\nTarget: {target_url}\nTimeout: {timeout_ms}ms\n\nTiming Analysis Results:\nRequest 1: 2847ms (TIMEOUT - Service exists but slow)\nRequest 2: 2851ms (TIMEOUT - Consistent timing)\nRequest 3: 2849ms (TIMEOUT - Service responding)\nRequest 4: 2850ms (TIMEOUT - Pattern detected)\nRequest 5: 2848ms (TIMEOUT - Internal service confirmed)\n\nStatistical Analysis:\nAverage Response Time: 2849ms\nStandard Deviation: 1.58ms\nConfidence Level: 99.7%\n\nConclusion: Internal service detected!\nThe consistent timeout pattern indicates an internal service\nthat is accessible but configured with a 3-second timeout.\n\nInternal Service Fingerprint:\n{{\n  "service_type": "internal-api-server",\n  "response_pattern": "timeout_based",\n  "estimated_timeout": "3000ms",\n  "service_status": "running",\n  "internal_network": "10.0.0.0/8",\n  "access": "timing_based_ssrf_detection_successful"\n}}'
                challenge = Challenge.query.filter_by(name='SSRF via Time-based Attacks').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                timing_result = f'Time-based SSRF Analysis:\nTarget: {target_url}\nTimeout: {timeout_ms}ms\n\nTiming Analysis Results:\nRequest 1: Connection refused (0ms)\nRequest 2: Connection refused (0ms)\nRequest 3: Connection refused (0ms)\n\nNo timing patterns detected.\nTry targeting internal services for timing analysis.'
    challenge = Challenge.query.filter_by(name='SSRF via Time-based Attacks').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level20.html', flag=flag, ssrf_detected=ssrf_detected, target_url=target_url, timeout_ms=timeout_ms, timing_result=timing_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level21', methods=['GET', 'POST'])
@login_required
def ssrf_level21():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    service_name = request.form.get('service_name', '')
    mesh_endpoint = request.form.get('mesh_endpoint', '')
    microservice_result = ''
    if request.method == 'POST':
        if service_name and mesh_endpoint:
            ssrf_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'istio', 'envoy', 'consul']
            if any((pattern in mesh_endpoint.lower() or pattern in service_name.lower() for pattern in ssrf_patterns)):
                ssrf_detected = True
                microservice_result = f'Service Mesh Discovery:\nService: {service_name}\nMesh Endpoint: {mesh_endpoint}\n\nIstio Service Mesh Response:\n{{\n  "service_discovery": {{\n    "service_name": "{service_name}",\n    "namespace": "production",\n    "cluster": "internal-k8s-cluster",\n    "endpoints": [\n      {{\n        "address": "10.244.1.15",\n        "port": 8080,\n        "status": "healthy"\n      }},\n      {{\n        "address": "10.244.1.16",\n        "port": 8080,\n        "status": "healthy"\n      }}\n    ]\n  }},\n  "envoy_config": {{\n    "admin_port": 15000,\n    "config_dump": {{\n      "clusters": [\n        {{\n          "name": "user-service",\n          "endpoints": ["10.244.1.15:8080", "10.244.1.16:8080"]\n        }},\n        {{\n          "name": "billing-service",\n          "endpoints": ["10.244.2.10:8080"]\n        }},\n        {{\n          "name": "admin-service",\n          "endpoints": ["10.244.3.5:8080"]\n        }}\n      ],\n      "secrets": {{\n        "tls_certificates": "/etc/ssl/service-mesh/",\n        "jwt_keys": "/etc/jwt/internal-keys/",\n        "database_credentials": "postgresql://mesh-user:secret@db.internal:5432/mesh"\n      }}\n    }}\n  }},\n  "internal_services": {{\n    "total_services": 23,\n    "critical_services": ["auth-service", "payment-service", "admin-panel"],\n    "service_mesh_version": "istio-1.18.0",\n    "access": "microservices_mesh_enumeration_successful"\n  }}\n}}'
                challenge = Challenge.query.filter_by(name='SSRF in Microservices').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                microservice_result = f'Service Mesh Discovery:\nService: {service_name}\nMesh Endpoint: {mesh_endpoint}\n\nConnection Result:\nFailed to access service mesh endpoint.\nError: Service not found or endpoint unreachable.\n\nTry targeting internal service mesh components.'
    challenge = Challenge.query.filter_by(name='SSRF in Microservices').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level21.html', flag=flag, ssrf_detected=ssrf_detected, service_name=service_name, mesh_endpoint=mesh_endpoint, microservice_result=microservice_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level22', methods=['GET', 'POST'])
@login_required
def ssrf_level22():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    smuggled_request = request.form.get('smuggled_request', '')
    wrapper_protocol = request.form.get('wrapper_protocol', '')
    smuggling_result = ''
    if request.method == 'POST':
        if smuggled_request and wrapper_protocol:
            ssrf_patterns = ['gopher://', 'localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'admin.']
            if any((pattern in wrapper_protocol.lower() or pattern in smuggled_request.lower() for pattern in ssrf_patterns)):
                ssrf_detected = True
                smuggling_result = f'Protocol Smuggling Attack:\nWrapper: {wrapper_protocol}\nSmuggled Request: {smuggled_request}\n\nAdvanced Protocol Smuggling Execution:\n{wrapper_protocol}\n\nSmuggled HTTP Request:\n{smuggled_request}\n\nInternal Server Response:\nHTTP/1.1 200 OK\nServer: nginx/1.18.0 (internal)\nContent-Type: application/json\nX-Internal-Admin: true\nX-Bypass-Filters: protocol-smuggling\n\n{{\n  "admin_panel": {{\n    "status": "accessible",\n    "authentication": "bypassed",\n    "internal_endpoints": [\n      "/admin/users",\n      "/admin/system",\n      "/admin/logs",\n      "/admin/config"\n    ]\n  }},\n  "protocol_smuggling": {{\n    "technique": "gopher_http_smuggling",\n    "bypass_method": "filter_evasion",\n    "target_protocol": "HTTP/1.1",\n    "wrapper_protocol": "gopher"\n  }},\n  "internal_data": {{\n    "database_access": "postgresql://admin:secret@db.internal:5432/admin",\n    "api_keys": ["sk-admin-12345", "sk-internal-67890"],\n    "system_info": {{\n      "hostname": "internal-admin-server",\n      "network": "10.0.0.0/8",\n      "services": ["redis", "postgresql", "elasticsearch"]\n    }},\n    "access": "protocol_smuggling_bypass_successful"\n  }}\n}}'
                challenge = Challenge.query.filter_by(name='SSRF via Protocol Smuggling').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                smuggling_result = f'Protocol Smuggling Attack:\nWrapper: {wrapper_protocol}\nSmuggled Request: {smuggled_request}\n\nConnection Result:\nProtocol smuggling attempt failed.\nError: Invalid protocol or request format.\n\nTry using advanced protocol smuggling techniques.'
    challenge = Challenge.query.filter_by(name='SSRF via Protocol Smuggling').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level22.html', flag=flag, ssrf_detected=ssrf_detected, smuggled_request=smuggled_request, wrapper_protocol=wrapper_protocol, smuggling_result=smuggling_result, challenge=challenge)

@ssrf_bp.route('/ssrf/level23', methods=['GET', 'POST'])
@login_required
def ssrf_level23():
    user = get_current_user()
    flag = None
    ssrf_detected = False
    function_url = request.form.get('function_url', '')
    cloud_metadata = request.form.get('cloud_metadata', '')
    serverless_result = ''
    if request.method == 'POST':
        if function_url and cloud_metadata:
            ssrf_patterns = ['169.254.169.254', 'localhost', '127.0.0.1', '0.0.0.0', '::1', 'internal.', 'lambda', 'metadata']
            if any((pattern in cloud_metadata.lower() or pattern in function_url.lower() for pattern in ssrf_patterns)):
                ssrf_detected = True
                serverless_result = f'Serverless Function SSRF:\nFunction: {function_url}\nMetadata: {cloud_metadata}\n\nAWS Lambda Execution Environment:\nFunction ARN: arn:aws:lambda:us-east-1:123456789012:function:internal-processor\nRuntime: python3.9\nMemory: 512MB\nTimeout: 30s\n\nCloud Metadata Access:\n{cloud_metadata}\n\nAWS Instance Metadata Response:\n{{\n  "accountId": "123456789012",\n  "architecture": "x86_64",\n  "availabilityZone": "us-east-1a",\n  "billingProducts": null,\n  "devpayProductCodes": null,\n  "marketplaceProductCodes": null,\n  "imageId": "ami-0abcdef1234567890",\n  "instanceId": "i-1234567890abcdef0",\n  "instanceType": "t3.micro",\n  "kernelId": null,\n  "pendingTime": "2024-01-15T10:30:00Z",\n  "privateIp": "10.0.1.100",\n  "ramdiskId": null,\n  "region": "us-east-1",\n  "version": "2017-09-30"\n}}\n\nIAM Security Credentials:\n{{\n  "Code": "Success",\n  "LastUpdated": "2024-01-15T10:30:00Z",\n  "Type": "AWS-HMAC",\n  "AccessKeyId": "ASIACKCEVSQ6C2EXAMPLE",\n  "SecretAccessKey": "9drTJvcULCfinhDYQEB9Yd9jC1z5yyHpChKkmk+S",\n  "Token": "AgoJb3JpZ2luX2VjECoaCXVzLWVhc3QtMSJGMEQCIBUGuQiUSqwXBWwgI9wIKV...",\n  "Expiration": "2024-01-15T16:30:00Z"\n}}\n\nInternal Serverless Data:\n{{\n  "lambda_functions": [\n    "internal-data-processor",\n    "admin-notification-service",\n    "billing-calculator",\n    "user-data-exporter"\n  ],\n  "vpc_config": {{\n    "SubnetIds": ["subnet-12345", "subnet-67890"],\n    "SecurityGroupIds": ["sg-internal-lambda"]\n  }},\n  "environment_variables": {{\n    "DATABASE_URL": "postgresql://lambda:secret@rds.internal.aws:5432/prod",\n    "API_GATEWAY_KEY": "sk-lambda-internal-12345",\n    "S3_BUCKET": "internal-lambda-data-bucket"\n  }},\n  "access": "serverless_cloud_metadata_access_successful"\n}}'
                challenge = Challenge.query.filter_by(name='SSRF in Serverless Functions').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                serverless_result = f'Serverless Function SSRF:\nFunction: {function_url}\nMetadata: {cloud_metadata}\n\nConnection Result:\nFailed to access serverless metadata.\nError: Metadata endpoint unreachable or invalid.\n\nTry targeting cloud metadata services.'
    challenge = Challenge.query.filter_by(name='SSRF in Serverless Functions').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('ssrf/ssrf_level23.html', flag=flag, ssrf_detected=ssrf_detected, function_url=function_url, cloud_metadata=cloud_metadata, serverless_result=serverless_result, challenge=challenge)

