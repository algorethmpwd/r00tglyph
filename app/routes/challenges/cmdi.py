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

cmdi_bp = Blueprint('cmdi', __name__)

@cmdi_bp.route('/cmdi/level1', methods=['GET', 'POST'])
@login_required
def cmdi_level1():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    hostname = request.form.get('hostname', '')
    ping_result = ''
    if request.method == 'POST':
        if hostname:
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\', '<', '>']
            for pattern in cmdi_patterns:
                if pattern in hostname:
                    cmdi_detected = True
                    ping_result = f'PING {hostname.split()[0]} (192.168.1.1): 56 data bytes\n'
                    ping_result += '64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=1.234 ms\n'
                    ping_result += '--- ping statistics ---\n'
                    ping_result += '1 packets transmitted, 1 packets received, 0.0% packet loss\n\n'
                    injected_cmd = hostname.split(pattern, 1)[1].strip() if pattern in hostname else ''
                    if injected_cmd:
                        ping_result += '[Command Output]\n'
                        ping_result += safe_execute_command(injected_cmd) + '\n'
                    challenge = Challenge.query.filter_by(name='Basic Command Injection').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                ping_result = f'PING {hostname} (192.168.1.1): 56 data bytes\n'
                ping_result += '64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=1.234 ms\n'
                ping_result += '--- ping statistics ---\n'
                ping_result += '1 packets transmitted, 1 packets received, 0.0% packet loss\n'
    challenge = Challenge.query.filter_by(name='Basic Command Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level1.html', flag=flag, cmdi_detected=cmdi_detected, hostname=hostname, ping_result=ping_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level2', methods=['GET', 'POST'])
@login_required
def cmdi_level2():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    command = request.form.get('command', '')
    output = ''
    filtered = False
    if request.method == 'POST':
        if command:
            filtered_command = command.replace('&', '').replace('|', '').replace(';', '')
            if filtered_command != command:
                filtered = True
                output = 'Security filter activated: Dangerous characters removed\n'
                output += f'Filtered command: {filtered_command}\n\n'
            bypass_patterns = ['$(', '`', '{', '}', '\\', '<', '>']
            for pattern in bypass_patterns:
                if pattern in command:
                    cmdi_detected = True
                    output += f'Executing deployment command: {command.split()[0]}\n'
                    output += 'Deployment started...\n'
                    output += 'Extracting files...\n'
                    if 'whoami' in command or 'id' in command:
                        output += '\nUnexpected output detected:\n'
                        output += 'root\n'
                    challenge = Challenge.query.filter_by(name='Command Injection with Filters').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                output += f'Executing deployment command: {filtered_command}\n'
                output += 'Deployment completed successfully\n'
    challenge = Challenge.query.filter_by(name='Command Injection with Filters').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level2.html', flag=flag, cmdi_detected=cmdi_detected, command=command, output=output, filtered=filtered, challenge=challenge)

@cmdi_bp.route('/cmdi/level3', methods=['GET', 'POST'])
@login_required
def cmdi_level3():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    email = request.form.get('email', '')
    status = ''
    if request.method == 'POST':
        if email:
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']
            for pattern in cmdi_patterns:
                if pattern in email:
                    cmdi_detected = True
                    status = 'Email notification sent successfully'
                    challenge = Challenge.query.filter_by(name='Blind Command Injection').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                status = 'Email notification sent successfully'
    challenge = Challenge.query.filter_by(name='Blind Command Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level3.html', flag=flag, cmdi_detected=cmdi_detected, email=email, status=status, challenge=challenge)

@cmdi_bp.route('/cmdi/level4', methods=['GET', 'POST'])
@login_required
def cmdi_level4():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    filename = request.form.get('filename', '')
    upload_result = ''
    if request.method == 'POST':
        if filename:
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')']
            for pattern in cmdi_patterns:
                if pattern in filename:
                    cmdi_detected = True
                    upload_result = f'Processing file: {filename.split()[0]}\n'
                    upload_result += 'File uploaded successfully\n'
                    upload_result += 'Running post-processing...\n\n'
                    if 'whoami' in filename:
                        upload_result += 'Post-processing output:\n'
                        upload_result += 'Current user: apache\n'
                    challenge = Challenge.query.filter_by(name='Command Injection via File Upload').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                upload_result = f'Processing file: {filename}\n'
                upload_result += 'File uploaded successfully\n'
    challenge = Challenge.query.filter_by(name='Command Injection via File Upload').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level4.html', flag=flag, cmdi_detected=cmdi_detected, filename=filename, upload_result=upload_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level5', methods=['GET', 'POST'])
@login_required
def cmdi_level5():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    service_name = request.form.get('service_name', '')
    api_result = ''
    if request.method == 'POST':
        if service_name:
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']
            for pattern in cmdi_patterns:
                if pattern in service_name:
                    cmdi_detected = True
                    api_result = f'Checking service status: {service_name.split()[0]}\n'
                    api_result += 'Service is running\n'
                    api_result += 'Health check: OK\n\n'
                    if 'env' in service_name or 'printenv' in service_name:
                        api_result += 'Environment variables:\n'
                        api_result += 'PATH=/usr/local/sbin:/usr/local/bin\n'
                    challenge = Challenge.query.filter_by(name='Command Injection in API Parameters').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                api_result = f'Checking service status: {service_name}\n'
                api_result += 'Service is running\n'
                api_result += 'Health check: OK\n'
    challenge = Challenge.query.filter_by(name='Command Injection in API Parameters').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level5.html', flag=flag, cmdi_detected=cmdi_detected, service_name=service_name, api_result=api_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level6', methods=['GET', 'POST'])
@login_required
def cmdi_level6():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    target = request.form.get('target', '')
    scan_result = ''
    waf_blocked = False
    if request.method == 'POST':
        if target:
            waf_patterns = ['&', '|', ';', 'whoami', 'id', 'cat', 'ls']
            for pattern in waf_patterns:
                if pattern in target.lower():
                    waf_blocked = True
                    scan_result = '⚠️ WAF Alert: Malicious input detected and blocked!'
                    break
            if not waf_blocked:
                bypass_patterns = ['`', '$', '(', ')', '\\', '{', '}']
                for pattern in bypass_patterns:
                    if pattern in target:
                        cmdi_detected = True
                        scan_result = f'Scanning target: {target.split()[0]}\n'
                        scan_result += 'Port scan completed\n'
                        scan_result += 'Open ports: 22, 80, 443\n\n'
                        if 'w' in target and 'h' in target:
                            scan_result += 'System information:\n'
                            scan_result += 'Current user: scanner\n'
                        challenge = Challenge.query.filter_by(name='Command Injection with WAF Bypass').first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(user.id, challenge.id, challenge.points)
                        break
                else:
                    scan_result = f'Scanning target: {target}\n'
                    scan_result += 'Port scan completed\n'
                    scan_result += 'Open ports: 22, 80, 443\n'
    challenge = Challenge.query.filter_by(name='Command Injection with WAF Bypass').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level6.html', flag=flag, cmdi_detected=cmdi_detected, target=target, scan_result=scan_result, waf_blocked=waf_blocked, challenge=challenge)

@cmdi_bp.route('/cmdi/level7', methods=['GET', 'POST'])
@login_required
def cmdi_level7():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    hostname = request.form.get('hostname', '')
    check_result = ''
    response_time = 0
    if request.method == 'POST':
        if hostname:
            import time
            start_time = time.time()
            cmdi_patterns = ['$', '`', '(', ')', '\\', '|', '&', ';', '<', '>', '{', '}']
            for pattern in cmdi_patterns:
                if pattern in hostname:
                    cmdi_detected = True
                    check_result = f'Checking status of {hostname.split()[0]}...\n\n'
                    if 'sleep' in hostname:
                        try:
                            sleep_duration = int(hostname.split('sleep')[1].strip().split()[0])
                            time.sleep(min(sleep_duration, 10))
                        except:
                            time.sleep(2)
                    if ('cat' in hostname or 'type' in hostname) and 'flag' in hostname:
                        check_result += 'Server status: Online\n'
                        challenge = Challenge.query.filter_by(name='Time-Based Blind Command Injection').first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(user.id, challenge.id, challenge.points)
                    elif 'grep' in hostname and 'flag' in hostname:
                        check_result += 'Server status: Online\n'
                        challenge = Challenge.query.filter_by(name='Time-Based Blind Command Injection').first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(user.id, challenge.id, challenge.points)
                    else:
                        check_result += 'Server status: Online\n'
                    break
            if not cmdi_detected:
                check_result = f'Checking status of {hostname}...\n\n'
                check_result += 'Server status: Online\n'
                time.sleep(0.5)
            response_time = round(time.time() - start_time, 2)
    challenge = Challenge.query.filter_by(name='Time-Based Blind Command Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level7.html', flag=flag, cmdi_detected=cmdi_detected, hostname=hostname, check_result=check_result, response_time=response_time, challenge=challenge)

@cmdi_bp.route('/cmdi/level8', methods=['GET', 'POST'])
@login_required
def cmdi_level8():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    device_id = request.form.get('device_id', '')
    management_result = ''
    if request.method == 'POST':
        if device_id:
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']
            for pattern in cmdi_patterns:
                if pattern in device_id:
                    cmdi_detected = True
                    management_result = f'Managing device: {device_id.split()[0]}\n'
                    management_result += 'Device status: Online\n'
                    management_result += 'Firmware version: 2.1.4\n\n'
                    if 'ps' in device_id or 'netstat' in device_id:
                        management_result += 'System processes:\n'
                        management_result += 'PID  COMMAND\n'
                        management_result += '1    /sbin/init\n'
                    challenge = Challenge.query.filter_by(name='Command Injection in Log Processing').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                management_result = f'Managing device: {device_id}\n'
                management_result += 'Device status: Online\n'
                management_result += 'Firmware version: 2.1.4\n'
    challenge = Challenge.query.filter_by(name='Command Injection in Log Processing').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level8.html', flag=flag, cmdi_detected=cmdi_detected, device_id=device_id, management_result=management_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level9', methods=['GET', 'POST'])
@login_required
def cmdi_level9():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    build_config = request.form.get('build_config', '{"branch": "main", "environment": "production"}')
    build_result = ''
    if request.method == 'POST':
        if build_config:
            try:
                config = json.loads(build_config)
                cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']
                for key, value in config.items():
                    if isinstance(value, str):
                        for pattern in cmdi_patterns:
                            if pattern in value:
                                cmdi_detected = True
                                build_result = f'Starting build for branch: {str(value).split()[0]}\n'
                                build_result += 'Build environment: production\n'
                                build_result += 'Build status: Running\n\n'
                                if 'uname' in value:
                                    build_result += 'Build system info:\n'
                                    build_result += 'Linux buildserver 5.4.0-74-generic\n'
                                challenge = Challenge.query.filter_by(name='Command Injection in JSON APIs').first()
                                if challenge:
                                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                    if challenge.id not in completed_ids:
                                        update_user_progress(user.id, challenge.id, challenge.points)
                                break
                        if cmdi_detected:
                            break
                if not cmdi_detected:
                    build_result = f"Starting build for branch: {config.get('branch', 'main')}\n"
                    build_result += f"Build environment: {config.get('environment', 'production')}\n"
                    build_result += 'Build completed successfully\n'
            except json.JSONDecodeError:
                build_result = 'Error: Invalid JSON configuration'
    challenge = Challenge.query.filter_by(name='Command Injection in JSON APIs').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level9.html', flag=flag, cmdi_detected=cmdi_detected, build_config=build_config, build_result=build_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level10', methods=['GET', 'POST'])
@login_required
def cmdi_level10():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    app_name = request.form.get('app_name', '')
    env_vars = request.form.get('env_vars', '')
    deploy_result = ''
    if request.method == 'POST':
        if app_name and env_vars:
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']
            for pattern in cmdi_patterns:
                if pattern in env_vars:
                    cmdi_detected = True
                    deploy_result = f'Deploying application: {app_name}\n'
                    deploy_result += 'Setting environment variables...\n'
                    deploy_result += 'Container started successfully\n\n'
                    if 'whoami' in env_vars or 'id' in env_vars:
                        deploy_result += 'Container initialization output:\n'
                        deploy_result += 'User: container-user\n'
                    challenge = Challenge.query.filter_by(name='Command Injection via Environment Variables').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                deploy_result = f'Deploying application: {app_name}\n'
                deploy_result += 'Setting environment variables...\n'
                deploy_result += 'Container started successfully\n'
    challenge = Challenge.query.filter_by(name='Command Injection via Environment Variables').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level10.html', flag=flag, cmdi_detected=cmdi_detected, app_name=app_name, env_vars=env_vars, deploy_result=deploy_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level11', methods=['GET', 'POST'])
@login_required
def cmdi_level11():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    xml_config = request.form.get('xml_config', '<?xml version="1.0"?><config><service>web</service><action>restart</action></config>')
    processing_result = ''
    if request.method == 'POST':
        if xml_config:
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']
            for pattern in cmdi_patterns:
                if pattern in xml_config:
                    cmdi_detected = True
                    processing_result = 'Processing XML configuration...\n'
                    processing_result += 'Parsing XML structure...\n'
                    processing_result += 'Executing service management commands...\n\n'
                    if 'whoami' in xml_config or 'id' in xml_config:
                        processing_result += 'Service management output:\n'
                        processing_result += 'Current system user: enterprise-admin\n'
                    challenge = Challenge.query.filter_by(name='Command Injection in XML Processing').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                processing_result = 'Processing XML configuration...\n'
                processing_result += 'Configuration applied successfully\n'
    challenge = Challenge.query.filter_by(name='Command Injection in XML Processing').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level11.html', flag=flag, cmdi_detected=cmdi_detected, xml_config=xml_config, processing_result=processing_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level12', methods=['GET', 'POST'])
@login_required
def cmdi_level12():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    target_network = request.form.get('target_network', '')
    scan_options = request.form.get('scan_options', '-sS -O')
    nmap_result = ''
    if request.method == 'POST':
        if target_network:
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']
            for pattern in cmdi_patterns:
                if pattern in target_network or pattern in scan_options:
                    cmdi_detected = True
                    nmap_result = f'Starting Nmap scan on {target_network.split()[0]}\n'
                    nmap_result += f'Scan options: {scan_options.split()[0]}\n'
                    nmap_result += 'Nmap scan report for target network\n'
                    nmap_result += 'Host is up (0.0010s latency)\n'
                    nmap_result += 'PORT     STATE SERVICE\n'
                    nmap_result += '22/tcp   open  ssh\n'
                    nmap_result += '80/tcp   open  http\n'
                    nmap_result += '443/tcp  open  https\n\n'
                    if 'uname' in target_network or 'uname' in scan_options:
                        nmap_result += 'System information leaked:\n'
                        nmap_result += 'Linux security-scanner 5.15.0-72-generic\n'
                    challenge = Challenge.query.filter_by(name='Command Injection in DevOps Tools').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                nmap_result = f'Starting Nmap scan on {target_network}\n'
                nmap_result += f'Scan options: {scan_options}\n'
                nmap_result += 'Scan completed successfully\n'
    challenge = Challenge.query.filter_by(name='Command Injection in DevOps Tools').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level12.html', flag=flag, cmdi_detected=cmdi_detected, target_network=target_network, scan_options=scan_options, nmap_result=nmap_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level13', methods=['GET', 'POST'])
@login_required
def cmdi_level13():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    graphql_query = request.form.get('graphql_query', 'query { systemInfo(hostname: "localhost") { status } }')
    query_result = ''
    if request.method == 'POST':
        if graphql_query:
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']
            for pattern in cmdi_patterns:
                if pattern in graphql_query:
                    cmdi_detected = True
                    query_result = 'Executing GraphQL query...\n'
                    query_result += 'Resolving systemInfo field...\n'
                    query_result += '{\n'
                    query_result += '  "data": {\n'
                    query_result += '    "systemInfo": {\n'
                    query_result += '      "status": "online"\n'
                    if 'whoami' in graphql_query:
                        query_result += '    },\n'
                        query_result += '    "debug": {\n'
                        query_result += '      "user": "graphql-api"\n'
                        query_result += '    }\n'
                    else:
                        query_result += '    }\n'
                    query_result += '  }\n'
                    query_result += '}\n'
                    challenge = Challenge.query.filter_by(name='Command Injection in GraphQL APIs').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                query_result = 'Executing GraphQL query...\n'
                query_result += '{\n'
                query_result += '  "data": {\n'
                query_result += '    "systemInfo": {\n'
                query_result += '      "status": "online"\n'
                query_result += '    }\n'
                query_result += '  }\n'
                query_result += '}\n'
    challenge = Challenge.query.filter_by(name='Command Injection in GraphQL APIs').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level13.html', flag=flag, cmdi_detected=cmdi_detected, graphql_query=graphql_query, query_result=query_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level14', methods=['GET', 'POST'])
@login_required
def cmdi_level14():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    websocket_message = request.form.get('websocket_message', '{"type": "monitor", "target": "server1", "action": "status"}')
    monitoring_result = ''
    if request.method == 'POST':
        if websocket_message:
            try:
                message = json.loads(websocket_message)
                cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']
                for key, value in message.items():
                    if isinstance(value, str):
                        for pattern in cmdi_patterns:
                            if pattern in value:
                                cmdi_detected = True
                                monitoring_result = 'WebSocket connection established\n'
                                monitoring_result += f"Processing message type: {message.get('type', 'unknown')}\n"
                                monitoring_result += f'Target: {str(value).split()[0]}\n'
                                monitoring_result += 'Real-time monitoring active...\n\n'
                                if 'ps' in value or 'netstat' in value:
                                    monitoring_result += 'System monitoring data:\n'
                                    monitoring_result += 'Active connections: 42\n'
                                    monitoring_result += 'System load: 0.8\n'
                                challenge = Challenge.query.filter_by(name='Command Injection in WebSocket Connections').first()
                                if challenge:
                                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                    if challenge.id not in completed_ids:
                                        update_user_progress(user.id, challenge.id, challenge.points)
                                break
                        if cmdi_detected:
                            break
                if not cmdi_detected:
                    monitoring_result = 'WebSocket connection established\n'
                    monitoring_result += f"Processing message type: {message.get('type', 'unknown')}\n"
                    monitoring_result += 'Monitoring data retrieved successfully\n'
            except json.JSONDecodeError:
                monitoring_result = 'Error: Invalid WebSocket message format'
    challenge = Challenge.query.filter_by(name='Command Injection in WebSocket Connections').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level14.html', flag=flag, cmdi_detected=cmdi_detected, websocket_message=websocket_message, monitoring_result=monitoring_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level15', methods=['GET', 'POST'])
@login_required
def cmdi_level15():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    function_payload = request.form.get('function_payload', '{"event": "process_data", "input": "sample.txt", "options": "--format json"}')
    lambda_result = ''
    if request.method == 'POST':
        if function_payload:
            try:
                payload = json.loads(function_payload)
                cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']
                for key, value in payload.items():
                    if isinstance(value, str):
                        for pattern in cmdi_patterns:
                            if pattern in value:
                                cmdi_detected = True
                                lambda_result = 'AWS Lambda Function Execution\n'
                                lambda_result += 'Function: data-processor-v2\n'
                                lambda_result += 'Runtime: python3.9\n'
                                lambda_result += f"Processing event: {payload.get('event', 'unknown')}\n"
                                lambda_result += 'Execution started...\n\n'
                                if 'env' in value or 'printenv' in value:
                                    lambda_result += 'Lambda environment variables:\n'
                                    lambda_result += 'AWS_REGION=us-east-1\n'
                                    lambda_result += 'AWS_LAMBDA_FUNCTION_NAME=data-processor\n'
                                    lambda_result += 'SECRET_FLAG=R00T{s3rv3rl3ss_cmd1_pwn3d}\n'
                                challenge = Challenge.query.filter_by(name='Command Injection in Serverless Functions').first()
                                if challenge:
                                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                    if challenge.id not in completed_ids:
                                        update_user_progress(user.id, challenge.id, challenge.points)
                                break
                        if cmdi_detected:
                            break
                if not cmdi_detected:
                    lambda_result = 'AWS Lambda Function Execution\n'
                    lambda_result += f"Processing event: {payload.get('event', 'unknown')}\n"
                    lambda_result += 'Function executed successfully\n'
            except json.JSONDecodeError:
                lambda_result = 'Error: Invalid Lambda payload format'
    challenge = Challenge.query.filter_by(name='Command Injection in Serverless Functions').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level15.html', flag=flag, cmdi_detected=cmdi_detected, function_payload=function_payload, lambda_result=lambda_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level16', methods=['GET', 'POST'])
@login_required
def cmdi_level16():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    automation_script = request.form.get('automation_script', 'backup_database.sh')
    script_params = request.form.get('script_params', '--target production --format tar.gz')
    execution_result = ''
    if request.method == 'POST':
        if automation_script and script_params:
            advanced_patterns = ['<(', '>(', '$(', '`', '{', '}', '\\', '|', '&']
            for pattern in advanced_patterns:
                if pattern in automation_script or pattern in script_params:
                    cmdi_detected = True
                    execution_result = f'Executing automation script: {automation_script.split()[0]}\n'
                    execution_result += f'Parameters: {script_params.split()[0]}\n'
                    execution_result += 'Script execution started...\n'
                    execution_result += 'Setting up environment...\n'
                    execution_result += 'Processing parameters...\n\n'
                    if 'whoami' in automation_script or 'whoami' in script_params:
                        execution_result += 'Process substitution executed:\n'
                        execution_result += 'Current user: automation-runner\n'
                        execution_result += 'Process ID: 12345\n'
                    challenge = Challenge.query.filter_by(name='Command Injection with Process Substitution').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                execution_result = f'Executing automation script: {automation_script}\n'
                execution_result += f'Parameters: {script_params}\n'
                execution_result += 'Script completed successfully\n'
    challenge = Challenge.query.filter_by(name='Command Injection with Process Substitution').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level16.html', flag=flag, cmdi_detected=cmdi_detected, automation_script=automation_script, script_params=script_params, execution_result=execution_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level17', methods=['GET', 'POST'])
@login_required
def cmdi_level17():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    container_image = request.form.get('container_image', 'nginx:latest')
    container_cmd = request.form.get('container_cmd', '/bin/sh -c "nginx -g \'daemon off;\'"')
    docker_result = ''
    if request.method == 'POST':
        if container_image and container_cmd:
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\', '..', '/proc', '/sys']
            for pattern in cmdi_patterns:
                if pattern in container_image or pattern in container_cmd:
                    cmdi_detected = True
                    docker_result = f'Creating container from image: {container_image.split()[0]}\n'
                    docker_result += f'Container command: {container_cmd.split()[0]}\n'
                    docker_result += 'Container ID: c4f3d2a1b5e6\n'
                    docker_result += 'Container started successfully\n'
                    docker_result += 'Monitoring container health...\n\n'
                    if 'proc' in container_cmd or 'sys' in container_cmd:
                        docker_result += 'Container escape detected:\n'
                        docker_result += 'Host filesystem access gained\n'
                        docker_result += 'Host kernel: Linux docker-host 5.15.0\n'
                    elif 'whoami' in container_cmd:
                        docker_result += 'Container execution output:\n'
                        docker_result += 'Container user: root\n'
                        docker_result += 'Container ID: c4f3d2a1b5e6\n'
                    challenge = Challenge.query.filter_by(name='Command Injection in Container Environments').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                docker_result = f'Creating container from image: {container_image}\n'
                docker_result += f'Container command: {container_cmd}\n'
                docker_result += 'Container started successfully\n'
    challenge = Challenge.query.filter_by(name='Command Injection in Container Environments').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level17.html', flag=flag, cmdi_detected=cmdi_detected, container_image=container_image, container_cmd=container_cmd, docker_result=docker_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level18', methods=['GET', 'POST'])
@login_required
def cmdi_level18():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    report_template = request.form.get('report_template', 'Report for {{customer_name}} generated on {{date}}')
    template_data = request.form.get('template_data', '{"customer_name": "Acme Corp", "date": "2024-12-19"}')
    report_result = ''
    if request.method == 'POST':
        if report_template and template_data:
            try:
                data = json.loads(template_data)
                ssti_patterns = ['{{', '}}', '{%', '%}', '__', 'import', 'os', 'subprocess']
                cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')']
                template_vulnerable = any((pattern in report_template for pattern in ssti_patterns))
                data_vulnerable = any((any((pattern in str(value) for pattern in cmdi_patterns)) for value in data.values() if isinstance(value, str)))
                if template_vulnerable or data_vulnerable:
                    cmdi_detected = True
                    report_result = 'Generating report from template...\n'
                    report_result += 'Template engine: Jinja2\n'
                    report_result += 'Processing template variables...\n'
                    report_result += 'Rendering report...\n\n'
                    if '__import__' in report_template or 'os' in report_template:
                        report_result += 'Template injection executed:\n'
                        report_result += 'System access gained through template engine\n'
                        report_result += 'Current working directory: /app/reports\n'
                    elif any(('whoami' in str(value) for value in data.values())):
                        report_result += 'Command injection in template data:\n'
                        report_result += 'Template user: report-generator\n'
                    challenge = Challenge.query.filter_by(name='Command Injection via Template Engines').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                else:
                    safe_template = report_template.replace('{{customer_name}}', data.get('customer_name', 'Unknown'))
                    safe_template = safe_template.replace('{{date}}', data.get('date', 'Unknown'))
                    report_result = f'Report generated successfully:\n\n{safe_template}\n'
            except json.JSONDecodeError:
                report_result = 'Error: Invalid JSON data format'
    challenge = Challenge.query.filter_by(name='Command Injection via Template Engines').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level18.html', flag=flag, cmdi_detected=cmdi_detected, report_template=report_template, template_data=template_data, report_result=report_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level19', methods=['GET', 'POST'])
@login_required
def cmdi_level19():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    queue_message = request.form.get('queue_message', '{"task": "process_file", "filename": "data.csv", "options": "--format json"}')
    processing_result = ''
    if request.method == 'POST':
        if queue_message:
            try:
                message = json.loads(queue_message)
                cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']
                for key, value in message.items():
                    if isinstance(value, str):
                        for pattern in cmdi_patterns:
                            if pattern in value:
                                cmdi_detected = True
                                processing_result = 'Message Queue Processing\n'
                                processing_result += 'Queue: task-processor\n'
                                processing_result += f"Task: {message.get('task', 'unknown')}\n"
                                processing_result += 'Worker node: worker-03\n'
                                processing_result += 'Processing message...\n\n'
                                if 'uname' in value or 'hostname' in value:
                                    processing_result += 'Worker system information:\n'
                                    processing_result += 'Worker hostname: task-worker-03\n'
                                    processing_result += 'Worker OS: Linux 5.15.0-72-generic\n'
                                challenge = Challenge.query.filter_by(name='Command Injection in Message Queues').first()
                                if challenge:
                                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                    if challenge.id not in completed_ids:
                                        update_user_progress(user.id, challenge.id, challenge.points)
                                break
                        if cmdi_detected:
                            break
                if not cmdi_detected:
                    processing_result = 'Message Queue Processing\n'
                    processing_result += f"Task: {message.get('task', 'unknown')}\n"
                    processing_result += 'Message processed successfully\n'
            except json.JSONDecodeError:
                processing_result = 'Error: Invalid message format'
    challenge = Challenge.query.filter_by(name='Command Injection in Message Queues').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level19.html', flag=flag, cmdi_detected=cmdi_detected, queue_message=queue_message, processing_result=processing_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level20', methods=['GET', 'POST'])
@login_required
def cmdi_level20():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    system_config = request.form.get('system_config', 'network.interface=eth0')
    webhook_url = request.form.get('webhook_url', 'https://webhook.site/unique-id')
    config_result = ''
    if request.method == 'POST':
        if system_config:
            oob_patterns = ['curl', 'wget', 'nc', 'netcat', 'ping', 'nslookup', 'dig']
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\']
            has_oob = any((pattern in system_config for pattern in oob_patterns))
            has_cmdi = any((pattern in system_config for pattern in cmdi_patterns))
            if has_oob and has_cmdi:
                cmdi_detected = True
                config_result = 'Industrial Control System Configuration\n'
                config_result += 'System: SCADA-HMI-01\n'
                config_result += 'Network: Air-gapped environment\n'
                config_result += 'Processing configuration...\n'
                config_result += 'Applying network settings...\n\n'
                if 'curl' in system_config or 'wget' in system_config:
                    config_result += 'Out-of-band communication detected:\n'
                    config_result += 'External connection established\n'
                    config_result += 'Data exfiltration in progress...\n'
                challenge = Challenge.query.filter_by(name='Command Injection with Out-of-Band').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                config_result = 'Industrial Control System Configuration\n'
                config_result += 'Configuration applied successfully\n'
                config_result += 'System status: Operational\n'
    challenge = Challenge.query.filter_by(name='Command Injection with Out-of-Band').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level20.html', flag=flag, cmdi_detected=cmdi_detected, system_config=system_config, webhook_url=webhook_url, config_result=config_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level21', methods=['GET', 'POST'])
@login_required
def cmdi_level21():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    function_code = request.form.get('function_code', 'def handler(event, context):\n    return {"status": "success"}')
    runtime_env = request.form.get('runtime_env', 'python3.9')
    cloud_result = ''
    if request.method == 'POST':
        if function_code:
            cmdi_patterns = ['os.system', 'subprocess', 'exec', 'eval', '__import__']
            for pattern in cmdi_patterns:
                if pattern in function_code:
                    cmdi_detected = True
                    cloud_result = 'Google Cloud Functions Deployment\n'
                    cloud_result += f'Runtime: {runtime_env}\n'
                    cloud_result += 'Function: data-processor-v3\n'
                    cloud_result += 'Region: us-central1\n'
                    cloud_result += 'Deploying function...\n'
                    cloud_result += 'Function deployed successfully\n'
                    cloud_result += 'Testing function execution...\n\n'
                    if 'os.system' in function_code or 'subprocess' in function_code:
                        cloud_result += 'Function execution output:\n'
                        cloud_result += 'Cloud environment: Google Cloud Platform\n'
                        cloud_result += 'Service account: cloud-function-sa@project.iam\n'
                    challenge = Challenge.query.filter_by(name='Command Injection in Cloud Functions').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                cloud_result = 'Google Cloud Functions Deployment\n'
                cloud_result += f'Runtime: {runtime_env}\n'
                cloud_result += 'Function deployed successfully\n'
    challenge = Challenge.query.filter_by(name='Command Injection in Cloud Functions').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level21.html', flag=flag, cmdi_detected=cmdi_detected, function_code=function_code, runtime_env=runtime_env, cloud_result=cloud_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level22', methods=['GET', 'POST'])
@login_required
def cmdi_level22():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    ssh_host = request.form.get('ssh_host', 'production-server.company.com')
    ssh_command = request.form.get('ssh_command', 'systemctl status nginx')
    ssh_result = ''
    if request.method == 'POST':
        if ssh_host and ssh_command:
            cmdi_patterns = ['&', '|', ';', '`', '$', '(', ')', '\\', '&&', '||']
            for pattern in cmdi_patterns:
                if pattern in ssh_command:
                    cmdi_detected = True
                    ssh_result = f'SSH Connection to {ssh_host.split()[0]}\n'
                    ssh_result += 'Authentication: Key-based\n'
                    ssh_result += f'Executing command: {ssh_command.split()[0]}\n'
                    ssh_result += 'Connection established...\n'
                    ssh_result += 'Command execution started...\n\n'
                    if 'whoami' in ssh_command or 'id' in ssh_command:
                        ssh_result += 'Remote command output:\n'
                        ssh_result += 'Remote user: deploy-user\n'
                        ssh_result += 'Remote host: production-server-01\n'
                        ssh_result += 'SSH session: pts/2\n'
                    challenge = Challenge.query.filter_by(name='Command Injection via SSH Commands').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            else:
                ssh_result = f'SSH Connection to {ssh_host}\n'
                ssh_result += f'Executing command: {ssh_command}\n'
                ssh_result += 'Command executed successfully\n'
    challenge = Challenge.query.filter_by(name='Command Injection via SSH Commands').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level22.html', flag=flag, cmdi_detected=cmdi_detected, ssh_host=ssh_host, ssh_command=ssh_command, ssh_result=ssh_result, challenge=challenge)

@cmdi_bp.route('/cmdi/level23', methods=['GET', 'POST'])
@login_required
def cmdi_level23():
    user = get_current_user()
    flag = None
    cmdi_detected = False
    infrastructure_config = request.form.get('infrastructure_config', '{"terraform": {"provider": "aws", "region": "us-east-1"}, "ansible": {"playbook": "deploy.yml", "inventory": "production"}}')
    deployment_result = ''
    if request.method == 'POST':
        if infrastructure_config:
            try:
                config = json.loads(infrastructure_config)
                advanced_patterns = ['$(', '`', '&&', '||', '|', ';', '&']
                terraform_cmdi = False
                ansible_cmdi = False
                if 'terraform' in config:
                    terraform_config = str(config['terraform'])
                    terraform_cmdi = any((pattern in terraform_config for pattern in advanced_patterns))
                if 'ansible' in config:
                    ansible_config = str(config['ansible'])
                    ansible_cmdi = any((pattern in ansible_config for pattern in advanced_patterns))
                if terraform_cmdi or ansible_cmdi:
                    cmdi_detected = True
                    deployment_result = 'Enterprise Infrastructure Deployment\n'
                    deployment_result += 'Platform: Multi-cloud hybrid infrastructure\n'
                    deployment_result += 'Tools: Terraform + Ansible + Kubernetes\n'
                    deployment_result += 'Environment: Production\n'
                    deployment_result += 'Initializing deployment pipeline...\n\n'
                    if terraform_cmdi:
                        deployment_result += 'Terraform execution:\n'
                        deployment_result += 'Provider: AWS\n'
                        deployment_result += 'Resources: EC2, RDS, S3\n'
                        deployment_result += 'Command injection in Terraform detected!\n\n'
                    if ansible_cmdi:
                        deployment_result += 'Ansible execution:\n'
                        deployment_result += 'Inventory: Production servers\n'
                        deployment_result += 'Playbook: Application deployment\n'
                        deployment_result += 'Command injection in Ansible detected!\n\n'
                    deployment_result += 'Infrastructure compromise achieved:\n'
                    deployment_result += 'Access level: Enterprise administrator\n'
                    deployment_result += 'Scope: Multi-cloud infrastructure\n'
                    challenge = Challenge.query.filter_by(name='Advanced Command Injection Chaining').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                else:
                    deployment_result = 'Enterprise Infrastructure Deployment\n'
                    deployment_result += 'Deployment completed successfully\n'
                    deployment_result += 'All systems operational\n'
            except json.JSONDecodeError:
                deployment_result = 'Error: Invalid infrastructure configuration format'
    challenge = Challenge.query.filter_by(name='Advanced Command Injection Chaining').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('cmdi/cmdi_level23.html', flag=flag, cmdi_detected=cmdi_detected, infrastructure_config=infrastructure_config, deployment_result=deployment_result, challenge=challenge)

