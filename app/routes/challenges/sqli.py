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

sqli_bp = Blueprint('sqli', __name__)

@sqli_bp.route('/sqli/level1', methods=['GET', 'POST'])
@login_required
def sqli_level1():
    user = get_current_user()
    flag = None
    sqli_detected = False
    error = None
    success = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        sqli_patterns = ["'", '"', '--', ';', 'OR', '=', 'UNION', 'SELECT', 'DROP', 'INSERT', 'DELETE', 'UPDATE']
        username_upper = username.upper()
        password_upper = password.upper()
        for pattern in sqli_patterns:
            if pattern.upper() in username_upper or pattern.upper() in password_upper:
                sqli_detected = True
                break
        if sqli_detected:
            challenge = Challenge.query.filter_by(name='Basic SQL Injection').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
            success = "SQL Injection detected! You've successfully bypassed the login."
        else:
            error = 'Invalid username or password.'
    challenge = Challenge.query.filter_by(name='Basic SQL Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level1.html', flag=flag, sqli_detected=sqli_detected, error=error, success=success)

@sqli_bp.route('/sqli/level2', methods=['GET'])
@login_required
def sqli_level2():
    user = get_current_user()
    flag = None
    sqli_detected = False
    search_term = request.args.get('search', '')
    search_performed = bool(search_term)
    products = []
    default_products = [{'id': 1, 'name': 'Smartphone X', 'category': 'Electronics', 'price': 999.99}, {'id': 2, 'name': 'Laptop Pro', 'category': 'Electronics', 'price': 1499.99}, {'id': 3, 'name': 'Wireless Headphones', 'category': 'Audio', 'price': 199.99}, {'id': 4, 'name': 'Smart Watch', 'category': 'Wearables', 'price': 299.99}, {'id': 5, 'name': 'Bluetooth Speaker', 'category': 'Audio', 'price': 129.99}]
    secret_product = {'id': 42, 'name': 'Secret Gadget', 'category': 'Classified', 'price': 9999.99}
    if search_term:
        sqli_patterns = ["'", '"', '--', ';', 'OR', '=', 'UNION', 'SELECT', 'DROP', 'INSERT', 'DELETE', 'UPDATE']
        search_upper = search_term.upper()
        for pattern in sqli_patterns:
            if pattern.upper() in search_upper:
                sqli_detected = True
                break
        products = [p for p in default_products if search_term.lower() in p['name'].lower()]
        if sqli_detected and ('42' in search_term or 'id=42' in search_term.lower() or 'id = 42' in search_term.lower()):
            products.append(secret_product)
            challenge = Challenge.query.filter_by(name='SQL Injection in Search').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
        elif sqli_detected and ('1=1' in search_term.lower() or 'or' in search_term.lower()):
            products = default_products.copy()
            products.append(secret_product)
            challenge = Challenge.query.filter_by(name='SQL Injection in Search').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
    challenge = Challenge.query.filter_by(name='SQL Injection in Search').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level2.html', flag=flag, sqli_detected=sqli_detected, search_term=search_term, search_performed=search_performed, products=products)

@sqli_bp.route('/sqli/level3', methods=['GET'])
@login_required
def sqli_level3():
    user = get_current_user()
    flag = None
    sqli_detected = False
    search_term = request.args.get('search', '')
    search_performed = bool(search_term)
    books = []
    default_books = [{'id': 1, 'title': 'The Great Gatsby', 'author': 'F. Scott Fitzgerald', 'category': 'Fiction', 'year': 1925}, {'id': 2, 'title': 'To Kill a Mockingbird', 'author': 'Harper Lee', 'category': 'Fiction', 'year': 1960}, {'id': 3, 'title': '1984', 'author': 'George Orwell', 'category': 'Science Fiction', 'year': 1949}, {'id': 4, 'title': 'Pride and Prejudice', 'author': 'Jane Austen', 'category': 'Romance', 'year': 1813}, {'id': 5, 'title': 'The Hobbit', 'author': 'J.R.R. Tolkien', 'category': 'Fantasy', 'year': 1937}]
    users = [{'id': 1, 'username': 'admin', 'password': 'FLAG{uni0n_b4s3d_sql1_m4st3r}', 'role': 'admin', 'created': 2023}]
    if search_term:
        sqli_patterns = ["'", '"', '--', ';', 'UNION', 'SELECT', 'FROM', 'WHERE']
        search_upper = search_term.upper()
        for pattern in sqli_patterns:
            if pattern.upper() in search_upper:
                sqli_detected = True
                break
        books = [b for b in default_books if search_term.lower() in b['title'].lower()]
        if sqli_detected and 'UNION' in search_upper and ('SELECT' in search_upper):
            if 'USER' in search_upper or 'ADMIN' in search_upper:
                admin_user = users[0]
                books.append({'id': admin_user['id'], 'title': admin_user['username'], 'author': admin_user['password'], 'category': admin_user['role'], 'year': admin_user['created']})
                challenge = Challenge.query.filter_by(name='SQL Injection with UNION').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
    challenge = Challenge.query.filter_by(name='SQL Injection with UNION').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level3.html', flag=flag, sqli_detected=sqli_detected, search_term=search_term, search_performed=search_performed, books=books)

@sqli_bp.route('/sqli/level4', methods=['GET'])
@login_required
def sqli_level4():
    user = get_current_user()
    flag = None
    sqli_detected = False
    user_id = request.args.get('id', '')
    user_exists = None
    hidden_users = {'1': {'username': 'admin', 'password': 'admin123'}, '2': {'username': 'user', 'password': 'password123'}, '3': {'username': 'guest', 'password': 'guest'}, '42': {'username': 'admin_secret', 'password': 'FLAG{bl1nd_sql1_3xtr4ct10n_pr0}'}}
    if user_id:
        sqli_patterns = ["'", '"', '--', ';', 'AND', 'OR', '=', 'SELECT', 'FROM', 'WHERE', 'SUBSTRING', 'ASCII']
        user_id_upper = user_id.upper()
        for pattern in sqli_patterns:
            if pattern.upper() in user_id_upper:
                sqli_detected = True
                break
        if sqli_detected:
            if '42' in user_id or 'admin_secret' in user_id.lower():
                user_exists = True
                challenge = Challenge.query.filter_by(name='Blind SQL Injection').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            elif 'SUBSTRING' in user_id_upper or 'ASCII' in user_id_upper or 'MID' in user_id_upper or ('CHAR' in user_id_upper):
                user_exists = True
                challenge = Challenge.query.filter_by(name='Blind SQL Injection').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                import random
                user_exists = random.choice([True, False])
        else:
            user_exists = user_id in hidden_users
    challenge = Challenge.query.filter_by(name='Blind SQL Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level4.html', flag=flag, sqli_detected=sqli_detected, user_id=user_id, user_exists=user_exists)

@sqli_bp.route('/sqli/level5', methods=['GET', 'POST'])
@login_required
def sqli_level5():
    user = get_current_user()
    flag = None
    sqli_detected = False
    message = None
    message_type = 'info'
    response_time = None
    if request.method == 'POST':
        email = request.form.get('email', '')
        sqli_patterns = ["'", '"', '--', ';', 'SLEEP', 'BENCHMARK', 'DELAY', 'PG_SLEEP', 'WAITFOR']
        email_upper = email.upper()
        for pattern in sqli_patterns:
            if pattern.upper() in email_upper:
                sqli_detected = True
                break
        import time
        start_time = time.time()
        if sqli_detected:
            if 'SLEEP' in email_upper or 'BENCHMARK' in email_upper or 'DELAY' in email_upper or ('PG_SLEEP' in email_upper) or ('WAITFOR' in email_upper):
                time.sleep(3)
                challenge = Challenge.query.filter_by(name='Time-Based Blind SQL Injection').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
                message = 'Thank you for subscribing to our newsletter!'
                message_type = 'success'
            else:
                message = 'Invalid email format. Please try again.'
                message_type = 'danger'
        else:
            message = 'Thank you for subscribing to our newsletter!'
            message_type = 'success'
        end_time = time.time()
        response_time = round(end_time - start_time, 2)
    challenge = Challenge.query.filter_by(name='Time-Based Blind SQL Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level5.html', flag=flag, sqli_detected=sqli_detected, message=message, message_type=message_type, response_time=response_time)

@sqli_bp.route('/sqli/level6', methods=['GET'])
@login_required
def sqli_level6():
    user = get_current_user()
    flag = None
    sqli_detected = False
    waf_blocked = False
    search_term = request.args.get('search', '')
    search_performed = bool(search_term)
    products = []
    default_products = [{'id': 1, 'name': 'Premium Smartphone', 'category': 'Electronics', 'price': 1299.99, 'stock': 45}, {'id': 2, 'name': 'Ultra Laptop', 'category': 'Electronics', 'price': 2499.99, 'stock': 20}, {'id': 3, 'name': 'Noise-Canceling Headphones', 'category': 'Audio', 'price': 349.99, 'stock': 78}, {'id': 4, 'name': 'Fitness Smartwatch', 'category': 'Wearables', 'price': 399.99, 'stock': 56}, {'id': 5, 'name': 'Portable Bluetooth Speaker', 'category': 'Audio', 'price': 199.99, 'stock': 112}]
    secret_product = {'id': 999, 'name': 'Classified Device', 'category': 'Restricted', 'price': 99999.99, 'stock': 1}
    if search_term:
        waf_patterns = ["'", '"', '--', '#', '/*', '*/', ';', 'UNION', 'SELECT', 'FROM', 'WHERE', 'OR', 'AND', '=']
        for pattern in waf_patterns:
            if pattern in search_term:
                waf_blocked = True
                break
        if not waf_blocked:
            bypass_patterns = ['||', 'oR', 'AnD', 'uNiOn', 'sElEcT', '1=1', '/**/', '%27', '0x']
            for pattern in bypass_patterns:
                if pattern in search_term:
                    sqli_detected = True
                    break
            products = [p for p in default_products if search_term.lower() in p['name'].lower()]
            if sqli_detected:
                products.append(secret_product)
                challenge = Challenge.query.filter_by(name='SQL Injection with WAF Bypass').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
    challenge = Challenge.query.filter_by(name='SQL Injection with WAF Bypass').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level6.html', flag=flag, sqli_detected=sqli_detected, search_term=search_term, search_performed=search_performed, products=products, waf_blocked=waf_blocked)

@sqli_bp.route('/sqli/level7', methods=['GET'])
@login_required
def sqli_level7():
    user = get_current_user()
    flag = None
    sqli_detected = False
    category_id = request.args.get('id', '')
    category = None
    error_message = None
    default_categories = {'1': {'id': 1, 'name': 'Electronics', 'description': 'Electronic devices and gadgets'}, '2': {'id': 2, 'name': 'Clothing', 'description': 'Apparel and fashion items'}, '3': {'id': 3, 'name': 'Books', 'description': 'Books, e-books, and publications'}, '4': {'id': 4, 'name': 'Home & Garden', 'description': 'Items for home and garden'}, '5': {'id': 5, 'name': 'Sports & Outdoors', 'description': 'Sports equipment and outdoor gear'}}
    if category_id:
        sqli_patterns = ["'", '"', '--', ';', 'UNION', 'SELECT', 'FROM', 'WHERE', 'CONCAT', 'GROUP BY', 'FLOOR', 'RAND', 'COUNT', 'EXTRACTVALUE', 'UPDATEXML']
        category_id_upper = category_id.upper()
        for pattern in sqli_patterns:
            if pattern.upper() in category_id_upper:
                sqli_detected = True
                break
        if sqli_detected:
            if 'CONCAT' in category_id_upper or 'GROUP BY' in category_id_upper or 'FLOOR' in category_id_upper or ('RAND' in category_id_upper) or ('EXTRACTVALUE' in category_id_upper) or ('UPDATEXML' in category_id_upper):
                error_message = "Error: SQLSTATE[42000]: Syntax error or access violation: 1690 BIGINT UNSIGNED value is out of range in '(SELECT 'FLAG{3rr0r_b4s3d_sql1_3xtr4ct10n}' FROM secrets WHERE key_name = 'level7_flag')'"
                challenge = Challenge.query.filter_by(name='Error-Based SQL Injection').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            else:
                error_message = "Error: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '" + category_id + "' at line 1"
        elif category_id in default_categories:
            category = default_categories[category_id]
        else:
            error_message = 'Error: Category not found'
    challenge = Challenge.query.filter_by(name='Error-Based SQL Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level7.html', flag=flag, sqli_detected=sqli_detected, category_id=category_id, category=category, error_message=error_message)

@sqli_bp.route('/sqli/level8', methods=['GET', 'POST'])
@login_required
def sqli_level8():
    user = get_current_user()
    flag = None
    sqli_detected = False
    username = 'test_user'
    bio = "I'm a security enthusiast."
    location = 'Cyberspace'
    website = 'https://example.com'
    profile = None
    view_user = request.args.get('view_user', '')
    users_db = {'admin': {'username': 'admin', 'bio': 'System administrator', 'location': 'Server Room', 'website': 'https://admin.example.com', 'is_admin': True, 'secret': 'The flag is: R00T{s3c0nd_0rd3r_sql1_1s_tr1cky}'}, 'test_user': {'username': 'test_user', 'bio': "I'm a security enthusiast.", 'location': 'Cyberspace', 'website': 'https://example.com', 'is_admin': False}}
    if request.method == 'POST':
        username = request.form.get('username', '')
        bio = request.form.get('bio', '')
        location = request.form.get('location', '')
        website = request.form.get('website', '')
        users_db['test_user'] = {'username': username, 'bio': bio, 'location': location, 'website': website, 'is_admin': False}
    if view_user:
        sqli_patterns = ["'", '"', '--', ';', 'OR', '=', 'UNION', 'SELECT', 'DROP', 'INSERT', 'DELETE', 'UPDATE']
        view_user_upper = view_user.upper()
        for pattern in sqli_patterns:
            if pattern.upper() in view_user_upper:
                sqli_detected = True
                break
        if sqli_detected:
            profile = users_db.get('admin')
            challenge = Challenge.query.filter_by(name='Second-Order SQL Injection').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
        else:
            profile = users_db.get(view_user)
    challenge = Challenge.query.filter_by(name='Second-Order SQL Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level8.html', flag=flag, sqli_detected=sqli_detected, username=username, bio=bio, location=location, website=website, view_user=view_user, profile=profile)

@sqli_bp.route('/sqli/level9', methods=['GET', 'POST'])
@login_required
def sqli_level9():
    user = get_current_user()
    flag = None
    sqli_detected = False
    request_body = None
    response = None
    if request.method == 'POST':
        request_body = request.form.get('request_body', '')
        try:
            json_data = json.loads(request_body)
            category = json_data.get('category', '')
            price = json_data.get('price', 0)
            in_stock = json_data.get('in_stock', False)
            sqli_patterns = ["'", '"', '--', ';', 'OR', '=', 'UNION', 'SELECT', 'FROM', 'WHERE', 'DROP', 'INSERT', 'DELETE', 'UPDATE']
            category_upper = category.upper() if isinstance(category, str) else ''
            price_str = str(price).upper()
            for pattern in sqli_patterns:
                if pattern.upper() in category_upper or pattern.upper() in price_str:
                    sqli_detected = True
                    break
            products = [{'id': 1, 'name': 'Smartphone Pro', 'category': 'Electronics', 'price': 999.99, 'description': 'Latest smartphone with advanced features'}, {'id': 2, 'name': 'Laptop Ultra', 'category': 'Electronics', 'price': 1499.99, 'description': 'Powerful laptop for professionals'}, {'id': 3, 'name': 'Wireless Earbuds', 'category': 'Electronics', 'price': 199.99, 'description': 'Premium wireless earbuds with noise cancellation'}]
            filtered_products = []
            for product in products:
                if (product['category'] == category or not category) and product['price'] <= price:
                    if not in_stock or (in_stock and product.get('stock', 10) > 0):
                        filtered_products.append(product)
            if sqli_detected:
                admin_product = {'id': 999, 'name': 'Admin Console', 'category': 'Restricted', 'price': 9999.99, 'description': 'Administrative product with flag: R00T{r3st_4p1_sql1_1nj3ct10n_pwn3d}'}
                filtered_products.append(admin_product)
                challenge = Challenge.query.filter_by(name='SQL Injection in REST API').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            response = json.dumps({'products': filtered_products})
        except json.JSONDecodeError:
            response = json.dumps({'error': 'Invalid JSON format'})
        except Exception as e:
            response = json.dumps({'error': str(e)})
    challenge = Challenge.query.filter_by(name='SQL Injection in REST API').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level9.html', flag=flag, sqli_detected=sqli_detected, request_body=request_body, response=response)

@sqli_bp.route('/sqli/level10', methods=['GET', 'POST'])
@login_required
def sqli_level10():
    user = get_current_user()
    flag = None
    sqli_detected = False
    error = None
    success = None
    documents = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        nosql_patterns = ['$ne', '$gt', '$lt', '$regex', '$where', '$exists', '$elemMatch', '$nin', '$in', '$all', '$size', '$or', '$and', '$not']
        for pattern in nosql_patterns:
            if pattern in username or pattern in password:
                sqli_detected = True
                break
        if username.startswith('{') and username.endswith('}') or (password.startswith('{') and password.endswith('}')):
            sqli_detected = True
        if '[' in username or '[' in password:
            sqli_detected = True
        if sqli_detected:
            success = 'Welcome, admin! You have successfully logged in.'
            documents = [{'id': 'doc001', 'title': 'System Architecture', 'category': 'Technical', 'content': 'Overview of the DocuStore system architecture and components.', 'created': '2023-01-15'}, {'id': 'doc002', 'title': 'Security Protocols', 'category': 'Security', 'content': 'Details of the security measures implemented in DocuStore.', 'created': '2023-02-20'}, {'id': 'doc003', 'title': 'Admin Credentials', 'category': 'Confidential', 'content': 'The flag is: R00T{n0sql_1nj3ct10n_byp4ss3d_4uth}', 'created': '2023-03-10'}]
            challenge = Challenge.query.filter_by(name='NoSQL Injection').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
        elif username == 'admin' and password == 'admin':
            success = 'Welcome, admin! You have successfully logged in.'
            documents = [{'id': 'doc001', 'title': 'System Architecture', 'category': 'Technical', 'content': 'Overview of the DocuStore system architecture and components.', 'created': '2023-01-15'}, {'id': 'doc002', 'title': 'Security Protocols', 'category': 'Security', 'content': 'Details of the security measures implemented in DocuStore.', 'created': '2023-02-20'}, {'id': 'doc003', 'title': 'Admin Credentials', 'category': 'Confidential', 'content': 'The flag is: R00T{n0sql_1nj3ct10n_byp4ss3d_4uth}', 'created': '2023-03-10'}]
            challenge = Challenge.query.filter_by(name='NoSQL Injection').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
        elif username == 'user' and password == 'password':
            success = 'Welcome, user! You have successfully logged in.'
            documents = [{'id': 'doc101', 'title': 'User Guide', 'category': 'Documentation', 'content': 'Guide for using the DocuStore system.', 'created': '2023-01-20'}, {'id': 'doc102', 'title': 'Project Plan', 'category': 'Project', 'content': 'Project plan for implementing DocuStore.', 'created': '2023-02-25'}]
        else:
            error = 'Invalid username or password. Please try again.'
    challenge = Challenge.query.filter_by(name='NoSQL Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level10.html', flag=flag, sqli_detected=sqli_detected, error=error, success=success, documents=documents)

@sqli_bp.route('/sqli/level11', methods=['GET', 'POST'])
@login_required
def sqli_level11():
    user = get_current_user()
    flag = None
    sqli_detected = False
    query = None
    response = None
    if request.method == 'POST':
        query = request.form.get('query', '')
        graphql_patterns = ['__schema', '__type', 'introspection', 'getPost(id: 999', 'isPrivate', 'admin']
        for pattern in graphql_patterns:
            if pattern in query:
                sqli_detected = True
                break
        if 'getPost(id: 1)' in query:
            response = '\n{\n  "data": {\n    "getPost": {\n      "id": "1",\n      "title": "Getting Started with GraphQL",\n      "content": "GraphQL is a query language for APIs and a runtime for fulfilling those queries with your existing data.",\n      "author": {\n        "name": "John Doe"\n      }\n    }\n  }\n}\n'
        elif 'getPost(id: 2)' in query:
            response = '\n{\n  "data": {\n    "getPost": {\n      "id": "2",\n      "title": "Advanced GraphQL Techniques",\n      "content": "Learn how to use fragments, variables, and directives in GraphQL to make your queries more efficient.",\n      "author": {\n        "name": "Jane Smith"\n      }\n    }\n  }\n}\n'
        elif 'getPosts' in query:
            response = '\n{\n  "data": {\n    "getPosts": [\n      {\n        "id": "1",\n        "title": "Getting Started with GraphQL",\n        "isPrivate": false\n      },\n      {\n        "id": "2",\n        "title": "Advanced GraphQL Techniques",\n        "isPrivate": false\n      },\n      {\n        "id": "3",\n        "title": "GraphQL Security Best Practices",\n        "isPrivate": false\n      },\n      {\n        "id": "999",\n        "title": "Admin Notes",\n        "isPrivate": true\n      }\n    ]\n  }\n}\n'
        elif '__schema' in query or '__type' in query:
            response = '\n{\n  "data": {\n    "__schema": {\n      "types": [\n        {\n          "name": "Query",\n          "fields": [\n            {\n              "name": "getPost",\n              "type": {\n                "name": "Post",\n                "kind": "OBJECT"\n              }\n            },\n            {\n              "name": "getPosts",\n              "type": {\n                "name": null,\n                "kind": "LIST"\n              }\n            },\n            {\n              "name": "searchPosts",\n              "type": {\n                "name": null,\n                "kind": "LIST"\n              }\n            }\n          ]\n        },\n        {\n          "name": "Post",\n          "fields": [\n            {\n              "name": "id",\n              "type": {\n                "name": null,\n                "kind": "NON_NULL"\n              }\n            },\n            {\n              "name": "title",\n              "type": {\n                "name": null,\n                "kind": "NON_NULL"\n              }\n            },\n            {\n              "name": "content",\n              "type": {\n                "name": null,\n                "kind": "NON_NULL"\n              }\n            },\n            {\n              "name": "isPrivate",\n              "type": {\n                "name": null,\n                "kind": "NON_NULL"\n              }\n            },\n            {\n              "name": "author",\n              "type": {\n                "name": "User",\n                "kind": "OBJECT"\n              }\n            }\n          ]\n        }\n      ]\n    }\n  }\n}\n'
        elif 'getPost(id: 999)' in query and 'isPrivate' in query:
            response = '\n{\n  "data": {\n    "getPost": {\n      "id": "999",\n      "title": "Admin Notes",\n      "content": "Security audit scheduled for next week. Flag: R00T{gr4phql_1nj3ct10n_3xpl01t3d}",\n      "isPrivate": true,\n      "author": {\n        "name": "Admin",\n        "role": "ADMIN"\n      }\n    }\n  }\n}\n'
            challenge = Challenge.query.filter_by(name='GraphQL Injection').first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(user.id, challenge.id, challenge.points)
        else:
            response = '\n{\n  "data": null,\n  "errors": [\n    {\n      "message": "Invalid query. Please check your syntax and try again."\n    }\n  ]\n}\n'
    challenge = Challenge.query.filter_by(name='GraphQL Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level11.html', flag=flag, sqli_detected=sqli_detected, query=query, response=response)

@sqli_bp.route('/sqli/level12', methods=['GET', 'POST'])
@login_required
def sqli_level12():
    user = get_current_user()
    flag = None
    sqli_detected = False
    department = request.form.get('department', 'IT')
    search_term = request.form.get('search_term', '')
    employees = []
    error = None
    default_employees = {'IT': [{'id': 'IT001', 'name': 'John Smith', 'position': 'IT Manager', 'department': 'IT', 'email': 'john.smith@corphr.com', 'phone': '555-1234', 'salary': '85,000', 'joined': '2018-05-15'}, {'id': 'IT002', 'name': 'Sarah Johnson', 'position': 'Senior Developer', 'department': 'IT', 'email': 'sarah.johnson@corphr.com', 'phone': '555-2345', 'salary': '78,000', 'joined': '2019-02-10'}, {'id': 'IT003', 'name': 'Michael Chen', 'position': 'System Administrator', 'department': 'IT', 'email': 'michael.chen@corphr.com', 'phone': '555-3456', 'salary': '72,000', 'joined': '2020-07-22'}], 'HR': [{'id': 'HR001', 'name': 'Emily Davis', 'position': 'HR Director', 'department': 'HR', 'email': 'emily.davis@corphr.com', 'phone': '555-4567', 'salary': '92,000', 'joined': '2017-11-05'}, {'id': 'HR002', 'name': 'Robert Wilson', 'position': 'Recruitment Specialist', 'department': 'HR', 'email': 'robert.wilson@corphr.com', 'phone': '555-5678', 'salary': '65,000', 'joined': '2021-03-18'}], 'Finance': [{'id': 'FIN001', 'name': 'Jennifer Lee', 'position': 'Finance Manager', 'department': 'Finance', 'email': 'jennifer.lee@corphr.com', 'phone': '555-6789', 'salary': '95,000', 'joined': '2016-09-30'}, {'id': 'FIN002', 'name': 'David Brown', 'position': 'Senior Accountant', 'department': 'Finance', 'email': 'david.brown@corphr.com', 'phone': '555-7890', 'salary': '82,000', 'joined': '2018-12-07'}], 'Marketing': [{'id': 'MKT001', 'name': 'Lisa Taylor', 'position': 'Marketing Director', 'department': 'Marketing', 'email': 'lisa.taylor@corphr.com', 'phone': '555-8901', 'salary': '90,000', 'joined': '2019-04-15'}], 'Sales': [{'id': 'SLS001', 'name': 'James Anderson', 'position': 'Sales Manager', 'department': 'Sales', 'email': 'james.anderson@corphr.com', 'phone': '555-9012', 'salary': '88,000', 'joined': '2017-06-22'}], 'Executive': [{'id': 'EXE001', 'name': 'Elizabeth Williams', 'position': 'CEO', 'department': 'Executive', 'email': 'elizabeth.williams@corphr.com', 'phone': '555-0123', 'salary': '250,000 (Flag: R00T{0rm_sql1_1nj3ct10n_byp4ss3d})', 'joined': '2015-01-01'}]}
    if request.method == 'POST':
        sqli_patterns = ["'", '"', '--', ';', 'OR', '=', 'UNION', 'SELECT', 'FROM', 'WHERE', 'DROP', 'INSERT', 'DELETE', 'UPDATE']
        search_term_upper = search_term.upper() if isinstance(search_term, str) else ''
        for pattern in sqli_patterns:
            if pattern.upper() in search_term_upper:
                sqli_detected = True
                break
        if department in default_employees:
            if sqli_detected:
                for dept in default_employees:
                    employees.extend(default_employees[dept])
                challenge = Challenge.query.filter_by(name='ORM-based SQL Injection').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            elif search_term:
                for employee in default_employees[department]:
                    if search_term.lower() in employee['name'].lower() or search_term.lower() in employee['position'].lower():
                        employees.append(employee)
                if not employees:
                    error = f"No employees found in {department} department matching '{search_term}'."
            else:
                employees = default_employees[department]
        else:
            error = 'Invalid department selected.'
    else:
        employees = default_employees['IT']
    challenge = Challenge.query.filter_by(name='ORM-based SQL Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level12.html', flag=flag, sqli_detected=sqli_detected, department=department, search_term=search_term, employees=employees, error=error)

@sqli_bp.route('/sqli/level13', methods=['GET', 'POST'])
@login_required
def sqli_level13():
    user = get_current_user()
    flag = None
    sqli_detected = False
    search_term = request.form.get('search_term', '')
    stocks = []
    error = None
    dns_logs = []
    default_stocks = [{'symbol': 'AAPL', 'name': 'Apple Inc.', 'price': '182.63', 'change': 1.25}, {'symbol': 'MSFT', 'name': 'Microsoft Corporation', 'price': '337.22', 'change': 0.87}, {'symbol': 'GOOGL', 'name': 'Alphabet Inc.', 'price': '131.86', 'change': -0.32}, {'symbol': 'AMZN', 'name': 'Amazon.com, Inc.', 'price': '127.74', 'change': 0.56}, {'symbol': 'TSLA', 'name': 'Tesla, Inc.', 'price': '237.49', 'change': -1.45}]
    if request.method == 'POST':
        sqli_patterns = ["'", '"', '--', ';', 'UNION', 'SELECT', 'FROM', 'WHERE', 'DROP', 'INSERT', 'DELETE', 'UPDATE', 'LOAD_FILE', 'UTL_HTTP', 'xp_dirtree', 'sp_OAMethod', 'UTL_INADDR', 'attacker.com']
        search_term_upper = search_term.upper() if isinstance(search_term, str) else ''
        for pattern in sqli_patterns:
            if pattern.upper() in search_term_upper:
                sqli_detected = True
                break
        if search_term:
            if sqli_detected:
                dns_logs = [{'timestamp': '2023-07-15 14:32:18', 'query': 'db-server.local', 'type': 'A', 'source': '192.168.1.10'}, {'timestamp': '2023-07-15 14:32:19', 'query': 'R00T{0ut_0f_b4nd_sql1_3xf1ltr4t10n}.attacker.com', 'type': 'A', 'source': '192.168.1.10'}]
                challenge = Challenge.query.filter_by(name='Out-of-band SQL Injection').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
                stocks = default_stocks
            else:
                for stock in default_stocks:
                    if search_term.upper() in stock['symbol'].upper() or search_term.lower() in stock['name'].lower():
                        stocks.append(stock)
                if not stocks:
                    error = f"No stocks found matching '{search_term}'."
        else:
            stocks = default_stocks
    else:
        stocks = default_stocks
    challenge = Challenge.query.filter_by(name='Out-of-band SQL Injection').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level13.html', flag=flag, sqli_detected=sqli_detected, search_term=search_term, stocks=stocks, error=error, dns_logs=dns_logs)

@sqli_bp.route('/sqli/level14', methods=['GET', 'POST'])
@login_required
def sqli_level14():
    user = get_current_user()
    flag = None
    sqli_detected = False
    category = request.form.get('category', 'Electronics')
    search_term = request.form.get('search_term', '')
    products = []
    error = None
    waf_blocked = False
    waf_logs = []
    if request.method == 'POST':

        def waf_check(input_str):
            blocked_patterns = ['SELECT', 'UNION', 'FROM', 'WHERE', '--', '/*', "'", '"', '=', '>', '<']
            for pattern in blocked_patterns:
                if pattern.upper() in input_str.upper():
                    import datetime
                    waf_logs.append({'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'rule_id': blocked_patterns.index(pattern) + 1, 'rule_name': f'Blocked pattern: {pattern}', 'action': 'BLOCK', 'ip': request.remote_addr})
                    return True
            return False
        if waf_check(category) or waf_check(search_term):
            waf_blocked = True
        else:
            if category == 'Electronics':
                products = [{'id': 1, 'name': 'Smartphone X', 'category': 'Electronics', 'price': 999.99, 'description': 'Latest smartphone with advanced features.'}, {'id': 2, 'name': 'Laptop Pro', 'category': 'Electronics', 'price': 1499.99, 'description': 'Professional laptop for developers.'}, {'id': 3, 'name': 'Wireless Headphones', 'category': 'Electronics', 'price': 199.99, 'description': 'Noise-cancelling wireless headphones.'}]
            elif category == 'Clothing':
                products = [{'id': 4, 'name': 'Designer T-shirt', 'category': 'Clothing', 'price': 49.99, 'description': 'Premium cotton t-shirt.'}, {'id': 5, 'name': 'Jeans', 'category': 'Clothing', 'price': 79.99, 'description': 'Comfortable denim jeans.'}, {'id': 6, 'name': 'Sneakers', 'category': 'Clothing', 'price': 129.99, 'description': 'Stylish and comfortable sneakers.'}]
            advanced_bypass_patterns = ['%27', '%2527', '%252527', 'un%69on', 'un%69%6fn', 'un%2569on', 'se%6cect', 'se%6c%65ct', 'se%2565ct', 'concat(0x', 'char(', 'hex(', '0x3', '0x4', '0x5', 'product%5fid', 'or%20product%5fid%3d999']
            for pattern in advanced_bypass_patterns:
                if pattern in category.lower() or pattern in search_term.lower():
                    sqli_detected = True
                    products.append({'id': 999, 'name': 'Restricted Product', 'category': 'ADMIN', 'price': 9999.99, 'description': 'This product contains the flag: R00T{4dv4nc3d_w4f_byp4ss_m4st3r}'})
                    challenge = Challenge.query.filter_by(name='SQL Injection with Advanced WAF Bypass').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
    challenge = Challenge.query.filter_by(name='SQL Injection with Advanced WAF Bypass').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level14.html', flag=flag, sqli_detected=sqli_detected, category=category, search_term=search_term, products=products, error=error, waf_blocked=waf_blocked, waf_logs=waf_logs)

@sqli_bp.route('/sqli/level15', methods=['GET', 'POST'])
@login_required
def sqli_level15():
    user = get_current_user()
    flag = None
    sqli_detected = False
    xml_data = None
    reports = []
    error = None
    if request.method == 'POST':
        xml_data = request.form.get('xml_data', '')
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_data)
            report_type = root.find('type').text if root.find('type') is not None else ''
            report_period = root.find('period').text if root.find('period') is not None else ''
            report_department = root.find('department').text if root.find('department') is not None else ''
            sqli_patterns = ["'", '"', '--', ';', 'UNION', 'SELECT', 'FROM', 'WHERE', 'OR', 'AND', '=']
            for pattern in sqli_patterns:
                if pattern in report_type or pattern in report_period or pattern in report_department:
                    sqli_detected = True
                    reports.append({'id': 999, 'title': 'Restricted Financial Report', 'type': 'confidential', 'period': 'annual', 'department': 'executive', 'data': 'This report contains the flag: R00T{xml_sql1_1nj3ct10n_3xpl01t3d}'})
                    challenge = Challenge.query.filter_by(name='SQL Injection via XML').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            if not sqli_detected:
                if report_type == 'sales':
                    reports = [{'id': 1, 'title': 'Sales Report Q1', 'type': 'sales', 'period': 'quarterly', 'department': report_department, 'data': 'Sales increased by 15% in Q1.'}, {'id': 2, 'title': 'Sales Report Q2', 'type': 'sales', 'period': 'quarterly', 'department': report_department, 'data': 'Sales increased by 10% in Q2.'}]
                elif report_type == 'inventory':
                    reports = [{'id': 3, 'title': 'Inventory Status', 'type': 'inventory', 'period': report_period, 'department': report_department, 'data': 'Current inventory levels are optimal.'}, {'id': 4, 'title': 'Inventory Forecast', 'type': 'inventory', 'period': report_period, 'department': report_department, 'data': 'Inventory forecast for next quarter is stable.'}]
                elif report_type == 'marketing':
                    reports = [{'id': 5, 'title': 'Marketing Campaign Results', 'type': 'marketing', 'period': report_period, 'department': report_department, 'data': 'Recent campaign resulted in 20% increase in leads.'}, {'id': 6, 'title': 'Marketing Budget', 'type': 'marketing', 'period': report_period, 'department': report_department, 'data': 'Marketing budget allocation for next quarter.'}]
        except Exception as e:
            error = f'Error processing XML: {str(e)}'
    challenge = Challenge.query.filter_by(name='SQL Injection via XML').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level15.html', flag=flag, sqli_detected=sqli_detected, xml_data=xml_data, reports=reports, error=error)

@sqli_bp.route('/sqli/level16', methods=['GET', 'POST'])
@login_required
def sqli_level16():
    user = get_current_user()
    flag = None
    sqli_detected = False
    ws_message = None
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            sqli_detected = data.get('sqli_detected', False)
            ws_message = data.get('ws_message', '')
            if sqli_detected:
                challenge = Challenge.query.filter_by(name='SQL Injection in WebSockets').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
                    return jsonify({'success': True})
                return jsonify({'success': False, 'error': 'Challenge not found'})
    challenge = Challenge.query.filter_by(name='SQL Injection in WebSockets').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level16.html', flag=flag, sqli_detected=sqli_detected, ws_message=ws_message)

@sqli_bp.route('/sqli/level17', methods=['GET', 'POST'])
@login_required
def sqli_level17():
    import json
    user = get_current_user()
    flag = None
    sqli_detected = False
    api_request = None
    api_response = None
    if request.method == 'POST':
        api_request = request.form.get('api_request', '')
        try:
            data = json.loads(api_request)
            action = data.get('action', '')
            category = data.get('category', '')
            sort = data.get('sort', 'price_asc')
            limit = data.get('limit', 10)
            search = data.get('search', '')
            sqli_patterns = ["'", '"', '--', ';', 'UNION', 'SELECT', 'FROM', 'WHERE', 'OR', 'AND', '=', '>', '<']
            for pattern in sqli_patterns:
                if pattern in category or pattern in sort or pattern in str(search):
                    sqli_detected = True
                    api_response = json.dumps({'status': 'success', 'products': [{'id': 999, 'name': 'Restricted Product', 'description': 'This product contains the flag: R00T{m0b1l3_4pp_b4ck3nd_sql1_pwn3d}', 'price': 9999.99, 'category': 'RESTRICTED'}]}, indent=2)
                    challenge = Challenge.query.filter_by(name='SQL Injection in Mobile App Backend').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            if not sqli_detected:
                products = []
                if category.lower() == 'electronics':
                    products = [{'id': 1, 'name': 'Smartphone X', 'description': 'Latest smartphone with advanced features.', 'price': 999.99, 'category': 'Electronics'}, {'id': 2, 'name': 'Laptop Pro', 'description': 'Professional laptop for developers.', 'price': 1499.99, 'category': 'Electronics'}, {'id': 3, 'name': 'Wireless Headphones', 'description': 'Noise-cancelling wireless headphones.', 'price': 199.99, 'category': 'Electronics'}]
                elif category.lower() == 'clothing':
                    products = [{'id': 4, 'name': 'Designer T-shirt', 'description': 'Premium cotton t-shirt.', 'price': 49.99, 'category': 'Clothing'}, {'id': 5, 'name': 'Jeans', 'description': 'Comfortable denim jeans.', 'price': 79.99, 'category': 'Clothing'}, {'id': 6, 'name': 'Sneakers', 'description': 'Stylish and comfortable sneakers.', 'price': 129.99, 'category': 'Clothing'}]
                if search:
                    products = [p for p in products if search.lower() in p['name'].lower() or search.lower() in p['description'].lower()]
                if sort == 'price_asc':
                    products.sort(key=lambda p: p['price'])
                elif sort == 'price_desc':
                    products.sort(key=lambda p: p['price'], reverse=True)
                elif sort == 'name_asc':
                    products.sort(key=lambda p: p['name'])
                elif sort == 'name_desc':
                    products.sort(key=lambda p: p['name'], reverse=True)
                products = products[:limit]
                api_response = json.dumps({'status': 'success', 'products': products}, indent=2)
        except Exception as e:
            api_response = json.dumps({'status': 'error', 'message': str(e)}, indent=2)
    challenge = Challenge.query.filter_by(name='SQL Injection in Mobile App Backend').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level17.html', flag=flag, sqli_detected=sqli_detected, api_request=api_request, api_response=api_response)

@sqli_bp.route('/sqli/level18', methods=['GET', 'POST'])
@login_required
def sqli_level18():
    import datetime
    import json
    import random
    user = get_current_user()
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
            data = json.loads(event_data)
            action = data.get('action', '')
            dataset = data.get('dataset', '')
            filter_condition = data.get('filter', '')
            format_type = data.get('format', 'json')
            start_time = datetime.datetime.now()
            function_logs.append({'timestamp': start_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], 'level': 'info', 'message': f'Function execution started with event: {json.dumps(data)}'})
            function_logs.append({'timestamp': (start_time + datetime.timedelta(milliseconds=50)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], 'level': 'info', 'message': f'Connecting to database...'})
            sqli_patterns = ["'", '"', '--', ';', 'UNION', 'SELECT', 'FROM', 'WHERE', 'OR', 'AND', '=', '>', '<']
            sql_query = f'SELECT * FROM {dataset} WHERE {filter_condition} LIMIT 1000'
            function_logs.append({'timestamp': (start_time + datetime.timedelta(milliseconds=100)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], 'level': 'info', 'message': f'Executing query: {sql_query}'})
            for pattern in sqli_patterns:
                if pattern in dataset or pattern in filter_condition:
                    sqli_detected = True
                    function_logs.append({'timestamp': (start_time + datetime.timedelta(milliseconds=150)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], 'level': 'warning', 'message': f'Unusual query pattern detected: {sql_query}'})
                    function_response = json.dumps({'status': 'success', 'data': [{'id': 1, 'flag': 'R00T{cl0ud_funct10n_sql1_1nj3ct10n_pwn3d}', 'created_at': '2023-01-01T00:00:00Z', 'is_active': True}]}, indent=2)
                    challenge = Challenge.query.filter_by(name='SQL Injection in Cloud Functions').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            if not sqli_detected:
                if dataset == 'sales_2023':
                    function_response = json.dumps({'status': 'success', 'data': [{'id': 1, 'product': 'Smartphone X', 'quantity': 150, 'revenue': 149998.5, 'region': 'US'}, {'id': 2, 'product': 'Laptop Pro', 'quantity': 75, 'revenue': 112499.25, 'region': 'US'}, {'id': 3, 'product': 'Wireless Headphones', 'quantity': 200, 'revenue': 39998.0, 'region': 'US'}]}, indent=2)
                elif dataset == 'customers_2023':
                    function_response = json.dumps({'status': 'success', 'data': [{'id': 1, 'name': 'John Doe', 'email': 'john.doe@example.com', 'region': 'US'}, {'id': 2, 'name': 'Jane Smith', 'email': 'jane.smith@example.com', 'region': 'US'}, {'id': 3, 'name': 'Bob Johnson', 'email': 'bob.johnson@example.com', 'region': 'US'}]}, indent=2)
                else:
                    function_response = json.dumps({'status': 'error', 'message': f"Dataset '{dataset}' not found or access denied"}, indent=2)
            end_time = datetime.datetime.now()
            duration = (end_time - start_time).total_seconds() * 1000
            function_logs.append({'timestamp': end_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], 'level': 'info', 'message': f'Function execution completed in {duration:.2f}ms'})
            function_duration = f'{duration:.2f}'
            function_memory = str(random.randint(50, 150))
            function_status = 'Success'
        except Exception as e:
            function_response = json.dumps({'status': 'error', 'message': str(e)}, indent=2)
            function_duration = str(random.randint(10, 50))
            function_memory = str(random.randint(50, 150))
            function_status = 'Error'
            function_logs.append({'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], 'level': 'error', 'message': f'Function execution failed: {str(e)}'})
    challenge = Challenge.query.filter_by(name='SQL Injection in Cloud Functions').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level18.html', flag=flag, sqli_detected=sqli_detected, event_data=event_data, function_response=function_response, function_duration=function_duration, function_memory=function_memory, function_status=function_status, function_logs=function_logs)

@sqli_bp.route('/sqli/level19', methods=['GET', 'POST'])
@login_required
def sqli_level19():
    user = get_current_user()
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
                import csv
                from io import StringIO
                csv_file = StringIO(csv_content)
                csv_reader = csv.reader(csv_file)
                csv_rows = list(csv_reader)
                if len(csv_rows) > 0:
                    csv_preview = csv_rows[:10]
                    header = csv_rows[0]
                    data_rows = csv_rows[1:]
                    rows_processed = len(data_rows)
                    rows_imported = 0
                    import_errors = []
                    import_output = ''
                    expected_columns = ['id', 'name', 'email', 'department']
                    if len(header) >= len(expected_columns) and all((col.lower() == expected_columns[i].lower() for i, col in enumerate(header[:len(expected_columns)]))):
                        for i, row in enumerate(data_rows):
                            if len(row) >= len(expected_columns):
                                id_val = row[0]
                                name_val = row[1]
                                email_val = row[2]
                                department_val = row[3]
                                sqli_patterns = ["'", '"', '--', ';', 'UNION', 'SELECT', 'FROM', 'WHERE', 'OR', 'AND', '=', '>', '<']
                                for pattern in sqli_patterns:
                                    if pattern in id_val or pattern in name_val or pattern in email_val or (pattern in department_val):
                                        sqli_detected = True
                                        import_output += f'SQL Error in row {i + 1}: Syntax error in SQL statement\n'
                                        import_output += f"Attempted query: INSERT INTO employees (id, name, email, department) VALUES ('{id_val}', '{name_val}', '{email_val}', '{department_val}')\n\n"
                                        import_output += 'Unexpected query result:\n'
                                        import_output += 'id | flag\n'
                                        import_output += '---+-----\n'
                                        import_output += f'1  | R00T{{f1l3_upl04d_sql1_1nj3ct10n_pwn3d}}\n'
                                        import_errors.append(f'Error in row {i + 1}: SQL syntax error')
                                        challenge = Challenge.query.filter_by(name='SQL Injection via File Upload').first()
                                        if challenge:
                                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                            if challenge.id not in completed_ids:
                                                update_user_progress(user.id, challenge.id, challenge.points)
                                        break
                                if not sqli_detected:
                                    import_output += f'Imported row {i + 1}: ID={id_val}, Name={name_val}, Email={email_val}, Department={department_val}\n'
                                    rows_imported += 1
                            else:
                                import_errors.append(f'Error in row {i + 1}: Insufficient columns')
                        if rows_imported == rows_processed:
                            import_status = 'Complete'
                        elif rows_imported > 0:
                            import_status = 'Partial'
                        else:
                            import_status = 'Failed'
                    else:
                        error = 'Invalid CSV format. Expected columns: id, name, email, department'
                else:
                    error = 'Empty CSV file'
                upload_success = True
            except Exception as e:
                error = f'Error processing CSV: {str(e)}'
        else:
            error = 'No CSV content provided'
    challenge = Challenge.query.filter_by(name='SQL Injection via File Upload').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level19.html', flag=flag, sqli_detected=sqli_detected, csv_content=csv_content, csv_preview=csv_preview, upload_success=upload_success, rows_processed=rows_processed, rows_imported=rows_imported, import_status=import_status, import_errors=import_errors, import_output=import_output, error=error)

@sqli_bp.route('/sqli/level20', methods=['GET', 'POST'])
@login_required
def sqli_level20():
    user = get_current_user()
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
        try:
            generated_sql = f"SELECT * FROM products WHERE category = '{category}' AND active = 1"
            if search_term:
                generated_sql += f" AND (name LIKE '%{search_term}%' OR description LIKE '%{search_term}%')"
            sqli_patterns = ["'", '"', '--', ';', 'UNION', 'SELECT', 'FROM', 'WHERE', 'OR', 'AND', '=', '>', '<']
            for pattern in sqli_patterns:
                if pattern in category or pattern in search_term:
                    sqli_detected = True
                    result_columns = ['id', 'flag', 'created_at', 'is_active']
                    if 'system_flags' in generated_sql:
                        result_rows = [[1, 'R00T{st0r3d_pr0c3dur3_sql1_1nj3ct10n_pwn3d}', '2023-01-01 00:00:00', 'true']]
                        challenge = Challenge.query.filter_by(name='SQL Injection in Stored Procedures').first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(user.id, challenge.id, challenge.points)
                    else:
                        result_rows = [[999, 'Suspicious query detected', '2023-01-01 00:00:00', 'true']]
                    procedure_result = True
                    break
            if not sqli_detected:
                result_columns = ['id', 'name', 'description', 'price', 'category']
                if category == 'Electronics':
                    result_rows = [[1, 'Smartphone X', 'Latest smartphone with advanced features.', 999.99, 'Electronics'], [2, 'Laptop Pro', 'Professional laptop for developers.', 1499.99, 'Electronics'], [3, 'Wireless Headphones', 'Noise-cancelling wireless headphones.', 199.99, 'Electronics']]
                elif category == 'Clothing':
                    result_rows = [[4, 'Designer T-shirt', 'Premium cotton t-shirt.', 49.99, 'Clothing'], [5, 'Jeans', 'Comfortable denim jeans.', 79.99, 'Clothing'], [6, 'Sneakers', 'Stylish and comfortable sneakers.', 129.99, 'Clothing']]
                else:
                    result_rows = []
                if search_term and result_rows:
                    result_rows = [row for row in result_rows if search_term.lower() in row[1].lower() or search_term.lower() in row[2].lower()]
                procedure_result = True
        except Exception as e:
            error = f'Error executing stored procedure: {str(e)}'
    challenge = Challenge.query.filter_by(name='SQL Injection in Stored Procedures').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level20.html', flag=flag, sqli_detected=sqli_detected, category=category, search_term=search_term, procedure_result=procedure_result, generated_sql=generated_sql, result_columns=result_columns, result_rows=result_rows, error=error)

@sqli_bp.route('/sqli/level21', methods=['GET', 'POST'])
@login_required
def sqli_level21():
    user = get_current_user()
    import json
    import re
    flag = None
    sqli_detected = False
    graphql_query = None
    graphql_result = None
    if request.method == 'POST':
        graphql_query = request.form.get('graphql_query', '')
        try:
            sqli_patterns = ["'", '"', '--', ';', 'UNION', 'SELECT', 'FROM', 'WHERE', 'OR', 'AND', '=', '>', '<']
            admin_secrets_pattern = re.compile('admin_secrets', re.IGNORECASE)
            for pattern in sqli_patterns:
                if pattern in graphql_query and admin_secrets_pattern.search(graphql_query):
                    sqli_detected = True
                    graphql_result = json.dumps({'data': {'user': {'id': '1', 'username': 'R00T{gr4phql_sql1_1nj3ct10n_pwn3d}', 'email': 'admin@example.com', 'role': 'admin'}}}, indent=2)
                    challenge = Challenge.query.filter_by(name='SQL Injection in GraphQL API').first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(user.id, challenge.id, challenge.points)
                    break
            if not sqli_detected:
                if 'user' in graphql_query:
                    graphql_result = json.dumps({'data': {'user': {'id': '1', 'username': 'johndoe', 'email': 'john.doe@example.com', 'role': 'user'}}}, indent=2)
                elif 'products' in graphql_query:
                    graphql_result = json.dumps({'data': {'products': [{'id': '1', 'name': 'Smartphone X', 'description': 'Latest smartphone with advanced features.', 'price': 999.99, 'category': 'Electronics'}, {'id': '2', 'name': 'Laptop Pro', 'description': 'Professional laptop for developers.', 'price': 1499.99, 'category': 'Electronics'}, {'id': '3', 'name': 'Wireless Headphones', 'description': 'Noise-cancelling wireless headphones.', 'price': 199.99, 'category': 'Electronics'}]}}, indent=2)
                elif 'order' in graphql_query:
                    graphql_result = json.dumps({'data': {'order': {'id': '1', 'userId': '1', 'total': 1199.98, 'status': 'completed', 'createdAt': '2023-01-01T00:00:00Z', 'products': [{'id': '1', 'name': 'Smartphone X', 'description': 'Latest smartphone with advanced features.', 'price': 999.99, 'category': 'Electronics'}, {'id': '3', 'name': 'Wireless Headphones', 'description': 'Noise-cancelling wireless headphones.', 'price': 199.99, 'category': 'Electronics'}]}}}, indent=2)
                else:
                    graphql_result = json.dumps({'errors': [{'message': 'Unknown query type'}]}, indent=2)
        except Exception as e:
            graphql_result = json.dumps({'errors': [{'message': str(e)}]}, indent=2)
    challenge = Challenge.query.filter_by(name='SQL Injection in GraphQL API').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level21.html', flag=flag, sqli_detected=sqli_detected, graphql_query=graphql_query, graphql_result=graphql_result)

@sqli_bp.route('/sqli/level22', methods=['GET', 'POST'])
@login_required
def sqli_level22():
    user = get_current_user()
    flag = None
    sqli_detected = False
    collection = request.form.get('collection', 'articles')
    query = request.form.get('query', '{"author": "John Doe"}')
    results = []
    error = None
    if request.method == 'POST':
        try:
            import re
            query_obj = json.loads(query)
            query_str = json.dumps(query_obj)
            secrets_pattern = re.compile('secrets', re.IGNORECASE)
            operator_pattern = re.compile('\\$where|\\$lookup|\\$function|\\$expr', re.IGNORECASE)
            if collection == 'secrets' or secrets_pattern.search(query_str) or operator_pattern.search(query_str):
                sqli_detected = True
                results = [{'_id': '1', 'title': 'Restricted Document', 'flag': 'R00T{n0sql_1nj3ct10n_3xpl01t3d}', 'author': 'admin', 'created_at': '2023-01-01'}]
                challenge = Challenge.query.filter_by(name='SQL Injection in NoSQL Database').first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(user.id, challenge.id, challenge.points)
            elif not sqli_detected:
                if collection == 'articles':
                    if 'author' in query_obj and query_obj['author'] == 'John Doe':
                        results = [{'_id': '1', 'title': 'Introduction to NoSQL Databases', 'content': 'NoSQL databases are designed to handle various data models, including document, key-value, wide-column, and graph formats.', 'author': 'John Doe', 'created_at': '2023-01-01'}, {'_id': '2', 'title': 'MongoDB vs. CouchDB', 'content': 'This article compares two popular document databases: MongoDB and CouchDB, highlighting their strengths and weaknesses.', 'author': 'John Doe', 'created_at': '2023-02-15'}]
                    elif 'author' in query_obj and query_obj['author'] == 'Jane Smith':
                        results = [{'_id': '3', 'title': 'Scaling NoSQL Databases', 'content': 'Learn how to scale NoSQL databases horizontally to handle large volumes of data and high traffic loads.', 'author': 'Jane Smith', 'created_at': '2023-03-10'}]
                    else:
                        results = []
                elif collection == 'users':
                    if 'username' in query_obj and query_obj['username'] == 'johndoe':
                        results = [{'_id': '1', 'username': 'johndoe', 'email': 'john.doe@example.com', 'role': 'author'}]
                    elif 'username' in query_obj and query_obj['username'] == 'janesmith':
                        results = [{'_id': '2', 'username': 'janesmith', 'email': 'jane.smith@example.com', 'role': 'author'}]
                    else:
                        results = []
                elif collection == 'products':
                    if 'category' in query_obj and query_obj['category'] == 'Electronics':
                        results = [{'_id': '1', 'title': 'Smartphone X', 'description': 'Latest smartphone with advanced features.', 'price': 999.99, 'category': 'Electronics'}, {'_id': '2', 'title': 'Laptop Pro', 'description': 'Professional laptop for developers.', 'price': 1499.99, 'category': 'Electronics'}]
                    elif 'category' in query_obj and query_obj['category'] == 'Clothing':
                        results = [{'_id': '3', 'title': 'Designer T-shirt', 'description': 'Premium cotton t-shirt.', 'price': 49.99, 'category': 'Clothing'}]
                    else:
                        results = []
                else:
                    results = []
        except Exception as e:
            error = f'Error executing query: {str(e)}'
    challenge = Challenge.query.filter_by(name='SQL Injection in NoSQL Database').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level22.html', flag=flag, sqli_detected=sqli_detected, collection=collection, query=query, results=results, error=error)

@sqli_bp.route('/sqli/level23', methods=['GET', 'POST'])
@login_required
def sqli_level23():
    user = get_current_user()
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
            orm_query = f"db.session.query(Article).filter(Article.{filter_by}.like('%{search_term}%'))"
            if sort_by and sort_order:
                if sort_order == 'asc':
                    orm_query += f'.order_by(Article.{sort_by})'
                else:
                    orm_query += f'.order_by(Article.{sort_by}.desc())'
            sqli_patterns = ["'", '"', '--', ';', 'UNION', 'SELECT', 'FROM', 'WHERE', 'OR', 'AND', '=', '>', '<']
            for pattern in sqli_patterns:
                if pattern in search_term or pattern in filter_by or pattern in sort_by:
                    sqli_detected = True
                    if 'admin_flag' in search_term or 'admin_flag' in filter_by or 'admin_flag' in sort_by:
                        results = [{'id': 999, 'title': 'Restricted Article', 'content': 'This article contains the flag: R00T{0rm_l4y3r_sql1_1nj3ct10n_pwn3d}', 'author': 'admin', 'created_at': '2023-01-01', 'is_published': False}]
                        challenge = Challenge.query.filter_by(name='SQL Injection in ORM Layer').first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(user.id, challenge.id, challenge.points)
                    else:
                        results = [{'id': 998, 'title': 'Suspicious Query Detected', 'content': 'The system has detected a potential SQL injection attempt. This incident has been logged.', 'author': 'system', 'created_at': '2023-01-01', 'is_published': True}]
                    break
            if not sqli_detected:
                if search_term.lower() in 'python programming':
                    results = [{'id': 1, 'title': 'Introduction to Python Programming', 'content': 'Python is a high-level, interpreted programming language known for its readability and simplicity.', 'author': 'John Doe', 'created_at': '2023-01-15', 'is_published': True}, {'id': 2, 'title': 'Advanced Python Techniques', 'content': 'Learn advanced Python techniques such as decorators, generators, and context managers.', 'author': 'Jane Smith', 'created_at': '2023-02-20', 'is_published': True}]
                elif search_term.lower() in 'web development':
                    results = [{'id': 3, 'title': 'Modern Web Development', 'content': 'Explore modern web development frameworks and tools for building responsive web applications.', 'author': 'Bob Johnson', 'created_at': '2023-03-10', 'is_published': True}, {'id': 4, 'title': 'Frontend vs Backend Development', 'content': 'Understanding the differences between frontend and backend web development roles and responsibilities.', 'author': 'Alice Williams', 'created_at': '2023-04-05', 'is_published': True}]
                elif search_term.lower() in 'database':
                    results = [{'id': 5, 'title': 'SQL Database Fundamentals', 'content': 'Learn the fundamentals of SQL databases, including tables, queries, and relationships.', 'author': 'John Doe', 'created_at': '2023-05-12', 'is_published': True}, {'id': 6, 'title': 'NoSQL Database Overview', 'content': 'Explore different types of NoSQL databases and their use cases in modern applications.', 'author': 'Jane Smith', 'created_at': '2023-06-18', 'is_published': True}]
                else:
                    results = []
                if sort_by == 'id':
                    results.sort(key=lambda x: x['id'], reverse=sort_order == 'desc')
                elif sort_by == 'title':
                    results.sort(key=lambda x: x['title'], reverse=sort_order == 'desc')
                elif sort_by == 'author':
                    results.sort(key=lambda x: x['author'], reverse=sort_order == 'desc')
                elif sort_by == 'created_at':
                    results.sort(key=lambda x: x['created_at'], reverse=sort_order == 'desc')
        except Exception as e:
            error = f'Error executing query: {str(e)}'
    challenge = Challenge.query.filter_by(name='SQL Injection in ORM Layer').first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, user.id)
    return render_template('sqli/sqli_level23.html', flag=flag, sqli_detected=sqli_detected, search_term=search_term, filter_by=filter_by, sort_by=sort_by, sort_order=sort_order, results=results, orm_query=orm_query, error=error)

