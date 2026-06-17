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

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('auth.register'))
        existing_user = LocalUser.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!', 'danger')
            return redirect(url_for('auth.register'))
        hashed_password = generate_password_hash(password)
        new_user = LocalUser(username=username, display_name=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=10, window_seconds=300, key_func=lambda: request.remote_addr)
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = LocalUser.query.filter_by(username=username).first()
        
        if user:
            from datetime import datetime, timezone, timedelta
            
            # Check if account is locked
            if user.locked_until and user.locked_until.tzinfo is None:
                # Add timezone info if missing from db
                user.locked_until = user.locked_until.replace(tzinfo=timezone.utc)
                
            if user.locked_until and datetime.now(timezone.utc) < user.locked_until:
                flash(f'Account locked until {user.locked_until.strftime("%H:%M:%S")} UTC.', 'danger')
                return render_template('login.html')
                
            if check_password_hash(user.password_hash, password):
                user.failed_login_attempts = 0
                user.locked_until = None
                session['user_id'] = user.id
                user.last_active = datetime.now(timezone.utc)
                db.session.commit()
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('core.index'))
            else:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
                    flash('Account locked for 15 minutes due to too many failed attempts.', 'danger')
                else:
                    flash('Invalid username or password', 'danger')
                db.session.commit()
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

