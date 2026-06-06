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

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin')
@admin_required
def admin_panel():
    user = get_current_user()
    total_users = LocalUser.query.count()
    total_challenges = Challenge.query.count()
    total_submissions = Submission.query.count()
    recent_submissions = Submission.query.order_by(Submission.timestamp.desc()).limit(20).all()
    top_users = LocalUser.query.order_by(LocalUser.score.desc()).limit(10).all()
    category_stats = {}
    for cat in ['xss', 'sqli', 'cmdi', 'csrf', 'ssrf', 'xxe', 'ssti', 'deserial', 'auth']:
        cat_challenges = Challenge.query.filter_by(category=cat).all()
        cat_total = len(cat_challenges)
        cat_completed = 0
        for c in cat_challenges:
            flags = Flag.query.filter_by(challenge_id=c.id, used=True).count()
            if flags > 0:
                cat_completed += 1
        category_stats[cat] = {'total': cat_total, 'completed': cat_completed}
    return render_template('admin.html', user=user, total_users=total_users, total_challenges=total_challenges, total_submissions=total_submissions, recent_submissions=recent_submissions, top_users=top_users, category_stats=category_stats)

@admin_bp.route('/admin/users')
@admin_required
def admin_users():
    users = LocalUser.query.order_by(LocalUser.score.desc()).all()
    return render_template('admin_users.html', users=users)

@admin_bp.route('/admin/users/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def admin_toggle_admin(user_id):
    user = db.session.get(LocalUser, user_id)
    if user:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash(f'User {user.username} admin status updated.', 'success')
    return redirect(url_for('admin_users'))

@admin_bp.route('/admin/challenges')
@admin_required
def admin_challenges():
    challenges = Challenge.query.order_by(Challenge.category, Challenge.id).all()
    return render_template('admin_challenges.html', challenges=challenges)

@admin_bp.route('/admin/challenges/<int:challenge_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_challenge(challenge_id):
    challenge = db.session.get(Challenge, challenge_id)
    if challenge:
        challenge.active = not challenge.active
        db.session.commit()
        flash(f"Challenge '{challenge.name}' {('activated' if challenge.active else 'deactivated')}.", 'success')
    return redirect(url_for('admin_challenges'))

