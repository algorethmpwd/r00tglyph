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

core_bp = Blueprint('core', __name__)

@core_bp.route('/change-theme/<theme>')
def change_theme(theme):
    valid_themes = ['dark', 'light', 'cyberpunk', 'hacker']
    if theme in valid_themes:
        session['theme'] = theme
    return redirect(request.referrer or url_for('core.index'))

@core_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = get_current_user()
    if request.method == 'POST':
        display_name = request.form.get('display_name')
        if display_name and len(display_name) <= 50:
            user.display_name = display_name
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename:
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
                filename = file.filename.lower()
                if '.' in filename and filename.rsplit('.', 1)[1] in allowed_extensions:
                    upload_folder = os.path.join('static', 'uploads', 'profiles')
                    os.makedirs(upload_folder, exist_ok=True)
                    import uuid
                    ext = filename.rsplit('.', 1)[1]
                    unique_filename = f'{user.id}_{uuid.uuid4().hex[:8]}.{ext}'
                    filepath = os.path.join(upload_folder, unique_filename)
                    file.save(filepath)
                    user.profile_picture = f'uploads/profiles/{unique_filename}'
        db.session.commit()
        return redirect(url_for('core.profile'))
    completed_challenges = user.completions.all()
    total_challenge_count = Challenge.query.filter_by(active=True).count()
    remaining_challenge_count = total_challenge_count - len(completed_challenges)
    return render_template('profile.html', user=user, completed_challenges=completed_challenges, total_challenge_count=total_challenge_count, remaining_challenge_count=remaining_challenge_count)

@core_bp.route('/')
def index():
    return render_template('index.html')

@core_bp.route('/challenges')
def vulnerabilities():
    categories_from_db = db.session.query(Challenge.category).distinct().all()
    all_categories = [c[0] for c in categories_from_db]
    if 'SQL Injection' in all_categories:
        all_categories.remove('SQL Injection')
    category_order = ['xss', 'sqli', 'cmdi', 'csrf', 'ssrf', 'xxe', 'ssti', 'deserial', 'auth']
    categories = []
    for category in category_order:
        if category in all_categories:
            categories.append(category)
    category_display_names = {'xss': 'Cross-Site Scripting (XSS)', 'sqli': 'SQL Injection (SQLi)', 'cmdi': 'Command Injection (CMDi)', 'csrf': 'Cross-Site Request Forgery (CSRF)', 'ssrf': 'Server-Side Request Forgery (SSRF)', 'xxe': 'XML External Entity (XXE)', 'ssti': 'Server-Side Template Injection (SSTI)', 'deserial': 'Insecure Deserialization', 'auth': 'Authentication Bypass'}
    user = get_current_user()
    if not user:
        return redirect(url_for('auth.login', next=request.url))
        
    completed_ids = [c.id for c in user.completions.all()]
    challenges_by_category = {}
    category_completion = {}
    total_count = 0
    completed_count = 0
    for category in categories:
        challenges = Challenge.query.filter_by(category=category, active=True).all()
        category_total = len(challenges)
        category_completed = 0
        for challenge in challenges:
            challenge.completed = challenge.id in completed_ids
            if challenge.completed:
                challenge.flag = get_or_create_flag(challenge.id, user.id)
                category_completed += 1
                completed_count += 1
            else:
                challenge.flag = None
        challenges_by_category[category] = challenges
        category_completion[category] = {'total': category_total, 'completed': category_completed}
        total_count += category_total
    return render_template('vulnerabilities.html', categories=categories, challenges_by_category=challenges_by_category, category_completion=category_completion, category_display_names=category_display_names, total_count=total_count, completed_count=completed_count)

@core_bp.route('/scoreboard')
def scoreboard():
    # Phase 2.2: Scoreboard Query Optimization using Association Table
    from app.models import user_completions
    top_users_query = db.session.query(
        LocalUser,
        db.func.coalesce(db.func.sum(Challenge.points), 0).label('total_score')
    ).outerjoin(user_completions, LocalUser.id == user_completions.c.user_id)\
     .outerjoin(Challenge, user_completions.c.challenge_id == Challenge.id)\
     .group_by(LocalUser.id)\
     .order_by(db.desc('total_score')).limit(20).all()
    
    # Update local score attribute temporarily for template compatibility
    top_users = []
    for u, score in top_users_query:
        u.score = int(score)
        top_users.append(u)

    total_challenges = Challenge.query.filter_by(active=True).count()
    total_players = LocalUser.query.count()
    total_flags = Flag.query.filter_by(used=True).count()
    recent_submissions = Submission.query.order_by(Submission.timestamp.desc()).limit(10).all()
    
    current_user_obj = get_current_user()
    my_rank = None
    my_score = None
    if current_user_obj:
        # Phase 2.3 Global Rank Optimisation uses LocalUser.score which has index
        rank_query = db.session.query(db.func.count(LocalUser.id)).filter(LocalUser.score > current_user_obj.score).scalar()
        my_rank = (rank_query or 0) + 1
        my_score = current_user_obj.score
        
    category_stats = {}
    for cat in ['xss', 'sqli', 'cmdi', 'csrf', 'ssrf', 'xxe', 'ssti', 'deserial', 'auth']:
        cat_challenges = Challenge.query.filter_by(category=cat, active=True).all()
        cat_total = len(cat_challenges)
        cat_completed = 0
        for c in cat_challenges:
            if Flag.query.filter_by(challenge_id=c.id, used=True).count() > 0:
                cat_completed += 1
        category_stats[cat] = {'total': cat_total, 'completed': cat_completed}
        
    recent_activity = []
    for sub in recent_submissions:
        user = db.session.get(LocalUser, sub.user_id)
        challenge = db.session.get(Challenge, sub.challenge_id)
        if user and challenge:
            from datetime import datetime, timezone
            diff = datetime.now(timezone.utc) - sub.timestamp
            if diff.days > 0:
                time_ago = f'{diff.days}d ago'
            elif diff.seconds > 3600:
                time_ago = f'{diff.seconds // 3600}h ago'
            else:
                time_ago = f'{diff.seconds // 60}m ago'
            recent_activity.append({'username': user.display_name, 'type': 'capture' if sub.correct else 'attempt', 'category': challenge.category, 'time_ago': time_ago})
            
    team_score = None
    if current_user_obj and current_user_obj.team_id:
        # Optimize team score query
        team_score = db.session.query(db.func.coalesce(db.func.sum(Challenge.points), 0))\
            .select_from(LocalUser)\
            .join(user_completions, LocalUser.id == user_completions.c.user_id)\
            .join(Challenge, user_completions.c.challenge_id == Challenge.id)\
            .filter(LocalUser.team_id == current_user_obj.team_id).scalar()
            
    return render_template('scoreboard.html', users=top_users, total_challenges=total_challenges, total_players=total_players, total_flags=total_flags, recent_activity=recent_activity, category_stats=category_stats, current_user=current_user_obj, my_rank=my_rank, my_score=my_score, team_score=int(team_score) if team_score else 0)

@core_bp.route('/team-scoreboard')
def team_scoreboard():
    from app.models import user_completions
    team_scores_query = db.session.query(
        Team,
        db.func.count(db.distinct(LocalUser.id)).label('member_count'),
        db.func.coalesce(db.func.sum(Challenge.points), 0).label('total_score')
    ).outerjoin(LocalUser, Team.id == LocalUser.team_id)\
     .outerjoin(user_completions, LocalUser.id == user_completions.c.user_id)\
     .outerjoin(Challenge, user_completions.c.challenge_id == Challenge.id)\
     .group_by(Team.id)\
     .order_by(db.desc('total_score')).all()
     
    team_scores = []
    for team, member_count, total_score in team_scores_query:
        team_scores.append({
            'team': team, 
            'score': int(total_score), 
            'member_count': member_count, 
            'avg_score': int(total_score) / member_count if member_count > 0 else 0
        })
        
    return render_template('team_scoreboard.html', team_scores=team_scores)

