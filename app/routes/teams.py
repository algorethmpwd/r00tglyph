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

teams_bp = Blueprint('teams', __name__)

@teams_bp.route('/teams')
@login_required
def teams():
    user = get_current_user()
    all_teams = Team.query.order_by(Team.created_at.desc()).all()
    team_scores = []
    for team in all_teams:
        members = LocalUser.query.filter_by(team_id=team.id).all()
        team_score = sum((m.score for m in members))
        team_scores.append({'team': team, 'score': team_score, 'member_count': len(members)})
    team_scores.sort(key=lambda x: x['score'], reverse=True)
    return render_template('teams.html', user=user, teams=team_scores)

@teams_bp.route('/teams/create', methods=['GET', 'POST'])
@login_required
def team_create():
    user = get_current_user()
    if user.team_id:
        flash('You are already a member of a team. Leave your current team first.', 'danger')
        return redirect(url_for('teams'))
    if request.method == 'POST':
        name = request.form.get('team_name', '').strip()
        description = request.form.get('description', '').strip()
        if not name:
            flash('Team name is required.', 'danger')
            return render_template('team_create.html')
        existing = Team.query.filter_by(name=name).first()
        if existing:
            flash('Team name already exists.', 'danger')
            return render_template('team_create.html')
        team = Team(name=name, description=description, created_by=user.id)
        db.session.add(team)
        db.session.commit()
        user.team_id = team.id
        db.session.commit()
        flash(f"Team '{name}' created successfully!", 'success')
        return redirect(url_for('teams'))
    return render_template('team_create.html')

@teams_bp.route('/teams/join/<int:team_id>', methods=['POST'])
@login_required
def team_join(team_id):
    user = get_current_user()
    if user.team_id:
        flash('You are already a member of a team. Leave your current team first.', 'danger')
        return redirect(url_for('teams'))
    team = db.session.get(Team, team_id)
    if not team:
        flash('Team not found.', 'danger')
        return redirect(url_for('teams'))
    user.team_id = team.id
    db.session.commit()
    flash(f"Joined team '{team.name}'!", 'success')
    return redirect(url_for('teams'))

@teams_bp.route('/teams/leave', methods=['POST'])
@login_required
def team_leave():
    user = get_current_user()
    if user.team_id:
        team = db.session.get(Team, user.team_id)
        user.team_id = None
        db.session.commit()
        flash(f"Left team '{team.name}'.", 'info')
    return redirect(url_for('teams'))

@teams_bp.route('/teams/<int:team_id>')
@login_required
def team_detail(team_id):
    team = db.session.get(Team, team_id)
    if not team:
        flash('Team not found.', 'danger')
        return redirect(url_for('teams'))
    members = LocalUser.query.filter_by(team_id=team_id).order_by(LocalUser.score.desc()).all()
    team_score = sum((m.score for m in members))
    return render_template('team_detail.html', team=team, members=members, team_score=team_score)

