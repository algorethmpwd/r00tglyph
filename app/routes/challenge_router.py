import os, yaml, json, subprocess
from flask import Blueprint, render_template, request, flash, redirect, url_for
from app.models import Challenge
from app.utils import get_current_user, login_required, update_user_progress, get_or_create_flag

dynamic_router_bp = Blueprint('dynamic_router', __name__)

def load_challenge_config(category, level):
    yaml_path = f"data/challenges/{category}_level{level}.yaml"
    if os.path.exists(yaml_path):
        with open(yaml_path, 'r') as f:
            return yaml.safe_load(f)
    return None

def extract_template_list_var(template_path):
    # Quick regex to find the list variable used in the template's for loop
    import re
    full_path = f"templates/{template_path}"
    if not os.path.exists(full_path): return "results"
    with open(full_path, 'r') as f:
        content = f.read()
    match = re.search(r"{%\s*for\s+\w+\s+in\s+(\w+)\s*%}", content)
    if match:
        return match.group(1)
    return "results"

@dynamic_router_bp.route('/<category>/level<int:level>', methods=['GET', 'POST'])
@login_required
def serve_challenge(category, level):
    user = get_current_user()
    config = load_challenge_config(category, level)
    
    if not config:
        flash("Challenge configuration not found.")
        return redirect(url_for('core.dashboard'))
        
    template_name = config.get('template', f"{category}/{category}_level{level}.html")
    challenge_name = config.get('name')
    db_challenge = Challenge.query.filter_by(name=challenge_name).first()
    
    flag = None
    if db_challenge:
        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
        if db_challenge.id in completed_ids:
            flag = get_or_create_flag(db_challenge.id, user.id)
            
    context = {
        'challenge': db_challenge,
        'flag': flag,
        'category': category,
        'level': level,
        'error': None,
        'success': None,
        'example_svgs': {},
        f'{category}_detected': False
    }
    
    # Add all form/args to context so they echo back
    for k, v in request.args.items(): context[k] = v
    for k, v in request.form.items(): context[k] = v
    
    if request.method == 'POST':
        # True Sinks processing
        from app.engine.sinks import process_sink
        
        sink_result, is_exploited = process_sink(category, level, request)
        
        list_var = extract_template_list_var(template_name)
        context[list_var] = sink_result
        context['results'] = sink_result
        context['output'] = sink_result if isinstance(sink_result, str) else ""
        context['ping_result'] = sink_result if isinstance(sink_result, str) else ""
        
        if is_exploited:
            context[f'{category}_detected'] = True
            if db_challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if db_challenge.id not in completed_ids:
                    update_user_progress(user.id, db_challenge.id, db_challenge.points)
                    flag = get_or_create_flag(db_challenge.id, user.id)
                    context['flag'] = flag
                    
    return render_template(template_name, **context)
