import os
import re

# Map of prefix -> blueprint name
mapping = {
    'index': 'core',
    'change_theme': 'core',
    'profile': 'core',
    'challenges': 'core',
    'vulnerabilities': 'core',
    'scoreboard': 'core',
    'team_scoreboard': 'core',
    'login': 'auth',
    'register': 'auth',
    'logout': 'auth',
    'submit_flag': 'api',
    'api_hints': 'api',
    'admin': 'admin',
    'admin_panel': 'admin',
    'admin_users': 'admin',
    'admin_challenges': 'admin',
    'admin_toggle_admin': 'admin',
    'admin_toggle_challenge': 'admin',
    'teams': 'teams',
    'team_create': 'teams',
    'team_detail': 'teams',
    'team_join': 'teams',
    'team_leave': 'teams',
    'xss_level': 'xss',
    'sqli_level': 'sqli',
    'cmdi_level': 'cmdi',
    'csrf_level': 'csrf',
    'ssrf_level': 'ssrf',
    'xxe_level': 'xxe',
    'ssti_level': 'dynamic',
    'deserial_level': 'dynamic',
    'auth_level': 'dynamic',
}

def get_bp(endpoint):
    if '.' in endpoint:
        return endpoint # already prefixed
    if endpoint == 'static':
        return endpoint
    for prefix, bp in mapping.items():
        if endpoint.startswith(prefix):
            return f"{bp}.{endpoint}"
    return endpoint

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Regex to find url_for('something') or url_for("something")
    def replacer(match):
        full = match.group(0)
        quote = match.group(1)
        endpoint = match.group(2)
        new_endpoint = get_bp(endpoint)
        return f"url_for({quote}{new_endpoint}{quote}"
    
    new_content = re.sub(r"url_for\((['\"])(.*?)\1", replacer, content)
    
    # Also handle jinja dynamic urls like: url_for(category ~ '_level' ~ level)
    # This is trickier, so we'll just fix the static ones first and see.
    # Actually for jinja dynamic: url_for(category ~ '_level' ~ level_number)
    # We can rewrite it to: url_for(category ~ '.' ~ category ~ '_level' ~ level_number)
    def dynamic_replacer(match):
        return r"url_for(category ~ '.' ~ category ~ '_level'"
    
    new_content = re.sub(r"url_for\(category ~ '_level'", dynamic_replacer, new_content)
    
    if new_content != content:
        with open(filepath, 'w') as f:
            f.write(new_content)
        print(f"Fixed {filepath}")

# Process templates
for root, dirs, files in os.walk('templates'):
    for file in files:
        if file.endswith('.html'):
            process_file(os.path.join(root, file))

# Process python files
for root, dirs, files in os.walk('app/routes'):
    for file in files:
        if file.endswith('.py'):
            process_file(os.path.join(root, file))

print("Done fixing url_for!")
