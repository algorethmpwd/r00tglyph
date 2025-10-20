#!/usr/bin/env python3
"""
Generate Flask routes for new challenge categories
This script outputs Python code to be added to app.py
"""

def generate_ssti_routes():
    """Generate SSTI challenge routes"""
    routes = []
    for level in range(1, 24):
        route = f'''
@app.route('/ssti/level{level}', methods=['GET', 'POST'])
def ssti_level{level}():
    user = get_current_user()
    challenge_id = Challenge.query.filter_by(category='ssti', name=f'SSTI Level {level}').first().id

    vulnerability_detected = False
    flag = None
    result = None

    if request.method == 'POST':
        payload = request.form.get('payload', '')

        # Level {level}: SSTI detection logic
        # Check for common SSTI payloads
        ssti_patterns = [
            '{{', '}}', '{%', '%}',  # Jinja2/Twig delimiters
            '${{', '}}', '#{{', '}}',  # Other template engines
            'self', 'request', 'config',  # Common Jinja2 objects
        ]

        if any(pattern in payload for pattern in ssti_patterns):
            # For educational purposes, we simulate successful SSTI
            vulnerability_detected = True
            flag = generate_flag(challenge_id, user.machine_id)

            # Mark challenge as completed
            mark_challenge_completed(user, challenge_id)

        result = "Template executed. Check for vulnerabilities!" if payload else None

    return render_template('ssti/ssti_level{level}.html',
                           user=user,
                           vulnerability_detected=vulnerability_detected,
                           flag=flag,
                           result=result,
                           ssti_level{level}_id=challenge_id)
'''
        routes.append(route)
    return '\n'.join(routes)


def generate_deserial_routes():
    """Generate Deserialization challenge routes"""
    routes = []
    for level in range(1, 6):  # Only 5 for now
        route = f'''
@app.route('/deserial/level{level}', methods=['GET', 'POST'])
def deserial_level{level}():
    user = get_current_user()
    challenge_id = Challenge.query.filter_by(category='deserial', name=f'Deserialization Level {level}').first().id

    vulnerability_detected = False
    flag = None
    result = None

    if request.method == 'POST':
        payload = request.form.get('payload', '')

        # Level {level}: Deserialization detection logic
        deserial_patterns = [
            'pickle', '__reduce__', 'os.system',  # Python pickle
            'O:', 'a:', 's:',  # PHP serialize
            'rO0',  # Java serialized (base64)
            'AAEAA',  # .NET BinaryFormatter
        ]

        if any(pattern in payload for pattern in deserial_patterns):
            vulnerability_detected = True
            flag = generate_flag(challenge_id, user.machine_id)
            mark_challenge_completed(user, challenge_id)

        result = "Deserialization attempted." if payload else None

    return render_template('deserial/deserial_level{level}.html',
                           user=user,
                           vulnerability_detected=vulnerability_detected,
                           flag=flag,
                           result=result,
                           deserial_level{level}_id=challenge_id)
'''
        routes.append(route)
    return '\n'.join(routes)


def generate_auth_routes():
    """Generate Authentication Bypass challenge routes"""
    routes = []
    for level in range(1, 6):  # Only 5 for now
        route = f'''
@app.route('/auth/level{level}', methods=['GET', 'POST'])
def auth_level{level}():
    user = get_current_user()
    challenge_id = Challenge.query.filter_by(category='auth', name=f'Auth Bypass Level {level}').first().id

    vulnerability_detected = False
    flag = None
    result = None

    if request.method == 'POST':
        payload = request.form.get('payload', '')

        # Level {level}: Auth bypass detection logic
        auth_bypass_patterns = [
            "' OR '1'='1", "' OR 1=1--",  # SQL injection
            "admin' --", "admin' #",
            '"alg": "none"',  # JWT none algorithm
            'sessionid=',  # Session manipulation
        ]

        if any(pattern.lower() in payload.lower() for pattern in auth_bypass_patterns):
            vulnerability_detected = True
            flag = generate_flag(challenge_id, user.machine_id)
            mark_challenge_completed(user, challenge_id)

        result = "Authentication check performed." if payload else None

    return render_template('auth/auth_level{level}.html',
                           user=user,
                           vulnerability_detected=vulnerability_detected,
                           flag=flag,
                           result=result,
                           auth_level{level}_id=challenge_id)
'''
        routes.append(route)
    return '\n'.join(routes)


if __name__ == '__main__':
    print("=" * 80)
    print("FLASK ROUTES FOR NEW CHALLENGES")
    print("=" * 80)
    print("\n# Add these routes to app.py\n")

    print("\n# ===== SSTI ROUTES (23 levels) =====")
    print(generate_ssti_routes())

    print("\n# ===== DESERIALIZATION ROUTES (5 levels) =====")
    print(generate_deserial_routes())

    print("\n# ===== AUTH BYPASS ROUTES (5 levels) =====")
    print(generate_auth_routes())

    print("\n" + "=" * 80)
    print("Copy the above routes and add them to app.py before the final if __name__ == '__main__' block")
    print("=" * 80)
