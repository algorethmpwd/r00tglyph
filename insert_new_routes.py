#!/usr/bin/env python3
"""
Smart script to insert new challenge routes into app.py
"""

# Compact route template for SSTI
SSTI_ROUTE_TEMPLATE = '''
# SSTI Level {level}
@app.route('/ssti/level{level}', methods=['GET', 'POST'])
def ssti_level{level}():
    user = get_current_user()
    challenge = Challenge.query.filter_by(category='ssti', name=f'SSTI Level {level}').first()
    vulnerability_detected = False
    flag = None
    result = None

    if request.method == 'POST':
        payload = request.form.get('payload', '')
        if any(p in payload for p in ['{{{{', '}}}}', '{{%', '%}}', 'config', 'self']):
            vulnerability_detected = True
            flag = generate_flag(challenge.id, user.machine_id)
            mark_challenge_completed(user, challenge.id)
        result = "Template processed." if payload else None

    return render_template('ssti/ssti_level{level}.html', user=user,
                         vulnerability_detected=vulnerability_detected,
                         flag=flag, result=result)
'''

def create_routes_file():
    """Create a separate routes file for new challenges"""
    routes_content = '''#!/usr/bin/env python3
"""
New challenge routes for R00tGlyph
These routes should be added to app.py
"""

# ===== SSTI CHALLENGE ROUTES =====
'''

    # Generate all SSTI routes
    for level in range(1, 24):
        routes_content += SSTI_ROUTE_TEMPLATE.format(level=level)

    # Save to file
    with open('/home/algorethm/Documents/code/R00tGlyph/new_routes.py', 'w') as f:
        f.write(routes_content)

    print("✅ Routes file created: new_routes.py")
    print("\nTo add these routes to app.py:")
    print("1. Find the line '# ===== CSRF CHALLENGE ROUTES =====' in app.py")
    print("2. Insert the content of new_routes.py before that line")
    print("3. Or, import the routes from new_routes.py")


if __name__ == '__main__':
    create_routes_file()
