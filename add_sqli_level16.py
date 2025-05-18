#!/usr/bin/env python3
from app import app, db

def add_sqli_level16_route():
    """Add the SQL Injection Level 16 route to app.py"""
    # Find the end of the sqli_level15 function
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the end of the sqli_level15 function
    sqli_level15_end = content.find("    return render_template('sqli/sqli_level15.html', flag=flag, sqli_detected=sqli_detected,")
    sqli_level15_end = content.find("\n", sqli_level15_end + 1)
    
    # Add the sqli_level16 function after sqli_level15
    new_route = '''
# SQL Injection Level 16 - SQL Injection in WebSockets
@app.route('/sqli/level16', methods=['GET', 'POST'])
def sqli_level16():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    ws_message = None
    
    if request.method == 'POST':
        # Handle AJAX request from the WebSocket simulation
        if request.is_json:
            data = request.get_json()
            sqli_detected = data.get('sqli_detected', False)
            ws_message = data.get('ws_message', '')
            
            # Mark challenge as completed if SQL injection is detected
            if sqli_detected:
                challenge = Challenge.query.filter_by(name="SQL Injection in WebSockets").first()
                if challenge:
                    # Add challenge to completed challenges
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        completed_ids.append(challenge.id)
                        user.completed_challenges = json.dumps(completed_ids)
                        db.session.commit()
                    
                    return jsonify({"success": True})
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in WebSockets").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level16.html', flag=flag, sqli_detected=sqli_detected,
                          ws_message=ws_message)
'''
    
    # Insert the new route
    updated_content = content[:sqli_level15_end + 1] + new_route + content[sqli_level15_end + 1:]
    
    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)
    
    print("Added SQL Injection Level 16 route to app.py")

if __name__ == '__main__':
    add_sqli_level16_route()
