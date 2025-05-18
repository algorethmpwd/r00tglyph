#!/usr/bin/env python3
from app import app, db

def add_sqli_level8_route():
    """Add the SQL Injection Level 8 route to app.py"""
    # Find the end of the sqli_level7 function
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the end of the sqli_level7 function
    sqli_level7_end = content.find("    return render_template('sqli/sqli_level7.html', flag=flag, sqli_detected=sqli_detected,")
    sqli_level7_end = content.find("\n", sqli_level7_end + 1)
    
    # Add the sqli_level8 function after sqli_level7
    new_route = """
# SQL Injection Level 8 - Second-Order SQL Injection
@app.route('/sqli/level8', methods=['GET', 'POST'])
def sqli_level8():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    
    # Default profile values
    username = "test_user"
    bio = "I'm a security enthusiast."
    location = "Cyberspace"
    website = "https://example.com"
    
    # Profile to display when viewing a user
    profile = None
    view_user = request.args.get('view_user', '')
    
    # Simulated database of users
    users_db = {
        "admin": {
            "username": "admin",
            "bio": "System administrator",
            "location": "Server Room",
            "website": "https://admin.example.com",
            "is_admin": True,
            "secret": "The flag is: R00T{s3c0nd_0rd3r_sql1_1s_tr1cky}"
        },
        "test_user": {
            "username": "test_user",
            "bio": "I'm a security enthusiast.",
            "location": "Cyberspace",
            "website": "https://example.com",
            "is_admin": False
        }
    }
    
    # Handle profile update (POST request)
    if request.method == 'POST':
        username = request.form.get('username', '')
        bio = request.form.get('bio', '')
        location = request.form.get('location', '')
        website = request.form.get('website', '')
        
        # Simulate storing the profile in the database
        # In a real second-order SQL injection, this would be sanitized but still vulnerable
        users_db["test_user"] = {
            "username": username,
            "bio": bio,
            "location": location,
            "website": website,
            "is_admin": False
        }
        
        # Success message would be shown here
    
    # Handle profile viewing (GET request with view_user parameter)
    if view_user:
        # This is where the second-order SQL injection vulnerability exists
        # The application doesn't properly sanitize the stored username when using it in a query
        
        # Check for SQL injection patterns in the view_user parameter
        sqli_patterns = ["'", "\"", "--", ";", "OR", "=", "UNION", "SELECT", "DROP", "INSERT", "DELETE", "UPDATE"]
        
        # Convert to uppercase for case-insensitive check
        view_user_upper = view_user.upper()
        
        # Check if any SQL injection pattern is in the input
        for pattern in sqli_patterns:
            if pattern.upper() in view_user_upper:
                # SQL injection detected!
                sqli_detected = True
                break
        
        if sqli_detected:
            # Simulate a successful SQL injection that reveals the admin profile
            profile = users_db.get("admin")
            
            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="Second-Order SQL Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
        else:
            # Normal user lookup
            profile = users_db.get(view_user)
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="Second-Order SQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level8.html', flag=flag, sqli_detected=sqli_detected,
                          username=username, bio=bio, location=location, website=website,
                          view_user=view_user, profile=profile)
"""
    
    # Insert the new route
    updated_content = content[:sqli_level7_end + 1] + new_route + content[sqli_level7_end + 1:]
    
    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)
    
    print("Added SQL Injection Level 8 route to app.py")

if __name__ == '__main__':
    add_sqli_level8_route()
