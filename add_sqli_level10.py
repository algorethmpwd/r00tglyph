#!/usr/bin/env python3
from app import app, db

def add_sqli_level10_route():
    """Add the SQL Injection Level 10 route to app.py"""
    # Find the end of the sqli_level9 function
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the end of the sqli_level9 function
    sqli_level9_end = content.find("    return render_template('sqli/sqli_level9.html', flag=flag, sqli_detected=sqli_detected,")
    sqli_level9_end = content.find("\n", sqli_level9_end + 1)
    
    # Add the sqli_level10 function after sqli_level9
    new_route = """
# SQL Injection Level 10 - NoSQL Injection
@app.route('/sqli/level10', methods=['GET', 'POST'])
def sqli_level10():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    error = None
    success = None
    documents = None
    
    # Handle login request (POST)
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Check for NoSQL injection patterns
        nosql_patterns = ["$ne", "$gt", "$lt", "$regex", "$where", "$exists", "$elemMatch", "$nin", "$in", "$all", "$size", "$or", "$and", "$not"]
        
        # Check if any NoSQL injection pattern is in the input
        for pattern in nosql_patterns:
            if pattern in username or pattern in password:
                # NoSQL injection detected!
                sqli_detected = True
                break
        
        # Also check for JSON-like input that might contain NoSQL operators
        if (username.startswith('{') and username.endswith('}')) or (password.startswith('{') and password.endswith('}')):
            sqli_detected = True
        
        # Check for array notation that might be used for NoSQL injection
        if '[' in username or '[' in password:
            sqli_detected = True
        
        # Simulate authentication
        if sqli_detected:
            # NoSQL injection successful - simulate admin access
            success = "Welcome, admin! You have successfully logged in."
            
            # Show admin documents
            documents = [
                {
                    "id": "doc001",
                    "title": "System Architecture",
                    "category": "Technical",
                    "content": "Overview of the DocuStore system architecture and components.",
                    "created": "2023-01-15"
                },
                {
                    "id": "doc002",
                    "title": "Security Protocols",
                    "category": "Security",
                    "content": "Details of the security measures implemented in DocuStore.",
                    "created": "2023-02-20"
                },
                {
                    "id": "doc003",
                    "title": "Admin Credentials",
                    "category": "Confidential",
                    "content": "The flag is: R00T{n0sql_1nj3ct10n_byp4ss3d_4uth}",
                    "created": "2023-03-10"
                }
            ]
            
            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="NoSQL Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
        elif username == "admin" and password == "admin":
            # Simulating a successful login with correct credentials (for testing)
            success = "Welcome, admin! You have successfully logged in."
            
            # Show admin documents
            documents = [
                {
                    "id": "doc001",
                    "title": "System Architecture",
                    "category": "Technical",
                    "content": "Overview of the DocuStore system architecture and components.",
                    "created": "2023-01-15"
                },
                {
                    "id": "doc002",
                    "title": "Security Protocols",
                    "category": "Security",
                    "content": "Details of the security measures implemented in DocuStore.",
                    "created": "2023-02-20"
                },
                {
                    "id": "doc003",
                    "title": "Admin Credentials",
                    "category": "Confidential",
                    "content": "The flag is: R00T{n0sql_1nj3ct10n_byp4ss3d_4uth}",
                    "created": "2023-03-10"
                }
            ]
            
            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="NoSQL Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
        elif username == "user" and password == "password":
            # Simulating a successful login with regular user credentials
            success = "Welcome, user! You have successfully logged in."
            
            # Show regular user documents
            documents = [
                {
                    "id": "doc101",
                    "title": "User Guide",
                    "category": "Documentation",
                    "content": "Guide for using the DocuStore system.",
                    "created": "2023-01-20"
                },
                {
                    "id": "doc102",
                    "title": "Project Plan",
                    "category": "Project",
                    "content": "Project plan for implementing DocuStore.",
                    "created": "2023-02-25"
                }
            ]
        else:
            # Authentication failed
            error = "Invalid username or password. Please try again."
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="NoSQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level10.html', flag=flag, sqli_detected=sqli_detected,
                          error=error, success=success, documents=documents)
"""
    
    # Insert the new route
    updated_content = content[:sqli_level9_end + 1] + new_route + content[sqli_level9_end + 1:]
    
    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)
    
    print("Added SQL Injection Level 10 route to app.py")

if __name__ == '__main__':
    add_sqli_level10_route()
