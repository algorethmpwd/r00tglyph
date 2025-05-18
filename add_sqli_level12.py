#!/usr/bin/env python3
from app import app, db

def add_sqli_level12_route():
    """Add the SQL Injection Level 12 route to app.py"""
    # Find the end of the sqli_level11 function
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the end of the sqli_level11 function
    sqli_level11_end = content.find("    return render_template('sqli/sqli_level11.html', flag=flag, sqli_detected=sqli_detected,")
    sqli_level11_end = content.find("\n", sqli_level11_end + 1)
    
    # Add the sqli_level12 function after sqli_level11
    new_route = '''
# SQL Injection Level 12 - ORM-based SQL Injection
@app.route('/sqli/level12', methods=['GET', 'POST'])
def sqli_level12():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    department = request.form.get('department', 'IT')
    search_term = request.form.get('search_term', '')
    employees = []
    error = None
    
    # Default employees for each department
    default_employees = {
        "IT": [
            {
                "id": "IT001",
                "name": "John Smith",
                "position": "IT Manager",
                "department": "IT",
                "email": "john.smith@corphr.com",
                "phone": "555-1234",
                "salary": "85,000",
                "joined": "2018-05-15"
            },
            {
                "id": "IT002",
                "name": "Sarah Johnson",
                "position": "Senior Developer",
                "department": "IT",
                "email": "sarah.johnson@corphr.com",
                "phone": "555-2345",
                "salary": "78,000",
                "joined": "2019-02-10"
            },
            {
                "id": "IT003",
                "name": "Michael Chen",
                "position": "System Administrator",
                "department": "IT",
                "email": "michael.chen@corphr.com",
                "phone": "555-3456",
                "salary": "72,000",
                "joined": "2020-07-22"
            }
        ],
        "HR": [
            {
                "id": "HR001",
                "name": "Emily Davis",
                "position": "HR Director",
                "department": "HR",
                "email": "emily.davis@corphr.com",
                "phone": "555-4567",
                "salary": "92,000",
                "joined": "2017-11-05"
            },
            {
                "id": "HR002",
                "name": "Robert Wilson",
                "position": "Recruitment Specialist",
                "department": "HR",
                "email": "robert.wilson@corphr.com",
                "phone": "555-5678",
                "salary": "65,000",
                "joined": "2021-03-18"
            }
        ],
        "Finance": [
            {
                "id": "FIN001",
                "name": "Jennifer Lee",
                "position": "Finance Manager",
                "department": "Finance",
                "email": "jennifer.lee@corphr.com",
                "phone": "555-6789",
                "salary": "95,000",
                "joined": "2016-09-30"
            },
            {
                "id": "FIN002",
                "name": "David Brown",
                "position": "Senior Accountant",
                "department": "Finance",
                "email": "david.brown@corphr.com",
                "phone": "555-7890",
                "salary": "82,000",
                "joined": "2018-12-07"
            }
        ],
        "Marketing": [
            {
                "id": "MKT001",
                "name": "Lisa Taylor",
                "position": "Marketing Director",
                "department": "Marketing",
                "email": "lisa.taylor@corphr.com",
                "phone": "555-8901",
                "salary": "90,000",
                "joined": "2019-04-15"
            }
        ],
        "Sales": [
            {
                "id": "SLS001",
                "name": "James Anderson",
                "position": "Sales Manager",
                "department": "Sales",
                "email": "james.anderson@corphr.com",
                "phone": "555-9012",
                "salary": "88,000",
                "joined": "2017-06-22"
            }
        ],
        "Executive": [
            {
                "id": "EXE001",
                "name": "Elizabeth Williams",
                "position": "CEO",
                "department": "Executive",
                "email": "elizabeth.williams@corphr.com",
                "phone": "555-0123",
                "salary": "250,000 (Flag: R00T{0rm_sql1_1nj3ct10n_byp4ss3d})",
                "joined": "2015-01-01"
            }
        ]
    }
    
    # Handle search request (POST)
    if request.method == 'POST':
        # Check for SQL injection patterns in the search term
        sqli_patterns = ["'", "\"", "--", ";", "OR", "=", "UNION", "SELECT", "FROM", "WHERE", "DROP", "INSERT", "DELETE", "UPDATE"]
        
        # Convert to uppercase for case-insensitive check
        search_term_upper = search_term.upper() if isinstance(search_term, str) else ""
        
        # Check if any SQL injection pattern is in the input
        for pattern in sqli_patterns:
            if pattern.upper() in search_term_upper:
                # SQL injection detected!
                sqli_detected = True
                break
        
        # Simulate ORM-based search
        if department in default_employees:
            if sqli_detected:
                # SQL injection successful - show all employees including the CEO
                for dept in default_employees:
                    employees.extend(default_employees[dept])
                
                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="ORM-based SQL Injection").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            elif search_term:
                # Normal search - filter employees by department and search term
                for employee in default_employees[department]:
                    if search_term.lower() in employee["name"].lower() or search_term.lower() in employee["position"].lower():
                        employees.append(employee)
                
                if not employees:
                    error = f"No employees found in {department} department matching '{search_term}'."
            else:
                # No search term - show all employees in the selected department
                employees = default_employees[department]
        else:
            error = "Invalid department selected."
    else:
        # Default view - show IT department employees
        employees = default_employees["IT"]
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="ORM-based SQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level12.html', flag=flag, sqli_detected=sqli_detected,
                          department=department, search_term=search_term, employees=employees, error=error)
'''
    
    # Insert the new route
    updated_content = content[:sqli_level11_end + 1] + new_route + content[sqli_level11_end + 1:]
    
    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)
    
    print("Added SQL Injection Level 12 route to app.py")

if __name__ == '__main__':
    add_sqli_level12_route()
