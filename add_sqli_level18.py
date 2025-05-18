#!/usr/bin/env python3
from app import app, db

def add_sqli_level18_route():
    """Add the SQL Injection Level 18 route to app.py"""
    # Find the end of the sqli_level17 function
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the end of the sqli_level17 function
    sqli_level17_end = content.find("    return render_template('sqli/sqli_level17.html', flag=flag, sqli_detected=sqli_detected,")
    sqli_level17_end = content.find("\n", sqli_level17_end + 1)
    
    # Add the sqli_level18 function after sqli_level17
    new_route = '''
# SQL Injection Level 18 - SQL Injection in Cloud Functions
@app.route('/sqli/level18', methods=['GET', 'POST'])
def sqli_level18():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    event_data = None
    function_response = None
    function_duration = None
    function_memory = None
    function_status = None
    function_logs = []
    
    if request.method == 'POST':
        event_data = request.form.get('event_data', '')
        
        try:
            # Parse the event data JSON
            import json
            import random
            import datetime
            
            data = json.loads(event_data)
            
            # Extract values from the event
            action = data.get('action', '')
            dataset = data.get('dataset', '')
            filter_condition = data.get('filter', '')
            format_type = data.get('format', 'json')
            
            # Simulate function execution
            start_time = datetime.datetime.now()
            
            # Add execution logs
            function_logs.append({
                'timestamp': start_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'level': 'info',
                'message': f"Function execution started with event: {json.dumps(data)}"
            })
            
            function_logs.append({
                'timestamp': (start_time + datetime.timedelta(milliseconds=50)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'level': 'info',
                'message': f"Connecting to database..."
            })
            
            # Check for SQL injection patterns
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]
            
            # Generate simulated SQL query
            sql_query = f"SELECT * FROM {dataset} WHERE {filter_condition} LIMIT 1000"
            
            function_logs.append({
                'timestamp': (start_time + datetime.timedelta(milliseconds=100)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'level': 'info',
                'message': f"Executing query: {sql_query}"
            })
            
            # Check if any SQL injection pattern is in the dataset or filter
            for pattern in sqli_patterns:
                if (pattern in dataset or pattern in filter_condition):
                    # SQL injection detected!
                    sqli_detected = True
                    
                    function_logs.append({
                        'timestamp': (start_time + datetime.timedelta(milliseconds=150)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                        'level': 'warning',
                        'message': f"Unusual query pattern detected: {sql_query}"
                    })
                    
                    # Return the flag
                    if "security_flags" in sql_query:
                        function_response = json.dumps({
                            "status": "success",
                            "data": [
                                {
                                    "id": 1,
                                    "flag": "R00T{cl0ud_funct10n_sql1_1nj3ct10n_pwn3d}",
                                    "created_at": "2023-01-01T00:00:00Z",
                                    "is_active": True
                                }
                            ]
                        }, indent=2)
                    else:
                        function_response = json.dumps({
                            "status": "success",
                            "data": [
                                {
                                    "id": random.randint(1, 100),
                                    "value": f"Suspicious query detected: {sql_query}",
                                    "timestamp": datetime.datetime.now().isoformat()
                                }
                            ]
                        }, indent=2)
                    break
            
            # If no SQL injection detected, return normal data
            if not sqli_detected:
                if dataset == 'sales_2023':
                    function_response = json.dumps({
                        "status": "success",
                        "data": [
                            {"id": 1, "product": "Smartphone X", "quantity": 150, "revenue": 149998.5, "region": "US"},
                            {"id": 2, "product": "Laptop Pro", "quantity": 75, "revenue": 112499.25, "region": "US"},
                            {"id": 3, "product": "Wireless Headphones", "quantity": 200, "revenue": 39998.0, "region": "US"}
                        ]
                    }, indent=2)
                elif dataset == 'customers_2023':
                    function_response = json.dumps({
                        "status": "success",
                        "data": [
                            {"id": 1, "name": "John Doe", "email": "john.doe@example.com", "region": "US"},
                            {"id": 2, "name": "Jane Smith", "email": "jane.smith@example.com", "region": "US"},
                            {"id": 3, "name": "Bob Johnson", "email": "bob.johnson@example.com", "region": "US"}
                        ]
                    }, indent=2)
                else:
                    function_response = json.dumps({
                        "status": "error",
                        "message": f"Dataset '{dataset}' not found or access denied"
                    }, indent=2)
            
            # Simulate function completion
            end_time = datetime.datetime.now()
            duration = (end_time - start_time).total_seconds() * 1000  # Convert to milliseconds
            
            function_logs.append({
                'timestamp': end_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'level': 'info',
                'message': f"Function execution completed in {duration:.2f}ms"
            })
            
            # Set function execution details
            function_duration = f"{duration:.2f}"
            function_memory = str(random.randint(50, 150))
            function_status = "Success"
            
        except Exception as e:
            function_response = json.dumps({
                "status": "error",
                "message": str(e)
            }, indent=2)
            
            function_duration = str(random.randint(10, 50))
            function_memory = str(random.randint(50, 150))
            function_status = "Error"
            
            function_logs.append({
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'level': 'error',
                'message': f"Function execution failed: {str(e)}"
            })
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in Cloud Functions").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level18.html', flag=flag, sqli_detected=sqli_detected,
                          event_data=event_data, function_response=function_response,
                          function_duration=function_duration, function_memory=function_memory,
                          function_status=function_status, function_logs=function_logs)
'''
    
    # Insert the new route
    updated_content = content[:sqli_level17_end + 1] + new_route + content[sqli_level17_end + 1:]
    
    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)
    
    print("Added SQL Injection Level 18 route to app.py")

if __name__ == '__main__':
    add_sqli_level18_route()
