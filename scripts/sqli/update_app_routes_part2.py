#!/usr/bin/env python3

def update_app_routes_part2():
    """Update app.py with the remaining SQL injection routes (levels 18-23)"""
    # Read the current app.py file
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the last SQL injection route (level 17)
    sqli_level17_end = content.find("    return render_template('sqli/sqli_level17.html', flag=flag, sqli_detected=sqli_detected,")
    sqli_level17_end = content.find("\n", sqli_level17_end + 1)
    
    # Define the new routes
    new_routes = """
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
                        
                        # Mark challenge as completed
                        challenge = Challenge.query.filter_by(name="SQL Injection in Cloud Functions").first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(machine_id, challenge.id, challenge.points)
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

# SQL Injection Level 19 - SQL Injection via File Upload
@app.route('/sqli/level19', methods=['GET', 'POST'])
def sqli_level19():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    csv_content = None
    csv_preview = []
    upload_success = False
    rows_processed = 0
    rows_imported = 0
    import_status = None
    import_errors = []
    import_output = None
    error = None
    
    if request.method == 'POST':
        csv_content = request.form.get('csv_content', '')
        
        if csv_content:
            try:
                # Parse the CSV content
                import csv
                from io import StringIO
                
                csv_file = StringIO(csv_content)
                csv_reader = csv.reader(csv_file)
                
                # Convert to list for preview
                csv_rows = list(csv_reader)
                
                if len(csv_rows) > 0:
                    # Set CSV preview (limit to 10 rows)
                    csv_preview = csv_rows[:10]
                    
                    # Process the CSV rows
                    header = csv_rows[0]
                    data_rows = csv_rows[1:]
                    
                    rows_processed = len(data_rows)
                    rows_imported = 0
                    import_errors = []
                    import_output = ""
                    
                    # Check if the header has the expected columns
                    expected_columns = ['id', 'name', 'email', 'department']
                    if len(header) >= len(expected_columns) and all(col.lower() == expected_columns[i].lower() for i, col in enumerate(header[:len(expected_columns)])):
                        # Process each row
                        for i, row in enumerate(data_rows):
                            if len(row) >= len(expected_columns):
                                # Extract values
                                id_val = row[0]
                                name_val = row[1]
                                email_val = row[2]
                                department_val = row[3]
                                
                                # Check for SQL injection patterns
                                sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]
                                
                                # Check if any SQL injection pattern is in the input
                                for pattern in sqli_patterns:
                                    if (pattern in id_val or pattern in name_val or pattern in email_val or pattern in department_val):
                                        # SQL injection detected!
                                        sqli_detected = True
                                        
                                        # Simulate SQL error
                                        import_output += f"SQL Error in row {i+1}: Syntax error in SQL statement\\n"
                                        import_output += f"Attempted query: INSERT INTO employees (id, name, email, department) VALUES ('{id_val}', '{name_val}', '{email_val}', '{department_val}')\\n\\n"
                                        
                                        # Add the flag to the output
                                        import_output += "Unexpected query result:\\n"
                                        import_output += "id | flag\\n"
                                        import_output += "---+-----\\n"
                                        import_output += f"1  | R00T{{f1l3_upl04d_sql1_1nj3ct10n_pwn3d}}\\n"
                                        
                                        import_errors.append(f"Error in row {i+1}: SQL syntax error")
                                        
                                        # Mark challenge as completed
                                        challenge = Challenge.query.filter_by(name="SQL Injection via File Upload").first()
                                        if challenge:
                                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                                            if challenge.id not in completed_ids:
                                                update_user_progress(machine_id, challenge.id, challenge.points)
                                        break
                                
                                if not sqli_detected:
                                    # Simulate successful import
                                    import_output += f"Imported row {i+1}: ID={id_val}, Name={name_val}, Email={email_val}, Department={department_val}\\n"
                                    rows_imported += 1
                            else:
                                import_errors.append(f"Error in row {i+1}: Insufficient columns")
                        
                        if rows_imported == rows_processed:
                            import_status = "Complete"
                        elif rows_imported > 0:
                            import_status = "Partial"
                        else:
                            import_status = "Failed"
                    else:
                        error = "Invalid CSV format. Expected columns: id, name, email, department"
                else:
                    error = "Empty CSV file"
                
                upload_success = True
                
            except Exception as e:
                error = f"Error processing CSV: {str(e)}"
        else:
            error = "No CSV content provided"
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection via File Upload").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level19.html', flag=flag, sqli_detected=sqli_detected,
                          csv_content=csv_content, csv_preview=csv_preview, upload_success=upload_success,
                          rows_processed=rows_processed, rows_imported=rows_imported,
                          import_status=import_status, import_errors=import_errors,
                          import_output=import_output, error=error)

# SQL Injection Level 20 - SQL Injection in Stored Procedures
@app.route('/sqli/level20', methods=['GET', 'POST'])
def sqli_level20():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    category = request.form.get('category', 'Electronics')
    search_term = request.form.get('search_term', '')
    procedure_result = False
    generated_sql = None
    result_columns = []
    result_rows = []
    error = None
    
    if request.method == 'POST':
        # Simulate stored procedure execution
        try:
            # Generate the dynamic SQL that would be created by the stored procedure
            generated_sql = f"SELECT * FROM products WHERE category = '{category}' AND active = 1"
            
            if search_term:
                generated_sql += f" AND (name LIKE '%{search_term}%' OR description LIKE '%{search_term}%')"
            
            # Check for SQL injection patterns
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]
            
            # Check if any SQL injection pattern is in the input
            for pattern in sqli_patterns:
                if (pattern in category or pattern in search_term):
                    # SQL injection detected!
                    sqli_detected = True
                    
                    # Set up result columns
                    result_columns = ["id", "flag", "created_at", "is_active"]
                    
                    # Return the flag
                    if "system_flags" in generated_sql:
                        result_rows = [
                            [1, "R00T{st0r3d_pr0c3dur3_sql1_1nj3ct10n_pwn3d}", "2023-01-01 00:00:00", "true"]
                        ]
                        
                        # Mark challenge as completed
                        challenge = Challenge.query.filter_by(name="SQL Injection in Stored Procedures").first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(machine_id, challenge.id, challenge.points)
                    else:
                        result_rows = [
                            [999, "Suspicious query detected", "2023-01-01 00:00:00", "true"]
                        ]
                    
                    procedure_result = True
                    break
            
            # If no SQL injection detected, return normal products
            if not sqli_detected:
                # Set up result columns
                result_columns = ["id", "name", "description", "price", "category"]
                
                if category == 'Electronics':
                    result_rows = [
                        [1, "Smartphone X", "Latest smartphone with advanced features.", 999.99, "Electronics"],
                        [2, "Laptop Pro", "Professional laptop for developers.", 1499.99, "Electronics"],
                        [3, "Wireless Headphones", "Noise-cancelling wireless headphones.", 199.99, "Electronics"]
                    ]
                elif category == 'Clothing':
                    result_rows = [
                        [4, "Designer T-shirt", "Premium cotton t-shirt.", 49.99, "Clothing"],
                        [5, "Jeans", "Comfortable denim jeans.", 79.99, "Clothing"],
                        [6, "Sneakers", "Stylish and comfortable sneakers.", 129.99, "Clothing"]
                    ]
                else:
                    result_rows = []
                
                # Apply search filter if provided
                if search_term and result_rows:
                    result_rows = [row for row in result_rows if search_term.lower() in row[1].lower() or search_term.lower() in row[2].lower()]
                
                procedure_result = True
        
        except Exception as e:
            error = f"Error executing stored procedure: {str(e)}"
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in Stored Procedures").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level20.html', flag=flag, sqli_detected=sqli_detected,
                          category=category, search_term=search_term, procedure_result=procedure_result,
                          generated_sql=generated_sql, result_columns=result_columns,
                          result_rows=result_rows, error=error)
"""
    
    # Insert the new routes after the last SQL injection route
    updated_content = content[:sqli_level17_end + 1] + new_routes + content[sqli_level17_end + 1:]
    
    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)
    
    print("Added SQL Injection Levels 18-20 to app.py")

if __name__ == '__main__':
    update_app_routes_part2()
