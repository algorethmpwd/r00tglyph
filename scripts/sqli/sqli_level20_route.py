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
