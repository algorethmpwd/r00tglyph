# SQL Injection Level 14 - SQL Injection with Advanced WAF Bypass
@app.route('/sqli/level14', methods=['GET', 'POST'])
def sqli_level14():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    category = request.form.get('category', 'Electronics')
    search_term = request.form.get('search_term', '')
    products = []
    error = None
    waf_blocked = False
    waf_logs = []
    
    if request.method == 'POST':
        # WAF implementation
        def waf_check(input_str):
            blocked_patterns = [
                'SELECT', 'UNION', 'FROM', 'WHERE',
                '--', '/*', "'", '"',
                '=', '>', '<'
            ]
            
            # Check if any blocked pattern is in the input (case-insensitive)
            for pattern in blocked_patterns:
                if pattern.upper() in input_str.upper():
                    # Log the WAF block
                    import datetime
                    waf_logs.append({
                        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'rule_id': blocked_patterns.index(pattern) + 1,
                        'rule_name': f"Blocked pattern: {pattern}",
                        'action': 'BLOCK',
                        'ip': request.remote_addr
                    })
                    return True
            return False
        
        # Check if the input contains SQL injection patterns
        if waf_check(category) or waf_check(search_term):
            waf_blocked = True
        else:
            # Simulate database query
            if category == 'Electronics':
                products = [
                    {"id": 1, "name": "Smartphone X", "category": "Electronics", "price": 999.99, "description": "Latest smartphone with advanced features."},
                    {"id": 2, "name": "Laptop Pro", "category": "Electronics", "price": 1499.99, "description": "Professional laptop for developers."},
                    {"id": 3, "name": "Wireless Headphones", "category": "Electronics", "price": 199.99, "description": "Noise-cancelling wireless headphones."}
                ]
            elif category == 'Clothing':
                products = [
                    {"id": 4, "name": "Designer T-shirt", "category": "Clothing", "price": 49.99, "description": "Premium cotton t-shirt."},
                    {"id": 5, "name": "Jeans", "category": "Clothing", "price": 79.99, "description": "Comfortable denim jeans."},
                    {"id": 6, "name": "Sneakers", "category": "Clothing", "price": 129.99, "description": "Stylish and comfortable sneakers."}
                ]
            
            # Check for advanced WAF bypass attempts
            advanced_bypass_patterns = [
                '%27', '%2527', '%252527',  # URL encoded single quotes
                'un%69on', 'un%69%6fn', 'un%2569on',  # URL encoded UNION
                'se%6cect', 'se%6c%65ct', 'se%2565ct',  # URL encoded SELECT
                'concat(0x', 'char(', 'hex(',  # Alternative string functions
                '0x3', '0x4', '0x5',  # Hex values
                'product%5fid',  # URL encoded underscore
                'or%20product%5fid%3d999'  # Encoded OR condition
            ]
            
            for pattern in advanced_bypass_patterns:
                if pattern in category.lower() or pattern in search_term.lower():
                    # Advanced WAF bypass detected!
                    sqli_detected = True
                    
                    # Add the restricted product (with the flag)
                    products.append({
                        "id": 999, 
                        "name": "Restricted Product", 
                        "category": "ADMIN", 
                        "price": 9999.99, 
                        "description": "This product contains the flag: R00T{4dv4nc3d_w4f_byp4ss_m4st3r}"
                    })
                    
                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="SQL Injection with Advanced WAF Bypass").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection with Advanced WAF Bypass").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level14.html', flag=flag, sqli_detected=sqli_detected,
                          category=category, search_term=search_term, products=products, 
                          error=error, waf_blocked=waf_blocked, waf_logs=waf_logs)
