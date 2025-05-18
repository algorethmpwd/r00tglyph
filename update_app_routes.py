#!/usr/bin/env python3

def update_app_routes():
    """Update app.py with the new SQL injection routes"""
    # Read the current app.py file
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the last SQL injection route (level 13)
    sqli_level13_end = content.find("    return render_template('sqli/sqli_level13.html', flag=flag, sqli_detected=sqli_detected,")
    sqli_level13_end = content.find("\n", sqli_level13_end + 1)
    
    # Define the new routes
    new_routes = """
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

# SQL Injection Level 15 - SQL Injection via XML
@app.route('/sqli/level15', methods=['GET', 'POST'])
def sqli_level15():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    xml_data = None
    reports = []
    error = None
    
    if request.method == 'POST':
        xml_data = request.form.get('xml_data', '')
        
        # Check if the XML is well-formed
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_data)
            
            # Extract values from XML
            report_type = root.find('type').text if root.find('type') is not None else ''
            report_period = root.find('period').text if root.find('period') is not None else ''
            report_department = root.find('department').text if root.find('department') is not None else ''
            
            # Check for SQL injection patterns in XML values
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "="]
            
            for pattern in sqli_patterns:
                if (pattern in report_type or pattern in report_period or pattern in report_department):
                    # SQL injection detected!
                    sqli_detected = True
                    
                    # Add the restricted report (with the flag)
                    reports.append({
                        "id": 999, 
                        "title": "Restricted Financial Report", 
                        "type": "confidential", 
                        "period": "annual", 
                        "department": "executive",
                        "data": "This report contains the flag: R00T{xml_sql1_1nj3ct10n_3xpl01t3d}"
                    })
                    
                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="SQL Injection via XML").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            
            # If no SQL injection detected, return normal reports
            if not sqli_detected:
                if report_type == 'sales':
                    reports = [
                        {"id": 1, "title": "Sales Report Q1", "type": "sales", "period": "quarterly", "department": report_department, "data": "Sales increased by 15% in Q1."},
                        {"id": 2, "title": "Sales Report Q2", "type": "sales", "period": "quarterly", "department": report_department, "data": "Sales increased by 10% in Q2."}
                    ]
                elif report_type == 'inventory':
                    reports = [
                        {"id": 3, "title": "Inventory Status", "type": "inventory", "period": report_period, "department": report_department, "data": "Current inventory levels are optimal."},
                        {"id": 4, "title": "Inventory Forecast", "type": "inventory", "period": report_period, "department": report_department, "data": "Inventory forecast for next quarter is stable."}
                    ]
                elif report_type == 'marketing':
                    reports = [
                        {"id": 5, "title": "Marketing Campaign Results", "type": "marketing", "period": report_period, "department": report_department, "data": "Recent campaign resulted in 20% increase in leads."},
                        {"id": 6, "title": "Marketing Budget", "type": "marketing", "period": report_period, "department": report_department, "data": "Marketing budget allocation for next quarter."}
                    ]
        except Exception as e:
            error = f"Error processing XML: {str(e)}"
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection via XML").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level15.html', flag=flag, sqli_detected=sqli_detected,
                          xml_data=xml_data, reports=reports, error=error)

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
                        update_user_progress(machine_id, challenge.id, challenge.points)
                    
                    return jsonify({"success": True})
                return jsonify({"success": False, "error": "Challenge not found"})
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in WebSockets").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level16.html', flag=flag, sqli_detected=sqli_detected,
                          ws_message=ws_message)

# SQL Injection Level 17 - SQL Injection in Mobile App Backend
@app.route('/sqli/level17', methods=['GET', 'POST'])
def sqli_level17():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    api_request = None
    api_response = None
    
    if request.method == 'POST':
        api_request = request.form.get('api_request', '')
        
        try:
            # Parse the API request JSON
            import json
            data = json.loads(api_request)
            
            # Extract values from the request
            action = data.get('action', '')
            category = data.get('category', '')
            sort = data.get('sort', 'price_asc')
            limit = data.get('limit', 10)
            search = data.get('search', '')
            
            # Check for SQL injection patterns
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]
            
            # Check if any SQL injection pattern is in the input
            for pattern in sqli_patterns:
                if (pattern in category or pattern in sort or pattern in str(search)):
                    # SQL injection detected!
                    sqli_detected = True
                    
                    # Return the restricted product (with the flag)
                    api_response = json.dumps({
                        "status": "success",
                        "products": [
                            {
                                "id": 999,
                                "name": "Restricted Product",
                                "description": "This product contains the flag: R00T{m0b1l3_4pp_b4ck3nd_sql1_pwn3d}",
                                "price": 9999.99,
                                "category": "RESTRICTED"
                            }
                        ]
                    }, indent=2)
                    
                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="SQL Injection in Mobile App Backend").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            
            # If no SQL injection detected, return normal products
            if not sqli_detected:
                products = []
                
                if category.lower() == 'electronics':
                    products = [
                        {"id": 1, "name": "Smartphone X", "description": "Latest smartphone with advanced features.", "price": 999.99, "category": "Electronics"},
                        {"id": 2, "name": "Laptop Pro", "description": "Professional laptop for developers.", "price": 1499.99, "category": "Electronics"},
                        {"id": 3, "name": "Wireless Headphones", "description": "Noise-cancelling wireless headphones.", "price": 199.99, "category": "Electronics"}
                    ]
                elif category.lower() == 'clothing':
                    products = [
                        {"id": 4, "name": "Designer T-shirt", "description": "Premium cotton t-shirt.", "price": 49.99, "category": "Clothing"},
                        {"id": 5, "name": "Jeans", "description": "Comfortable denim jeans.", "price": 79.99, "category": "Clothing"},
                        {"id": 6, "name": "Sneakers", "description": "Stylish and comfortable sneakers.", "price": 129.99, "category": "Clothing"}
                    ]
                
                # Apply search filter if provided
                if search:
                    products = [p for p in products if search.lower() in p['name'].lower() or search.lower() in p['description'].lower()]
                
                # Sort products
                if sort == 'price_asc':
                    products.sort(key=lambda p: p['price'])
                elif sort == 'price_desc':
                    products.sort(key=lambda p: p['price'], reverse=True)
                elif sort == 'name_asc':
                    products.sort(key=lambda p: p['name'])
                elif sort == 'name_desc':
                    products.sort(key=lambda p: p['name'], reverse=True)
                
                # Apply limit
                products = products[:limit]
                
                api_response = json.dumps({
                    "status": "success",
                    "products": products
                }, indent=2)
        
        except Exception as e:
            api_response = json.dumps({
                "status": "error",
                "message": str(e)
            }, indent=2)
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in Mobile App Backend").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level17.html', flag=flag, sqli_detected=sqli_detected,
                          api_request=api_request, api_response=api_response)
"""
    
    # Insert the new routes after the last SQL injection route
    updated_content = content[:sqli_level13_end + 1] + new_routes + content[sqli_level13_end + 1:]
    
    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)
    
    print("Added SQL Injection Levels 14-17 to app.py")

if __name__ == '__main__':
    update_app_routes()
