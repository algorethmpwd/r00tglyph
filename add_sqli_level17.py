#!/usr/bin/env python3
from app import app, db

def add_sqli_level17_route():
    """Add the SQL Injection Level 17 route to app.py"""
    # Find the end of the sqli_level16 function
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the end of the sqli_level16 function
    sqli_level16_end = content.find("    return render_template('sqli/sqli_level16.html', flag=flag, sqli_detected=sqli_detected,")
    sqli_level16_end = content.find("\n", sqli_level16_end + 1)
    
    # Add the sqli_level17 function after sqli_level16
    new_route = '''
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
                    break
            
            # If no SQL injection detected, return normal products
            if not sqli_detected:
                products = []
                
                if category == 'electronics' or category == 'Electronics':
                    products = [
                        {"id": 1, "name": "Smartphone X", "description": "Latest smartphone with advanced features.", "price": 999.99, "category": "Electronics"},
                        {"id": 2, "name": "Laptop Pro", "description": "Professional laptop for developers.", "price": 1499.99, "category": "Electronics"},
                        {"id": 3, "name": "Wireless Headphones", "description": "Noise-cancelling wireless headphones.", "price": 199.99, "category": "Electronics"}
                    ]
                elif category == 'clothing' or category == 'Clothing':
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
'''
    
    # Insert the new route
    updated_content = content[:sqli_level16_end + 1] + new_route + content[sqli_level16_end + 1:]
    
    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)
    
    print("Added SQL Injection Level 17 route to app.py")

if __name__ == '__main__':
    add_sqli_level17_route()
