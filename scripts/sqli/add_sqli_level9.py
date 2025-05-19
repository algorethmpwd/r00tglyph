#!/usr/bin/env python3
from app import app, db

def add_sqli_level9_route():
    """Add the SQL Injection Level 9 route to app.py"""
    # Find the end of the sqli_level8 function
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the end of the sqli_level8 function
    sqli_level8_end = content.find("    return render_template('sqli/sqli_level8.html', flag=flag, sqli_detected=sqli_detected,")
    sqli_level8_end = content.find("\n", sqli_level8_end + 1)
    
    # Add the sqli_level9 function after sqli_level8
    new_route = """
# SQL Injection Level 9 - SQL Injection in REST API
@app.route('/sqli/level9', methods=['GET', 'POST'])
def sqli_level9():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    request_body = None
    response = None
    
    # Handle API request (POST)
    if request.method == 'POST':
        request_body = request.form.get('request_body', '')
        
        try:
            # Parse the JSON request body
            json_data = json.loads(request_body)
            
            # Extract parameters
            category = json_data.get('category', '')
            price = json_data.get('price', 0)
            in_stock = json_data.get('in_stock', False)
            
            # Check for SQL injection patterns in the category parameter
            sqli_patterns = ["'", "\"", "--", ";", "OR", "=", "UNION", "SELECT", "FROM", "WHERE", "DROP", "INSERT", "DELETE", "UPDATE"]
            
            # Convert to uppercase for case-insensitive check
            category_upper = category.upper() if isinstance(category, str) else ""
            price_str = str(price).upper()
            
            # Check if any SQL injection pattern is in the input
            for pattern in sqli_patterns:
                if pattern.upper() in category_upper or pattern.upper() in price_str:
                    # SQL injection detected!
                    sqli_detected = True
                    break
            
            # Simulate API response
            products = [
                {"id": 1, "name": "Smartphone Pro", "category": "Electronics", "price": 999.99, "description": "Latest smartphone with advanced features"},
                {"id": 2, "name": "Laptop Ultra", "category": "Electronics", "price": 1499.99, "description": "Powerful laptop for professionals"},
                {"id": 3, "name": "Wireless Earbuds", "category": "Electronics", "price": 199.99, "description": "Premium wireless earbuds with noise cancellation"}
            ]
            
            # Filter products based on category and price (simulating normal behavior)
            filtered_products = []
            for product in products:
                if (product['category'] == category or not category) and product['price'] <= price:
                    if not in_stock or (in_stock and product.get('stock', 10) > 0):
                        filtered_products.append(product)
            
            # If SQL injection is detected, add the hidden admin product
            if sqli_detected:
                admin_product = {
                    "id": 999, 
                    "name": "Admin Console", 
                    "category": "Restricted", 
                    "price": 9999.99, 
                    "description": "Administrative product with flag: R00T{r3st_4p1_sql1_1nj3ct10n_pwn3d}"
                }
                filtered_products.append(admin_product)
                
                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="SQL Injection in REST API").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            
            # Generate JSON response
            response = json.dumps({"products": filtered_products})
            
        except json.JSONDecodeError:
            response = json.dumps({"error": "Invalid JSON format"})
        except Exception as e:
            response = json.dumps({"error": str(e)})
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in REST API").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level9.html', flag=flag, sqli_detected=sqli_detected,
                          request_body=request_body, response=response)
"""
    
    # Insert the new route
    updated_content = content[:sqli_level8_end + 1] + new_route + content[sqli_level8_end + 1:]
    
    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)
    
    print("Added SQL Injection Level 9 route to app.py")

if __name__ == '__main__':
    add_sqli_level9_route()
