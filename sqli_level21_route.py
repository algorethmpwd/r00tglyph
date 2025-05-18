# SQL Injection Level 21 - SQL Injection in GraphQL API
@app.route('/sqli/level21', methods=['GET', 'POST'])
def sqli_level21():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    graphql_query = None
    graphql_result = None
    
    if request.method == 'POST':
        graphql_query = request.form.get('graphql_query', '')
        
        try:
            # Parse the GraphQL query
            import json
            import re
            
            # Check for SQL injection patterns
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]
            admin_secrets_pattern = re.compile(r'admin_secrets', re.IGNORECASE)
            
            # Check if any SQL injection pattern is in the input
            for pattern in sqli_patterns:
                if pattern in graphql_query and admin_secrets_pattern.search(graphql_query):
                    # SQL injection detected!
                    sqli_detected = True
                    
                    # Return the flag
                    graphql_result = json.dumps({
                        "data": {
                            "user": {
                                "id": "1",
                                "username": "R00T{gr4phql_sql1_1nj3ct10n_pwn3d}",
                                "email": "admin@example.com",
                                "role": "admin"
                            }
                        }
                    }, indent=2)
                    
                    # Mark challenge as completed
                    challenge = Challenge.query.filter_by(name="SQL Injection in GraphQL API").first()
                    if challenge:
                        completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                        if challenge.id not in completed_ids:
                            update_user_progress(machine_id, challenge.id, challenge.points)
                    break
            
            # If no SQL injection detected, return normal response
            if not sqli_detected:
                if "user" in graphql_query:
                    graphql_result = json.dumps({
                        "data": {
                            "user": {
                                "id": "1",
                                "username": "johndoe",
                                "email": "john.doe@example.com",
                                "role": "user"
                            }
                        }
                    }, indent=2)
                elif "products" in graphql_query:
                    graphql_result = json.dumps({
                        "data": {
                            "products": [
                                {
                                    "id": "1",
                                    "name": "Smartphone X",
                                    "description": "Latest smartphone with advanced features.",
                                    "price": 999.99,
                                    "category": "Electronics"
                                },
                                {
                                    "id": "2",
                                    "name": "Laptop Pro",
                                    "description": "Professional laptop for developers.",
                                    "price": 1499.99,
                                    "category": "Electronics"
                                },
                                {
                                    "id": "3",
                                    "name": "Wireless Headphones",
                                    "description": "Noise-cancelling wireless headphones.",
                                    "price": 199.99,
                                    "category": "Electronics"
                                }
                            ]
                        }
                    }, indent=2)
                elif "order" in graphql_query:
                    graphql_result = json.dumps({
                        "data": {
                            "order": {
                                "id": "1",
                                "userId": "1",
                                "total": 1199.98,
                                "status": "completed",
                                "createdAt": "2023-01-01T00:00:00Z",
                                "products": [
                                    {
                                        "id": "1",
                                        "name": "Smartphone X",
                                        "description": "Latest smartphone with advanced features.",
                                        "price": 999.99,
                                        "category": "Electronics"
                                    },
                                    {
                                        "id": "3",
                                        "name": "Wireless Headphones",
                                        "description": "Noise-cancelling wireless headphones.",
                                        "price": 199.99,
                                        "category": "Electronics"
                                    }
                                ]
                            }
                        }
                    }, indent=2)
                else:
                    graphql_result = json.dumps({
                        "errors": [
                            {
                                "message": "Unknown query type"
                            }
                        ]
                    }, indent=2)
        
        except Exception as e:
            graphql_result = json.dumps({
                "errors": [
                    {
                        "message": str(e)
                    }
                ]
            }, indent=2)
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in GraphQL API").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level21.html', flag=flag, sqli_detected=sqli_detected,
                          graphql_query=graphql_query, graphql_result=graphql_result)
