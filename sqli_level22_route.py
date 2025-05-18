# SQL Injection Level 22 - SQL Injection in NoSQL Database
@app.route('/sqli/level22', methods=['GET', 'POST'])
def sqli_level22():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    collection = request.form.get('collection', 'articles')
    query = request.form.get('query', '{\n  "author": "John Doe"\n}')
    results = []
    error = None
    
    if request.method == 'POST':
        try:
            # Parse the query JSON
            import json
            import re
            
            query_obj = json.loads(query)
            
            # Check for NoSQL injection patterns
            query_str = json.dumps(query_obj)
            secrets_pattern = re.compile(r'secrets', re.IGNORECASE)
            operator_pattern = re.compile(r'\$where|\$lookup|\$function|\$expr', re.IGNORECASE)
            
            # Check if the collection is 'secrets' or if the query contains suspicious patterns
            if collection == 'secrets' or secrets_pattern.search(query_str) or operator_pattern.search(query_str):
                # NoSQL injection detected!
                sqli_detected = True
                
                # Return the flag
                results = [
                    {
                        "_id": "1",
                        "title": "Restricted Document",
                        "flag": "R00T{n0sql_1nj3ct10n_3xpl01t3d}",
                        "author": "admin",
                        "created_at": "2023-01-01"
                    }
                ]
                
                # Mark challenge as completed
                challenge = Challenge.query.filter_by(name="SQL Injection in NoSQL Database").first()
                if challenge:
                    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                    if challenge.id not in completed_ids:
                        update_user_progress(machine_id, challenge.id, challenge.points)
            
            # If no NoSQL injection detected, return normal results
            elif not sqli_detected:
                if collection == 'articles':
                    # Check if the query matches any articles
                    if 'author' in query_obj and query_obj['author'] == 'John Doe':
                        results = [
                            {
                                "_id": "1",
                                "title": "Introduction to NoSQL Databases",
                                "content": "NoSQL databases are designed to handle various data models, including document, key-value, wide-column, and graph formats.",
                                "author": "John Doe",
                                "created_at": "2023-01-01"
                            },
                            {
                                "_id": "2",
                                "title": "MongoDB vs. CouchDB",
                                "content": "This article compares two popular document databases: MongoDB and CouchDB, highlighting their strengths and weaknesses.",
                                "author": "John Doe",
                                "created_at": "2023-02-15"
                            }
                        ]
                    elif 'author' in query_obj and query_obj['author'] == 'Jane Smith':
                        results = [
                            {
                                "_id": "3",
                                "title": "Scaling NoSQL Databases",
                                "content": "Learn how to scale NoSQL databases horizontally to handle large volumes of data and high traffic loads.",
                                "author": "Jane Smith",
                                "created_at": "2023-03-10"
                            }
                        ]
                    else:
                        results = []
                elif collection == 'users':
                    # Check if the query matches any users
                    if 'username' in query_obj and query_obj['username'] == 'johndoe':
                        results = [
                            {
                                "_id": "1",
                                "username": "johndoe",
                                "email": "john.doe@example.com",
                                "role": "author"
                            }
                        ]
                    elif 'username' in query_obj and query_obj['username'] == 'janesmith':
                        results = [
                            {
                                "_id": "2",
                                "username": "janesmith",
                                "email": "jane.smith@example.com",
                                "role": "author"
                            }
                        ]
                    else:
                        results = []
                elif collection == 'products':
                    # Check if the query matches any products
                    if 'category' in query_obj and query_obj['category'] == 'Electronics':
                        results = [
                            {
                                "_id": "1",
                                "title": "Smartphone X",
                                "description": "Latest smartphone with advanced features.",
                                "price": 999.99,
                                "category": "Electronics"
                            },
                            {
                                "_id": "2",
                                "title": "Laptop Pro",
                                "description": "Professional laptop for developers.",
                                "price": 1499.99,
                                "category": "Electronics"
                            }
                        ]
                    elif 'category' in query_obj and query_obj['category'] == 'Clothing':
                        results = [
                            {
                                "_id": "3",
                                "title": "Designer T-shirt",
                                "description": "Premium cotton t-shirt.",
                                "price": 49.99,
                                "category": "Clothing"
                            }
                        ]
                    else:
                        results = []
                else:
                    results = []
        
        except Exception as e:
            error = f"Error executing query: {str(e)}"
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in NoSQL Database").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level22.html', flag=flag, sqli_detected=sqli_detected,
                          collection=collection, query=query, results=results, error=error)
