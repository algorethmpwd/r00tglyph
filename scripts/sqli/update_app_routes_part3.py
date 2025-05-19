#!/usr/bin/env python3

def update_app_routes_part3():
    """Update app.py with the final SQL injection routes (levels 21-23)"""
    # Read the current app.py file
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the last SQL injection route (level 20)
    sqli_level20_end = content.find("    return render_template('sqli/sqli_level20.html', flag=flag, sqli_detected=sqli_detected,")
    sqli_level20_end = content.find("\n", sqli_level20_end + 1)
    
    # Define the new routes
    new_routes = """
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

# SQL Injection Level 23 - SQL Injection in ORM Layer
@app.route('/sqli/level23', methods=['GET', 'POST'])
def sqli_level23():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    search_term = request.form.get('search_term', '')
    filter_by = request.form.get('filter_by', 'title')
    sort_by = request.form.get('sort_by', 'id')
    sort_order = request.form.get('sort_order', 'asc')
    results = []
    orm_query = None
    error = None
    
    if request.method == 'POST':
        try:
            # Generate the ORM query
            orm_query = f"db.session.query(Article).filter(Article.{filter_by}.like('%{search_term}%'))"
            
            if sort_by and sort_order:
                if sort_order == 'asc':
                    orm_query += f".order_by(Article.{sort_by})"
                else:
                    orm_query += f".order_by(Article.{sort_by}.desc())"
            
            # Check for SQL injection patterns
            sqli_patterns = ["'", '"', "--", ";", "UNION", "SELECT", "FROM", "WHERE", "OR", "AND", "=", ">", "<"]
            
            # Check if any SQL injection pattern is in the input
            for pattern in sqli_patterns:
                if pattern in search_term or pattern in filter_by or pattern in sort_by:
                    # SQL injection detected!
                    sqli_detected = True
                    
                    # Return the flag
                    if "admin_flag" in search_term or "admin_flag" in filter_by or "admin_flag" in sort_by:
                        results = [
                            {
                                "id": 999,
                                "title": "Restricted Article",
                                "content": "This article contains the flag: R00T{0rm_l4y3r_sql1_1nj3ct10n_pwn3d}",
                                "author": "admin",
                                "created_at": "2023-01-01",
                                "is_published": False
                            }
                        ]
                        
                        # Mark challenge as completed
                        challenge = Challenge.query.filter_by(name="SQL Injection in ORM Layer").first()
                        if challenge:
                            completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                            if challenge.id not in completed_ids:
                                update_user_progress(machine_id, challenge.id, challenge.points)
                    else:
                        results = [
                            {
                                "id": 998,
                                "title": "Suspicious Query Detected",
                                "content": "The system has detected a potential SQL injection attempt. This incident has been logged.",
                                "author": "system",
                                "created_at": "2023-01-01",
                                "is_published": True
                            }
                        ]
                    break
            
            # If no SQL injection detected, return normal results
            if not sqli_detected:
                if search_term.lower() in "python programming":
                    results = [
                        {
                            "id": 1,
                            "title": "Introduction to Python Programming",
                            "content": "Python is a high-level, interpreted programming language known for its readability and simplicity.",
                            "author": "John Doe",
                            "created_at": "2023-01-15",
                            "is_published": True
                        },
                        {
                            "id": 2,
                            "title": "Advanced Python Techniques",
                            "content": "Learn advanced Python techniques such as decorators, generators, and context managers.",
                            "author": "Jane Smith",
                            "created_at": "2023-02-20",
                            "is_published": True
                        }
                    ]
                elif search_term.lower() in "web development":
                    results = [
                        {
                            "id": 3,
                            "title": "Modern Web Development",
                            "content": "Explore modern web development frameworks and tools for building responsive web applications.",
                            "author": "Bob Johnson",
                            "created_at": "2023-03-10",
                            "is_published": True
                        },
                        {
                            "id": 4,
                            "title": "Frontend vs Backend Development",
                            "content": "Understanding the differences between frontend and backend web development roles and responsibilities.",
                            "author": "Alice Williams",
                            "created_at": "2023-04-05",
                            "is_published": True
                        }
                    ]
                elif search_term.lower() in "database":
                    results = [
                        {
                            "id": 5,
                            "title": "SQL Database Fundamentals",
                            "content": "Learn the fundamentals of SQL databases, including tables, queries, and relationships.",
                            "author": "John Doe",
                            "created_at": "2023-05-12",
                            "is_published": True
                        },
                        {
                            "id": 6,
                            "title": "NoSQL Database Overview",
                            "content": "Explore different types of NoSQL databases and their use cases in modern applications.",
                            "author": "Jane Smith",
                            "created_at": "2023-06-18",
                            "is_published": True
                        }
                    ]
                else:
                    results = []
                
                # Sort the results
                if sort_by == 'id':
                    results.sort(key=lambda x: x['id'], reverse=(sort_order == 'desc'))
                elif sort_by == 'title':
                    results.sort(key=lambda x: x['title'], reverse=(sort_order == 'desc'))
                elif sort_by == 'author':
                    results.sort(key=lambda x: x['author'], reverse=(sort_order == 'desc'))
                elif sort_by == 'created_at':
                    results.sort(key=lambda x: x['created_at'], reverse=(sort_order == 'desc'))
        
        except Exception as e:
            error = f"Error executing query: {str(e)}"
    
    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="SQL Injection in ORM Layer").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)
    
    return render_template('sqli/sqli_level23.html', flag=flag, sqli_detected=sqli_detected,
                          search_term=search_term, filter_by=filter_by, sort_by=sort_by,
                          sort_order=sort_order, results=results, orm_query=orm_query, error=error)
"""
    
    # Insert the new routes after the last SQL injection route
    updated_content = content[:sqli_level20_end + 1] + new_routes + content[sqli_level20_end + 1:]
    
    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)
    
    print("Added SQL Injection Levels 21-23 to app.py")

if __name__ == '__main__':
    update_app_routes_part3()
