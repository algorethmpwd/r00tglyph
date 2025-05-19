#!/usr/bin/env python3
from app import app, db

def add_sqli_level11_route():
    """Add the SQL Injection Level 11 route to app.py"""
    # Find the end of the sqli_level10 function
    with open('app.py', 'r') as f:
        content = f.read()

    # Find the end of the sqli_level10 function
    sqli_level10_end = content.find("    return render_template('sqli/sqli_level10.html', flag=flag, sqli_detected=sqli_detected,")
    sqli_level10_end = content.find("\n", sqli_level10_end + 1)

    # Add the sqli_level11 function after sqli_level10
    new_route = """
# SQL Injection Level 11 - GraphQL Injection
@app.route('/sqli/level11', methods=['GET', 'POST'])
def sqli_level11():
    machine_id = get_machine_id()
    user = get_local_user()
    flag = None
    sqli_detected = False
    query = None
    response = None

    # Handle GraphQL query (POST)
    if request.method == 'POST':
        query = request.form.get('query', '')

        # Check for GraphQL injection patterns
        graphql_patterns = ["__schema", "__type", "introspection", "getPost(id: 999", "isPrivate", "admin"]

        # Check if any GraphQL injection pattern is in the input
        for pattern in graphql_patterns:
            if pattern in query:
                # GraphQL injection detected!
                sqli_detected = True
                break

        # Simulate GraphQL query execution
        if "getPost(id: 1)" in query:
            # Regular public post
            response = '''
{
  "data": {
    "getPost": {
      "id": "1",
      "title": "Getting Started with GraphQL",
      "content": "GraphQL is a query language for APIs and a runtime for fulfilling those queries with your existing data.",
      "author": {
        "name": "John Doe"
      }
    }
  }
}
'''
        elif "getPost(id: 2)" in query:
            # Another public post
            response = '''
{
  "data": {
    "getPost": {
      "id": "2",
      "title": "Advanced GraphQL Techniques",
      "content": "Learn how to use fragments, variables, and directives in GraphQL to make your queries more efficient.",
      "author": {
        "name": "Jane Smith"
      }
    }
  }
}
'''
        elif "getPosts" in query:
            # List of posts
            response = '''
{
  "data": {
    "getPosts": [
      {
        "id": "1",
        "title": "Getting Started with GraphQL",
        "isPrivate": false
      },
      {
        "id": "2",
        "title": "Advanced GraphQL Techniques",
        "isPrivate": false
      },
      {
        "id": "3",
        "title": "GraphQL Security Best Practices",
        "isPrivate": false
      },
      {
        "id": "999",
        "title": "Admin Notes",
        "isPrivate": true
      }
    ]
  }
}
'''
        elif "__schema" in query or "__type" in query:
            # Introspection query
            response = '''
{
  "data": {
    "__schema": {
      "types": [
        {
          "name": "Query",
          "fields": [
            {
              "name": "getPost",
              "type": {
                "name": "Post",
                "kind": "OBJECT"
              }
            },
            {
              "name": "getPosts",
              "type": {
                "name": null,
                "kind": "LIST"
              }
            },
            {
              "name": "searchPosts",
              "type": {
                "name": null,
                "kind": "LIST"
              }
            }
          ]
        },
        {
          "name": "Post",
          "fields": [
            {
              "name": "id",
              "type": {
                "name": null,
                "kind": "NON_NULL"
              }
            },
            {
              "name": "title",
              "type": {
                "name": null,
                "kind": "NON_NULL"
              }
            },
            {
              "name": "content",
              "type": {
                "name": null,
                "kind": "NON_NULL"
              }
            },
            {
              "name": "isPrivate",
              "type": {
                "name": null,
                "kind": "NON_NULL"
              }
            },
            {
              "name": "author",
              "type": {
                "name": "User",
                "kind": "OBJECT"
              }
            }
          ]
        }
      ]
    }
  }
}
'''
        elif "getPost(id: 999)" in query and "isPrivate" in query:
            # Private admin post with the flag - successful exploitation
            response = '''
{
  "data": {
    "getPost": {
      "id": "999",
      "title": "Admin Notes",
      "content": "Security audit scheduled for next week. Flag: R00T{gr4phql_1nj3ct10n_3xpl01t3d}",
      "isPrivate": true,
      "author": {
        "name": "Admin",
        "role": "ADMIN"
      }
    }
  }
}
'''

            # Mark challenge as completed
            challenge = Challenge.query.filter_by(name="GraphQL Injection").first()
            if challenge:
                completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
                if challenge.id not in completed_ids:
                    update_user_progress(machine_id, challenge.id, challenge.points)
        else:
            # Default response for other queries
            response = '''
{
  "data": null,
  "errors": [
    {
      "message": "Invalid query. Please check your syntax and try again."
    }
  ]
}
'''

    # Generate a flag for this challenge only if completed
    challenge = Challenge.query.filter_by(name="GraphQL Injection").first()
    completed_ids = json.loads(user.completed_challenges) if user.completed_challenges else []
    if challenge and challenge.id in completed_ids:
        flag = get_or_create_flag(challenge.id, machine_id)

    return render_template('sqli/sqli_level11.html', flag=flag, sqli_detected=sqli_detected,
                          query=query, response=response)
"""

    # Insert the new route
    updated_content = content[:sqli_level10_end + 1] + new_route + content[sqli_level10_end + 1:]

    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)

    print("Added SQL Injection Level 11 route to app.py")

if __name__ == '__main__':
    add_sqli_level11_route()
