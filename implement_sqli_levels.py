#!/usr/bin/env python3
import os
import subprocess

def run_script(script_path):
    """Run a Python script"""
    print(f"Running {script_path}...")
    result = subprocess.run(['python', script_path], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"Successfully ran {script_path}")
        if result.stdout:
            print(result.stdout)
    else:
        print(f"Error running {script_path}")
        if result.stderr:
            print(result.stderr)
    print()

def main():
    """Main function to implement all SQL injection levels"""
    print("Starting SQL Injection Levels Implementation")
    print("=" * 50)

    # Step 1: Add new challenges to the database
    run_script('add_new_challenges.py')

    # Step 2: Update app.py with the new routes
    run_script('update_app_routes.py')
    run_script('update_app_routes_part2.py')
    run_script('update_app_routes_part3.py')

    # Step 3: Create the templates directory if it doesn't exist
    os.makedirs('templates/sqli', exist_ok=True)
    os.makedirs('templates/solutions', exist_ok=True)

    # Step 4: Update the solutions route in app.py
    print("Updating solutions route in app.py...")
    with open('app.py', 'r') as f:
        content = f.read()

    # Find the solutions route
    solutions_start = content.find("@app.route('/solutions/<level>')")
    solutions_end = content.find("def show_help():")

    # Extract the solutions route
    solutions_route = content[solutions_start:solutions_end]

    # Update the challenge name map for SQL injection levels 21-23
    old_challenge_map = """            'sqli21': 'SQL Injection in Microservices',
            'sqli22': 'SQL Injection with Data Exfiltration via DNS',
            'sqli23': 'Advanced Blind SQL Injection with Machine Learning Bypass'"""

    new_challenge_map = """            'sqli21': 'SQL Injection in GraphQL API',
            'sqli22': 'SQL Injection in NoSQL Database',
            'sqli23': 'SQL Injection in ORM Layer'"""

    # Replace the old challenge map with the new one
    updated_solutions_route = solutions_route.replace(old_challenge_map, new_challenge_map)

    # Update the app.py file
    updated_content = content.replace(solutions_route, updated_solutions_route)

    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)

    print("Updated solutions route in app.py")

    print("SQL Injection Levels Implementation Complete")
    print("=" * 50)
    print("Next steps:")
    print("1. Restart the Flask application")
    print("2. Test each SQL injection level")
    print("3. Update the README.md file with the new levels")

if __name__ == '__main__':
    main()
