#!/usr/bin/env python3
import os
import subprocess
import time

def run_command(command):
    """Run a shell command and return the output"""
    print(f"Running command: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print("Command executed successfully")
        if result.stdout:
            print(result.stdout)
    else:
        print(f"Error executing command: {command}")
        if result.stderr:
            print(result.stderr)
    return result.returncode == 0

def check_file_exists(file_path):
    """Check if a file exists"""
    return os.path.exists(file_path)

def create_directory(directory):
    """Create a directory if it doesn't exist"""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")
    else:
        print(f"Directory already exists: {directory}")

def main():
    """Main function to implement all SQL injection levels"""
    print("Starting SQL Injection Levels Implementation")
    print("=" * 50)
    
    # Step 1: Create necessary directories
    print("Creating necessary directories...")
    create_directory('templates/sqli')
    create_directory('templates/solutions')
    
    # Step 2: Add new challenges to the database
    print("Adding new challenges to the database...")
    if check_file_exists('add_new_challenges.py'):
        run_command('python add_new_challenges.py')
    else:
        print("Error: add_new_challenges.py not found")
        return
    
    # Step 3: Update app.py with the new routes
    print("Updating app.py with the new routes...")
    if check_file_exists('update_app_routes.py'):
        run_command('python update_app_routes.py')
    else:
        print("Error: update_app_routes.py not found")
        return
    
    time.sleep(1)  # Wait a bit to ensure file operations complete
    
    if check_file_exists('update_app_routes_part2.py'):
        run_command('python update_app_routes_part2.py')
    else:
        print("Error: update_app_routes_part2.py not found")
        return
    
    time.sleep(1)  # Wait a bit to ensure file operations complete
    
    if check_file_exists('update_app_routes_part3.py'):
        run_command('python update_app_routes_part3.py')
    else:
        print("Error: update_app_routes_part3.py not found")
        return
    
    # Step 4: Update the solutions route in app.py
    print("Updating solutions route in app.py...")
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the solutions route
    solutions_start = content.find("@app.route('/solutions/<level>')")
    solutions_end = content.find("def show_help():")
    
    if solutions_start != -1 and solutions_end != -1:
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
    else:
        print("Error: Could not find solutions route in app.py")
    
    # Step 5: Update the README.md file
    print("Updating README.md file...")
    with open('README.md', 'r') as f:
        readme_content = f.read()
    
    old_sqli_section = """- **SQL Injection (SQLi)**
  - Level 1: Basic SQL Injection
  - Level 2: SQL Injection in Search
  - Level 3: SQL Injection with UNION
  - Level 4: Blind SQL Injection
  - Level 5: Time-Based Blind SQL Injection
  - Level 6: SQL Injection with WAF Bypass
  - Level 7: Error-Based SQL Injection
  - Level 8: Second-Order SQL Injection
  - Level 9: SQL Injection in REST API
  - Level 10: NoSQL Injection
  - Level 11: GraphQL Injection
  - Level 12: ORM-based SQL Injection
  - Level 13: Out-of-band SQL Injection
  - Level 14: SQL Injection with Advanced WAF Bypass
  - Level 15: SQL Injection via XML
  - Level 16: SQL Injection in WebSockets
  - Level 17: SQL Injection in Mobile App Backend
  - Level 18: SQL Injection in Cloud Functions
  - Level 19: SQL Injection via File Upload
  - Level 20: SQL Injection in Stored Procedures
  - Level 21: SQL Injection in Microservices
  - Level 22: SQL Injection with Data Exfiltration via DNS
  - Level 23: Advanced Blind SQL Injection with Machine Learning Bypass"""
    
    new_sqli_section = """- **SQL Injection (SQLi)**
  - Level 1: Basic SQL Injection
  - Level 2: SQL Injection in Search
  - Level 3: SQL Injection with UNION
  - Level 4: Blind SQL Injection
  - Level 5: Time-Based Blind SQL Injection
  - Level 6: SQL Injection with WAF Bypass
  - Level 7: Error-Based SQL Injection
  - Level 8: Second-Order SQL Injection
  - Level 9: SQL Injection in REST API
  - Level 10: NoSQL Injection
  - Level 11: GraphQL Injection
  - Level 12: ORM-based SQL Injection
  - Level 13: Out-of-band SQL Injection
  - Level 14: SQL Injection with Advanced WAF Bypass
  - Level 15: SQL Injection via XML
  - Level 16: SQL Injection in WebSockets
  - Level 17: SQL Injection in Mobile App Backend
  - Level 18: SQL Injection in Cloud Functions
  - Level 19: SQL Injection via File Upload
  - Level 20: SQL Injection in Stored Procedures
  - Level 21: SQL Injection in GraphQL API
  - Level 22: SQL Injection in NoSQL Database
  - Level 23: SQL Injection in ORM Layer"""
    
    updated_readme_content = readme_content.replace(old_sqli_section, new_sqli_section)
    
    with open('README.md', 'w') as f:
        f.write(updated_readme_content)
    
    print("Updated README.md file")
    
    print("SQL Injection Levels Implementation Complete")
    print("=" * 50)
    print("Next steps:")
    print("1. Restart the Flask application")
    print("2. Test each SQL injection level")
    print("3. Verify that all levels are working correctly")

if __name__ == '__main__':
    main()
