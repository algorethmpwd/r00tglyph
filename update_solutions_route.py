#!/usr/bin/env python3
from app import app, db

def update_solutions_route():
    """Update the solutions route to include the new SQL injection levels"""
    # Find the solutions route
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Find the challenge_name_map in the solutions route
    challenge_map_start = content.find("        challenge_name_map = {")
    challenge_map_end = content.find("        }", challenge_map_start)
    
    # Extract the current challenge_name_map
    current_map = content[challenge_map_start:challenge_map_end + 9]
    
    # Create the updated challenge_name_map with the new SQL injection levels
    updated_map = """        challenge_name_map = {
            'sqli1': 'Basic SQL Injection',
            'sqli2': 'SQL Injection in Search',
            'sqli3': 'SQL Injection with UNION',
            'sqli4': 'Blind SQL Injection',
            'sqli5': 'Time-Based Blind SQL Injection',
            'sqli6': 'SQL Injection with WAF Bypass',
            'sqli7': 'Error-Based SQL Injection',
            'sqli8': 'Second-Order SQL Injection',
            'sqli9': 'SQL Injection in REST API',
            'sqli10': 'NoSQL Injection',
            'sqli11': 'GraphQL Injection',
            'sqli12': 'ORM-based SQL Injection',
            'sqli13': 'Out-of-band SQL Injection',
            'sqli14': 'SQL Injection with Advanced WAF Bypass',
            'sqli15': 'SQL Injection via XML',
            'sqli16': 'SQL Injection in WebSockets',
            'sqli17': 'SQL Injection in Mobile App Backend',
            'sqli18': 'SQL Injection in Cloud Functions',
            'sqli19': 'SQL Injection via File Upload',
            'sqli20': 'SQL Injection in Stored Procedures'
        }"""
    
    # Replace the current challenge_name_map with the updated one
    updated_content = content.replace(current_map, updated_map)
    
    # Write the updated content back to app.py
    with open('app.py', 'w') as f:
        f.write(updated_content)
    
    print("Updated solutions route to include the new SQL injection levels")

if __name__ == '__main__':
    update_solutions_route()
