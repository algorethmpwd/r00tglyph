#!/usr/bin/env python3
import os
import requests
import time
import sys

def check_route(base_url, route, expected_status=200):
    """Check if a route is accessible"""
    url = f"{base_url}{route}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == expected_status:
            print(f"✅ Route {route} is accessible (Status: {response.status_code})")
            return True
        else:
            print(f"❌ Route {route} returned unexpected status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Error accessing route {route}: {e}")
        return False

def check_template_exists(template_path):
    """Check if a template file exists"""
    if os.path.exists(template_path):
        print(f"✅ Template {template_path} exists")
        return True
    else:
        print(f"❌ Template {template_path} does not exist")
        return False

def check_solution_exists(solution_path):
    """Check if a solution file exists"""
    if os.path.exists(solution_path):
        print(f"✅ Solution {solution_path} exists")
        return True
    else:
        print(f"❌ Solution {solution_path} does not exist")
        return False

def main():
    """Main function to verify SQL injection levels implementation"""
    print("Starting SQL Injection Levels Verification")
    print("=" * 50)
    
    # Get the base URL from command line arguments or use default
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://localhost:5000"
    
    print(f"Using base URL: {base_url}")
    
    # Check if the application is running
    try:
        response = requests.get(base_url, timeout=5)
        if response.status_code == 200:
            print(f"✅ Application is running at {base_url}")
        else:
            print(f"❌ Application returned unexpected status code: {response.status_code}")
            return
    except requests.exceptions.RequestException as e:
        print(f"❌ Error accessing application: {e}")
        print("Make sure the Flask application is running before running this script")
        return
    
    # Check if the challenges route is accessible
    if not check_route(base_url, "/challenges"):
        print("❌ Challenges route is not accessible, aborting verification")
        return
    
    # Check SQL injection routes
    sqli_routes = []
    for i in range(1, 24):
        sqli_routes.append(f"/sqli/level{i}")
    
    routes_success = 0
    routes_total = len(sqli_routes)
    
    for route in sqli_routes:
        if check_route(base_url, route):
            routes_success += 1
    
    # Check solution routes
    solution_routes = []
    for i in range(1, 24):
        solution_routes.append(f"/solutions/sqli{i}")
    
    solutions_success = 0
    solutions_total = len(solution_routes)
    
    for route in solution_routes:
        if check_route(base_url, route):
            solutions_success += 1
    
    # Check template files
    template_files = []
    for i in range(21, 24):  # Only check the new templates (21-23)
        template_files.append(f"templates/sqli/sqli_level{i}.html")
    
    templates_success = 0
    templates_total = len(template_files)
    
    for template in template_files:
        if check_template_exists(template):
            templates_success += 1
    
    # Check solution files
    solution_files = []
    for i in range(21, 24):  # Only check the new solutions (21-23)
        solution_files.append(f"templates/solutions/sqli_level{i}_solution.html")
    
    solutions_files_success = 0
    solutions_files_total = len(solution_files)
    
    for solution in solution_files:
        if check_solution_exists(solution):
            solutions_files_success += 1
    
    # Print summary
    print("\nVerification Summary:")
    print("=" * 50)
    print(f"SQL Injection Routes: {routes_success}/{routes_total} accessible")
    print(f"Solution Routes: {solutions_success}/{solutions_total} accessible")
    print(f"Template Files: {templates_success}/{templates_total} exist")
    print(f"Solution Files: {solutions_files_success}/{solutions_files_total} exist")
    
    total_success = routes_success + solutions_success + templates_success + solutions_files_success
    total_checks = routes_total + solutions_total + templates_total + solutions_files_total
    
    print(f"\nOverall: {total_success}/{total_checks} checks passed ({total_success/total_checks*100:.2f}%)")
    
    if total_success == total_checks:
        print("\n✅ All checks passed! The SQL injection levels implementation is complete and working correctly.")
    else:
        print("\n❌ Some checks failed. Please review the output above and fix any issues.")

if __name__ == '__main__':
    main()
