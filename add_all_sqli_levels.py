#!/usr/bin/env python3
import os
import subprocess

def run_script(script_name):
    """Run a Python script and print its output"""
    print(f"Running {script_name}...")
    result = subprocess.run(['python3', script_name], capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(f"Error: {result.stderr}")
    print(f"Finished running {script_name}")
    print("-" * 50)

def main():
    """Run all scripts to add the new SQL injection levels"""
    # Add the new challenges to the database
    run_script('add_new_sqli_challenges.py')
    
    # Add the new routes to app.py
    run_script('add_sqli_level14.py')
    run_script('add_sqli_level15.py')
    run_script('add_sqli_level16.py')
    run_script('add_sqli_level17.py')
    run_script('add_sqli_level18.py')
    run_script('add_sqli_level19.py')
    run_script('add_sqli_level20.py')
    
    # Update the solutions route
    run_script('update_solutions_route.py')
    
    print("All SQL injection levels 14-20 have been added successfully!")
    print("Please restart the application to see the changes.")

if __name__ == '__main__':
    main()
