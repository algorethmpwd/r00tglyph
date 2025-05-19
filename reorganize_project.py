#!/usr/bin/env python3
"""
Script to reorganize the R00tGlyph project structure.
This script will create a cleaner directory structure and move files to their appropriate locations.
"""

import os
import shutil
import glob
import re

def create_directory_structure():
    """Create the new directory structure."""
    directories = [
        'modules',
        'routes',
        'routes/xss',
        'routes/sqli',
        'scripts',
        'scripts/setup',
        'scripts/maintenance',
        'scripts/development'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        # Create __init__.py files in Python package directories
        if directory in ['modules', 'routes'] or directory.startswith('routes/'):
            init_file = os.path.join(directory, '__init__.py')
            if not os.path.exists(init_file):
                with open(init_file, 'w') as f:
                    f.write('# This file makes the directory a Python package\n')
    
    print("✅ Created directory structure")

def move_files():
    """Move files to their appropriate locations."""
    # Move SQLi route files
    for file in glob.glob('sqli_level*_route.py'):
        shutil.move(file, os.path.join('routes/sqli', file))
    
    # Move SQLi development scripts
    for file in glob.glob('add_sqli_*.py'):
        shutil.move(file, os.path.join('scripts/development', file))
    
    # Move utility scripts
    for file in glob.glob('update_*.py'):
        shutil.move(file, os.path.join('scripts/maintenance', file))
    
    for file in glob.glob('check_*.py'):
        shutil.move(file, os.path.join('scripts/maintenance', file))
    
    # Move implementation scripts
    for file in glob.glob('*implementation*.py'):
        shutil.move(file, os.path.join('scripts/development', file))
    
    # Move verification scripts
    for file in glob.glob('*verify*.py'):
        shutil.move(file, os.path.join('scripts/development', file))
    
    print("✅ Moved files to their appropriate locations")

def create_module_files():
    """Create initial module files with placeholder content."""
    module_files = {
        'modules/auth.py': '"""Authentication functions for R00tGlyph."""\n\n# Authentication functions will be moved here\n',
        'modules/challenges.py': '"""Challenge management functions for R00tGlyph."""\n\n# Challenge management functions will be moved here\n',
        'modules/database.py': '"""Database models and functions for R00tGlyph."""\n\n# Database models will be moved here\n',
        'modules/utils.py': '"""Utility functions for R00tGlyph."""\n\n# Utility functions will be moved here\n',
        'modules/waf.py': '"""WAF emulation functions for R00tGlyph."""\n\n# WAF emulation functions will be moved here\n',
        'routes/main.py': '"""Main route handlers for R00tGlyph."""\n\n# Main route handlers will be moved here\n'
    }
    
    for file_path, content in module_files.items():
        with open(file_path, 'w') as f:
            f.write(content)
    
    print("✅ Created module files")

def update_gitignore():
    """Update .gitignore file."""
    gitignore_entries = [
        '__pycache__/',
        '*.py[cod]',
        '*$py.class',
        '.venv/',
        '.env',
        '*.log',
        '*.tmp',
        '.DS_Store',
        'instance/',
        'backup/',
        'scripts/development/'
    ]
    
    # Read existing .gitignore
    existing_entries = []
    if os.path.exists('.gitignore'):
        with open('.gitignore', 'r') as f:
            existing_entries = [line.strip() for line in f.readlines()]
    
    # Add new entries
    with open('.gitignore', 'w') as f:
        for entry in existing_entries:
            if entry and entry not in gitignore_entries:
                f.write(f"{entry}\n")
        
        for entry in gitignore_entries:
            if entry not in existing_entries:
                f.write(f"{entry}\n")
    
    print("✅ Updated .gitignore file")

def create_readme_for_directories():
    """Create README.md files for each directory explaining its purpose."""
    directory_descriptions = {
        'modules': 'This directory contains the core modules of the R00tGlyph application.',
        'routes': 'This directory contains the route handlers for the R00tGlyph application.',
        'routes/xss': 'This directory contains the route handlers for XSS challenges.',
        'routes/sqli': 'This directory contains the route handlers for SQL injection challenges.',
        'scripts': 'This directory contains utility scripts for the R00tGlyph application.',
        'scripts/setup': 'This directory contains setup scripts for the R00tGlyph application.',
        'scripts/maintenance': 'This directory contains maintenance scripts for the R00tGlyph application.',
        'scripts/development': 'This directory contains development scripts for the R00tGlyph application.'
    }
    
    for directory, description in directory_descriptions.items():
        readme_path = os.path.join(directory, 'README.md')
        with open(readme_path, 'w') as f:
            f.write(f"# {os.path.basename(directory).capitalize()}\n\n{description}\n")
    
    print("✅ Created README.md files for directories")

def main():
    """Main function to reorganize the project."""
    print("🔄 Starting project reorganization...")
    
    # Create the directory structure
    create_directory_structure()
    
    # Create module files
    create_module_files()
    
    # Move files
    move_files()
    
    # Update .gitignore
    update_gitignore()
    
    # Create README.md files for directories
    create_readme_for_directories()
    
    print("✅ Project reorganization complete!")
    print("\nNext steps:")
    print("1. Review the changes and make sure everything is in the right place")
    print("2. Update imports in app.py to use the new module structure")
    print("3. Test the application to ensure everything still works")

if __name__ == "__main__":
    main()
