#!/usr/bin/env python3
import os
import re

def update_template(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Extract the level number from the file name
    level_num = re.search(r'sqli_level(\d+)\.html', file_path).group(1)
    
    # Extract the challenge title from the content
    title_match = re.search(r'{% block title %}Level \d+: (.*?) - R00tGlyph{% endblock %}', content)
    if title_match:
        challenge_title = title_match.group(1)
    else:
        challenge_title = f"SQL Injection Level {level_num}"
    
    # Replace the hidden challenge description with the alert-style description
    content = re.sub(
        r'<!-- Hidden challenge description that will be used by JavaScript -->\s+<div class="challenge-description" style="display: none;">',
        '<!-- Challenge description -->\n        <div class="alert alert-dark challenge-description">',
        content
    )
    
    # Add a card with dark header if it doesn't exist
    if '<div class="card-header bg-dark text-white">' not in content:
        # Find where to insert the card
        if '<div class="library-header">' in content:
            content = content.replace(
                '<div class="library-header">',
                f'<div class="card">\n            <div class="card-header bg-dark text-white">\n                <h2 class="text-center">Level {level_num}: {challenge_title}</h2>\n            </div>\n            <div class="card-body">\n                <div class="library-header">'
            )
            
            # Find the closing div for the content and add the missing closing divs
            content = re.sub(
                r'<div class="mt-4">\s+<a href="\{\{ url_for\(\'solutions\', level=\'sqli\d+\'\) \}\}" class="btn btn-outline-secondary"><i class="bi bi-lightbulb-fill me-2"></i>View Solution</a>\s+<a href="\{\{ url_for\(\'vulnerabilities\'\) \}\}" class="btn btn-outline-primary float-end"><i class="bi bi-arrow-left me-2"></i>Back to Challenges</a>\s+</div>\s+</div>\s+</div>',
                '                <div class="mt-4">\n                    <a href="{{ url_for(\'solutions\', level=\'sqli' + level_num + '\') }}" class="btn btn-outline-secondary"><i class="bi bi-lightbulb-fill me-2"></i>View Solution</a>\n                    <a href="{{ url_for(\'vulnerabilities\') }}" class="btn btn-outline-primary float-end"><i class="bi bi-arrow-left me-2"></i>Back to Challenges</a>\n                </div>\n            </div>\n        </div>\n    </div>\n</div>',
                content
            )
    
    # Add a mission briefing card if it doesn't exist
    if '<div class="card mb-3 border-secondary">' not in content:
        # Find where to insert the mission briefing
        task_match = re.search(r'<p>\s+<strong>Your Task:</strong>(.*?)</p>', content, re.DOTALL)
        if task_match:
            mission_briefing = f'''
                    <div class="card mb-3 border-secondary">
                        <div class="card-header bg-secondary text-white">
                            <i class="bi bi-briefcase-fill me-2"></i>Mission Briefing
                        </div>
                        <div class="card-body">
                            <p class="mb-0">
                                <strong>Client:</strong> Security Testing Client<br>
                                <strong>Target:</strong> SQL Injection Vulnerability<br>
                                <strong>Vulnerability:</strong> Suspected SQL Injection<br>
                                <strong>Objective:</strong> Exploit the vulnerability to extract data
                            </p>
                        </div>
                    </div>'''
            
            content = content.replace(
                task_match.group(0),
                task_match.group(0) + mission_briefing
            )
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Updated {file_path}")

def main():
    template_dir = "./templates/sqli"
    for filename in os.listdir(template_dir):
        if filename.startswith("sqli_level") and filename.endswith(".html") and filename not in ["sqli_level1.html", "sqli_level2.html"]:
            file_path = os.path.join(template_dir, filename)
            update_template(file_path)

if __name__ == "__main__":
    main()
