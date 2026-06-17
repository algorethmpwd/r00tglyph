import os
import re

templates_dir = '/home/algorethm/Documents/code/r00tglyph/templates'

# Regex to match url_for('cat.cat_levelX')
pattern = re.compile(r"url_for\(['\"]([a-z]+)\.\1_level([0-9]+)['\"]\)")

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    new_content = pattern.sub(r"url_for('dynamic_router.serve_challenge', category='\1', level=\2)", content)
    
    if new_content != content:
        with open(filepath, 'w') as f:
            f.write(new_content)
        print(f"Updated {filepath}")

for root, _, files in os.walk(templates_dir):
    for file in files:
        if file.endswith('.html'):
            process_file(os.path.join(root, file))
