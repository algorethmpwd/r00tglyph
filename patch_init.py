with open('app/__init__.py', 'r') as f:
    content = f.read()

import re
# Remove old blueprint imports and registers
old_bps = ['xss_bp', 'sqli_bp', 'cmdi_bp', 'ssrf_bp', 'xxe_bp', 'dynamic_bp', 'csrf_bp']
for bp in old_bps:
    content = re.sub(rf"from app\.routes\.challenges\.[a-z_]+ import {bp}\n\s*app\.register_blueprint\({bp}\)", "", content)

# Add new router
if 'dynamic_router_bp' not in content:
    content = content.replace("from app.routes.admin import admin_bp", "from app.routes.challenge_router import dynamic_router_bp\n    app.register_blueprint(dynamic_router_bp)\n    from app.routes.admin import admin_bp")

with open('app/__init__.py', 'w') as f:
    f.write(content)
