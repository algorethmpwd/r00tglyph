#!/usr/bin/env python3
"""Generate interactive challenge templates for all categories that have placeholder content."""
import os

TEMPLATES_DIR = "templates"

def write_template(filepath, content):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        f.write(content)
    print(f"  ✓ {filepath}")

# ============================================================
# SSRF TEMPLATES
# ============================================================
SSRF_SCENARIOS = [
    {"level": 1, "title": "Basic SSRF", "context": "A web proxy service that fetches URLs on your behalf.", "form_label": "Enter URL to fetch:", "placeholder": "https://example.com"},
    {"level": 2, "title": "SSRF with Internal Network Scanning", "context": "A network monitoring dashboard that checks service health by URL.", "form_label": "Service URL to check:", "placeholder": "http://internal-service:8080/health"},
    {"level": 3, "title": "Cloud Metadata SSRF", "context": "An image processing service that loads images from URLs.", "form_label": "Image URL:", "placeholder": "https://example.com/image.jpg"},
    {"level": 4, "title": "Blind SSRF with DNS Exfiltration", "context": "A webhook registration system that validates URLs by making requests.", "form_label": "Webhook URL:", "placeholder": "https://your-callback.example.com/webhook"},
    {"level": 5, "title": "SSRF with Basic Filters", "context": "A URL shortener that previews destination URLs before redirecting.", "form_label": "URL to preview:", "placeholder": "https://example.com"},
    {"level": 6, "title": "SSRF via File Upload", "context": "An SVG image processor that fetches external resources referenced in SVG files.", "form_label": "SVG Content:", "placeholder": "<svg><image href=\"http://internal/secret\"/></svg>"},
    {"level": 7, "title": "SSRF in Webhooks", "context": "A CI/CD pipeline that sends build notifications to webhook URLs.", "form_label": "Webhook URL:", "placeholder": "https://hooks.example.com/notify"},
    {"level": 8, "title": "SSRF with WAF Bypass", "context": "A URL validation service with basic IP filtering.", "form_label": "URL to validate:", "placeholder": "https://example.com"},
    {"level": 9, "title": "SSRF via XXE", "context": "An XML document processor that resolves external entities.", "form_label": "XML Document:", "placeholder": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://internal\">]><root>&xxe;</root>"},
    {"level": 10, "title": "SSRF with DNS Rebinding", "context": "A DNS lookup tool that resolves and fetches URLs.", "form_label": "Domain to resolve:", "placeholder": "example.com"},
    {"level": 11, "title": "SSRF in GraphQL", "context": "A GraphQL API that fetches data from internal microservices.", "form_label": "GraphQL Query:", "placeholder": "{ fetchUrl(url: \"http://internal/api\") }"},
    {"level": 12, "title": "SSRF via Redis Protocol", "context": "A cache management tool that connects to Redis via URL.", "form_label": "Redis URL:", "placeholder": "redis://localhost:6379"},
    {"level": 13, "title": "SSRF in WebSocket Upgrade", "context": "A WebSocket proxy that connects to backend services.", "form_label": "WebSocket URL:", "placeholder": "ws://internal-service:8080/ws"},
    {"level": 14, "title": "SSRF via SMTP Protocol", "context": "An email preview service that connects to mail servers.", "form_label": "Mail Server URL:", "placeholder": "smtp://internal-mail:25"},
    {"level": 15, "title": "SSRF in OAuth Callbacks", "context": "An OAuth integration that validates redirect URIs.", "form_label": "Redirect URI:", "placeholder": "https://example.com/callback"},
    {"level": 16, "title": "SSRF via LDAP Protocol", "context": "A directory lookup tool that queries LDAP servers.", "form_label": "LDAP URL:", "placeholder": "ldap://internal-dc:389"},
    {"level": 17, "title": "SSRF in Container Metadata", "context": "A container diagnostics tool that fetches metadata endpoints.", "form_label": "Metadata URL:", "placeholder": "http://169.254.169.254/latest/meta-data/"},
    {"level": 18, "title": "SSRF via FTP Protocol", "context": "A file transfer preview service that connects to FTP servers.", "form_label": "FTP URL:", "placeholder": "ftp://internal-ftp:21/pub"},
    {"level": 19, "title": "SSRF in API Gateway", "context": "An API gateway that routes requests to backend services.", "form_label": "Backend URL:", "placeholder": "http://backend-api:3000/users"},
    {"level": 20, "title": "SSRF via Time-based Attacks", "context": "A URL response time analyzer.", "form_label": "URL to analyze:", "placeholder": "http://internal-service/api"},
    {"level": 21, "title": "SSRF in Microservices", "context": "A service mesh dashboard that probes internal services.", "form_label": "Service URL:", "placeholder": "http://user-service:8080/health"},
    {"level": 22, "title": "SSRF via Protocol Smuggling", "context": "A multi-protocol proxy that supports gopher, dict, and file protocols.", "form_label": "Protocol URL:", "placeholder": "gopher://localhost:6379/_INFO"},
    {"level": 23, "title": "SSRF in Serverless Functions", "context": "A serverless function that fetches external data sources.", "form_label": "Data Source URL:", "placeholder": "https://api.example.com/data"},
]

for s in SSRF_SCENARIOS:
    content = f'''{{% extends 'base.html' %}}

{{% block title %}}SSRF Level {s['level']}: {s['title']} - R00tGlyph{{% endblock %}}

{{% block content %}}
<div class="container mt-4">
    <div class="row">
        <div class="col-lg-8">
            <div class="card mb-4">
                <div class="card-header bg-danger text-white">
                    <h4 class="mb-0"><i class="bi bi-globe2 me-2"></i>SSRF Level {s['level']}: {s['title']}</h4>
                </div>
                <div class="card-body">
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle me-2"></i><strong>Scenario:</strong> {s['context']}
                    </div>

                    <div class="mb-4">
                        <h5><i class="bi bi-bullseye me-2"></i>Your Mission</h5>
                        <p>Exploit the SSRF vulnerability to access internal resources. Try targeting:</p>
                        <ul>
                            <li><code>http://127.0.0.1</code> - Localhost</li>
                            <li><code>http://169.254.169.254</code> - Cloud metadata</li>
                            <li><code>http://internal-service:8080</code> - Internal services</li>
                        </ul>
                    </div>

                    <form method="POST">
                        <div class="mb-3">
                            <label for="url" class="form-label">{s['form_label']}</label>
                            <input type="text" class="form-control" id="url" name="url" placeholder="{s['placeholder']}" value="{{ url_input or '' }}">
                        </div>
                        <button type="submit" class="btn btn-danger">
                            <i class="bi bi-send me-1"></i>Send Request
                        </button>
                    </form>

                    {{% if response_output %}}
                    <div class="mt-4">
                        <h6><i class="bi bi-terminal me-2"></i>Response:</h6>
                        <pre class="bg-dark text-success p-3 rounded"><code>{{{{ response_output }}}}</code></pre>
                    </div>
                    {{% endif %}}

                    {{% if error_message %}}
                    <div class="alert alert-danger mt-3">{{{{ error_message }}}}</div>
                    {{% endif %}}
                </div>
            </div>
        </div>

        <div class="col-lg-4">
            <div class="card mb-3">
                <div class="card-header">
                    <h5 class="mb-0"><i class="bi bi-lightbulb me-2"></i>Tips</h5>
                </div>
                <div class="card-body">
                    <ul class="small text-muted mb-0">
                        <li>Try <code>127.0.0.1</code>, <code>0.0.0.0</code>, <code>localhost</code></li>
                        <li>Cloud metadata: <code>169.254.169.254</code></li>
                        <li>Bypass filters with encodings: <code>0x7f000001</code>, <code>2130706433</code></li>
                        <li>Try protocols: <code>file://</code>, <code>gopher://</code>, <code>dict://</code></li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>
{{% endblock %}}
'''
    write_template(f"{TEMPLATES_DIR}/ssrf/ssrf_level{s['level']}.html", content)

print("\n✅ SSRF templates generated!")
