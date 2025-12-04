#!/usr/bin/env python
"""
Complete XSS Template Generator - All Levels 3-23
Generates all remaining XSS challenge templates with tailored hints
"""

# Complete XSS Challenge Data for levels 3-23
xss_challenges = [
    # Levels 3-7 (already generated, included for completeness)
    {
        "level": 3, "title": "Stored XSS", "app_name": "BlogHub", "url": "bloghub.local/post",
        "objective": "Inject persistent JavaScript via comment storage",
        "hints": [
            {"title": "Understanding Stored XSS", "icon": "lightbulb", "content": "Stored XSS occurs when malicious scripts are permanently stored on the server. Look for input fields that store and display user content like comments or posts."},
            {"title": "Finding the Injection Point", "icon": "code-slash", "content": "Test if HTML is sanitized by entering <code>&lt;b&gt;test&lt;/b&gt;</code>. If it renders as bold, you can inject scripts."},
            {"title": "Solution", "icon": "shield-check", "content": "Enter <code>&lt;script&gt;alert('XSS Level 3 Completed!')&lt;/script&gt;</code> in the comment field. The script persists and executes for all viewers."}
        ]
    },
    {
        "level": 4, "title": "Attribute Injection XSS", "app_name": "UserProfile", "url": "userprofile.local/edit",
        "objective": "Exploit HTML attribute injection",
        "hints": [
            {"title": "Attribute Context", "icon": "lightbulb", "content": "XSS can occur within HTML attributes. View source to find where your input appears in attributes like <code>value=\"\"</code>."},
            {"title": "Breaking Out", "icon": "code-slash", "content": "Close the attribute with a quote and add an event handler: <code>\" onfocus=\"alert(1)\"</code>"},
            {"title": "Solution", "icon": "shield-check", "content": "Inject: <code>\" onfocus=\"alert('XSS Level 4 Completed!')\" autofocus=\"</code> to break out and execute code."}
        ]
    },
    {
        "level": 5, "title": "Event Handler XSS", "app_name": "ImageGallery", "url": "gallery.local/upload",
        "objective": "Use event handlers without script tags",
        "hints": [
            {"title": "Event Handlers", "icon": "lightbulb", "content": "HTML elements support event handlers: onclick, onerror, onload. These execute JavaScript without <code>&lt;script&gt;</code> tags."},
            {"title": "Image Tag Trick", "icon": "code-slash", "content": "Use: <code>&lt;img src=x onerror=\"alert(1)\"&gt;</code>. When the image fails to load, onerror fires."},
            {"title": "Solution", "icon": "shield-check", "content": "Enter: <code>&lt;img src=x onerror=\"alert('XSS Level 5 Completed!')\"&gt;</code>"}
        ]
    },
    {
        "level": 6, "title": "XSS with HTML Encoding", "app_name": "SecureForm", "url": "secureform.local/submit",
        "objective": "Bypass incomplete HTML encoding",
        "hints": [
            {"title": "Encoding Bypass", "icon": "lightbulb", "content": "Test which characters are encoded. Sometimes only <code>&lt;&gt;</code> are encoded, leaving quotes vulnerable."},
            {"title": "Using Existing Tags", "icon": "code-slash", "content": "If angle brackets are encoded, inject into existing tag attributes using quotes."},
            {"title": "Solution", "icon": "shield-check", "content": "Use: <code>\" onclick=\"alert('XSS Level 6 Completed!')\"</code> in an attribute context."}
        ]
    },
    {
        "level": 7, "title": "XSS via JavaScript String", "app_name": "UserDashboard", "url": "dashboard.local/welcome",
        "objective": "Break out of JavaScript string context",
        "hints": [
            {"title": "JavaScript Context", "icon": "lightbulb", "content": "Your input might be in a JS string: <code>var name = \"YOUR_INPUT\";</code>. Break out of the string."},
            {"title": "String Escape", "icon": "code-slash", "content": "Use: <code>\"; alert(\"XSS\"); //</code> to close the string, execute code, and comment out the rest."},
            {"title": "Solution", "icon": "shield-check", "content": "Enter: <code>\"; alert(\"XSS Level 7 Completed!\"); //</code>"}
        ]
    },
    # Levels 8-23
    {
        "level": 8, "title": "XSS with Character Filtering", "app_name": "FilteredInput", "url": "filtered.local/search",
        "objective": "Bypass basic character filters",
        "hints": [
            {"title": "Filter Detection", "icon": "lightbulb", "content": "Test what's blocked: try <code>&lt;script&gt;</code>, <code>alert</code>, <code>onerror</code>. Identify the filter patterns."},
            {"title": "Encoding Bypass", "icon": "code-slash", "content": "Try alternatives: <code>&lt;img src=x onerror=prompt(1)&gt;</code> or <code>&lt;svg onload=alert(1)&gt;</code>"},
            {"title": "Solution", "icon": "shield-check", "content": "Use: <code>&lt;svg onload=\"alert('XSS Level 8 Completed!')\"&gt;</code> to bypass script tag filters."}
        ]
    },
    {
        "level": 9, "title": "XSS via SVG", "app_name": "GraphicsEditor", "url": "graphics.local/create",
        "objective": "Exploit SVG tags for XSS",
        "hints": [
            {"title": "SVG Tags", "icon": "lightbulb", "content": "SVG elements support event handlers. <code>&lt;svg&gt;</code> tags are often overlooked by filters."},
            {"title": "SVG Payload", "icon": "code-slash", "content": "Try: <code>&lt;svg onload=alert(1)&gt;</code> or <code>&lt;svg&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;/svg&gt;</code>"},
            {"title": "Solution", "icon": "shield-check", "content": "Enter: <code>&lt;svg onload=\"alert('XSS Level 9 Completed!')\"&gt;</code>"}
        ]
    },
    {
        "level": 10, "title": "XSS via Data URI", "app_name": "LinkShortener", "url": "short.link/create",
        "objective": "Use data URIs for XSS",
        "hints": [
            {"title": "Data URIs", "icon": "lightbulb", "content": "Data URIs embed data in URLs: <code>data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;</code>"},
            {"title": "Link Injection", "icon": "code-slash", "content": "Try: <code>javascript:alert(1)</code> or data URIs in href attributes."},
            {"title": "Solution", "icon": "shield-check", "content": "Use: <code>javascript:alert('XSS Level 10 Completed!')</code> in the URL field."}
        ]
    },
    {
        "level": 11, "title": "XSS via CSS", "app_name": "StyleEditor", "url": "style.local/custom",
        "objective": "Exploit CSS for JavaScript execution",
        "hints": [
            {"title": "CSS Expressions", "icon": "lightbulb", "content": "Older browsers supported CSS expressions. Modern attacks use CSS imports or background URLs."},
            {"title": "CSS Injection", "icon": "code-slash", "content": "Try: <code>@import 'javascript:alert(1)';</code> or <code>background:url('javascript:alert(1)')</code>"},
            {"title": "Solution", "icon": "shield-check", "content": "Inject CSS that loads external resources or uses expression() in legacy contexts."}
        ]
    },
    {
        "level": 12, "title": "XSS with CSP Bypass", "app_name": "SecureApp", "url": "secure.app/protected",
        "objective": "Bypass Content Security Policy",
        "hints": [
            {"title": "Understanding CSP", "icon": "lightbulb", "content": "CSP restricts script sources. Check the CSP header for allowed sources and misconfigurations."},
            {"title": "CSP Weaknesses", "icon": "code-slash", "content": "Look for unsafe-inline, unsafe-eval, or whitelisted CDNs you can abuse."},
            {"title": "Solution", "icon": "shield-check", "content": "Exploit CSP misconfigurations like JSONP endpoints on whitelisted domains."}
        ]
    },
    {
        "level": 13, "title": "XSS via Template Injection", "app_name": "TemplateEngine", "url": "template.local/render",
        "objective": "Exploit template engine vulnerabilities",
        "hints": [
            {"title": "Template Engines", "icon": "lightbulb", "content": "Template engines like Jinja2, Handlebars process special syntax. Test for template injection."},
            {"title": "Template Syntax", "icon": "code-slash", "content": "Try: <code>{{7*7}}</code> or <code>${7*7}</code>. If it evaluates to 49, you have template injection."},
            {"title": "Solution", "icon": "shield-check", "content": "Use template-specific payloads to execute JavaScript in the rendered output."}
        ]
    },
    {
        "level": 14, "title": "XSS in JSON Context", "app_name": "APIViewer", "url": "api.local/view",
        "objective": "Break out of JSON context",
        "hints": [
            {"title": "JSON Context", "icon": "lightbulb", "content": "Your input might be in JSON: <code>{\"name\":\"YOUR_INPUT\"}</code>. Break out of the JSON structure."},
            {"title": "JSON Escape", "icon": "code-slash", "content": "Use: <code>\",\"xss\":\"&lt;script&gt;alert(1)&lt;/script&gt;</code> to inject new JSON keys."},
            {"title": "Solution", "icon": "shield-check", "content": "Break JSON structure and inject HTML that gets rendered."}
        ]
    },
    {
        "level": 15, "title": "XSS via File Upload", "app_name": "FileShare", "url": "files.local/upload",
        "objective": "Upload HTML/SVG files with scripts",
        "hints": [
            {"title": "File Upload XSS", "icon": "lightbulb", "content": "Upload HTML or SVG files containing JavaScript. If served with wrong Content-Type, they execute."},
            {"title": "SVG Upload", "icon": "code-slash", "content": "Create an SVG file: <code>&lt;svg onload=\"alert(1)\"&gt;&lt;/svg&gt;</code>"},
            {"title": "Solution", "icon": "shield-check", "content": "Upload malicious SVG/HTML file and access it directly to execute scripts."}
        ]
    },
    {
        "level": 16, "title": "XSS in WebAssembly", "app_name": "WasmApp", "url": "wasm.local/execute",
        "objective": "Exploit WASM integration",
        "hints": [
            {"title": "WebAssembly Context", "icon": "lightbulb", "content": "WASM modules interact with JavaScript. Look for unsafe data passing between WASM and JS."},
            {"title": "WASM Exploitation", "icon": "code-slash", "content": "Inject malicious data that WASM passes to JavaScript functions."},
            {"title": "Solution", "icon": "shield-check", "content": "Exploit the WASM-JS bridge to execute arbitrary JavaScript."}
        ]
    },
    {
        "level": 17, "title": "XSS in Progressive Web Apps", "app_name": "PWA Store", "url": "pwa.app/install",
        "objective": "Exploit PWA vulnerabilities",
        "hints": [
            {"title": "PWA Architecture", "icon": "lightbulb", "content": "PWAs use service workers and manifest files. Look for XSS in cached resources."},
            {"title": "Service Worker XSS", "icon": "code-slash", "content": "Inject scripts that get cached by the service worker."},
            {"title": "Solution", "icon": "shield-check", "content": "Exploit service worker caching to persist XSS payloads."}
        ]
    },
    {
        "level": 18, "title": "XSS via Markdown", "app_name": "MarkdownEditor", "url": "markdown.local/preview",
        "objective": "Exploit Markdown parser",
        "hints": [
            {"title": "Markdown Parsers", "icon": "lightbulb", "content": "Markdown parsers convert text to HTML. Some allow raw HTML or have XSS vulnerabilities."},
            {"title": "Markdown XSS", "icon": "code-slash", "content": "Try: <code>[link](javascript:alert(1))</code> or raw HTML if allowed."},
            {"title": "Solution", "icon": "shield-check", "content": "Use Markdown syntax that generates malicious HTML."}
        ]
    },
    {
        "level": 19, "title": "XSS with WAF Bypass", "app_name": "ProtectedSite", "url": "protected.local/input",
        "objective": "Evade Web Application Firewall",
        "hints": [
            {"title": "WAF Detection", "icon": "lightbulb", "content": "WAFs block common XSS patterns. Test to identify what's blocked."},
            {"title": "Obfuscation Techniques", "icon": "code-slash", "content": "Use encoding, case variations, or uncommon tags to bypass WAF rules."},
            {"title": "Solution", "icon": "shield-check", "content": "Craft payloads that evade WAF signatures using obfuscation."}
        ]
    },
    {
        "level": 20, "title": "XSS via Polyglot", "app_name": "MultiContext", "url": "multi.local/render",
        "objective": "Create multi-context payloads",
        "hints": [
            {"title": "Polyglot Payloads", "icon": "lightbulb", "content": "Polyglots work in multiple contexts (HTML, JS, CSS). They're versatile XSS vectors."},
            {"title": "Crafting Polyglots", "icon": "code-slash", "content": "Create payloads that work in both HTML and JavaScript contexts."},
            {"title": "Solution", "icon": "shield-check", "content": "Use polyglot payloads that execute regardless of context."}
        ]
    },
    {
        "level": 21, "title": "XSS in Angular", "app_name": "AngularApp", "url": "angular.app/view",
        "objective": "Exploit Angular template injection",
        "hints": [
            {"title": "Angular Templates", "icon": "lightbulb", "content": "Angular uses {{}} for expressions. Test for template injection."},
            {"title": "Angular Sandbox", "icon": "code-slash", "content": "Try: <code>{{constructor.constructor('alert(1)')()}}</code>"},
            {"title": "Solution", "icon": "shield-check", "content": "Bypass Angular's sandbox to execute arbitrary JavaScript."}
        ]
    },
    {
        "level": 22, "title": "XSS in React", "app_name": "ReactApp", "url": "react.app/render",
        "objective": "Exploit React dangerouslySetInnerHTML",
        "hints": [
            {"title": "React XSS", "icon": "lightbulb", "content": "React escapes by default, but dangerouslySetInnerHTML bypasses this."},
            {"title": "Finding Vulnerable Code", "icon": "code-slash", "content": "Look for components using dangerouslySetInnerHTML with user input."},
            {"title": "Solution", "icon": "shield-check", "content": "Inject HTML through dangerouslySetInnerHTML to execute scripts."}
        ]
    },
    {
        "level": 23, "title": "Mutation XSS (mXSS)", "app_name": "DOMParser", "url": "parser.local/sanitize",
        "objective": "Exploit DOM mutations",
        "hints": [
            {"title": "Mutation XSS", "icon": "lightbulb", "content": "mXSS occurs when sanitized HTML mutates during DOM parsing, creating XSS."},
            {"title": "Mutation Vectors", "icon": "code-slash", "content": "Use payloads that change meaning after sanitization: <code>&lt;noscript&gt;&lt;p title=\"&lt;/noscript&gt;&lt;img src=x onerror=alert(1)&gt;\"&gt;</code>"},
            {"title": "Solution", "icon": "shield-check", "content": "Craft payloads that mutate during parsing to bypass sanitizers."}
        ]
    }
]

def generate_xss_template(challenge):
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
    
    template = f"""{{%extends 'base.html' %}}

{{%block title %}}Level {challenge['level']}: {challenge['title']} - R00tGlyph{{%endblock %}}

{{%block breadcrumb %}}
<span class="text-muted">Challenges</span> / <span class="text-muted">XSS</span> / <span>Level {challenge['level']}</span>
{{%endblock %}}

{{%block content %}}
<div class="challenge-lab">
    <!-- LEFT PANEL: Mission & Intel -->
    <div class="mission-panel">
        <div class="mission-header">
            <i class="bi bi-crosshair me-2"></i>Mission Control
        </div>
        <div class="mission-content">
            <h5 class="mb-3">{challenge['title']}</h5>
            <p class="text-secondary small mb-4">
                Welcome to <strong>{challenge['app_name']}</strong>. Test the security of this application.
            </p>

            <div class="card mb-4 border-0 bg-light">
                <div class="card-body p-3">
                    <h6 class="card-title small text-uppercase text-muted mb-2">Objective</h6>
                    <p class="mb-0 small">{challenge['objective']}</p>
                </div>
            </div>

            <!-- Integrated Hints System -->
            <div class="hint-accordion accordion" id="hintsAccordion">{hints_html}
            </div>

            {{%if xss_detected %}}
            <div class="flag-success mt-4">
                <div class="d-flex align-items-center gap-2 mb-2">
                    <i class="bi bi-check-circle-fill text-success"></i>
                    <strong>Mission Accomplished!</strong>
                </div>
                <p class="small text-secondary mb-2">You've successfully exploited the XSS vulnerability.</p>
                {{%if flag %}}
                <span class="flag-value">{{{{ flag }}}}</span>
                {{%endif %}}
            </div>
            {{%endif %}}
        </div>
    </div>

    <!-- RIGHT PANEL: The Vulnerable App -->
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
            <p class="text-muted">Challenge interface for XSS Level {challenge['level']}</p>
        </div>
    </div>
</div>
{{%endblock %}}
"""
    return template

if __name__ == '__main__':
    import os
    
    template_dir = 'templates/xss'
    os.makedirs(template_dir, exist_ok=True)
    
    for challenge in xss_challenges:
        template_content = generate_xss_template(challenge)
        filename = f"{template_dir}/xss_level{challenge['level']}.html"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(template_content)
        
        print(f"✅ Generated {filename}")
    
    print(f"\n✅ Successfully generated {len(xss_challenges)} XSS templates (Levels 3-23)!")
