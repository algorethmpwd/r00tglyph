#!/usr/bin/env python3
"""Generate hints and solutions JSON files for all R00tGlyph challenges."""
import json
import os

HINTS_DIR = "data/hints"
SOLUTIONS_DIR = "data/solutions"

os.makedirs(HINTS_DIR, exist_ok=True)
os.makedirs(SOLUTIONS_DIR, exist_ok=True)

CHALLENGES = {}
for cat in ["xss", "sqli", "cmdi", "csrf", "ssrf", "xxe", "ssti", "deserial", "auth"]:
    CHALLENGES[cat] = {}

CHALLENGES["xss"] = {
        1: {
            "name": "Basic Reflected XSS",
            "hints": [
                "Look at how user input is reflected in the page.",
                "Try submitting a simple script tag in the name parameter.",
                "The input is reflected without any encoding or sanitization."
            ],
            "solution": "Submit <script>alert('XSS')</script> in the name parameter. The application reflects user input directly into the HTML without sanitization, allowing arbitrary JavaScript execution.",
            "prevention": "Always encode user input before rendering it in HTML. Use frameworks' built-in escaping functions and implement Content Security Policy headers."
        },
        2: {
            "name": "DOM-based XSS",
            "hints": [
                "This vulnerability exists in the client-side JavaScript, not server-side.",
                "Check how the URL parameters are used in JavaScript.",
                "Look for document.write or innerHTML usage with URL parameters."
            ],
            "solution": "Use a payload like ?name=<script>alert('XSS')</script>. The JavaScript reads the URL parameter and writes it directly to the DOM using document.write or innerHTML without sanitization.",
            "prevention": "Never use document.write or innerHTML with user-controlled data. Use textContent instead, or sanitize input with DOMPurify before inserting into the DOM."
        },
        3: {
            "name": "Stored XSS",
            "hints": [
                "This vulnerability persists across page loads and sessions.",
                "Try submitting a comment with a script tag.",
                "The stored content is rendered for all users who view the page."
            ],
            "solution": "Submit a comment containing <script>alert('XSS')</script>. The comment is stored in the database and rendered without sanitization when other users view the page.",
            "prevention": "Sanitize all user input before storing it. Use output encoding when rendering stored content. Implement Content Security Policy headers."
        },
        4: {
            "name": "XSS with Basic Filters",
            "hints": [
                "The application filters <script> tags but other vectors exist.",
                "Try using event handlers like onerror on img tags.",
                "The filter only removes exact matches of <script> and </script>."
            ],
            "solution": "Use <img src=x onerror=\"alert('XSS')\">. The basic filter only removes script tags but doesn't sanitize event handlers on other HTML elements.",
            "prevention": "Implement comprehensive input sanitization that removes all HTML tags and event handlers. Use allowlists instead of blocklists."
        },
        5: {
            "name": "XSS with Advanced Filters",
            "hints": [
                "The filter converts input to lowercase and removes common vectors.",
                "Try using SVG elements with onload handlers.",
                "The filter doesn't catch all HTML elements that can execute JavaScript."
            ],
            "solution": "Use <svg onload=\"alert('XSS')\">. The advanced filter removes script tags and common event handlers but misses SVG elements.",
            "prevention": "Use a comprehensive HTML sanitization library. Implement strict Content Security Policy. Validate input against an allowlist of safe characters."
        },
        6: {
            "name": "XSS with ModSecurity WAF",
            "hints": [
                "The WAF blocks common XSS patterns but has gaps.",
                "Try using iframe with srcdoc attribute.",
                "The WAF doesn't check all possible XSS vectors."
            ],
            "solution": "Use <iframe srcdoc=\"<script>alert('XSS')<\/script>\">. The WAF rules don't cover iframe srcdoc attribute injection.",
            "prevention": "Keep WAF rules updated. Implement defense in depth with input validation, output encoding, and CSP headers."
        },
        7: {
            "name": "XSS via HTTP Headers",
            "hints": [
                "The User-Agent header is reflected in the page.",
                "Use a proxy tool to modify the User-Agent header.",
                "Try injecting script tags in the User-Agent."
            ],
            "solution": "Set the User-Agent header to <script>alert('XSS')</script>. The application displays the User-Agent without sanitization.",
            "prevention": "Never reflect HTTP headers in HTML output without encoding. Treat all HTTP headers as untrusted input."
        },
        8: {
            "name": "XSS in JSON API",
            "hints": [
                "The API returns JSON that is rendered in the page.",
                "Look for how the JSON response is processed client-side.",
                "Try injecting payloads in the note title."
            ],
            "solution": "Inject <img src=x onerror=\"alert('XSS Level 8 Completed!');\"> in the note title via the API. The frontend renders the JSON response without escaping.",
            "prevention": "Set Content-Type: application/json header. Sanitize API responses before rendering. Use DOMPurify for client-side sanitization."
        },
        9: {
            "name": "XSS with CSP Bypass",
            "hints": [
                "The CSP allows scripts from cdnjs.cloudflare.com.",
                "Look for JSONP endpoints or exploitable scripts on allowed domains.",
                "Try using inline event handlers which may not be blocked."
            ],
            "solution": "The CSP misconfiguration allows 'unsafe-inline' for styles and permits external scripts. Exploit by finding a bypass vector in the allowed domains or using event handlers.",
            "prevention": "Use strict CSP with nonce-based or hash-based script allowlisting. Never use 'unsafe-inline' or 'unsafe-eval'."
        },
        10: {
            "name": "XSS with Mutation Observer Bypass",
            "hints": [
                "The Mutation Observer removes malicious nodes after insertion.",
                "Try using mutation XSS (mXSS) techniques.",
                "Some payloads can survive DOM sanitization."
            ],
            "solution": "Use mXSS techniques where the payload transforms after the Mutation Observer checks it. For example, using nested elements that restructure after DOM parsing.",
            "prevention": "Use established sanitization libraries like DOMPurify. Don't rely on custom Mutation Observer implementations for security."
        }
    }

# Generate remaining XSS levels 11-30
for i in range(11, 31):
    CHALLENGES["xss"][i] = {
        "name": f"XSS Level {i}",
        "hints": [
            f"Analyze the application context for level {i}.",
            "Look for input vectors that aren't properly sanitized.",
            "Consider alternative XSS vectors beyond script tags."
        ],
        "solution": f"Submit a payload containing 'alert(\"XSS Level {i} Completed!\")' to trigger the XSS detection mechanism.",
        "prevention": "Implement comprehensive input validation, output encoding, and Content Security Policy headers."
    }

# SQLi challenges
for i in range(1, 24):
    CHALLENGES["sqli"][i] = {
        "name": f"SQLi Level {i}",
        "hints": [
            "Try injecting a single quote (') to test for SQL injection.",
            "Look for error messages that reveal database information.",
            f"Use UNION-based or boolean-based techniques for level {i}."
        ],
        "solution": f"Inject SQL payloads to extract data or bypass authentication. Common patterns include ' OR 1=1--, UNION SELECT, and boolean-based blind injection.",
        "prevention": "Use parameterized queries/prepared statements. Never concatenate user input into SQL queries. Implement input validation and least privilege database accounts."
    }

# CMDi challenges
for i in range(1, 24):
    CHALLENGES["cmdi"][i] = {
        "name": f"CMDi Level {i}",
        "hints": [
            "Try command separators like ; | & to chain commands.",
            "Look for input that gets passed to system commands.",
            "Use command substitution with $() or backticks."
        ],
        "solution": f"Inject command separators and system commands like whoami, id, or cat /etc/passwd. Bypass filters using encoding or alternative syntax.",
        "prevention": "Never pass user input to system commands. Use language-specific APIs instead of shell commands. Implement strict input validation."
    }

# CSRF challenges
for i in range(1, 24):
    CHALLENGES["csrf"][i] = {
        "name": f"CSRF Level {i}",
        "hints": [
            "Check if the form has any CSRF token protection.",
            "Try crafting a malicious form that auto-submits.",
            "Look for predictable or missing anti-CSRF tokens."
        ],
        "solution": f"Create a malicious form/page that submits a request to the vulnerable endpoint. Exploit missing or weak CSRF protections.",
        "prevention": "Implement anti-CSRF tokens. Use SameSite cookie attribute. Validate Origin and Referer headers. Require re-authentication for sensitive actions."
    }

# SSRF challenges
for i in range(1, 24):
    CHALLENGES["ssrf"][i] = {
        "name": f"SSRF Level {i}",
        "hints": [
            "Try providing internal IP addresses like 127.0.0.1 or 169.254.169.254.",
            "Look for URL parameters that fetch external resources.",
            "Try DNS rebinding or URL encoding to bypass filters."
        ],
        "solution": f"Provide URLs pointing to internal services or cloud metadata endpoints. Bypass URL validation using encoding, redirects, or DNS tricks.",
        "prevention": "Validate and whitelist allowed URLs. Block requests to internal IP ranges. Use network-level controls. Implement allowlists for domains."
    }

# XXE challenges
for i in range(1, 24):
    CHALLENGES["xxe"][i] = {
        "name": f"XXE Level {i}",
        "hints": [
            "Try injecting a DOCTYPE with external entity declarations.",
            "Use SYSTEM entities to read local files.",
            "Try parameter entities for blind XXE attacks."
        ],
        "solution": f"Inject XML with <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]> to read files or <!ENTITY xxe SYSTEM \"http://internal\"> for SSRF.",
        "prevention": "Disable external entity processing in XML parsers. Use less complex data formats like JSON. Implement input validation."
    }

# SSTI challenges
for i in range(1, 24):
    CHALLENGES["ssti"][i] = {
        "name": f"SSTI Level {i}",
        "hints": [
            "Try injecting {{7*7}} to test for template injection.",
            "Look for input that gets rendered in templates.",
            "Access configuration or class objects through template syntax."
        ],
        "solution": f"Use template syntax like {{config}} or {{self.__dict__}} to access sensitive data. Escalate to RCE using {{''.__class__.__mro__[2].__subclasses__()}}.",
        "prevention": "Never render user input in templates. Use sandboxed template engines. Implement input validation and output encoding."
    }

# Deserialization challenges
for i in range(1, 11):
    CHALLENGES["deserial"][i] = {
        "name": f"Deserialization Level {i}",
        "hints": [
            "Try submitting serialized payloads with malicious objects.",
            "Look for pickle, PHP serialize, or other serialization formats.",
            "Craft payloads with __reduce__ or magic methods for code execution."
        ],
        "solution": f"Submit a serialized payload containing a malicious object that executes code when deserialized. Use __reduce__ in Python or magic methods in PHP.",
        "prevention": "Never deserialize untrusted data. Use safe serialization formats like JSON. Implement integrity checks on serialized data."
    }

# Auth challenges
for i in range(1, 11):
    CHALLENGES["auth"][i] = {
        "name": f"Auth Level {i}",
        "hints": [
            "Try common authentication bypass techniques.",
            "Look for SQL injection in login forms.",
            "Check for weak token generation or JWT vulnerabilities."
        ],
        "solution": f"Exploit authentication weaknesses like SQL injection in login, JWT algorithm confusion, or predictable session tokens.",
        "prevention": "Use strong authentication mechanisms. Implement proper session management. Use secure JWT algorithms. Implement rate limiting on login attempts."
    }

# Write all hints and solutions
for category, levels in CHALLENGES.items():
    for level_num, data in levels.items():
        # Write hints
        hint_file = os.path.join(HINTS_DIR, f"{category}_level{level_num}.json")
        hint_data = {
            "challenge": data["name"],
            "category": category,
            "level": level_num,
            "hints": data["hints"]
        }
        with open(hint_file, 'w') as f:
            json.dump(hint_data, f, indent=2)

        # Write solutions
        solution_file = os.path.join(SOLUTIONS_DIR, f"{category}_level{level_num}.json")
        solution_data = {
            "challenge": data["name"],
            "category": category,
            "level": level_num,
            "solution": data["solution"],
            "prevention": data["prevention"]
        }
        with open(solution_file, 'w') as f:
            json.dump(solution_data, f, indent=2)

print(f"Generated hints for {sum(len(v) for v in CHALLENGES.values())} challenges")
print(f"Generated solutions for {sum(len(v) for v in CHALLENGES.values())} challenges")
print(f"Hints directory: {HINTS_DIR}")
print(f"Solutions directory: {SOLUTIONS_DIR}")
