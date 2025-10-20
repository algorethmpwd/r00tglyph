#!/usr/bin/env python3
"""
Challenge generation script for R00tGlyph
Quickly generates challenge templates for new categories
"""

SSTI_CHALLENGES = [
    # Beginner (1-5)
    {
        "level": 1,
        "title": "Basic Jinja2 Template Injection",
        "difficulty": "beginner",
        "description": "A simple Flask application renders user input directly in a Jinja2 template. Find a way to execute arbitrary code.",
        "points": 100,
        "framework": "Jinja2",
        "context": "A greeting card generator that takes your name and creates a personalized message.",
    },
    {
        "level": 2,
        "title": "Twig Template Injection",
        "difficulty": "beginner",
        "description": "This PHP application uses Twig templates. User input is rendered without proper sanitization.",
        "points": 100,
        "framework": "Twig",
        "context": "An email template builder for a marketing platform.",
    },
    {
        "level": 3,
        "title": "Freemarker SSTI",
        "difficulty": "beginner",
        "description": "A Java web app uses Freemarker templates. Exploit the template injection to read sensitive files.",
        "points": 100,
        "framework": "Freemarker",
        "context": "A document generation service for creating invoices.",
    },
    {
        "level": 4,
        "title": "Velocity Template Injection",
        "difficulty": "beginner",
        "description": "This application uses Apache Velocity. Find the SSTI vulnerability in the template rendering.",
        "points": 100,
        "framework": "Velocity",
        "context": "A blog post preview generator.",
    },
    {
        "level": 5,
        "title": "Pug/Jade SSTI",
        "difficulty": "beginner",
        "description": "A Node.js application uses Pug templates. User-controlled input is passed to template compilation.",
        "points": 150,
        "framework": "Pug",
        "context": "A resume builder application.",
    },

    # Intermediate (6-10)
    {
        "level": 6,
        "title": "SSTI with Basic Filter",
        "difficulty": "intermediate",
        "description": "Template injection with basic blacklist filter. Bypass filters that block common payloads.",
        "points": 150,
        "framework": "Jinja2",
        "context": "A web analytics dashboard with filtered template rendering.",
    },
    {
        "level": 7,
        "title": "SSTI in Error Messages",
        "difficulty": "intermediate",
        "description": "Error messages are rendered through templates. Trigger an error with malicious payload.",
        "points": 150,
        "framework": "Jinja2",
        "context": "A form validation system that shows custom error messages.",
    },
    {
        "level": 8,
        "title": "SSTI with WAF",
        "difficulty": "intermediate",
        "description": "Web Application Firewall blocks common SSTI payloads. Find creative bypasses.",
        "points": 200,
        "framework": "Twig",
        "context": "An e-commerce product description generator.",
    },
    {
        "level": 9,
        "title": "Blind SSTI",
        "difficulty": "intermediate",
        "description": "No direct output visible. Use time-based or out-of-band techniques to confirm exploitation.",
        "points": 200,
        "framework": "Jinja2",
        "context": "A background job processor that logs template rendering.",
    },
    {
        "level": 10,
        "title": "SSTI in Email Templates",
        "difficulty": "intermediate",
        "description": "User input is rendered in email templates. Exploit SSTI to execute commands on the mail server.",
        "points": 200,
        "framework": "Freemarker",
        "context": "An automated email marketing system.",
    },

    # Advanced (11-17)
    {
        "level": 11,
        "title": "SSTI with Sandboxed Environment",
        "difficulty": "advanced",
        "description": "Template engine runs in a sandbox. Escape the sandbox to achieve RCE.",
        "points": 250,
        "framework": "Jinja2",
        "context": "A code playground for testing Python templates.",
    },
    {
        "level": 12,
        "title": "SSTI in React SSR",
        "difficulty": "advanced",
        "description": "Server-side rendering in React with template strings. Exploit the SSR vulnerability.",
        "points": 250,
        "framework": "React",
        "context": "A Next.js application with dynamic page generation.",
    },
    {
        "level": 13,
        "title": "SSTI via PDF Generation",
        "difficulty": "advanced",
        "description": "User input is used in PDF templates. Exploit SSTI during PDF generation process.",
        "points": 250,
        "framework": "Jinja2",
        "context": "An invoice PDF generator for a SaaS billing system.",
    },
    {
        "level": 14,
        "title": "Polyglot SSTI Payload",
        "difficulty": "advanced",
        "description": "Application uses multiple template engines. Craft payload that works across engines.",
        "points": 300,
        "framework": "Mixed",
        "context": "A multi-tenant platform supporting various template formats.",
    },
    {
        "level": 15,
        "title": "SSTI in Custom Template Engine",
        "difficulty": "advanced",
        "description": "A custom-built template engine with unique syntax. Reverse engineer and exploit.",
        "points": 300,
        "framework": "Custom",
        "context": "A proprietary content management system.",
    },
    {
        "level": 16,
        "title": "SSTI with Character Limit",
        "difficulty": "advanced",
        "description": "Strict character limit on user input. Craft minimal SSTI payload under 30 characters.",
        "points": 300,
        "framework": "Jinja2",
        "context": "A Twitter-like microblogging platform.",
    },
    {
        "level": 17,
        "title": "SSTI in GraphQL Resolver",
        "difficulty": "advanced",
        "description": "GraphQL resolvers use templates for dynamic field resolution. Exploit SSTI in resolver.",
        "points": 300,
        "framework": "Jinja2",
        "context": "A GraphQL API gateway with template-based transformations.",
    },

    # Expert (18-23)
    {
        "level": 18,
        "title": "SSTI in Kubernetes ConfigMaps",
        "difficulty": "expert",
        "description": "Template injection in Kubernetes ConfigMap generation. Escape to cluster control.",
        "points": 350,
        "framework": "Helm",
        "context": "A Kubernetes deployment automation platform.",
    },
    {
        "level": 19,
        "title": "SSTI in Serverless Functions",
        "difficulty": "expert",
        "description": "AWS Lambda function uses templates for response generation. Exploit in serverless context.",
        "points": 350,
        "framework": "Jinja2",
        "context": "A serverless API for generating dynamic content.",
    },
    {
        "level": 20,
        "title": "SSTI Chain with XXE",
        "difficulty": "expert",
        "description": "Combine SSTI with XXE to achieve file read and RCE. Multi-step exploitation required.",
        "points": 400,
        "framework": "Freemarker",
        "context": "A document processing pipeline.",
    },
    {
        "level": 21,
        "title": "SSTI in Microservices",
        "difficulty": "expert",
        "description": "Exploit SSTI in one microservice to pivot to others. Chain multiple vulnerabilities.",
        "points": 400,
        "framework": "Twig",
        "context": "A distributed e-commerce platform.",
    },
    {
        "level": 22,
        "title": "SSTI in CI/CD Pipeline",
        "difficulty": "expert",
        "description": "Template injection in GitHub Actions/GitLab CI configs. Compromise build pipeline.",
        "points": 400,
        "framework": "YAML",
        "context": "A continuous integration platform.",
    },
    {
        "level": 23,
        "title": "SSTI in Cloud Functions",
        "difficulty": "expert",
        "description": "Google Cloud Functions with template rendering. Exploit to access cloud metadata API.",
        "points": 500,
        "framework": "Jinja2",
        "context": "A cloud-native data processing platform.",
    },
]

DESERIAL_CHALLENGES = [
    # Beginner (1-5)
    {
        "level": 1,
        "title": "Basic Python Pickle Deserialization",
        "difficulty": "beginner",
        "description": "Exploit insecure deserialization of Python pickle objects to execute arbitrary code.",
        "points": 100,
        "language": "Python",
        "context": "A session management system using pickled session data.",
    },
    {
        "level": 2,
        "title": "PHP Unserialize Vulnerability",
        "difficulty": "beginner",
        "description": "PHP unserialize() function processes user-controlled data. Achieve remote code execution.",
        "points": 100,
        "language": "PHP",
        "context": "A content management system with object caching.",
    },
    {
        "level": 3,
        "title": "Java Deserialization RCE",
        "difficulty": "beginner",
        "description": "Java application deserializes untrusted data. Use gadget chains for code execution.",
        "points": 100,
        "language": "Java",
        "context": "A legacy enterprise application server.",
    },
    {
        "level": 4,
        "title": ".NET BinaryFormatter Exploit",
        "difficulty": "beginner",
        "description": "Exploit .NET BinaryFormatter deserialization to gain remote code execution.",
        "points": 100,
        "language": ".NET",
        "context": "A Windows service with network communication.",
    },
    {
        "level": 5,
        "title": "Node.js node-serialize",
        "difficulty": "beginner",
        "description": "Node.js application uses node-serialize library. Exploit deserialization vulnerability.",
        "points": 150,
        "language": "JavaScript",
        "context": "A real-time messaging application.",
    },

    # Add more levels...
]

AUTH_CHALLENGES = [
    # Beginner (1-5)
    {
        "level": 1,
        "title": "SQL Injection Auth Bypass",
        "difficulty": "beginner",
        "description": "Login form vulnerable to SQL injection. Bypass authentication without valid credentials.",
        "points": 100,
        "technique": "SQL Injection",
        "context": "A corporate intranet login portal.",
    },
    {
        "level": 2,
        "title": "Default Credentials",
        "difficulty": "beginner",
        "description": "Admin interface uses common default credentials. Find and use them to gain access.",
        "points": 100,
        "technique": "Default Creds",
        "context": "An IoT device management dashboard.",
    },
    {
        "level": 3,
        "title": "Password Reset Token Bypass",
        "difficulty": "beginner",
        "description": "Password reset tokens are predictable. Generate valid token for admin account.",
        "points": 100,
        "technique": "Token Prediction",
        "context": "A social media platform password recovery.",
    },
    {
        "level": 4,
        "title": "Session Fixation",
        "difficulty": "beginner",
        "description": "Application doesn't regenerate session IDs after login. Exploit session fixation.",
        "points": 100,
        "technique": "Session Attack",
        "context": "An online banking simulation.",
    },
    {
        "level": 5,
        "title": "JWT None Algorithm",
        "difficulty": "beginner",
        "description": "JWT tokens accept 'none' algorithm. Bypass signature verification.",
        "points": 150,
        "technique": "JWT Exploit",
        "context": "A microservices API gateway.",
    },

    # Add more levels...
]


def generate_template(category, challenge):
    """Generate a challenge template file"""
    level = challenge['level']

    template = f'''{{%extends 'components/base_challenge.html' %}}

{{%block challenge_content %}}
<div class="card">
    <div class="card-header">
        <h5><i class="bi bi-info-circle me-2"></i>Scenario</h5>
    </div>
    <div class="card-body">
        <p><strong>Context:</strong> {challenge['context']}</p>
        {f'<p><strong>Framework/Language:</strong> {challenge.get("framework", challenge.get("language", challenge.get("technique", "N/A")))}</p>' if any(k in challenge for k in ['framework', 'language', 'technique']) else ''}
        <p><strong>Your Mission:</strong> Exploit the vulnerability to capture the flag.</p>
    </div>
</div>

<div class="card mt-3">
    <div class="card-header">
        <h5><i class="bi bi-laptop me-2"></i>Vulnerable Application</h5>
    </div>
    <div class="card-body">
        <!-- Challenge-specific interactive content will go here -->
        <form method="POST">
            <div class="mb-3">
                <label for="payload" class="form-label">Enter your payload:</label>
                <textarea class="form-control" id="payload" name="payload" rows="5" placeholder="Your exploit payload here..."></textarea>
            </div>
            <button type="submit" class="btn btn-primary">
                <i class="bi bi-play-fill me-1"></i>Execute
            </button>
        </form>

        {{%if result %}}
        <div class="alert alert-secondary mt-3">
            <strong>Output:</strong>
            <pre>{{{{ result }}}}</pre>
        </div>
        {{%endif %}}
    </div>
</div>
{{%endblock %}}
'''

    return template


if __name__ == '__main__':
    import os

    categories = {
        'ssti': SSTI_CHALLENGES,
        'deserial': DESERIAL_CHALLENGES[:5],  # Only generate 5 for now
        'auth': AUTH_CHALLENGES[:5],  # Only generate 5 for now
    }

    for category, challenges in categories.items():
        print(f"\nGenerating {category.upper()} challenges...")
        for challenge in challenges:
            level = challenge['level']
            filename = f"templates/{category}/{category}_level{level}.html"

            # Set variables for template
            content = generate_template(category, challenge)

            # Prepend variable declarations
            category_upper = category.upper()
            var_block = f'''{{%- set level_number = {level} -%}}
{{%- set category = "{category_upper}" -%}}
{{%- set category_lower = "{category}" -%}}
{{%- set title = "{challenge['title']}" -%}}
{{%- set difficulty = "{challenge['difficulty']}" -%}}
{{%- set description = "{challenge['description']}" -%}}
{{%- set challenge_id = {category}_level{level}_id -%}}

'''
            content = var_block + content

            # Write file
            with open(filename, 'w') as f:
                f.write(content)

            print(f"  ✓ Created {filename}")

    print("\n✅ Challenge generation complete!")
    print(f"\nNext steps:")
    print(f"1. Update app.py with routes for new challenges")
    print(f"2. Add challenges to database via update_db.py")
    print(f"3. Implement backend logic for each challenge")
