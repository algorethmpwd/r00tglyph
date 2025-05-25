#!/usr/bin/env python3
from app import app, db, Challenge

def initialize_challenges():
    """Initialize all challenges in the database with modern, realistic contexts"""

    # XSS Challenges (23 levels) - Modern web application contexts
    xss_challenges = [
        {
            "name": "Basic Reflected XSS",
            "category": "xss",
            "difficulty": "beginner",
            "description": "Exploit a reflected XSS vulnerability in a modern e-commerce search feature.",
            "points": 100,
            "active": True
        },
        {
            "name": "DOM-based XSS",
            "category": "xss",
            "difficulty": "beginner",
            "description": "Find DOM-based XSS in a React-based social media platform.",
            "points": 200,
            "active": True
        },
        {
            "name": "Stored XSS",
            "category": "xss",
            "difficulty": "intermediate",
            "description": "Exploit stored XSS in a healthcare patient portal comment system.",
            "points": 300,
            "active": True
        },
        {
            "name": "XSS with Basic Filters",
            "category": "xss",
            "difficulty": "intermediate",
            "description": "Bypass basic XSS filters in a fintech banking application.",
            "points": 400,
            "active": True
        },
        {
            "name": "XSS with Advanced Filters",
            "category": "xss",
            "difficulty": "advanced",
            "description": "Bypass advanced XSS filters in a cloud-based CRM system.",
            "points": 500,
            "active": True
        },
        {
            "name": "XSS with ModSecurity WAF",
            "category": "xss",
            "difficulty": "advanced",
            "description": "Bypass ModSecurity WAF in an enterprise API gateway.",
            "points": 600,
            "active": True
        },
        {
            "name": "XSS via HTTP Headers",
            "category": "xss",
            "difficulty": "advanced",
            "description": "Exploit XSS via HTTP headers in a microservices architecture.",
            "points": 700,
            "active": True
        },
        {
            "name": "XSS in JSON API",
            "category": "xss",
            "difficulty": "advanced",
            "description": "Exploit XSS in a GraphQL API used by a mobile banking app.",
            "points": 750,
            "active": True
        },
        {
            "name": "XSS with CSP Bypass",
            "category": "xss",
            "difficulty": "expert",
            "description": "Bypass Content Security Policy in a Progressive Web App.",
            "points": 800,
            "active": True
        },
        {
            "name": "XSS with Mutation Observer Bypass",
            "category": "xss",
            "difficulty": "expert",
            "description": "Bypass DOM sanitization in a real-time collaboration platform.",
            "points": 900,
            "active": True
        },
        {
            "name": "XSS via SVG and CDATA",
            "category": "xss",
            "difficulty": "expert",
            "description": "Exploit SVG features in a digital asset management system.",
            "points": 1000,
            "active": True
        },
        {
            "name": "Blind XSS with Webhook Exfiltration",
            "category": "xss",
            "difficulty": "expert",
            "description": "Exploit blind XSS in an admin panel using webhook exfiltration.",
            "points": 1100,
            "active": True
        },
        {
            "name": "XSS in PDF Generation",
            "category": "xss",
            "difficulty": "expert",
            "description": "Exploit XSS in a serverless PDF generation service.",
            "points": 1200,
            "active": True
        },
        {
            "name": "XSS via Prototype Pollution",
            "category": "xss",
            "difficulty": "expert",
            "description": "Chain prototype pollution to achieve XSS in a Node.js application.",
            "points": 1300,
            "active": True
        },
        {
            "name": "XSS via Template Injection",
            "category": "xss",
            "difficulty": "expert",
            "description": "Exploit template injection in a Vue.js e-learning platform.",
            "points": 1400,
            "active": True
        },
        {
            "name": "XSS in WebAssembly Applications",
            "category": "xss",
            "difficulty": "expert",
            "description": "Find XSS vulnerabilities in a WebAssembly-powered game platform.",
            "points": 1500,
            "active": True
        },
        {
            "name": "XSS in Progressive Web Apps",
            "category": "xss",
            "difficulty": "expert",
            "description": "Exploit XSS in a PWA food delivery application.",
            "points": 1600,
            "active": True
        },
        {
            "name": "XSS via Web Components",
            "category": "xss",
            "difficulty": "expert",
            "description": "Exploit XSS in Web Components and Shadow DOM of an IoT dashboard.",
            "points": 1700,
            "active": True
        },
        {
            "name": "XSS in GraphQL APIs",
            "category": "xss",
            "difficulty": "expert",
            "description": "Exploit XSS in GraphQL API responses of a social media platform.",
            "points": 1800,
            "active": True
        },
        {
            "name": "XSS in WebRTC Applications",
            "category": "xss",
            "difficulty": "expert",
            "description": "Exploit XSS in a WebRTC-based video conferencing platform.",
            "points": 1900,
            "active": True
        },
        {
            "name": "XSS via Web Bluetooth/USB",
            "category": "xss",
            "difficulty": "expert",
            "description": "Exploit XSS in Web Bluetooth/USB APIs of an IoT management portal.",
            "points": 2000,
            "active": True
        },
        {
            "name": "XSS in WebGPU Applications",
            "category": "xss",
            "difficulty": "expert",
            "description": "Exploit XSS in WebGPU-powered 3D visualization applications.",
            "points": 2100,
            "active": True
        },
        {
            "name": "XSS in Federated Identity Systems",
            "category": "xss",
            "difficulty": "expert",
            "description": "Exploit XSS in SAML/OAuth federated identity systems.",
            "points": 2200,
            "active": True
        }
    ]

    # SQL Injection Challenges (23 levels) - Modern database contexts
    sqli_challenges = [
        {
            "name": "Basic SQL Injection",
            "category": "sqli",
            "difficulty": "beginner",
            "description": "Exploit basic SQL injection in a modern e-commerce login system.",
            "points": 100,
            "active": True
        },
        {
            "name": "SQL Injection in Search",
            "category": "sqli",
            "difficulty": "beginner",
            "description": "Find SQL injection in a cloud-based inventory management search.",
            "points": 200,
            "active": True
        },
        {
            "name": "SQL Injection with UNION",
            "category": "sqli",
            "difficulty": "intermediate",
            "description": "Use UNION-based injection in a healthcare patient database.",
            "points": 300,
            "active": True
        },
        {
            "name": "Blind SQL Injection",
            "category": "sqli",
            "difficulty": "intermediate",
            "description": "Exploit blind SQL injection in a fintech user verification system.",
            "points": 400,
            "active": True
        },
        {
            "name": "Time-Based Blind SQL Injection",
            "category": "sqli",
            "difficulty": "advanced",
            "description": "Use time-based techniques in a microservices API gateway.",
            "points": 500,
            "active": True
        },
        {
            "name": "SQL Injection with WAF Bypass",
            "category": "sqli",
            "difficulty": "advanced",
            "description": "Bypass WAF protection in an enterprise CRM system.",
            "points": 600,
            "active": True
        },
        {
            "name": "Second-Order SQL Injection",
            "category": "sqli",
            "difficulty": "advanced",
            "description": "Exploit second-order injection in a social media profile system.",
            "points": 700,
            "active": True
        },
        {
            "name": "SQL Injection in JSON Parameters",
            "category": "sqli",
            "difficulty": "advanced",
            "description": "Find injection in JSON API parameters of a mobile banking app.",
            "points": 750,
            "active": True
        },
        {
            "name": "SQL Injection with SQLMap",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Use SQLMap to exploit complex injection in a real estate platform.",
            "points": 800,
            "active": True
        },
        {
            "name": "SQL Injection in Stored Procedures",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit stored procedure injection in a legacy banking system.",
            "points": 900,
            "active": True
        },
        {
            "name": "ORM-based SQL Injection",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Find injection vulnerabilities in Django ORM queries.",
            "points": 1000,
            "active": True
        },
        {
            "name": "SQL Injection in XML Parameters",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit injection in XML-based SOAP API of an insurance system.",
            "points": 1100,
            "active": True
        },
        {
            "name": "SQL Injection with Burp Suite",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Use Burp Suite Intruder to exploit injection in an IoT device portal.",
            "points": 1200,
            "active": True
        },
        {
            "name": "SQL Injection in Column Names",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit column name injection in a Laravel-based e-learning platform.",
            "points": 1300,
            "active": True
        },
        {
            "name": "SQL Injection in ORDER BY",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit ORDER BY injection in a data analytics dashboard.",
            "points": 1400,
            "active": True
        },
        {
            "name": "SQL Injection with Error-Based Extraction",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Use error-based techniques in a containerized microservice.",
            "points": 1500,
            "active": True
        },
        {
            "name": "SQL Injection in LIMIT Clause",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit LIMIT clause injection in a serverless API function.",
            "points": 1600,
            "active": True
        },
        {
            "name": "SQL Injection with Boolean-Based Blind",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Use boolean-based blind techniques in a CI/CD pipeline dashboard.",
            "points": 1700,
            "active": True
        },
        {
            "name": "SQL Injection in Subqueries",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit subquery injection in a multi-tenant SaaS platform.",
            "points": 1800,
            "active": True
        },
        {
            "name": "SQL Injection with Out-of-Band",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Use out-of-band techniques in an air-gapped enterprise system.",
            "points": 1900,
            "active": True
        },
        {
            "name": "GraphQL SQL Injection",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit SQL injection through GraphQL resolvers in a social platform.",
            "points": 2000,
            "active": True
        },
        {
            "name": "NoSQL Injection",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit NoSQL injection in a MongoDB-based content management system.",
            "points": 2100,
            "active": True
        },
        {
            "name": "SQL Injection in Cloud Databases",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit injection in AWS RDS through a serverless application.",
            "points": 2200,
            "active": True
        }
    ]

    # Command Injection Challenges (23 levels) - Modern system contexts
    cmdi_challenges = [
        {
            "name": "Basic Command Injection",
            "category": "cmdi",
            "difficulty": "beginner",
            "description": "Exploit basic command injection in a cloud server monitoring tool.",
            "points": 100,
            "active": True
        },
        {
            "name": "Command Injection with Filters",
            "category": "cmdi",
            "difficulty": "beginner",
            "description": "Bypass basic filters in a DevOps deployment pipeline.",
            "points": 200,
            "active": True
        },
        {
            "name": "Blind Command Injection",
            "category": "cmdi",
            "difficulty": "intermediate",
            "description": "Exploit blind command injection in a container orchestration platform.",
            "points": 300,
            "active": True
        },
        {
            "name": "Command Injection via File Upload",
            "category": "cmdi",
            "difficulty": "intermediate",
            "description": "Chain file upload with command injection in a document management system.",
            "points": 400,
            "active": True
        },
        {
            "name": "Command Injection in API Parameters",
            "category": "cmdi",
            "difficulty": "advanced",
            "description": "Exploit injection in REST API parameters of a microservices gateway.",
            "points": 500,
            "active": True
        },
        {
            "name": "Command Injection with WAF Bypass",
            "category": "cmdi",
            "difficulty": "advanced",
            "description": "Bypass WAF protection in an enterprise network management tool.",
            "points": 600,
            "active": True
        },
        {
            "name": "Time-Based Blind Command Injection",
            "category": "cmdi",
            "difficulty": "advanced",
            "description": "Use time-based techniques in a serverless function monitoring system.",
            "points": 700,
            "active": True
        },
        {
            "name": "Command Injection with Burp Suite",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Use Burp Suite to exploit injection in an IoT device management portal.",
            "points": 800,
            "active": True
        },
        {
            "name": "Command Injection in JSON APIs",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Exploit injection in JSON API calls of a CI/CD automation platform.",
            "points": 900,
            "active": True
        },
        {
            "name": "Command Injection via Environment Variables",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Exploit injection through environment variables in a containerized app.",
            "points": 1000,
            "active": True
        },
        {
            "name": "Command Injection in XML Processing",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Exploit injection in XML processing of a legacy enterprise system.",
            "points": 1100,
            "active": True
        },
        {
            "name": "Command Injection with Nmap",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Use Nmap to exploit network scanning functionality in a security tool.",
            "points": 1200,
            "active": True
        },
        {
            "name": "Command Injection in GraphQL",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Exploit injection through GraphQL mutations in a data analytics platform.",
            "points": 1300,
            "active": True
        },
        {
            "name": "Command Injection via WebSockets",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Exploit injection through WebSocket messages in a real-time monitoring system.",
            "points": 1400,
            "active": True
        },
        {
            "name": "Command Injection in Serverless Functions",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Exploit injection in AWS Lambda functions of a data processing pipeline.",
            "points": 1500,
            "active": True
        },
        {
            "name": "Command Injection with Process Substitution",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Use process substitution techniques in a Linux-based automation tool.",
            "points": 1600,
            "active": True
        },
        {
            "name": "Command Injection in Container Environments",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Exploit injection to escape Docker containers in a Kubernetes cluster.",
            "points": 1700,
            "active": True
        },
        {
            "name": "Command Injection via Template Engines",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Exploit injection through template engines in a report generation system.",
            "points": 1800,
            "active": True
        },
        {
            "name": "Command Injection in Message Queues",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Exploit injection through message queue processing in a distributed system.",
            "points": 1900,
            "active": True
        },
        {
            "name": "Command Injection with Out-of-Band",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Use out-of-band techniques in an air-gapped industrial control system.",
            "points": 2000,
            "active": True
        },
        {
            "name": "Command Injection in Cloud Functions",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Exploit injection in Google Cloud Functions of a data processing pipeline.",
            "points": 2100,
            "active": True
        },
        {
            "name": "Command Injection via SSH Commands",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Exploit injection in SSH command execution of a remote management tool.",
            "points": 2200,
            "active": True
        },
        {
            "name": "Advanced Command Injection Chaining",
            "category": "cmdi",
            "difficulty": "expert",
            "description": "Chain multiple injection techniques in a complex enterprise infrastructure.",
            "points": 2300,
            "active": True
        }
    ]

    # Combine all challenges
    all_challenges = xss_challenges + sqli_challenges + cmdi_challenges

    with app.app_context():
        # Clear existing challenges
        Challenge.query.delete()

        # Add new challenges
        for challenge_data in all_challenges:
            challenge = Challenge(**challenge_data)
            db.session.add(challenge)

        # Commit changes
        db.session.commit()

        # Verify all challenges
        print("\n=== R00tGlyph Challenge Database Initialized ===")
        print(f"Total challenges added: {len(all_challenges)}")

        # Count by category
        xss_count = len([c for c in all_challenges if c['category'] == 'xss'])
        sqli_count = len([c for c in all_challenges if c['category'] == 'sqli'])
        cmdi_count = len([c for c in all_challenges if c['category'] == 'cmdi'])

        print(f"XSS challenges: {xss_count}")
        print(f"SQL Injection challenges: {sqli_count}")
        print(f"Command Injection challenges: {cmdi_count}")

        # Verify database contents
        print("\nDatabase verification:")
        for category in ['xss', 'sqli', 'cmdi']:
            challenges = Challenge.query.filter_by(category=category).all()
            print(f"{category.upper()}: {len(challenges)} challenges")

        print("\nDatabase initialization complete!")

if __name__ == '__main__':
    initialize_challenges()