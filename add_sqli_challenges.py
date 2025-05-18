#!/usr/bin/env python3
from app import app, db, Challenge

def add_sqli_challenges():
    """Add new SQL injection challenges to the database"""
    new_challenges = [
        {
            "name": "Second-Order SQL Injection",
            "category": "sqli",
            "difficulty": "advanced",
            "description": "Exploit a second-order SQL injection vulnerability where the payload is stored and executed later.",
            "points": 800,
            "active": True
        },
        {
            "name": "SQL Injection in REST API",
            "category": "sqli",
            "difficulty": "advanced",
            "description": "Exploit a SQL injection vulnerability in a REST API that accepts JSON data.",
            "points": 850,
            "active": True
        },
        {
            "name": "NoSQL Injection",
            "category": "sqli",
            "difficulty": "advanced",
            "description": "Exploit a NoSQL injection vulnerability in a MongoDB-based application.",
            "points": 900,
            "active": True
        },
        {
            "name": "GraphQL Injection",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit a GraphQL injection vulnerability to extract unauthorized data.",
            "points": 950,
            "active": True
        },
        {
            "name": "ORM-based SQL Injection",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit a SQL injection vulnerability in an application using an ORM.",
            "points": 1000,
            "active": True
        },
        {
            "name": "Out-of-band SQL Injection",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit an out-of-band SQL injection vulnerability using DNS or HTTP requests.",
            "points": 1050,
            "active": True
        },
        {
            "name": "SQL Injection with Advanced WAF Bypass",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Bypass advanced WAF protections to exploit a SQL injection vulnerability.",
            "points": 1100,
            "active": True
        },
        {
            "name": "SQL Injection via XML",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit a SQL injection vulnerability through XML parameters.",
            "points": 1150,
            "active": True
        },
        {
            "name": "SQL Injection in WebSockets",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit a SQL injection vulnerability in WebSocket messages.",
            "points": 1200,
            "active": True
        },
        {
            "name": "SQL Injection in Mobile App Backend",
            "category": "sqli",
            "difficulty": "expert",
            "description": "Exploit a SQL injection vulnerability in a mobile app's backend API.",
            "points": 1250,
            "active": True
        },
        {
            "name": "SQL Injection in Cloud Functions",
            "category": "sqli",
            "difficulty": "master",
            "description": "Exploit a SQL injection vulnerability in a serverless cloud function.",
            "points": 1300,
            "active": True
        },
        {
            "name": "SQL Injection via File Upload",
            "category": "sqli",
            "difficulty": "master",
            "description": "Exploit a SQL injection vulnerability through metadata in uploaded files.",
            "points": 1350,
            "active": True
        },
        {
            "name": "SQL Injection in Stored Procedures",
            "category": "sqli",
            "difficulty": "master",
            "description": "Exploit a SQL injection vulnerability in a stored procedure.",
            "points": 1400,
            "active": True
        },
        {
            "name": "SQL Injection in Microservices",
            "category": "sqli",
            "difficulty": "master",
            "description": "Exploit a SQL injection vulnerability in a microservices architecture.",
            "points": 1450,
            "active": True
        },
        {
            "name": "SQL Injection with Data Exfiltration via DNS",
            "category": "sqli",
            "difficulty": "master",
            "description": "Use DNS queries to exfiltrate data from a SQL injection vulnerability.",
            "points": 1500,
            "active": True
        },
        {
            "name": "Advanced Blind SQL Injection with Machine Learning Bypass",
            "category": "sqli",
            "difficulty": "master",
            "description": "Bypass machine learning-based protections to exploit a blind SQL injection vulnerability.",
            "points": 1550,
            "active": True
        }
    ]

    with app.app_context():
        # Check if challenges already exist
        for challenge_data in new_challenges:
            existing_challenge = Challenge.query.filter_by(name=challenge_data["name"]).first()
            if not existing_challenge:
                challenge = Challenge(**challenge_data)
                db.session.add(challenge)
                print(f"Added challenge: {challenge_data['name']}")
            else:
                print(f"Challenge already exists: {challenge_data['name']}")
        
        # Commit changes
        db.session.commit()
        
        # Verify all challenges
        print("\nAll SQL injection challenges in database:")
        for c in Challenge.query.filter_by(category="sqli").order_by(Challenge.id).all():
            print(f"{c.id}: {c.name} - Difficulty: {c.difficulty} - Points: {c.points}")

if __name__ == '__main__':
    add_sqli_challenges()
