#!/usr/bin/env python3
from app import app, db, Challenge

def add_sqli_challenges():
    """Add SQL Injection challenges to the database"""
    sqli_challenges = [
        {
            "name": "Basic SQL Injection",
            "category": "sqli",
            "difficulty": "beginner",
            "description": "Find and exploit a basic SQL injection vulnerability in a login form.",
            "points": 100,
            "active": True
        },
        {
            "name": "SQL Injection in Search",
            "category": "sqli",
            "difficulty": "beginner",
            "description": "Exploit a SQL injection vulnerability in a product search feature.",
            "points": 200,
            "active": True
        },
        {
            "name": "SQL Injection with UNION",
            "category": "sqli",
            "difficulty": "intermediate",
            "description": "Use UNION-based SQL injection to extract data from other tables.",
            "points": 300,
            "active": True
        },
        {
            "name": "Blind SQL Injection",
            "category": "sqli",
            "difficulty": "intermediate",
            "description": "Exploit a blind SQL injection vulnerability to extract data.",
            "points": 400,
            "active": True
        },
        {
            "name": "Time-Based Blind SQL Injection",
            "category": "sqli",
            "difficulty": "advanced",
            "description": "Use time-based techniques to extract data from a blind SQL injection vulnerability.",
            "points": 500,
            "active": True
        },
        {
            "name": "SQL Injection with WAF Bypass",
            "category": "sqli",
            "difficulty": "advanced",
            "description": "Bypass a Web Application Firewall (WAF) to exploit a SQL injection vulnerability.",
            "points": 600,
            "active": True
        }
    ]

    with app.app_context():
        # Check if challenges already exist
        existing_challenges = Challenge.query.filter_by(category="sqli").all()
        if existing_challenges:
            print("SQL Injection challenges already exist in the database.")
            print("Existing challenges:")
            for c in existing_challenges:
                print(f"{c.id}: {c.name} - Active: {c.active}")
            return

        # Add new challenges
        for challenge_data in sqli_challenges:
            challenge = Challenge(**challenge_data)
            db.session.add(challenge)
        
        # Commit changes
        db.session.commit()
        
        # Verify all challenges
        print("\nAll SQL Injection challenges in database:")
        for c in Challenge.query.filter_by(category="sqli").all():
            print(f"{c.id}: {c.name} - Active: {c.active}")

if __name__ == '__main__':
    add_sqli_challenges()
