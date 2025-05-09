#!/usr/bin/env python3
from app import app, db, Challenge

def initialize_challenges():
    """Initialize all challenges in the database"""
    challenges = [
        {
            "name": "Basic Reflected XSS",
            "category": "xss",
            "difficulty": "beginner",
            "description": "Find and exploit a basic reflected XSS vulnerability.",
            "points": 100,
            "active": True
        },
        {
            "name": "DOM-based XSS",
            "category": "xss",
            "difficulty": "beginner",
            "description": "Exploit a DOM-based XSS vulnerability.",
            "points": 200,
            "active": True
        },
        {
            "name": "Stored XSS",
            "category": "xss",
            "difficulty": "intermediate",
            "description": "Find and exploit a stored XSS vulnerability.",
            "points": 300,
            "active": True
        },
        {
            "name": "XSS with Basic Filters",
            "category": "xss",
            "difficulty": "intermediate",
            "description": "Bypass basic XSS filters.",
            "points": 400,
            "active": True
        },
        {
            "name": "XSS with Advanced Filters",
            "category": "xss",
            "difficulty": "advanced",
            "description": "Bypass advanced XSS filters.",
            "points": 500,
            "active": True
        },
        {
            "name": "XSS with ModSecurity WAF",
            "category": "xss",
            "difficulty": "advanced",
            "description": "Bypass ModSecurity WAF rules.",
            "points": 600,
            "active": True
        },
        {
            "name": "XSS via HTTP Headers",
            "category": "xss",
            "difficulty": "advanced",
            "description": "Exploit XSS via HTTP headers.",
            "points": 700,
            "active": True
        },
        {
            "name": "XSS in JSON API",
            "category": "xss",
            "difficulty": "advanced",
            "description": "Exploit XSS in a JSON API.",
            "points": 750,
            "active": True
        },
        {
            "name": "XSS with CSP Bypass",
            "category": "xss",
            "difficulty": "expert",
            "description": "Bypass Content Security Policy protections.",
            "points": 800,
            "active": True
        }
    ]

    with app.app_context():
        # Clear existing challenges
        Challenge.query.delete()
        
        # Add new challenges
        for challenge_data in challenges:
            challenge = Challenge(**challenge_data)
            db.session.add(challenge)
        
        # Commit changes
        db.session.commit()
        
        # Verify all challenges
        print("\nAll challenges in database:")
        for c in Challenge.query.all():
            print(f"{c.id}: {c.name} - Active: {c.active}")

if __name__ == '__main__':
    initialize_challenges()
