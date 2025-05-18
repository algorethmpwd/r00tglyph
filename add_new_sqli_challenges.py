#!/usr/bin/env python3
from app import app, db
from models import Challenge

def add_new_sqli_challenges():
    """Add the new SQL injection challenges to the database"""
    with app.app_context():
        # Define the new challenges
        new_challenges = [
            {
                'name': 'SQL Injection with Advanced WAF Bypass',
                'category': 'SQL Injection',
                'description': 'Learn how to bypass advanced Web Application Firewalls (WAFs) using sophisticated SQL injection techniques.',
                'difficulty': 'Hard',
                'points': 300
            },
            {
                'name': 'SQL Injection via XML',
                'category': 'SQL Injection',
                'description': 'Exploit SQL injection vulnerabilities in XML processing to access sensitive data.',
                'difficulty': 'Hard',
                'points': 300
            },
            {
                'name': 'SQL Injection in WebSockets',
                'category': 'SQL Injection',
                'description': 'Discover and exploit SQL injection vulnerabilities in real-time WebSocket communications.',
                'difficulty': 'Hard',
                'points': 300
            },
            {
                'name': 'SQL Injection in Mobile App Backend',
                'category': 'SQL Injection',
                'description': 'Exploit SQL injection vulnerabilities in mobile application backend APIs.',
                'difficulty': 'Hard',
                'points': 300
            },
            {
                'name': 'SQL Injection in Cloud Functions',
                'category': 'SQL Injection',
                'description': 'Discover and exploit SQL injection vulnerabilities in serverless cloud functions.',
                'difficulty': 'Hard',
                'points': 300
            },
            {
                'name': 'SQL Injection via File Upload',
                'category': 'SQL Injection',
                'description': 'Exploit SQL injection vulnerabilities in file upload processing to access sensitive data.',
                'difficulty': 'Hard',
                'points': 300
            },
            {
                'name': 'SQL Injection in Stored Procedures',
                'category': 'SQL Injection',
                'description': 'Discover and exploit SQL injection vulnerabilities in database stored procedures.',
                'difficulty': 'Hard',
                'points': 300
            }
        ]
        
        # Add the new challenges to the database
        for challenge_data in new_challenges:
            # Check if the challenge already exists
            existing_challenge = Challenge.query.filter_by(name=challenge_data['name']).first()
            if not existing_challenge:
                # Create a new challenge
                challenge = Challenge(
                    name=challenge_data['name'],
                    category=challenge_data['category'],
                    description=challenge_data['description'],
                    difficulty=challenge_data['difficulty'],
                    points=challenge_data['points']
                )
                db.session.add(challenge)
                print(f"Added challenge: {challenge_data['name']}")
            else:
                print(f"Challenge already exists: {challenge_data['name']}")
        
        # Commit the changes
        db.session.commit()
        print("All new SQL injection challenges added to the database")

if __name__ == '__main__':
    add_new_sqli_challenges()
