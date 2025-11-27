#!/usr/bin/env python
"""
Initialize challenges in the database
This script populates the Challenge table with all available challenges
"""

from app import app, db, Challenge

def initialize_challenges():
    with app.app_context():
        # Check if challenges already exist
        existing_count = Challenge.query.count()
        if existing_count > 0:
            print(f"✅ Database already has {existing_count} challenges.")
            return
        
        print("Initializing challenges...")
        
        # Import the challenges data from app.py
        from app import challenges_data
        
        for challenge_data in challenges_data:
            challenge = Challenge(
                name=challenge_data['name'],
                category=challenge_data['category'],
                difficulty=challenge_data['difficulty'],
                description=challenge_data['description'],
                points=challenge_data['points'],
                active=True
            )
            db.session.add(challenge)
        
        db.session.commit()
        total = Challenge.query.count()
        print(f"✅ Successfully initialized {total} challenges!")

if __name__ == '__main__':
    initialize_challenges()
