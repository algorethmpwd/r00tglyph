#!/usr/bin/env python3
"""
Add new challenges to the database
Run this after adding routes to app.py
"""
from app import app, db, Challenge

# Import challenge data from generate_challenges.py
import sys
sys.path.insert(0, '/home/algorethm/Documents/code/R00tGlyph')
from generate_challenges import SSTI_CHALLENGES, DESERIAL_CHALLENGES, AUTH_CHALLENGES


def add_challenges():
    with app.app_context():
        # Add SSTI challenges
        print("Adding SSTI challenges...")
        for challenge_data in SSTI_CHALLENGES:
            existing = Challenge.query.filter_by(
                category='ssti',
                name=f"SSTI Level {challenge_data['level']}"
            ).first()

            if not existing:
                challenge = Challenge(
                    name=f"SSTI Level {challenge_data['level']}",
                    category='ssti',
                    difficulty=challenge_data['difficulty'],
                    description=challenge_data['description'],
                    points=challenge_data['points'],
                    active=True
                )
                db.session.add(challenge)
                print(f"  ✓ Added SSTI Level {challenge_data['level']}")
            else:
                print(f"  - SSTI Level {challenge_data['level']} already exists")

        # Add Deserialization challenges
        print("\nAdding Deserialization challenges...")
        for challenge_data in DESERIAL_CHALLENGES:
            existing = Challenge.query.filter_by(
                category='deserial',
                name=f"Deserialization Level {challenge_data['level']}"
            ).first()

            if not existing:
                challenge = Challenge(
                    name=f"Deserialization Level {challenge_data['level']}",
                    category='deserial',
                    difficulty=challenge_data['difficulty'],
                    description=challenge_data['description'],
                    points=challenge_data['points'],
                    active=True
                )
                db.session.add(challenge)
                print(f"  ✓ Added Deserialization Level {challenge_data['level']}")
            else:
                print(f"  - Deserialization Level {challenge_data['level']} already exists")

        # Add Auth Bypass challenges
        print("\nAdding Auth Bypass challenges...")
        for challenge_data in AUTH_CHALLENGES:
            existing = Challenge.query.filter_by(
                category='auth',
                name=f"Auth Bypass Level {challenge_data['level']}"
            ).first()

            if not existing:
                challenge = Challenge(
                    name=f"Auth Bypass Level {challenge_data['level']}",
                    category='auth',
                    difficulty=challenge_data['difficulty'],
                    description=challenge_data['description'],
                    points=challenge_data['points'],
                    active=True
                )
                db.session.add(challenge)
                print(f"  ✓ Added Auth Bypass Level {challenge_data['level']}")
            else:
                print(f"  - Auth Bypass Level {challenge_data['level']} already exists")

        db.session.commit()
        print("\n✅ All challenges added to database!")

        # Print statistics
        total_challenges = Challenge.query.count()
        ssti_count = Challenge.query.filter_by(category='ssti').count()
        deserial_count = Challenge.query.filter_by(category='deserial').count()
        auth_count = Challenge.query.filter_by(category='auth').count()

        print(f"\n📊 Database Statistics:")
        print(f"  Total Challenges: {total_challenges}")
        print(f"  SSTI: {ssti_count}")
        print(f"  Deserialization: {deserial_count}")
        print(f"  Auth Bypass: {auth_count}")


if __name__ == '__main__':
    add_challenges()
