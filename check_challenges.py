#!/usr/bin/env python3
from app import app, db, Challenge

with app.app_context():
    # Check if our new challenges are already in the database
    new_challenges = ['NoSQL Injection', 'GraphQL Injection', 'ORM-based SQL Injection', 'Out-of-band SQL Injection']
    existing_challenges = Challenge.query.filter(Challenge.name.in_(new_challenges)).all()

    print("Existing challenges:")
    for challenge in existing_challenges:
        print(f"- {challenge.name} (ID: {challenge.id}, Points: {challenge.points})")

    # Check what challenges need to be added
    existing_names = [c.name for c in existing_challenges]
    missing_challenges = [name for name in new_challenges if name not in existing_names]

    print("\nMissing challenges that need to be added:")
    for name in missing_challenges:
        print(f"- {name}")

    # Print all SQL injection challenges
    print("\nAll SQL injection challenges:")
    sqli_challenges = Challenge.query.filter(Challenge.name.like('%SQL%')).order_by(Challenge.id).all()
    for challenge in sqli_challenges:
        print(f"- {challenge.name} (ID: {challenge.id}, Points: {challenge.points})")

    # Print total challenges
    challenges = Challenge.query.all()
    print(f"\nTotal challenges: {len(challenges)}")
