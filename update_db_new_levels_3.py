from app import app, db, Challenge

with app.app_context():
    # Check if challenges 14 and 15 exist
    challenge14 = Challenge.query.filter_by(name="XSS via Prototype Pollution").first()
    challenge15 = Challenge.query.filter_by(name="XSS via Template Injection").first()
    
    # Add challenge 14 if it doesn't exist
    if not challenge14:
        challenge14 = Challenge(
            name="XSS via Prototype Pollution", 
            category="xss", 
            difficulty="expert",
            description="Exploit prototype pollution to achieve XSS.", 
            points=1300,
            active=True
        )
        db.session.add(challenge14)
        print("Added challenge 14: XSS via Prototype Pollution")
    
    # Add challenge 15 if it doesn't exist
    if not challenge15:
        challenge15 = Challenge(
            name="XSS via Template Injection", 
            category="xss", 
            difficulty="expert",
            description="Exploit template injection to achieve XSS.", 
            points=1400,
            active=True
        )
        db.session.add(challenge15)
        print("Added challenge 15: XSS via Template Injection")
    
    # Commit changes
    db.session.commit()
    
    # Verify all challenges
    challenges = Challenge.query.all()
    print("\nAll challenges in database:")
    for c in challenges:
        print(f"{c.id}: {c.name} - Active: {c.active}")
