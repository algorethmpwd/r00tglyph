from app import app, db, Challenge

with app.app_context():
    # Check if challenges 10 and 11 exist
    challenge10 = Challenge.query.filter_by(name="XSS with Mutation Observer Bypass").first()
    challenge11 = Challenge.query.filter_by(name="XSS via SVG and CDATA").first()
    
    # Add challenge 10 if it doesn't exist
    if not challenge10:
        challenge10 = Challenge(
            name="XSS with Mutation Observer Bypass", 
            category="xss", 
            difficulty="expert",
            description="Bypass DOM sanitization with Mutation Observers.", 
            points=900,
            active=True
        )
        db.session.add(challenge10)
        print("Added challenge 10: XSS with Mutation Observer Bypass")
    
    # Add challenge 11 if it doesn't exist
    if not challenge11:
        challenge11 = Challenge(
            name="XSS via SVG and CDATA", 
            category="xss", 
            difficulty="expert",
            description="Exploit SVG features to execute JavaScript.", 
            points=1000,
            active=True
        )
        db.session.add(challenge11)
        print("Added challenge 11: XSS via SVG and CDATA")
    
    # Commit changes
    db.session.commit()
    
    # Verify all challenges
    challenges = Challenge.query.all()
    print("\nAll challenges in database:")
    for c in challenges:
        print(f"{c.id}: {c.name} - Active: {c.active}")
