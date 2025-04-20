from app import app, db, Challenge

with app.app_context():
    # Check if challenges 7, 8, and 9 exist
    challenge7 = Challenge.query.filter_by(name="XSS via HTTP Headers").first()
    challenge8 = Challenge.query.filter_by(name="XSS in JSON API").first()
    challenge9 = Challenge.query.filter_by(name="XSS with CSP Bypass").first()
    
    # Add challenge 7 if it doesn't exist
    if not challenge7:
        challenge7 = Challenge(
            name="XSS via HTTP Headers", 
            category="xss", 
            difficulty="advanced",
            description="Exploit XSS vulnerabilities in HTTP header processing.", 
            points=600,
            active=True
        )
        db.session.add(challenge7)
        print("Added challenge 7: XSS via HTTP Headers")
    
    # Add challenge 8 if it doesn't exist
    if not challenge8:
        challenge8 = Challenge(
            name="XSS in JSON API", 
            category="xss", 
            difficulty="advanced",
            description="Exploit XSS vulnerabilities in JSON API responses.", 
            points=700,
            active=True
        )
        db.session.add(challenge8)
        print("Added challenge 8: XSS in JSON API")
    
    # Add challenge 9 if it doesn't exist
    if not challenge9:
        challenge9 = Challenge(
            name="XSS with CSP Bypass", 
            category="xss", 
            difficulty="expert",
            description="Bypass Content Security Policy protections.", 
            points=800,
            active=True
        )
        db.session.add(challenge9)
        print("Added challenge 9: XSS with CSP Bypass")
    
    # Commit changes
    db.session.commit()
    
    # Verify all challenges
    challenges = Challenge.query.all()
    print("\nAll challenges in database:")
    for c in challenges:
        print(f"{c.id}: {c.name} - Active: {c.active}")
