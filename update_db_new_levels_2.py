from app import app, db, Challenge

with app.app_context():
    # Check if challenges 12 and 13 exist
    challenge12 = Challenge.query.filter_by(name="Blind XSS with Webhook Exfiltration").first()
    challenge13 = Challenge.query.filter_by(name="XSS in PDF Generation").first()
    
    # Add challenge 12 if it doesn't exist
    if not challenge12:
        challenge12 = Challenge(
            name="Blind XSS with Webhook Exfiltration", 
            category="xss", 
            difficulty="expert",
            description="Exploit a blind XSS vulnerability and exfiltrate data.", 
            points=1100,
            active=True
        )
        db.session.add(challenge12)
        print("Added challenge 12: Blind XSS with Webhook Exfiltration")
    
    # Add challenge 13 if it doesn't exist
    if not challenge13:
        challenge13 = Challenge(
            name="XSS in PDF Generation", 
            category="xss", 
            difficulty="expert",
            description="Exploit an XSS vulnerability in PDF generation.", 
            points=1200,
            active=True
        )
        db.session.add(challenge13)
        print("Added challenge 13: XSS in PDF Generation")
    
    # Commit changes
    db.session.commit()
    
    # Verify all challenges
    challenges = Challenge.query.all()
    print("\nAll challenges in database:")
    for c in challenges:
        print(f"{c.id}: {c.name} - Active: {c.active}")
