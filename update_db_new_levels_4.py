from app import app, db, Challenge

with app.app_context():
    # Check if the new challenges exist
    challenge16 = Challenge.query.filter_by(name="XSS in WebAssembly Applications").first()
    challenge17 = Challenge.query.filter_by(name="XSS in Progressive Web Apps").first()
    challenge18 = Challenge.query.filter_by(name="XSS via Web Components").first()
    challenge19 = Challenge.query.filter_by(name="XSS in GraphQL APIs").first()
    challenge20 = Challenge.query.filter_by(name="XSS in WebRTC Applications").first()
    challenge21 = Challenge.query.filter_by(name="XSS via Web Bluetooth/USB").first()
    challenge22 = Challenge.query.filter_by(name="XSS in WebGPU Applications").first()
    challenge23 = Challenge.query.filter_by(name="XSS in Federated Identity Systems").first()
    
    # Add challenge 16 if it doesn't exist
    if not challenge16:
        challenge16 = Challenge(
            name="XSS in WebAssembly Applications", 
            category="xss", 
            difficulty="expert",
            description="Exploit XSS vulnerabilities in WebAssembly applications.", 
            points=1500,
            active=True
        )
        db.session.add(challenge16)
        print("Added challenge 16: XSS in WebAssembly Applications")
    
    # Add challenge 17 if it doesn't exist
    if not challenge17:
        challenge17 = Challenge(
            name="XSS in Progressive Web Apps", 
            category="xss", 
            difficulty="expert",
            description="Exploit XSS vulnerabilities in Progressive Web Apps.", 
            points=1600,
            active=True
        )
        db.session.add(challenge17)
        print("Added challenge 17: XSS in Progressive Web Apps")
    
    # Add challenge 18 if it doesn't exist
    if not challenge18:
        challenge18 = Challenge(
            name="XSS via Web Components", 
            category="xss", 
            difficulty="expert",
            description="Exploit XSS vulnerabilities in Web Components and Shadow DOM.", 
            points=1700,
            active=True
        )
        db.session.add(challenge18)
        print("Added challenge 18: XSS via Web Components")
    
    # Add challenge 19 if it doesn't exist
    if not challenge19:
        challenge19 = Challenge(
            name="XSS in GraphQL APIs", 
            category="xss", 
            difficulty="expert",
            description="Exploit XSS vulnerabilities in GraphQL API responses.", 
            points=1800,
            active=True
        )
        db.session.add(challenge19)
        print("Added challenge 19: XSS in GraphQL APIs")
    
    # Add challenge 20 if it doesn't exist
    if not challenge20:
        challenge20 = Challenge(
            name="XSS in WebRTC Applications", 
            category="xss", 
            difficulty="expert",
            description="Exploit XSS vulnerabilities in WebRTC applications.", 
            points=1900,
            active=True
        )
        db.session.add(challenge20)
        print("Added challenge 20: XSS in WebRTC Applications")
    
    # Add challenge 21 if it doesn't exist
    if not challenge21:
        challenge21 = Challenge(
            name="XSS via Web Bluetooth/USB", 
            category="xss", 
            difficulty="expert",
            description="Exploit XSS vulnerabilities in Web Bluetooth/USB APIs.", 
            points=2000,
            active=True
        )
        db.session.add(challenge21)
        print("Added challenge 21: XSS via Web Bluetooth/USB")
    
    # Add challenge 22 if it doesn't exist
    if not challenge22:
        challenge22 = Challenge(
            name="XSS in WebGPU Applications", 
            category="xss", 
            difficulty="expert",
            description="Exploit XSS vulnerabilities in WebGPU applications.", 
            points=2100,
            active=True
        )
        db.session.add(challenge22)
        print("Added challenge 22: XSS in WebGPU Applications")
    
    # Add challenge 23 if it doesn't exist
    if not challenge23:
        challenge23 = Challenge(
            name="XSS in Federated Identity Systems", 
            category="xss", 
            difficulty="expert",
            description="Exploit XSS vulnerabilities in federated identity systems.", 
            points=2200,
            active=True
        )
        db.session.add(challenge23)
        print("Added challenge 23: XSS in Federated Identity Systems")
    
    # Commit changes
    db.session.commit()
    
    # Verify all challenges
    challenges = Challenge.query.all()
    print("\nAll challenges in database:")
    for c in challenges:
        print(f"{c.id}: {c.name} - Active: {c.active}")
