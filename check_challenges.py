from app import app, Challenge

with app.app_context():
    challenges = Challenge.query.all()
    print(f"Total challenges: {len(challenges)}")
    for c in challenges:
        print(f"{c.id}. {c.name} ({c.category})")
