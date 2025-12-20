import sys
import os

# Add current directory to path so we can import app
sys.path.append(os.getcwd())

from app import app, db, LocalUser, Challenge
from flask_login import login_user

def verify_sqli_levels():
    print("Verifying SQLi Levels 1-10...")
    
    with app.test_client() as client:
        with app.app_context():
            # Create a test user
            user = LocalUser.query.filter_by(username="testverif").first()
            if not user:
                user = LocalUser(username="testverif", display_name="Test Verif", password_hash="hash")
                db.session.add(user)
                db.session.commit()
            
            # Login
            with client.session_transaction() as sess:
                sess['user_id'] = user.id
                sess['_fresh'] = True

        # List of endpoints to check
        endpoints = [
            "/sqli/level1",
            "/sqli/level2",
            "/sqli/level3",
            "/sqli/level4",
            "/sqli/level5",
            "/sqli/level6",
            "/sqli/level7",
            "/sqli/level8",
            "/sqli/level9",
            "/sqli/level10"
        ]

        failures = []
        for endpoint in endpoints:
            try:
                # GET request
                resp = client.get(endpoint, follow_redirects=True)
                if resp.status_code == 200:
                    print(f"[PASS] {endpoint}: 200 OK")
                    # Check if template rendered (basic check)
                    if b"Challenge interface" in resp.data or b"Mission Control" in resp.data:
                         print(f"       Content Verified.")
                    else:
                         print(f"       [WARN] Content might be missing.")
                else:
                    print(f"[FAIL] {endpoint}: {resp.status_code}")
                    failures.append(endpoint)
            except Exception as e:
                print(f"[ERROR] {endpoint}: {str(e)}")
                failures.append(endpoint)

        if failures:
            print(f"\nFailures: {failures}")
            sys.exit(1)
        else:
            print("\nAll SQLi levels accessible.")
            sys.exit(0)

if __name__ == "__main__":
    verify_sqli_levels()
