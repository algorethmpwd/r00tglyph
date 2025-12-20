import requests
import sys

BASE_URL = "http://127.0.0.1:5000"

def get_authenticated_session():
    session = requests.Session()
    # Register a new user
    username = "test_verifier"
    password = "test_password"
    
    # Try to register
    reg_data = {
        "username": username,
        "password": password,
        "confirm_password": password
    }
    try:
        session.post(f"{BASE_URL}/register", data=reg_data)
        # We don't care if it fails (e.g. user already exists), just proceed to login
    except requests.exceptions.RequestException:
        pass

    # Login
    login_data = {
        "username": username,
        "password": password
    }
    response = session.post(f"{BASE_URL}/login", data=login_data)
    
    if response.status_code == 200 and "Login successful" in response.text or response.url.endswith('/'):
        # Login success (either flash message or redirect to index)
        return session
    else:
        # Check if we were redirected to index or similar
        print("Login response URL:", response.url)
        return session

def verify_level(session, level_num, expected_content):
    url = f"{BASE_URL}/cmdi/level{level_num}"
    try:
        response = session.get(url)
        if response.status_code == 200:
            if expected_content in response.text:
                print(f"[PASS] /cmdi/level{level_num}: 200 OK")
                print(f"       Content Verified: found '{expected_content}'")
                return True
            else:
                print(f"[FAIL] /cmdi/level{level_num}: 200 OK but content mismatch")
                print(f"       Expected '{expected_content}' not found.")
                return False
        else:
            print(f"[FAIL] /cmdi/level{level_num}: Status Code {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not connect to {url}: {e}")
        return False

def main():
    print("Verifying CMDI Levels 1-10...")
    session = get_authenticated_session()
    
    levels = [
        (1, "Network Connectivity Tester"),
        (2, "Deployment Console"),
        (3, "System Notification Service"),
        (4, "Secure File Uploader"),
        (5, "Microservice Health Check"),
        (6, "Secure Network Scanner (WAF Enabled)"),
        (7, "Server Status Checker"),
        (8, "IoT Device Manager"),
        (9, "CI/CD Build Configuration"),
        (10, "Container Deployment")
    ]

    all_passed = True
    for level_num, content in levels:
        if not verify_level(session, level_num, content):
            all_passed = False

    if all_passed:
        print("\nAll CMDI levels 1-10 accessible and rendering correctly.")
    else:
        print("\nSome verification checks failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
