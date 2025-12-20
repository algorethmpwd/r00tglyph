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
    
    # Basic check to see if we are logged in (redirect or success message)
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
    print("Verifying CMDI Levels 11-23...")
    session = get_authenticated_session()
    
    levels = [
        (11, "Command Injection in XML"),
        (12, "Command Injection with Nmap"),
        (13, "Command Injection in GraphQL"),
        (14, "Command Injection via WebSockets"),
        (15, "Command Injection in Serverless Functions"),
        (16, "Advanced CMDI: Process Substitution"),
        (17, "Command Injection in Containers"),
        (18, "Command Injection via Template Engines"),
        (19, "Command Injection in Message Queues"),
        (20, "Out-of-Band Command Injection"),
        (21, "Command Injection in Cloud Functions"),
        (22, "Command Injection via SSH"),
        (23, "Advanced Command Injection Chaining")
    ]

    all_passed = True
    for level_num, content in levels:
        if not verify_level(session, level_num, content):
            all_passed = False

    if all_passed:
        print("\nAll CMDI levels 11-23 accessible and rendering correctly.")
    else:
        print("\nSome verification checks failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
