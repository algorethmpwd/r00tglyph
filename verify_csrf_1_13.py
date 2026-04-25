import requests
import sys

BASE_URL = "http://127.0.0.1:5000"

def get_authenticated_session():
    session = requests.Session()
    username = "test_csrf_verifier"
    password = "test_password"
    
    # Try to register
    reg_data = {
        "username": username,
        "password": password,
        "confirm_password": password
    }
    try:
        session.post(f"{BASE_URL}/register", data=reg_data)
    except requests.exceptions.RequestException:
        pass

    # Login
    login_data = {
        "username": username,
        "password": password
    }
    response = session.post(f"{BASE_URL}/login", data=login_data)
    return session

def verify_level(session, level_num):
    url = f"{BASE_URL}/csrf/level{level_num}"
    try:
        response = session.get(url)
        if response.status_code == 200:
            # Check for generic "Mission Control" text which should be in all levels
            if "Mission Control" in response.text:
                print(f"[PASS] /csrf/level{level_num}: 200 OK")
                return True
            else:
                print(f"[FAIL] /csrf/level{level_num}: 200 OK but 'Mission Control' not found")
                # print(response.text[:200]) # Debug
                return False
        else:
            print(f"[FAIL] /csrf/level{level_num}: Status Code {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not connect to {url}: {e}")
        return False

def main():
    print("Verifying CSRF Levels 1-13...")
    session = get_authenticated_session()
    
    # List of levels to verify
    levels = range(1, 14)

    all_passed = True
    for level_num in levels:
        if not verify_level(session, level_num):
            all_passed = False

    if all_passed:
        print("\nAll CSRF levels 1-13 accessible and contain basic structure.")
    else:
        print("\nSome verification checks failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
