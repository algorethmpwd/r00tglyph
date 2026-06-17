#!/usr/bin/env python3
"""
Automated test suite for R00tGlyph challenges
Tests all pages load correctly and themes work
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import os
os.environ['FLASK_ENV'] = 'testing'
os.environ['SECRET_KEY'] = 'test-secret'
@pytest.fixture(autouse=True)
def auto_login(client, app):
    with app.app_context():
        from app.models import LocalUser
        from werkzeug.security import generate_password_hash
        user = LocalUser.query.filter_by(username='test').first()
        if not user:
            user = LocalUser(username='test', password_hash=generate_password_hash('test'), display_name='Test')
            from app.extensions import db
            db.session.add(user)
            db.session.commit()
    client.post('/login', data={'username': 'test', 'password': 'test'})



def test_homepage(client):
    """Test homepage loads"""
    response = client.get('/')
    assert response.status_code == 200
    assert b'R00tGlyph' in response.data


def test_profile_page(client):
    """Test profile page loads"""
    response = client.get('/profile')
    assert response.status_code == 200
    assert b'Your Hacker Profile' in response.data


def test_scoreboard(client):
    """Test scoreboard loads"""
    response = client.get('/scoreboard')
    assert response.status_code == 200


def test_challenges_page(client):
    """Test challenges directory loads"""
    response = client.get('/challenges')
    assert response.status_code == 200


# Test all XSS challenges load
@pytest.mark.parametrize("level", range(1, 24))
def test_xss_levels(client, level):
    """Test all XSS challenge pages load"""
    response = client.get(f'/xss/level{level}')
    assert response.status_code == 200


# Test all SQLi challenges load
@pytest.mark.parametrize("level", range(1, 24))
def test_sqli_levels(client, level):
    """Test all SQLi challenge pages load"""
    response = client.get(f'/sqli/level{level}')
    assert response.status_code == 200


# Test all CSRF challenges load
@pytest.mark.parametrize("level", range(1, 16))
def test_csrf_levels(client, level):
    """Test all CSRF challenge pages load"""
    response = client.get(f'/csrf/level{level}')
    assert response.status_code == 200





if __name__ == '__main__':
    pytest.main([__file__, '-v'])
