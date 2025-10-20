#!/usr/bin/env python3
"""
Automated test suite for R00tGlyph challenges
Tests all pages load correctly and themes work
"""
import pytest
import sys
sys.path.insert(0, '/home/algorethm/Documents/code/R00tGlyph')
from app import app, db

@pytest.fixture
def client():
    """Create test client"""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client


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


# Test theme consistency
def test_no_hardcoded_colors_in_templates():
    """Verify no hardcoded Bootstrap colors in templates"""
    import os
    import re

    templates_dir = '/home/algorethm/Documents/code/R00tGlyph/templates'
    violations = []

    for root, dirs, files in os.walk(templates_dir):
        for file in files:
            if file.endswith('.html'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r') as f:
                    content = f.read()
                    # Check for hardcoded color classes
                    if re.search(r'bg-dark text-white', content):
                        violations.append(f"{file}: Found hardcoded bg-dark text-white")
                    if re.search(r'bg-primary text-white', content):
                        violations.append(f"{file}: Found hardcoded bg-primary text-white")

    if violations:
        pytest.fail(f"Found hardcoded colors:\\n" + "\\n".join(violations))


def test_css_utility_classes_exist():
    """Verify all new CSS utility classes are defined"""
    css_file = '/home/algorethm/Documents/code/R00tGlyph/static/css/style.css'

    with open(css_file, 'r') as f:
        css_content = f.read()

    required_classes = [
        '.icon-lg',
        '.icon-xl',
        '.icon-xxl',
        '.progress-standard',
        '.mongodb-header',
        '.query-box',
        '.document-card',
    ]

    for class_name in required_classes:
        assert class_name in css_content, f"Missing CSS class: {class_name}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
