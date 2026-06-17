import pytest
from app.models import LocalUser
from app.extensions import db
from werkzeug.security import generate_password_hash

def test_user_registration(client, app):
    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'password123',
        'confirm_password': 'password123',
        'display_name': 'Test User'
    })
    assert response.status_code == 302
    with app.app_context():
        user = LocalUser.query.filter_by(username='testuser').first()
        assert user is not None
        assert user.display_name == 'Test User'

def test_login(client, app):
    with app.app_context():
        user = LocalUser(username='testuser', password_hash=generate_password_hash('password123'), display_name='Test User')
        db.session.add(user)
        db.session.commit()
        
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'password123'
    })
    assert response.status_code == 302
    assert response.headers['Location'] == '/'
