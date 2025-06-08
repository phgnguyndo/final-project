# tests/test_auth.py
import pytest
from app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_register(client):
    response = client.post('/api/auth/register', json={
        'username': 'testuser',
        'password': 'testpass',
        'full_name': 'Test User'
    })
    assert response.status_code == 201
    assert response.json['message'] == 'User registered successfully'

def test_login(client):
    client.post('/api/auth/register', json={
        'username': 'testuser',
        'password': 'testpass',
        'full_name': 'Test User'
    })
    
    response = client.post('/api/auth/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    assert response.status_code == 200
    assert 'access_token' in response.json

def test_current_user(client):
    client.post('/api/auth/register', json={
        'username': 'testuser',
        'password': 'testpass',
        'full_name': 'Test User'
    })
    login_response = client.post('/api/auth/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    token = login_response.json['access_token']
    
    response = client.get('/api/auth/me', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert response.json['username'] == 'testuser'
    assert response.json['full_name'] == 'Test User'