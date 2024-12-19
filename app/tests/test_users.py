from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_create_user():
    data = {
        "first_name": "Test",
        "last_name": "User",
        "email": "test@example.com",
        "password": "password"
    }
    response = client.post("/api/v1/signup", json=data)
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()

def test_user_authentication():
    data = {
        "email": "test@example.com",
        "password": "password"
    }
    response = client.post("/api/v1/auth", json=data)
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()
