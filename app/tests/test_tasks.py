from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_create_task():
    ip = "127.0.0.1"
    response = client.post("/api/v1/task", json={"ip": ip})
    assert response.status_code == 200
    assert "task_id" in response.json()

def test_get_task_status():
    ip = "127.0.0.1"
    create_task_response = client.post("/api/v1/task", json={"ip": ip})
    task_id = create_task_response.json()["task_id"]
    status_response = client.get(f"/api/v1/status/{task_id}")
    assert status_response.status_code == 200
    assert "status" in status_response.json()
