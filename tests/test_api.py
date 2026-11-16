
from fastapi.testclient import TestClient

from api.main import app


client = TestClient(app)


def test_api_home():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "online"


def test_analyze_suspicious_event():
    event = {
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc abc123",
        "parent_process": "cmd.exe",
    }

    response = client.post("/analyze", json=event)

    assert response.status_code == 200

    data = response.json()

    assert data["detection"]["suspicious"] is True
    assert data["detection"]["risk"] == "high"
    assert data["mitre_attack"]["technique_id"] == "T1059.001"


def test_analyze_normal_event():
    event = {
        "process_name": "notepad.exe",
        "command_line": "notepad.exe",
        "parent_process": "explorer.exe",
    }

    response = client.post("/analyze", json=event)

    assert response.status_code == 200

    data = response.json()

    assert data["detection"]["suspicious"] is False
    assert data["detection"]["risk"] == "low"
    assert data["mitre_attack"] is None
