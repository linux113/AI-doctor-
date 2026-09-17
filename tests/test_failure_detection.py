"""
Tests for intentional failure generation and incident detection.
"""

from fastapi.testclient import TestClient
from backend.main import app
from runner.remediation import stop_ollama, start_ollama

client = TestClient(app)


def test_failure_detection_yields_500_and_creates_incident():
    # Stop Ollama to induce failure
    stop_ollama()

    response = client.post("/api/demo/query", json={"prompt": "Diagnose connection failure"})
    assert response.status_code == 500
    data = response.json()
    assert data["status"] == "error"
    assert "ConnectionRefusedError" in data["error"]
    assert "incident_id" in data
    assert data["incident_status"] == "DETECTED"

    # Verify incident was persisted
    incident_id = data["incident_id"]
    inc_resp = client.get(f"/api/incidents/{incident_id}")
    assert inc_resp.status_code == 200
    inc_data = inc_resp.json()
    assert inc_data["incident_id"] == incident_id
    assert inc_data["status"] == "DETECTED"
    assert inc_data["http_status"] == 500
    assert len(inc_data["timeline"]) >= 1
    assert inc_data["timeline"][0]["stage"] == "DETECTED"

    # Clean up
    start_ollama()
